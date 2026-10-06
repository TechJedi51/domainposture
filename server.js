'use strict';

const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { version: PACKAGE_VERSION } = require('./package.json');
const { smtpDiagnostics, evaluateSmtpEvidence, smtpResult, smtpBannerHostname, smtpCapabilities, validHostname: validSmtpHostname, timingTest: smtpTimingTest, resolveSmtpProfile, smtpProfile } = require('./smtp');
const { spfCheck, tlsRptCheck, reputationCheck, validateTlsRptRecord, reverseIp } = require('./dns-security');
const sslMonitor = require('./ssl-monitor');

const PORT = Number(process.env.PORT || 8080);
const APP_VERSION = process.env.APP_VERSION || PACKAGE_VERSION;
const SETTINGS_PATH = process.env.DOMAINPOSTURE_SETTINGS_FILE || process.env.SETTINGS_PATH || '/data/settings.json';
const SECRETS_PATH = process.env.DOMAINPOSTURE_SECRETS_FILE || process.env.SECRETS_PATH || '/data/secrets.json';
const STATE_PATH = process.env.DOMAINPOSTURE_STATE_PATH || '/data/domainposture-state.json';
const PARSEDMARC_CONFIG_PATH = process.env.PARSEDMARC_CONFIG_PATH || '/data/parsedmarc/config.ini';
const PARSEDMARC_STATUS_PATH = process.env.PARSEDMARC_STATUS_PATH || '/run/parsedmarc/status.json';
const SERVICE_LOGS_ENABLED = String(process.env.SERVICE_LOGS_ENABLED || 'false').toLowerCase() === 'true';
const SERVICE_LOG_PATHS = {
  domainposture: process.env.DOMAINPOSTURE_LOG_PATH || process.env.MAILPOSTURE_LOG_PATH || '/data/logs/domainposture.log',
  mailposture: process.env.MAILPOSTURE_LOG_PATH || '/data/logs/mailposture.log',
  opensearch: process.env.OPENSEARCH_LOG_PATH || '/logs/opensearch',
  parsedmarc: process.env.PARSEDMARC_LOG_PATH || '/run/parsedmarc/parsedmarc.log'
};
const PUBLIC = path.join(__dirname, 'public');
const startedAt = Date.now();
let snapshot = { version: APP_VERSION, generated_at: null, refreshing: false, domains: [], summary: { critical: 0, warning: 0, ignored: 0, healthy: 0 } };
let activeRefresh = null;
let runtimeSettings = null;
let refreshTimer = null;
let requestTimeoutMs = 8000;
let operationalState = null;
const diagnosticEvents = [];
const diagnosticStates = new Map();
const bimiLogos = new Map();

function redactLogText(value) {
  return String(value || '')
    .replace(/\u001b\[[0-9;]*m/g, '')
    .replace(/((?:password|authorization|token|secret)["']?\s*[=:]\s*["']?)[^\s,;"']+/gi, '$1[REDACTED]');
}

function appendDomainpostureLog(level, service, message, detail) {
  if (!SERVICE_LOGS_ENABLED) return;
  const line = `${new Date().toISOString()} [${level.toUpperCase()}] [${service}] ${message}${detail ? ` — ${detail}` : ''}\n`;
  fs.promises.mkdir(path.dirname(SERVICE_LOG_PATHS.domainposture), { recursive: true })
    .then(() => fs.promises.appendFile(SERVICE_LOG_PATHS.domainposture, redactLogText(line), { mode: 0o600 }))
    .catch(() => {});
}

function addDiagnosticEvent(service, level, message, detail = '') {
  diagnosticEvents.push({
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    service,
    level,
    message,
    detail
  });
  if (diagnosticEvents.length > 300) diagnosticEvents.splice(0, diagnosticEvents.length - 300);
  appendDomainpostureLog(level, service, message, detail);
}

function diagnosticService(check) {
  if (check.id === 'opensearch' || check.id === 'report_indices') return 'opensearch';
  if (check.id.startsWith('parsedmarc')) return 'parsedmarc';
  return 'domainposture';
}

function recordSystemChecks(checks) {
  for (const check of checks) {
    const service = diagnosticService(check);
    const key = `${service}:${check.id}`;
    const signature = `${check.status}:${check.summary}`;
    if (diagnosticStates.get(key) === signature) continue;
    diagnosticStates.set(key, signature);
    addDiagnosticEvent(service, check.status === 'critical' ? 'error' : check.status === 'warning' ? 'warning' : 'info', check.summary, `${check.label}: ${check.detail}`);
  }
}

function diagnosticLog() {
  return { generated_at: new Date().toISOString(), events: [...diagnosticEvents].reverse() };
}

async function tailLogFile(filename, maxBytes = 262144) {
  const handle = await fs.promises.open(filename, 'r');
  try {
    const stat = await handle.stat();
    const length = Math.min(stat.size, maxBytes);
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, Math.max(0, stat.size - length));
    return { name: path.basename(filename), updated_at: stat.mtime.toISOString(), content: redactLogText(buffer.toString('utf8')).replace(/^.*\n/, stat.size > length ? '' : '$&') };
  } finally { await handle.close(); }
}

async function serviceLog(service) {
  if (!SERVICE_LOGS_ENABLED) return { service, available: false, reason: 'Service log viewing is disabled. Enable SERVICE_LOGS_ENABLED and use the standalone log mounts.' };
  const target = SERVICE_LOG_PATHS[service];
  if (!target) return { service, available: false, reason: 'Unknown service.' };
  try {
    const stat = await fs.promises.stat(target);
    if (stat.isFile()) {
      const file = await tailLogFile(target);
      return { service, available: true, files: [file] };
    }
    const entries = await fs.promises.readdir(target, { withFileTypes: true });
    const candidates = [];
    for (const entry of entries) {
      if (!entry.isFile() || !/\.(?:log|json|txt)$/i.test(entry.name)) continue;
      const filename = path.join(target, entry.name);
      const metadata = await fs.promises.stat(filename);
      candidates.push({ filename, mtime: metadata.mtimeMs });
    }
    candidates.sort((a, b) => b.mtime - a.mtime);
    const files = await Promise.all(candidates.slice(0, 8).map(candidate => tailLogFile(candidate.filename, 131072)));
    return files.length ? { service, available: true, files } : { service, available: false, reason: 'No log files are available yet.' };
  } catch (error) {
    return { service, available: false, reason: error.code === 'ENOENT' ? 'The service log volume is not mounted.' : error.message };
  }
}

function assignments(value) {
  const output = {};
  for (const item of String(value || '').split(';').map(v => v.trim()).filter(Boolean)) {
    const i = item.indexOf('=');
    if (i < 1) throw new Error(`Invalid mapping "${item}"; expected domain=value|value`);
    output[item.slice(0, i).trim().toLowerCase()] = item.slice(i + 1).split('|').map(v => v.trim()).filter(Boolean);
  }
  return output;
}

function endpointValue(value) {
  const match = String(value).trim().match(/^(.*?)(?::(\d+))?$/);
  return { host: match[1].toLowerCase().replace(/\.$/, ''), port: Number(match[2] || 443) };
}

function settingsFromEnv() {
  const domains = String(process.env.MONITORED_DOMAINS || '').split(',').map(v => v.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean);
  const selectors = assignments(process.env.DKIM_SELECTORS);
  const endpoints = assignments(process.env.TLS_ENDPOINTS);
  return normalizeSettings({
    monitored_domains: domains,
    dkim_selectors: selectors,
    tls_endpoints: Object.fromEntries(Object.entries(endpoints).map(([domain, values]) => [domain, values.map(endpointValue)])),
    smtp_probe_hostname: process.env.SMTP_PROBE_HOSTNAME || '',
    report_days: Number(process.env.REPORT_DAYS || 7),
    refresh_minutes: Number(process.env.REFRESH_MINUTES || 15),
    request_timeout_ms: Number(process.env.REQUEST_TIMEOUT_MS || 8000),
    opensearch_enabled: String(process.env.OPENSEARCH_ENABLED || 'true').toLowerCase() !== 'false'
  });
}

function validDomain(value) {
  return /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(value);
}

function boundedNumber(value, fallback, min, max, label) {
  const number = Number(value ?? fallback);
  if (!Number.isFinite(number) || number < min || number > max) throw new Error(`${label} must be between ${min} and ${max}`);
  return Math.round(number);
}

function boundedDecimal(value, fallback, min, max, label) {
  const number = Number(value ?? fallback);
  if (!Number.isFinite(number) || number < min || number > max) throw new Error(`${label} must be between ${min} and ${max}`);
  return number;
}

function textValue(value, fallback = '', max = 2048) {
  const normalized = String(value ?? fallback).trim();
  if (normalized.length > max || /[\r\n]/.test(normalized)) throw new Error('Settings contain an invalid text value');
  return normalized;
}

function validHttpUrl(value) {
  try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password; } catch (_) { return false; }
}

function validCron(value) {
  const fields = String(value || '').trim().split(/\s+/);
  if (fields.length !== 5) return false;
  const limits = [[0, 59], [0, 23], [1, 31], [1, 12], [0, 7]];
  return fields.every((field, index) => {
    if (!/^(?:\*|\d+)(?:[-/,](?:\*|\d+))*$/.test(field) || /\/0(?:\D|$)/.test(field)) return false;
    return (field.match(/\d+/g) || []).every(number => Number(number) >= limits[index][0] && Number(number) <= limits[index][1]);
  });
}

function normalizeBimiExceptions(input = {}, monitoredDomains = []) {
  const output = {};
  const normalizedException = (rawException, domain, label) => {
    const exception = rawException || {};
    if (exception.mode === 'permanent') return { mode: 'permanent' };
    if (exception.mode === 'until') {
      const timestamp = Date.parse(exception.expires_at);
      if (!Number.isFinite(timestamp)) throw new Error(`Invalid BIMI ${label} exception expiration for ${domain}`);
      return { mode: 'until', expires_at: new Date(timestamp).toISOString() };
    }
    return null;
  };
  for (const [rawDomain, rawException] of Object.entries(input || {})) {
    const domain = String(rawDomain).trim().toLowerCase().replace(/\.$/, '');
    if (!validDomain(domain) || !monitoredDomains.includes(domain)) continue;
    const exception = rawException || {};
    const selfAsserted = normalizedException(exception.self_asserted || (exception.mode ? exception : null), domain, 'self-asserted logo');
    const noLogo = normalizedException(exception.no_logo, domain, 'missing logo');
    if (selfAsserted || noLogo) output[domain] = { ...(selfAsserted ? { self_asserted: selfAsserted } : {}), ...(noLogo ? { no_logo: noLogo } : {}) };
  }
  return output;
}

function normalizeControlExceptions(input = {}, monitoredDomains = []) {
  const output = {};
  const normalizedException = (rawException, domain, label) => {
    const exception = rawException || {};
    if (exception.mode === 'permanent') return { mode: 'permanent' };
    if (exception.mode === 'until') {
      const timestamp = Date.parse(exception.expires_at);
      if (!Number.isFinite(timestamp)) throw new Error(`Invalid ${label} exception expiration for ${domain}`);
      return { mode: 'until', expires_at: new Date(timestamp).toISOString() };
    }
    return null;
  };
  for (const [rawDomain, rawExceptions] of Object.entries(input || {})) {
    const domain = String(rawDomain).trim().toLowerCase().replace(/\.$/, '');
    if (!validDomain(domain) || !monitoredDomains.includes(domain)) continue;
    const exceptions = rawExceptions || {};
    const mtaSts = normalizedException(exceptions.mta_sts, domain, 'MTA-STS');
    const tlsCertificates = normalizedException(exceptions.tls_certificates, domain, 'TLS certificate');
    if (mtaSts || tlsCertificates) output[domain] = { ...(mtaSts ? { mta_sts: mtaSts } : {}), ...(tlsCertificates ? { tls_certificates: tlsCertificates } : {}) };
  }
  return output;
}

function normalizeSmtpProfiles(input = {}, monitoredDomains = []) {
  const output = {};
  for (const [rawDomain, rawProfile] of Object.entries(input || {})) {
    const domain = String(rawDomain).trim().toLowerCase().replace(/\.$/, '');
    if (!validDomain(domain) || !monitoredDomains.includes(domain)) continue;
    const profile = rawProfile || {};
    const hostingType = ['auto', 'self_hosted', 'managed', 'no_inbound'].includes(profile.hosting_type) ? profile.hosting_type : 'auto';
    const provider = ['auto', 'kerio', 'google', 'microsoft', 'hover', 'icloud', 'self_hosted', 'other'].includes(profile.provider) ? profile.provider : 'auto';
    const relayContext = ['auto', 'external', 'internal'].includes(profile.relay_context) ? profile.relay_context : 'auto';
    const expectedHostname = textValue(profile.expected_hostname, '', 253).toLowerCase().replace(/\.$/, '');
    if (expectedHostname && !validDomain(expectedHostname)) throw new Error(`Invalid expected SMTP hostname for ${domain}`);
    output[domain] = { hosting_type: hostingType, provider, expected_hostname: expectedHostname, relay_context: relayContext };
  }
  return output;
}

function normalizeCertificateChecks(input = {}, monitoredDomains = []) {
  const output = {};
  for (const domain of monitoredDomains) {
    const configured = input?.[domain] || {};
    const checkPublic = configured.check_public === undefined
      ? configured.check_public_cert === undefined ? true : configured.check_public_cert !== false
      : configured.check_public !== false;
    const checkOrigin = configured.check_origin === true || configured.check_origin_cert === true;
    const originIp = textValue(configured.origin_ip, '', 64);
    if (!checkPublic && !checkOrigin) throw new Error(`Enable at least one certificate check for ${domain}`);
    if (checkOrigin && !net.isIP(originIp)) throw new Error(`Enter a valid origin IPv4 or IPv6 address for ${domain}`);
    output[domain] = { check_public: checkPublic, check_origin: checkOrigin, origin_ip: checkOrigin ? originIp : '' };
  }
  return output;
}

function normalizeNotifications(input = {}) {
  const warningThreshold = boundedNumber(input.ssl_warning_threshold, 30, 7, 365, 'SSL warning threshold');
  return {
    discord_enabled: input.discord_enabled !== false,
    ssl_enabled: input.ssl_enabled !== false,
    needs_attention_enabled: input.needs_attention_enabled !== false,
    ssl_warning_threshold: warningThreshold,
    ssl_milestones: [...new Set([warningThreshold, 14, 7])].sort((a, b) => b - a)
  };
}

function activeBimiException(exception, now = Date.now()) {
  if (exception?.mode === 'permanent') return { active: true, mode: 'permanent', label: 'permanently' };
  if (exception?.mode === 'until') {
    const timestamp = Date.parse(exception.expires_at);
    if (Number.isFinite(timestamp) && timestamp > now) return { active: true, mode: 'until', expires_at: new Date(timestamp).toISOString(), label: `until ${new Date(timestamp).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' })}` };
  }
  return { active: false };
}

function applyMissingControlException(check, exception, reason) {
  const ignored = activeBimiException(exception);
  if (!ignored.active) return check;
  return result(check.id, check.label, 'ignored', `${check.summary} · Ignored`, `${check.detail} This review item is ignored ${ignored.label}.`, 'No action is required while this exception remains active. Edit the domain to change or remove it.', { ...check.evidence, ignored: true, ignore_reason: reason, ignore_mode: ignored.mode, ignored_until: ignored.expires_at || null, original_status: check.status });
}

function isMissingMtaSts(check) {
  return check?.summary === 'Not configured' && Array.isArray(check?.evidence?.raw_dns) && check.evidence.raw_dns.length === 0;
}

function normalizeSettings(input = {}) {
  const domains = [...new Set((Array.isArray(input.monitored_domains) ? input.monitored_domains : []).map(v => String(v).trim().toLowerCase().replace(/\.$/, '')).filter(Boolean))];
  for (const domain of domains) if (!validDomain(domain)) throw new Error(`Invalid monitored domain: ${domain}`);
  const selectors = {};
  for (const [rawDomain, values] of Object.entries(input.dkim_selectors || {})) {
    const domain = rawDomain.trim().toLowerCase().replace(/\.$/, '');
    if (!validDomain(domain)) throw new Error(`Invalid DKIM domain: ${domain}`);
    selectors[domain] = [...new Set((Array.isArray(values) ? values : []).map(v => String(v).trim()).filter(Boolean))];
    for (const selector of selectors[domain]) if (!/^[a-z0-9_-]{1,63}$/i.test(selector)) throw new Error(`Invalid DKIM selector: ${selector}`);
  }
  const endpoints = {};
  for (const [rawDomain, values] of Object.entries(input.tls_endpoints || {})) {
    const domain = rawDomain.trim().toLowerCase().replace(/\.$/, '');
    if (!validDomain(domain)) throw new Error(`Invalid TLS domain: ${domain}`);
    endpoints[domain] = (Array.isArray(values) ? values : []).map(value => typeof value === 'string' ? endpointValue(value) : { host: String(value.host || '').trim().toLowerCase().replace(/\.$/, ''), port: Number(value.port || 443) });
    for (const endpoint of endpoints[domain]) {
      if (!validDomain(endpoint.host)) throw new Error(`Invalid TLS endpoint host: ${endpoint.host || '(empty)'}`);
      if (!Number.isInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535) throw new Error(`Invalid TLS endpoint port for ${endpoint.host}`);
    }
  }
  const configuredMode = process.env.DOMAINPOSTURE_DEPLOYMENT_MODE || process.env.MAILPOSTURE_DEPLOYMENT_MODE;
  const environmentMode = ['standalone', 'external'].includes(configuredMode) ? configuredMode : 'external';
  const reportSource = ['standalone', 'external', 'disabled'].includes(input.report_source) ? input.report_source : (input.opensearch_enabled === false ? 'disabled' : environmentMode);
  const opensearchUrl = textValue(input.opensearch_url, process.env.OPENSEARCH_URL || 'http://parsedmarc-opensearch:9200');
  if (!validHttpUrl(opensearchUrl)) throw new Error('OpenSearch URL must be an HTTP or HTTPS URL without embedded credentials');
  const snapshotCron = textValue(input.snapshots?.cron, input.snapshot_cron || '0 2 * * *', 100);
  const snapshotDeleteCron = textValue(input.snapshots?.delete_cron, input.snapshot_delete_cron || '30 2 * * *', 100);
  if (!validCron(snapshotCron) || !validCron(snapshotDeleteCron)) throw new Error('Snapshot schedules must use five-field cron expressions');
  const mailbox = input.mailbox || {};
  const parsedmarc = input.parsedmarc || {};
  const parsedmarcGeneral = parsedmarc.general || {};
  const parsedmarcMailbox = parsedmarc.mailbox || {};
  const parsedmarcImap = parsedmarc.imap || {};
  const parsedmarcOpensearch = parsedmarc.opensearch || {};
  const since = textValue(parsedmarcMailbox.since, '1d', 20);
  if (!/^\d+[mhdw]$/i.test(since)) throw new Error('Mailbox lookback must be a number followed by m, h, d, or w');
  const snapshotMin = boundedNumber(input.snapshots?.min_count, 7, 1, 1000, 'Minimum snapshots');
  const snapshotMax = boundedNumber(input.snapshots?.max_count, 60, 1, 10000, 'Maximum snapshots');
  if (snapshotMin > snapshotMax) throw new Error('Minimum snapshots cannot exceed maximum snapshots');
  const smtpProbeHostname = textValue(input.smtp_probe_hostname, process.env.SMTP_PROBE_HOSTNAME || '', 253).toLowerCase().replace(/\.$/, '');
  if (smtpProbeHostname && !validDomain(smtpProbeHostname)) throw new Error('SMTP probe hostname must be a fully qualified domain name');
  return {
    schema_version: 8,
    monitored_domains: domains,
    dkim_selectors: selectors,
    tls_endpoints: endpoints,
    certificate_checks: normalizeCertificateChecks(input.certificate_checks, domains),
    certificate_check_minutes: boundedNumber(input.certificate_check_minutes, 360, 5, 10080, 'Certificate check interval'),
    notifications: normalizeNotifications(input.notifications),
    smtp_profiles: normalizeSmtpProfiles(input.smtp_profiles, domains),
    smtp_probe_hostname: smtpProbeHostname,
    bimi_exceptions: normalizeBimiExceptions(input.bimi_exceptions, domains),
    control_exceptions: normalizeControlExceptions(input.control_exceptions, domains),
    report_days: boundedNumber(input.report_days, 7, 1, 365, 'Report days'),
    refresh_minutes: boundedNumber(input.refresh_minutes, 15, 1, 1440, 'Refresh minutes'),
    request_timeout_ms: boundedNumber(input.request_timeout_ms, 8000, 1000, 60000, 'Request timeout'),
    opensearch_enabled: reportSource !== 'disabled',
    report_source: reportSource,
    opensearch_url: opensearchUrl.replace(/\/$/, ''),
    opensearch_aggregate_index: textValue(input.opensearch_aggregate_index, process.env.OPENSEARCH_INDEX || 'dmarc_aggregate*', 255),
    opensearch_failure_index: textValue(input.opensearch_failure_index, process.env.OPENSEARCH_FAILURE_INDEX || 'dmarc_failure*,dmarc_forensic*', 255),
    opensearch_smtp_tls_index: textValue(input.opensearch_smtp_tls_index, process.env.OPENSEARCH_SMTP_TLS_INDEX || 'smtp_tls*', 255),
    opensearch_username: textValue(input.opensearch_username, process.env.OPENSEARCH_USERNAME || 'admin', 255),
    opensearch_verify_tls: input.opensearch_verify_tls === undefined
      ? String(process.env.OPENSEARCH_VERIFY_TLS || 'false').toLowerCase() === 'true'
      : input.opensearch_verify_tls === true,
    mailbox: {
      enabled: mailbox.enabled === true,
      host: textValue(mailbox.host, process.env.PARSEDMARC_IMAP_HOST || '', 255),
      port: boundedNumber(mailbox.port, 993, 1, 65535, 'IMAP port'),
      username: textValue(mailbox.username, process.env.PARSEDMARC_IMAP_USER || '', 512),
      ssl: mailbox.ssl !== false,
      reports_folder: textValue(mailbox.reports_folder, 'INBOX', 255),
      archive_folder: textValue(mailbox.archive_folder, 'Archive', 255),
      watch: mailbox.watch !== false,
      password_set: false
    },
    parsedmarc: {
      general: {
        save_aggregate: parsedmarcGeneral.save_aggregate !== false,
        save_failure: parsedmarcGeneral.save_failure !== false,
        save_smtp_tls: parsedmarcGeneral.save_smtp_tls !== false,
        strip_attachment_payloads: parsedmarcGeneral.strip_attachment_payloads === true,
        offline: parsedmarcGeneral.offline === true,
        always_use_local_files: parsedmarcGeneral.always_use_local_files === true,
        silent: parsedmarcGeneral.silent !== false,
        warnings: parsedmarcGeneral.warnings !== false,
        verbose: parsedmarcGeneral.verbose === true,
        debug: parsedmarcGeneral.debug === true,
        fail_on_output_error: parsedmarcGeneral.fail_on_output_error === true,
        n_procs: boundedNumber(parsedmarcGeneral.n_procs, 1, 1, 64, 'Parser processes'),
        dns_timeout: boundedDecimal(parsedmarcGeneral.dns_timeout, 2, 0.1, 120, 'DNS timeout'),
        dns_retries: boundedNumber(parsedmarcGeneral.dns_retries, 0, 0, 20, 'DNS retries')
      },
      mailbox: {
        test: parsedmarcMailbox.test === true,
        delete: parsedmarcMailbox.delete === true,
        delete_aggregate: parsedmarcMailbox.delete_aggregate === true,
        delete_failure: parsedmarcMailbox.delete_failure === true,
        delete_smtp_tls: parsedmarcMailbox.delete_smtp_tls === true,
        delete_invalid: parsedmarcMailbox.delete_invalid === true,
        batch_size: boundedNumber(parsedmarcMailbox.batch_size, 10, 0, 10000, 'Mailbox batch size'),
        check_timeout: boundedNumber(parsedmarcMailbox.check_timeout, 30, 1, 3600, 'Mailbox check timeout'),
        max_unsaved_retries: boundedNumber(parsedmarcMailbox.max_unsaved_retries, 2, 0, 100, 'Unsaved retries'),
        since
      },
      imap: {
        skip_certificate_verification: parsedmarcImap.skip_certificate_verification === true,
        timeout: boundedNumber(parsedmarcImap.timeout, 30, 1, 3600, 'IMAP timeout'),
        max_retries: boundedNumber(parsedmarcImap.max_retries, 4, 0, 100, 'IMAP retries')
      },
      opensearch: {
        timeout: boundedNumber(parsedmarcOpensearch.timeout, 60, 1, 3600, 'OpenSearch output timeout'),
        monthly_indexes: parsedmarcOpensearch.monthly_indexes !== false,
        number_of_shards: boundedNumber(parsedmarcOpensearch.number_of_shards, 1, 1, 100, 'OpenSearch shards'),
        number_of_replicas: boundedNumber(parsedmarcOpensearch.number_of_replicas, 0, 0, 100, 'OpenSearch replicas')
      }
    },
    snapshots: {
      enabled: input.snapshots?.enabled === undefined ? reportSource === 'standalone' : input.snapshots.enabled === true,
      cron: snapshotCron,
      delete_cron: snapshotDeleteCron,
      timezone: textValue(input.snapshots?.timezone, process.env.TZ || 'UTC', 100),
      retention_days: boundedNumber(input.snapshots?.retention_days, 30, 1, 3650, 'Snapshot retention'),
      min_count: snapshotMin,
      max_count: snapshotMax
    }
  };
}

function readSecrets() {
  try { return JSON.parse(fs.readFileSync(SECRETS_PATH, 'utf8')); } catch (_) { return {}; }
}

function defaultOperationalState() {
  return { schema_version: 1, certificates: {}, notifications: { certificates: {}, domains: {} } };
}

function getOperationalState() {
  if (operationalState) return operationalState;
  try {
    const saved = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
    operationalState = {
      ...defaultOperationalState(),
      ...saved,
      certificates: saved.certificates && typeof saved.certificates === 'object' ? saved.certificates : {},
      notifications: {
        certificates: saved.notifications?.certificates && typeof saved.notifications.certificates === 'object' ? saved.notifications.certificates : {},
        domains: saved.notifications?.domains && typeof saved.notifications.domains === 'object' ? saved.notifications.domains : {}
      }
    };
  } catch (_) { operationalState = defaultOperationalState(); }
  return operationalState;
}

async function saveOperationalState() {
  await atomicWrite(STATE_PATH, `${JSON.stringify(getOperationalState(), null, 2)}\n`);
}

function validDiscordWebhookUrl(value) {
  try {
    const url = new URL(value);
    const allowedHosts = new Set(['discord.com', 'discordapp.com', 'canary.discord.com', 'ptb.discord.com']);
    const validPath = /^\/api\/webhooks\/\d+\/[^/?#]+\/?$/.test(url.pathname);
    return url.protocol === 'https:' && allowedHosts.has(url.hostname) && validPath && !url.username && !url.password && !url.search && !url.hash ? url : null;
  } catch (_) { return null; }
}

function discordWebhookConfiguration(secrets = readSecrets()) {
  const saved = validDiscordWebhookUrl(String(secrets.discord_webhook || '').trim());
  if (saved) return { url: saved, source: 'settings' };
  const environment = validDiscordWebhookUrl(String(process.env.DOMAINPOSTURE_DISCORD_WEBHOOK || process.env.MAILPOSTURE_DISCORD_WEBHOOK || '').trim());
  return { url: environment, source: environment ? 'environment' : null };
}

function discordWebhookUrl() {
  return discordWebhookConfiguration().url;
}

function publicSettings(settings = getSettings()) {
  const secrets = readSecrets();
  const discord = discordWebhookConfiguration(secrets);
  return {
    ...settings,
    mailbox: { ...settings.mailbox, password: '', password_set: Boolean(secrets.imap_password) },
    notifications: { ...settings.notifications, discord_webhook_configured: Boolean(discord.url), discord_webhook_source: discord.source }
  };
}

async function atomicWrite(filename, content, mode = 0o600) {
  const temporary = `${filename}.tmp`;
  await fs.promises.mkdir(path.dirname(filename), { recursive: true });
  await fs.promises.writeFile(temporary, content, { mode });
  await fs.promises.rename(temporary, filename);
}

function parsedmarcIni(settings, secrets = {}) {
  if (!settings.mailbox.enabled) return '# Mailbox collection is disabled in DomainPosture.\n';
  const value = input => String(input ?? '').replace(/%/g, '%%');
  const bool = input => input ? 'True' : 'False';
  const pm = settings.parsedmarc;
  const lines = [
    '[general]',
    `save_aggregate = ${bool(pm.general.save_aggregate)}`,
    `save_failure = ${bool(pm.general.save_failure)}`,
    `save_smtp_tls = ${bool(pm.general.save_smtp_tls)}`,
    `strip_attachment_payloads = ${bool(pm.general.strip_attachment_payloads)}`,
    `offline = ${bool(pm.general.offline)}`,
    `always_use_local_files = ${bool(pm.general.always_use_local_files)}`,
    `silent = ${bool(pm.general.silent)}`,
    `warnings = ${bool(pm.general.warnings)}`,
    `verbose = ${bool(pm.general.verbose)}`,
    `debug = ${bool(pm.general.debug)}`,
    `fail_on_output_error = ${bool(pm.general.fail_on_output_error)}`,
    `n_procs = ${pm.general.n_procs}`,
    `dns_timeout = ${pm.general.dns_timeout}`,
    `dns_retries = ${pm.general.dns_retries}`, '',
    '[mailbox]', `reports_folder = ${value(settings.mailbox.reports_folder)}`, `archive_folder = ${value(settings.mailbox.archive_folder)}`,
    `watch = ${bool(settings.mailbox.watch)}`, `test = ${bool(pm.mailbox.test)}`, `delete = ${bool(pm.mailbox.delete)}`,
    `delete_aggregate = ${bool(pm.mailbox.delete_aggregate)}`,
    `delete_failure = ${bool(pm.mailbox.delete_failure)}`,
    `delete_smtp_tls = ${bool(pm.mailbox.delete_smtp_tls)}`,
    `delete_invalid = ${bool(pm.mailbox.delete_invalid)}`,
    `batch_size = ${pm.mailbox.batch_size}`,
    `check_timeout = ${pm.mailbox.check_timeout}`,
    `max_unsaved_retries = ${pm.mailbox.max_unsaved_retries}`,
    `since = ${value(pm.mailbox.since)}`, '',
    '[imap]', `host = ${value(settings.mailbox.host)}`, `port = ${settings.mailbox.port}`, `ssl = ${bool(settings.mailbox.ssl)}`,
    `skip_certificate_verification = ${bool(pm.imap.skip_certificate_verification)}`,
    `timeout = ${pm.imap.timeout}`, `max_retries = ${pm.imap.max_retries}`,
    `user = ${value(settings.mailbox.username)}`, `password = ${value(secrets.imap_password || '')}`, '',
    '[opensearch]', `hosts = ${value(settings.opensearch_url)}`, `user = ${value(settings.opensearch_username)}`,
    `password = ${value(process.env.OPENSEARCH_PASSWORD || '')}`, `ssl = ${bool(settings.opensearch_url.startsWith('https:'))}`,
    `skip_certificate_verification = ${bool(!settings.opensearch_verify_tls)}`,
    `timeout = ${pm.opensearch.timeout}`,
    `monthly_indexes = ${bool(pm.opensearch.monthly_indexes)}`,
    `number_of_shards = ${pm.opensearch.number_of_shards}`,
    `number_of_replicas = ${pm.opensearch.number_of_replicas}`, ''
  ];
  return lines.join('\n');
}

function getSettings() {
  if (runtimeSettings) return runtimeSettings;
  if (fs.existsSync(SETTINGS_PATH)) runtimeSettings = normalizeSettings(JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8')));
  else runtimeSettings = settingsFromEnv();
  requestTimeoutMs = runtimeSettings.request_timeout_ms;
  return runtimeSettings;
}

async function saveSettings(value) {
  const settings = normalizeSettings(value);
  const secrets = readSecrets();
  if (value.mailbox?.password) secrets.imap_password = textValue(value.mailbox.password, '', 4096);
  if (value.mailbox?.clear_password === true) delete secrets.imap_password;
  const webhook = textValue(value.notifications?.discord_webhook, '', 2048);
  const clearWebhook = value.notifications?.clear_discord_webhook === true;
  if (webhook && clearWebhook) throw new Error('Enter a Discord webhook or remove the saved webhook, not both');
  if (clearWebhook) delete secrets.discord_webhook;
  else if (webhook) {
    const validatedWebhook = validDiscordWebhookUrl(webhook);
    if (!validatedWebhook) throw new Error('Discord webhook must be an HTTPS discord.com webhook URL without query parameters');
    secrets.discord_webhook = validatedWebhook.toString();
  }
  if (settings.mailbox.enabled && (!settings.mailbox.host || !settings.mailbox.username || !secrets.imap_password)) throw new Error('IMAP host, username, and password are required when report collection is enabled');
  await atomicWrite(SECRETS_PATH, `${JSON.stringify(secrets, null, 2)}\n`);
  await atomicWrite(SETTINGS_PATH, `${JSON.stringify(settings, null, 2)}\n`);
  await atomicWrite(PARSEDMARC_CONFIG_PATH, parsedmarcIni(settings, secrets));
  runtimeSettings = settings;
  requestTimeoutMs = settings.request_timeout_ms;
  scheduleRefresh(settings.refresh_minutes);
  let snapshot_notice = null;
  if (settings.report_source === 'standalone') {
    try { await configureSnapshots(settingsConfig(settings).opensearch, settings.snapshots); }
    catch (error) { snapshot_notice = `Settings were saved, but the snapshot policy could not be updated: ${error.message}`; }
  }
  addDiagnosticEvent('domainposture', 'info', 'Settings saved', settings.report_source === 'standalone' ? 'The active ParseDMARC configuration was regenerated.' : 'Runtime settings were updated.');
  return {
    ...publicSettings(settings),
    snapshot_notice,
    parsedmarc_config_path: PARSEDMARC_CONFIG_PATH,
    parsedmarc_reload_automatic: settings.report_source === 'standalone',
    parsedmarc_reload_seconds: settings.report_source === 'standalone' ? 10 : null
  };
}

function settingsConfig(settings = getSettings()) {
  return {
    smtp_probe_hostname: settings.smtp_probe_hostname,
    certificate_check_minutes: settings.certificate_check_minutes,
    notifications: settings.notifications,
    opensearch: {
      enabled: settings.report_source !== 'disabled',
      url: settings.opensearch_url,
      index: settings.opensearch_aggregate_index,
      aggregate_index: settings.opensearch_aggregate_index,
      failure_index: settings.opensearch_failure_index,
      smtp_tls_index: settings.opensearch_smtp_tls_index,
      username: settings.opensearch_username,
      password: process.env.OPENSEARCH_PASSWORD || '',
      verify_tls: settings.opensearch_verify_tls
    },
    domains: settings.monitored_domains.map(domain => ({
      domain,
      dkim_selectors: settings.dkim_selectors[domain] || [],
      tls_endpoints: settings.tls_endpoints[domain] || [],
      certificate_checks: settings.certificate_checks[domain],
      smtp_profile: settings.smtp_profiles[domain] || { hosting_type: 'auto', provider: 'auto', expected_hostname: '', relay_context: 'auto' },
      bimi_exception: settings.bimi_exceptions[domain] || null,
      control_exception: settings.control_exceptions[domain] || null,
      report_days: settings.report_days
    }))
  };
}

function envConfig() { return settingsConfig(settingsFromEnv()); }

function result(id, label, status, summary, detail, action, evidence = {}) { return { id, label, status, summary, detail, action, evidence }; }
function overallStatus(checks) {
  const rank = { healthy: 0, info: 0, warning: 1, critical: 2 };
  return checks.reduce((current, check) => rank[check.status] > rank[current] ? check.status : current, 'healthy');
}

function parsedmarcConfigurationStatus(settings, content, metadata = {}) {
  if (settings.report_source !== 'standalone') return result('parsedmarc_config', 'ParseDMARC configuration', 'warning', 'Managed externally', 'DomainPosture cannot verify the active configuration used by an external ParseDMARC service.', 'Confirm the external service mounts the generated configuration and reloads it after changes.');
  if (!settings.mailbox.enabled) return result('parsedmarc_config', 'ParseDMARC configuration', 'warning', 'Collection disabled', 'The report mailbox is not enabled, so ParseDMARC is not expected to collect reports.', 'Enable report collection in Settings when you are ready to process the mailbox.');
  const required = ['general', 'mailbox', 'imap', 'opensearch'];
  const sections = new Set(String(content || '').split(/\r?\n/).map(line => line.match(/^\[([^\]]+)\]$/)?.[1]).filter(Boolean));
  const missing = required.filter(section => !sections.has(section));
  if (missing.length) return result('parsedmarc_config', 'ParseDMARC configuration', 'critical', 'Configuration incomplete', `The active configuration is missing: ${missing.join(', ')}.`, 'Save the ParseDMARC settings again and verify that DomainPosture can write its data directory.', { path: PARSEDMARC_CONFIG_PATH, missing_sections: missing });
  return result('parsedmarc_config', 'ParseDMARC configuration', 'healthy', 'Active configuration ready', 'The generated configuration contains the mailbox, IMAP, and OpenSearch sections required by ParseDMARC.', 'No action required.', { path: PARSEDMARC_CONFIG_PATH, updated_at: metadata.updated_at || null, size_bytes: metadata.size_bytes || Buffer.byteLength(content) });
}

async function readJsonFile(filename) {
  return JSON.parse(await fs.promises.readFile(filename, 'utf8'));
}

function globPattern(pattern) {
  const escaped = String(pattern).trim().replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
}

function matchesIndexPattern(index, patterns) {
  return String(patterns || '').split(',').map(value => value.trim()).filter(Boolean).some(pattern => globPattern(pattern).test(index));
}

function unassignedShardSummary(shards, settings) {
  const unassigned = shards.filter(shard => String(shard.state).toUpperCase() === 'UNASSIGNED');
  const reportPatterns = [settings.opensearch_aggregate_index, settings.opensearch_failure_index, settings.opensearch_smtp_tls_index];
  const groups = new Map();
  for (const shard of unassigned) {
    const index = String(shard.index || 'unknown');
    const category = reportPatterns.some(pattern => matchesIndexPattern(index, pattern))
      ? 'DomainPosture report indexes'
      : index.startsWith('security-auditlog-')
        ? 'OpenSearch security audit logs'
        : index.startsWith('.')
          ? 'OpenSearch internal indexes'
          : 'Other indexes';
    const group = groups.get(category) || { category, indexes: new Set(), unassigned_shards: 0, primary_shards: 0, replica_shards: 0 };
    group.indexes.add(index);
    group.unassigned_shards += 1;
    if (String(shard.prirep).toLowerCase() === 'p') group.primary_shards += 1; else group.replica_shards += 1;
    groups.set(category, group);
  }
  return {
    total: unassigned.length,
    all_replicas: unassigned.length > 0 && unassigned.every(shard => String(shard.prirep).toLowerCase() === 'r'),
    affected_report_shards: unassigned.filter(shard => reportPatterns.some(pattern => matchesIndexPattern(String(shard.index || ''), pattern))).length,
    groups: [...groups.values()].map(group => ({ ...group, index_count: group.indexes.size, indexes: [...group.indexes].sort() }))
  };
}

async function systemStatus() {
  const checkedAt = new Date().toISOString();
  let settings;
  try { settings = getSettings(); }
  catch (error) {
    const checks = [result('mailposture', 'DomainPosture', 'critical', 'Settings unavailable', error.message, 'Verify the persistent data mount and settings file.')];
    recordSystemChecks(checks);
    return { version: APP_VERSION, checked_at: checkedAt, status: 'critical', checks };
  }

  const checks = [];
  const lastRefresh = snapshot.generated_at ? new Date(snapshot.generated_at).getTime() : 0;
  const staleAfter = Math.max(2, settings.refresh_minutes * 2) * 60000;
  const appStatus = snapshot.error ? 'critical' : (!lastRefresh || Date.now() - lastRefresh > staleAfter ? 'warning' : 'healthy');
  checks.push(result('mailposture', 'DomainPosture', appStatus, snapshot.error ? 'Checks failed' : appStatus === 'warning' ? 'Checks are stale' : 'Application checks running', snapshot.error || (lastRefresh ? `The most recent domain check completed ${Math.max(0, Math.floor((Date.now() - lastRefresh) / 60000))} minutes ago.` : 'The first domain check has not completed yet.'), appStatus === 'healthy' ? 'No action required.' : 'Run checks again and review the application logs if the condition remains.', { version: APP_VERSION, uptime_seconds: Math.floor((Date.now() - startedAt) / 1000), last_domain_check: snapshot.generated_at }));

  try {
    await Promise.all([
      fs.promises.access(path.dirname(SETTINGS_PATH), fs.constants.R_OK | fs.constants.W_OK),
      fs.promises.access(path.dirname(PARSEDMARC_CONFIG_PATH), fs.constants.R_OK | fs.constants.W_OK),
      fs.promises.access(path.dirname(STATE_PATH), fs.constants.R_OK | fs.constants.W_OK)
    ]);
    checks.push(result('storage', 'Settings storage', 'healthy', 'Persistent storage writable', 'DomainPosture can read and write its settings, certificate state, and generated ParseDMARC configuration directories.', 'No action required.'));
  } catch (error) {
    checks.push(result('storage', 'Settings storage', 'critical', 'Storage is not writable', error.message, 'Correct ownership and permissions on the DomainPosture data directories.', { settings_directory: path.dirname(SETTINGS_PATH), parsedmarc_directory: path.dirname(PARSEDMARC_CONFIG_PATH) }));
  }

  try {
    await fs.promises.access(sslMonitor.SSL_WATCH_PATH, fs.constants.X_OK);
    checks.push(result('ssl_watch', 'ssl-watch', 'healthy', 'Certificate checker available', 'The ssl-watch executable is installed and executable.', 'No action required.', { path: sslMonitor.SSL_WATCH_PATH }));
  } catch (_) {
    checks.push(result('ssl_watch', 'ssl-watch', 'critical', 'Certificate checker unavailable', 'The ssl-watch executable is missing or not executable.', 'Rebuild the DomainPosture image with the pinned ssl-watch stage.', { path: sslMonitor.SSL_WATCH_PATH }));
  }

  let configContent = '';
  let configMetadata = {};
  try {
    configContent = await fs.promises.readFile(PARSEDMARC_CONFIG_PATH, 'utf8');
    const stat = await fs.promises.stat(PARSEDMARC_CONFIG_PATH);
    configMetadata = { updated_at: stat.mtime.toISOString(), size_bytes: stat.size };
  } catch (_) {}
  checks.push(parsedmarcConfigurationStatus(settings, configContent, configMetadata));

  if (settings.report_source === 'standalone' && settings.mailbox.enabled) {
    try {
      const heartbeat = await readJsonFile(PARSEDMARC_STATUS_PATH);
      const age = Date.now() - new Date(heartbeat.updated_at).getTime();
      const fresh = Number.isFinite(age) && age < 45000;
      const running = heartbeat.state === 'running';
      const heartbeatStatus = fresh && running ? 'healthy' : heartbeat.state === 'error' || !fresh ? 'critical' : 'warning';
      checks.push(result('parsedmarc_runtime', 'ParseDMARC service', heartbeatStatus, fresh && running ? 'Collector running' : fresh ? `Collector ${heartbeat.state || 'not ready'}` : 'Heartbeat is stale', fresh ? `The standalone supervisor last reported “${heartbeat.state || 'unknown'}”.` : 'DomainPosture has not received a current heartbeat from the standalone ParseDMARC supervisor.', heartbeatStatus === 'healthy' ? 'No action required.' : 'Review the ParseDMARC container health and logs.', { heartbeat_at: heartbeat.updated_at || null, state: heartbeat.state || 'unknown', exit_code: heartbeat.exit_code ?? null }));
    } catch (error) {
      checks.push(result('parsedmarc_runtime', 'ParseDMARC service', 'warning', 'Runtime heartbeat unavailable', 'The configuration is available, but this deployment does not expose the optional ParseDMARC runtime heartbeat.', 'Add the ParseDMARC status volume from the current standalone Compose example, then redeploy the stack.', { expected_path: PARSEDMARC_STATUS_PATH }));
    }
  } else {
    checks.push(result('parsedmarc_runtime', 'ParseDMARC service', 'warning', settings.mailbox.enabled ? 'External runtime not observable' : 'Collector not enabled', settings.mailbox.enabled ? 'DomainPosture cannot directly observe an externally managed ParseDMARC process.' : 'ParseDMARC remains idle until report collection is enabled.', settings.mailbox.enabled ? 'Confirm the external service is running and writing reports to OpenSearch.' : 'Enable report collection in Settings when needed.'));
  }

  const osConfig = settingsConfig(settings).opensearch;
  if (!osConfig.enabled) {
    checks.push(result('opensearch', 'OpenSearch', 'warning', 'Report source disabled', 'DomainPosture is running live domain checks without historical DMARC or SMTP TLS data.', 'Choose a bundled or external report source in Settings.'));
  } else {
    let connected = false;
    try {
      const cluster = await osApiRequest(osConfig, '_cluster/health');
      connected = true;
      let shardSummary = null;
      try {
        const shards = await osApiRequest(osConfig, '_cat/shards?format=json&h=index,shard,prirep,state,unassigned.reason,node&s=index,shard');
        shardSummary = unassignedShardSummary(shards, settings);
      } catch (_) {}
      const rawClusterStatus = cluster.status || 'unknown';
      const expectedSingleNodeReplicas = rawClusterStatus === 'yellow' && cluster.number_of_nodes === 1 && shardSummary?.all_replicas && shardSummary.affected_report_shards === 0;
      const clusterStatus = rawClusterStatus === 'red' ? 'critical' : rawClusterStatus === 'green' || expectedSingleNodeReplicas ? 'healthy' : 'warning';
      const breakdown = shardSummary?.groups.map(group => `${group.unassigned_shards} ${group.category.toLowerCase()} shard${group.unassigned_shards === 1 ? '' : 's'}`).join(' and ');
      const clusterSummary = expectedSingleNodeReplicas ? 'Operational on one node' : `Cluster ${rawClusterStatus}`;
      const clusterDetail = expectedSingleNodeReplicas
        ? `OpenSearch reports yellow because ${shardSummary.total} replica shards cannot be placed on their primary's single node: ${breakdown}. All primary shards and DomainPosture report indexes are available.`
        : `Authenticated connection succeeded with ${cluster.number_of_nodes || 0} node${cluster.number_of_nodes === 1 ? '' : 's'} and ${cluster.unassigned_shards || 0} unassigned shards.`;
      const clusterAction = clusterStatus === 'healthy'
        ? 'No action required.'
        : rawClusterStatus === 'yellow' && cluster.number_of_nodes === 1
          ? 'For a single-node deployment, open Settings → ParseDMARC → OpenSearch output and set Replicas to 0 for new indexes. Existing indexes also need index.number_of_replicas set to 0 with the OpenSearch _settings API. Then run checks again. Keep replicas enabled on multi-node clusters.'
          : clusterStatus === 'warning'
            ? 'Use OpenSearch allocation explain to identify why the shards are unassigned, correct the reported storage, node, or allocation issue, then run checks again.'
            : 'Restore the unavailable primary shards before relying on report data. Review OpenSearch logs and use allocation explain to identify the affected indexes.';
      checks.push(result('opensearch', 'OpenSearch', clusterStatus, clusterSummary, clusterDetail, clusterAction, { actual_cluster_status: rawClusterStatus, cluster_name: cluster.cluster_name, nodes: cluster.number_of_nodes, active_primary_shards: cluster.active_primary_shards, unassigned_shards: cluster.unassigned_shards, affected_report_shards: shardSummary?.affected_report_shards ?? null, unassigned_breakdown: shardSummary?.groups || [], expected_single_node_replicas: expectedSingleNodeReplicas }));
    } catch (error) {
      checks.push(result('opensearch', 'OpenSearch', 'critical', 'Connection failed', error.message, 'Verify the URL, credentials, network, TLS settings, and OpenSearch container health.'));
    }
    if (connected) {
      const patterns = [
        ['aggregate', 'DMARC aggregate reports', settings.opensearch_aggregate_index],
        ['failure', 'Individual DMARC failure reports (RUF)', settings.opensearch_failure_index],
        ['smtp_tls', 'SMTP TLS reports', settings.opensearch_smtp_tls_index]
      ];
      const probes = await Promise.all(patterns.map(async ([type, label, pattern]) => {
        try {
          const [data, indexRows] = await Promise.all([
            osApiRequest(osConfig, `${pattern}/_count?ignore_unavailable=true&allow_no_indices=true`),
            osApiRequest(osConfig, `_cat/indices/${pattern}?format=json&h=health,index,pri,rep,docs.count,store.size&s=index&expand_wildcards=all`)
          ]);
          const indexes = (indexRows || []).map(row => ({ name: row.index, health: row.health, primary_shards: Number(row.pri || 0), replicas: Number(row.rep || 0), documents: Number(row['docs.count'] || 0), storage: row['store.size'] || null }));
          return { type, label, pattern, count: data.count || 0, available: indexes.length > 0, indexes };
        } catch (error) { return { type, label, pattern, count: 0, available: false, indexes: [], error: error.message }; }
      }));
      const unavailable = probes.filter(probe => !probe.available);
      const requiredUnavailable = unavailable.filter(probe => probe.type !== 'failure');
      const missingFailureOnly = unavailable.length > 0 && requiredUnavailable.length === 0;
      const rufDomains = snapshot.domains.map(domain => {
        const dmarcCheck = domain.checks.find(check => check.id === 'dmarc');
        return { domain: domain.domain, destination: dmarcCheck?.evidence?.tags?.ruf || null };
      });
      const indexAction = !unavailable.length
        ? 'No action required.'
        : missingFailureOnly
          ? 'No action is required. No individual RUF report has been stored yet. If you want this optional detail, confirm the domain publishes a ruf= destination, the destination reaches the report mailbox, and the receiving provider supports RUF.'
          : `Open Settings → ParseDMARC and enable the missing required report type${requiredUnavailable.length === 1 ? '' : 's'} (${requiredUnavailable.map(probe => probe.label).join(', ')}). Confirm matching reports reach the configured mailbox, then run checks after parsedmarc processes the first report.${unavailable.some(probe => probe.type === 'failure') ? ' The missing individual RUF index is optional and does not require correction.' : ''}`;
      const reportStatus = requiredUnavailable.length ? 'warning' : missingFailureOnly ? 'info' : 'healthy';
      const reportSummary = requiredUnavailable.length ? `${requiredUnavailable.length} required index pattern${requiredUnavailable.length === 1 ? '' : 's'} unavailable` : missingFailureOnly ? 'Optional RUF data not received' : 'Report indexes queryable';
      checks.push(result('report_indices', 'Report indexes — All domains', reportStatus, reportSummary, 'All configured index patterns were checked across all domains. Open the pattern list below for matching indexes and document counts.', indexAction, { scope: 'All domains', patterns: probes, ruf_domains: rufDomains, failure_reports_optional: true }));
    }
  }

  recordSystemChecks(checks);
  return { version: APP_VERSION, checked_at: checkedAt, status: overallStatus(checks), checks };
}
function tags(record) {
  return Object.fromEntries(String(record || '').split(';').map(v => v.trim()).filter(Boolean).map(term => {
    const i = term.indexOf('='); return i < 0 ? [term.toLowerCase(), ''] : [term.slice(0, i).trim().toLowerCase(), term.slice(i + 1).trim()];
  }));
}
async function txt(name) { return (await dns.resolveTxt(name)).map(parts => parts.join('')); }
function protocol(records, prefix) { return records.filter(v => v.trim().toLowerCase().startsWith(prefix.toLowerCase())); }

async function dmarc(domain) {
  try {
    const found = protocol(await txt(`_dmarc.${domain}`), 'v=DMARC1');
    if (found.length !== 1) return result('dmarc', 'DMARC', 'critical', found.length ? 'Multiple DMARC records' : 'No DMARC policy', 'Receivers require exactly one DMARC1 TXT record.', 'Publish exactly one DMARC record with aggregate reporting.', { records: found });
    const parsed = tags(found[0]); const policy = (parsed.p || '').toLowerCase(); const pct = Number(parsed.pct || 100); const issues = [];
    if (!policy) issues.push('The required p tag is missing.');
    if (policy === 'none') issues.push('The policy monitors but does not enforce.');
    if (pct < 100) issues.push(`Enforcement covers only ${pct}% of failing mail.`);
    if (!parsed.rua) issues.push('No aggregate-report destination is published.');
    const status = !policy ? 'critical' : issues.length ? 'warning' : 'healthy';
    const policyLabel = policy ? `${policy.charAt(0).toUpperCase()}${policy.slice(1)}` : 'Incomplete';
    return result('dmarc', 'DMARC', status, `${policyLabel} · ${pct}%`, issues.join(' ') || 'Enforcement and aggregate reporting are configured.', status === 'healthy' ? 'Keep reviewing legitimate sources and failures.' : 'Align every legitimate sender, then move toward p=reject; pct=100.', { record: found[0], tags: parsed });
  } catch (error) { return result('dmarc', 'DMARC', 'critical', 'No DMARC policy', error.message, 'Publish exactly one DMARC1 TXT record.'); }
}

function get(url, maxBytes = 1048576) {
  return new Promise((resolve, reject) => {
    const req = (url.startsWith('https:') ? https : http).get(url, { timeout: requestTimeoutMs, headers: { 'user-agent': `DomainPosture/${APP_VERSION}` } }, res => {
      const chunks = []; let size = 0;
      res.on('data', c => { size += c.length; if (size > maxBytes) req.destroy(new Error('Response is too large')); else chunks.push(c); });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('timeout', () => req.destroy(new Error('Request timed out'))); req.on('error', reject);
  });
}

function policyFile(body) {
  const values = {};
  for (const line of body.split(/\r?\n/)) { const i = line.indexOf(':'); if (i < 0) continue; const key = line.slice(0, i).trim().toLowerCase(); const value = line.slice(i + 1).trim(); if (key === 'mx') (values.mx ||= []).push(value); else values[key] = value; }
  return values;
}
function mxMatch(host, pattern) { const h = host.toLowerCase().replace(/\.$/, ''); const p = pattern.toLowerCase().replace(/\.$/, ''); return p.startsWith('*.') ? h.endsWith(p.slice(1)) && h !== p.slice(2) : h === p; }

async function mtaSts(domain) {
  const evidence = {};
  try {
    const rawRecords = await txt(`_mta-sts.${domain}`); const records = protocol(rawRecords, 'v=STSv1'); evidence.raw_dns = rawRecords; evidence.dns = records;
    if (records.length !== 1) return result('mta_sts', 'MTA-STS', 'critical', 'Not configured', 'Expected exactly one STSv1 DNS signal.', 'Publish the DNS signal and a valid HTTPS policy.', evidence);
    const response = await get(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, 65536); evidence.http_status = response.status;
    if (response.status !== 200) return result('mta_sts', 'MTA-STS', 'critical', `Policy returned HTTP ${response.status}`, 'Senders require a successful policy fetch.', 'Serve the policy at the exact well-known path.', evidence);
    const policy = policyFile(response.body); const mx = await dns.resolveMx(domain); evidence.policy = policy; evidence.domain_mx = mx;
    if (policy.version !== 'STSv1' || !['enforce', 'testing', 'none'].includes(policy.mode) || !policy.max_age || (policy.mode !== 'none' && !(policy.mx || []).length)) return result('mta_sts', 'MTA-STS', 'critical', 'Invalid policy', 'Required policy fields are missing or invalid.', 'Set version, mode, max_age, and the MX entries.', evidence);
    const uncovered = mx.map(v => v.exchange).filter(host => !(policy.mx || []).some(pattern => mxMatch(host, pattern)));
    if (uncovered.length) return result('mta_sts', 'MTA-STS', 'critical', 'MX hosts not covered', uncovered.join(', '), 'Add every active mail exchanger to the policy.', evidence);
    if (policy.mode !== 'enforce') return result('mta_sts', 'MTA-STS', 'warning', `${policy.mode} mode`, 'Authenticated TLS is not yet required.', 'Review TLS reports, change to enforce, and rotate the DNS id.', evidence);
    return result('mta_sts', 'MTA-STS', 'healthy', 'Enforced', `${mx.length} MX host(s) covered.`, 'Rotate the DNS id whenever the policy changes.', evidence);
  } catch (error) {
    if (!evidence.raw_dns && ['ENOTFOUND', 'ENODATA', 'EAI_NONAME'].includes(error.code)) return result('mta_sts', 'MTA-STS', 'critical', 'Not configured', 'No STSv1 DNS signal is published.', 'Publish the DNS signal and a valid HTTPS policy, or ignore an intentionally absent MTA-STS configuration in the domain settings.', { raw_dns: [], dns: [] });
    return result('mta_sts', 'MTA-STS', 'critical', 'Check failed', error.message, 'Verify DNS, HTTPS, and the policy endpoint.', evidence);
  }
}

async function bimi(domain, dmarcResult, configuredException = null, options = {}) {
  bimiLogos.delete(domain);
  const resolveTxt = options.txt || txt; const fetchResource = options.get || get;
  const selfAssertedException = configuredException?.self_asserted || (configuredException?.mode ? configuredException : null);
  const noLogoException = configuredException?.no_logo || null;
  const ignoredNoLogo = activeBimiException(noLogoException);
  const ignoredResult = detail => result('bimi', 'BIMI', 'ignored', 'No logo · Ignored', `${detail} This review item is ignored ${ignoredNoLogo.label}.`, 'No action is required while this exception remains active. Edit the domain to change or remove it.', { ignored: true, ignore_reason: 'no_logo', ignore_mode: ignoredNoLogo.mode, ignored_until: ignoredNoLogo.expires_at || null, original_status: 'warning' });
  try {
    const found = protocol(await resolveTxt(`default._bimi.${domain}`), 'v=BIMI1');
    if (found.length !== 1) {
      if (!found.length && ignoredNoLogo.active) return ignoredResult('No BIMI1 record or logo is published.');
      return result('bimi', 'BIMI', found.length ? 'critical' : 'warning', found.length ? 'Multiple records' : 'Not configured', 'Expected exactly one BIMI1 record.', 'Publish exactly one BIMI record after DMARC enforcement and a compliant logo are ready.');
    }
    const parsed = tags(found[0]); const dm = dmarcResult.evidence.tags || {}; const enforced = ['quarantine', 'reject'].includes((dm.p || '').toLowerCase()) && Number(dm.pct || 100) === 100;
    if (!enforced) return result('bimi', 'BIMI', 'critical', 'DMARC prerequisite not met', 'BIMI requires enforcement applied to all mail.', 'Enforce DMARC before troubleshooting BIMI.', { record: found[0] });
    if (!parsed.l) {
      if (ignoredNoLogo.active) return ignoredResult('The BIMI record does not publish a logo URL.');
      return result('bimi', 'BIMI', 'warning', 'Logo URL missing', 'The l tag does not publish an SVG logo URL.', 'Publish a compliant SVG Tiny P/S logo, or ignore the intentionally absent logo in domain settings.', { record: found[0] });
    }
    if (!parsed.l.startsWith('https://')) return result('bimi', 'BIMI', 'critical', 'Invalid logo URL', 'The l tag must contain an HTTPS SVG URL.', 'Publish the logo from a valid HTTPS URL.', { record: found[0] });
    const logo = await fetchResource(parsed.l, 2097152); const safeSvg = logo.status === 200 && /<svg\b/i.test(logo.body) && !/<script\b|javascript:|<foreignObject\b/i.test(logo.body);
    if (!safeSvg) return result('bimi', 'BIMI', 'critical', 'Logo cannot be validated', `Logo endpoint returned HTTP ${logo.status}.`, 'Serve a safe, compliant SVG directly over HTTPS.', { record: found[0], logo_status: logo.status });
    bimiLogos.set(domain, { body: logo.body, etag: crypto.createHash('sha256').update(logo.body).digest('hex') });
    if (parsed.a) return result('bimi', 'BIMI', 'healthy', 'Logo and certificate published', 'Record, logo, and evidence URL are present.', 'Recheck after changes.', { record: found[0], tags: parsed, logo_available: true });
    const ignored = activeBimiException(selfAssertedException);
    if (ignored.active) return result('bimi', 'BIMI', 'ignored', 'Self-asserted logo · Ignored', `No VMC/CMC evidence URL is published. This review item is ignored ${ignored.label}.`, 'No action is required while this exception remains active. Edit the domain to change or remove it.', { record: found[0], tags: parsed, logo_available: true, ignored: true, ignore_mode: ignored.mode, ignored_until: ignored.expires_at || null, original_status: 'warning' });
    return result('bimi', 'BIMI', 'warning', 'Self-asserted logo', 'No VMC/CMC evidence URL is published.', 'Consider a VMC or CMC for broader support, or ignore this review item in the domain settings.', { record: found[0], tags: parsed, logo_available: true });
  } catch (error) {
    if (ignoredNoLogo.active && ['ENOTFOUND', 'ENODATA', 'EAI_NONAME'].includes(error.code)) return ignoredResult('No BIMI1 record or logo is published.');
    return result('bimi', 'BIMI', 'warning', 'Not configured', error.message, 'Publish BIMI after DMARC enforcement is ready, or ignore an intentionally absent logo in domain settings.');
  }
}

async function certificate(endpoint) {
  const checked = await sslMonitor.runCertificateCheck({ domain: endpoint.host, port: endpoint.port, checkType: 'endpoint', timeoutMs: requestTimeoutMs });
  const status = checked.status === 'good' ? 'healthy' : ['needs_attention', 'urgent'].includes(checked.status) ? 'warning' : 'critical';
  return result(
    `tls_${endpoint.host}_${endpoint.port}`,
    'TLS certificate',
    status,
    checked.days_remaining === null ? checked.status_label : `${checked.days_remaining} days remaining`,
    checked.error || `${endpoint.host}:${endpoint.port} presents a ${checked.chain_valid ? 'trusted' : 'failing'} certificate.`,
    status === 'healthy' ? 'No action required.' : checked.error ? 'Check routing, TLS service availability, and the ssl-watch installation.' : 'Confirm renewal is scheduled and correct certificate trust or hostname problems.',
    { ...checked, host: endpoint.host, port: endpoint.port }
  );
}

async function domainCertificateComponent(entry, config, options = {}) {
  const state = getOperationalState();
  const domainCache = state.certificates[entry.domain] ||= {};
  const settings = entry.certificate_checks;
  const checks = [];
  const definitions = [
    { enabled: settings.check_public, checkType: 'public' },
    { enabled: settings.check_origin, checkType: 'origin', originIp: settings.origin_ip }
  ];
  for (const definition of definitions) {
    if (!definition.enabled) continue;
    const previous = domainCache[definition.checkType] || null;
    const sameTarget = definition.checkType !== 'origin' || previous?.configured_origin_ip === definition.originIp;
    if (!options.forceCertificates && sameTarget && sslMonitor.resultIsFresh(previous, config.certificate_check_minutes)) {
      checks.push(previous);
      continue;
    }
    const checked = await sslMonitor.runCertificateCheck({
      domain: entry.domain,
      checkType: definition.checkType,
      originIp: definition.originIp,
      timeoutMs: requestTimeoutMs,
      warningThreshold: config.notifications.ssl_warning_threshold,
      previous,
      execute: options.execute
    });
    domainCache[definition.checkType] = checked;
    checks.push(checked);
  }
  return sslMonitor.componentResult(entry.domain, checks);
}

async function dkim(domain, selectors, mailProfile = {}) {
  if (!selectors.length) return result('dkim', 'DKIM', 'warning', 'No selectors configured', 'Selectors cannot be discovered reliably from DNS.', 'Add the active selectors for this domain in Settings.');
  const keys = [];
  for (const selector of selectors) {
    try {
      const found = protocol(await txt(`${selector}._domainkey.${domain}`), 'v=DKIM1'); if (found.length !== 1) { keys.push({ selector, status: 'critical', issue: found.length ? 'multiple records' : 'record missing' }); continue; }
      const parsed = tags(found[0]); if (!parsed.p) { keys.push({ selector, status: 'critical', issue: 'key missing or revoked' }); continue; }
      let bits = null; try { const pem = `-----BEGIN PUBLIC KEY-----\n${parsed.p.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`; bits = crypto.createPublicKey(pem).asymmetricKeyDetails?.modulusLength || null; } catch (_) {}
      keys.push({ selector, bits, status: bits && bits < 1024 ? 'critical' : bits && bits < 2048 ? 'warning' : 'healthy', issue: bits && bits < 2048 ? `${bits}-bit RSA key` : null });
    } catch (error) { keys.push({ selector, status: 'critical', issue: 'record missing' }); }
  }
  const bad = keys.filter(v => v.status !== 'healthy'); const status = keys.some(v => v.status === 'critical') ? 'critical' : bad.length ? 'warning' : 'healthy';
  const providerManagedWeakKey = mailProfile.hosting_type === 'managed' && bad.length > 0 && bad.every(key => key.status === 'warning' && key.bits >= 1024);
  const action = status === 'healthy'
    ? 'Retire old selectors only after mail has aged out.'
    : providerManagedWeakKey
      ? `Ask ${mailProfile.provider_label || 'the mail provider'} whether it supports a 2048-bit or stronger DKIM key. Keep the provider-issued record until a replacement is supplied.`
      : 'Replace missing, revoked, or weak keys.';
  const detail = bad.map(v => `${v.selector}: ${v.issue}`).join('; ') || 'Every configured selector publishes a usable key.';
  return result('dkim', 'DKIM', status, `${keys.length - bad.length}/${keys.length} selectors healthy`, providerManagedWeakKey ? `${detail}. The managed mail provider controls key rotation.` : detail, action, { selectors: keys, mail_profile: mailProfile, provider_managed_key: providerManagedWeakKey });
}

function osApiRequest(config, resource, method = 'GET', body = null) {
  const url = new URL(`${config.url.replace(/\/$/, '')}/${resource.replace(/^\//, '')}`); const payload = body === null ? null : Buffer.from(JSON.stringify(body)); const auth = Buffer.from(`${config.username}:${config.password}`).toString('base64');
  return new Promise((resolve, reject) => {
    const headers = { authorization: `Basic ${auth}`, accept: 'application/json' }; if (payload) { headers['content-type'] = 'application/json'; headers['content-length'] = payload.length; }
    const req = (url.protocol === 'https:' ? https : http).request(url, { method, timeout: requestTimeoutMs, rejectUnauthorized: config.verify_tls, headers }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => { try { const data = JSON.parse(Buffer.concat(chunks)); const reason = data.error?.root_cause?.[0]?.reason || data.error?.caused_by?.reason || data.error?.reason; res.statusCode < 300 ? resolve(data) : reject(new Error(reason || `OpenSearch HTTP ${res.statusCode}`)); } catch (e) { reject(e); } });
    }); req.on('timeout', () => req.destroy(new Error('OpenSearch timed out'))); req.on('error', reject); req.end(payload || undefined);
  });
}

function osRequest(config, endpoint, method = 'GET', body = null, index = config.index) {
  return osApiRequest(config, `${index}/${endpoint}`, method, body);
}

async function configureSnapshots(config, settings) {
  if (!settings.enabled) {
    try { await osApiRequest(config, '_plugins/_sm/policies/mailposture/_stop', 'POST', {}); } catch (_) {}
    return;
  }
  await osApiRequest(config, '_snapshot/mailposture', 'PUT', { type: 'fs', settings: { location: '/usr/share/opensearch/snapshots', compress: true } });
  const policy = {
    description: 'DomainPosture automated OpenSearch snapshots',
    creation: { schedule: { cron: { expression: settings.cron, timezone: settings.timezone } }, time_limit: '1h' },
    deletion: {
      schedule: { cron: { expression: settings.delete_cron, timezone: settings.timezone } },
      condition: { max_age: `${settings.retention_days}d`, min_count: settings.min_count, max_count: settings.max_count },
      time_limit: '1h', snapshot_pattern: 'mailposture-*'
    },
    snapshot_config: {
      date_format: 'yyyy-MM-dd-HH-mm', timezone: settings.timezone, indices: '*', repository: 'mailposture',
      ignore_unavailable: 'true', include_global_state: 'true', partial: 'false'
    }
  };
  let current = null;
  try { current = await osApiRequest(config, '_plugins/_sm/policies/mailposture'); } catch (_) {}
  if (current?._seq_no !== undefined && current?._primary_term !== undefined) {
    await osApiRequest(config, `_plugins/_sm/policies/mailposture?if_seq_no=${current._seq_no}&if_primary_term=${current._primary_term}`, 'PUT', policy);
  } else {
    await osApiRequest(config, '_plugins/_sm/policies/mailposture', 'POST', policy);
  }
  await osApiRequest(config, '_plugins/_sm/policies/mailposture/_start', 'POST', {});
}

function selectSourceField(fields = {}) {
  const base = Object.values(fields.source_ip_address || {}).some(definition => definition.aggregatable);
  if (base) return 'source_ip_address';
  const keyword = Object.values(fields['source_ip_address.keyword'] || {}).some(definition => definition.aggregatable);
  return keyword ? 'source_ip_address.keyword' : null;
}

const sourceFieldCache = new Map();
async function sourceAggregationField(config) {
  const key = `${config.url}/${config.index}`;
  if (!sourceFieldCache.has(key)) sourceFieldCache.set(key, osRequest(config, '_field_caps?fields=source_ip_address,source_ip_address.keyword').then(data => selectSourceField(data.fields)).catch(() => null));
  return sourceFieldCache.get(key);
}

function contactDomain(value) {
  const candidate = Array.isArray(value) ? value[0] : value;
  if (!candidate) return null;
  const text = String(candidate).trim();
  try {
    const parsed = new URL(text);
    if (parsed.hostname) return parsed.hostname.toLowerCase();
    if (parsed.protocol === 'mailto:') return decodeURIComponent(parsed.pathname).split('@').pop().toLowerCase() || null;
  } catch (_) {}
  const match = text.match(/@([^>\s,;?]+)(?:\?.*)?$/);
  return match ? match[1].toLowerCase().replace(/\.$/, '') : null;
}

function summarizeDmarcReporters(hits = []) {
  const reporters = new Map();
  for (const hit of hits) {
    const source = hit._source || hit;
    const name = String(source.org_name || source.organization_name || 'Reporter name not provided').trim();
    const domain = contactDomain(source.org_email) || contactDomain(source.org_extra_contact_info);
    const key = `${name.toLowerCase()}|${domain || ''}`;
    const reporter = reporters.get(key) || { name, domain, reports: new Set(), messages: 0, last_report: null };
    if (source.report_id) reporter.reports.add(String(source.report_id));
    else if (source.date_begin || source.date_end) reporter.reports.add(`${source.date_begin || ''}|${source.date_end || ''}`);
    reporter.messages += Number(source.message_count || 0);
    const date = source.date_end || source.date_begin;
    if (date && (!reporter.last_report || String(date) > reporter.last_report)) reporter.last_report = String(date);
    reporters.set(key, reporter);
  }
  return [...reporters.values()].map(item => ({ ...item, reports: item.reports.size || 1 })).sort((a, b) => b.messages - a.messages || a.name.localeCompare(b.name));
}

async function reports(domain, config, days) {
  if (!config.enabled) return result('dmarc_reports', 'DMARC reports', 'info', 'OpenSearch disabled', 'DNS posture is monitored, but parsedmarc aggregate results are not connected.', 'Enable OpenSearch in Settings and supply the connection variables to add observed authentication results.');
  try {
    const sourceField = await sourceAggregationField(config);
    const alignmentAggregations = { dkim_aligned: { filter: { term: { dkim_aligned: true } }, aggs: { total: { sum: { field: 'message_count' } } } }, spf_aligned: { filter: { term: { spf_aligned: true } }, aggs: { total: { sum: { field: 'message_count' } } } } };
    const failedAggregations = { total: { sum: { field: 'message_count' } }, ...alignmentAggregations };
    if (sourceField) failedAggregations.sources = { terms: { field: sourceField, size: 5 }, aggs: { messages: { sum: { field: 'message_count' } }, identity: { top_hits: { size: 1, _source: ['source_reverse_dns', 'source_name', 'source_base_domain', 'source_as_name', 'source_as_domain', 'source_as_description'] } } } };
    const data = await osRequest(config, '_search', 'POST', { size: 1000, track_total_hits: true, sort: [{ date_begin: 'desc' }], _source: ['org_name', 'organization_name', 'org_email', 'org_extra_contact_info', 'report_id', 'date_begin', 'date_end', 'message_count'], query: { bool: { must: [{ range: { date_begin: { gte: `now-${days}d` } } }, { match_phrase: { header_from: domain } }] } }, aggs: { total: { sum: { field: 'message_count' } }, passed: { filter: { term: { passed_dmarc: true } }, aggs: { total: { sum: { field: 'message_count' } }, ...alignmentAggregations } }, failed: { filter: { term: { passed_dmarc: false } }, aggs: failedAggregations }, timeline: { date_histogram: { field: 'date_begin', calendar_interval: 'day', min_doc_count: 0 }, aggs: { total: { sum: { field: 'message_count' } }, failed: { filter: { term: { passed_dmarc: false } }, aggs: { total: { sum: { field: 'message_count' } } } } } } } });
    const total = data.aggregations?.total?.value || 0; const passed = data.aggregations?.passed?.total?.value || 0; const failed = data.aggregations?.failed?.total?.value || 0; const rate = total ? Math.round(passed / total * 1000) / 10 : null;
    const sources = await Promise.all((data.aggregations?.failed?.sources?.buckets || []).map(async bucket => {
      const identity = bucket.identity?.hits?.hits?.[0]?._source || {};
      const savedReverse = Array.isArray(identity.source_reverse_dns) ? identity.source_reverse_dns[0] : identity.source_reverse_dns;
      let fqdn = savedReverse || identity.source_name || identity.source_base_domain || null;
      if (!fqdn) fqdn = await reverseDnsName(bucket.key);
      return { ip: bucket.key, fqdn, base_domain: identity.source_base_domain || null, network_owner: identity.source_as_name || identity.source_as_description || identity.source_as_domain || null, messages: bucket.messages?.value || bucket.doc_count };
    }));
    const status = !total ? 'warning' : rate < 90 ? 'critical' : rate < 98 ? 'warning' : 'healthy';
    const mappingNote = sourceField ? '' : ' Source-IP ranking is unavailable because the field is not aggregatable in these indices.';
    const timeline = (data.aggregations?.timeline?.buckets || []).map(bucket => ({ date: bucket.key_as_string, total: Math.round(bucket.total?.value || 0), failed: Math.round(bucket.failed?.total?.value || 0) }));
    const passedDkim = data.aggregations?.passed?.dkim_aligned?.total?.value || 0; const passedSpf = data.aggregations?.passed?.spf_aligned?.total?.value || 0;
    const failedDkim = data.aggregations?.failed?.dkim_aligned?.total?.value || 0; const failedSpf = data.aggregations?.failed?.spf_aligned?.total?.value || 0;
    const alignedDkim = passedDkim + failedDkim; const alignedSpf = passedSpf + failedSpf;
    const totalHits = typeof data.hits?.total === 'object' ? Number(data.hits.total.value || 0) : Number(data.hits?.total || 0);
    return result('dmarc_reports', 'DMARC reports', status, total ? `${rate}% aligned` : 'No recent reports', (total ? `${Math.round(failed)} of ${Math.round(total)} messages failed in ${days} days.` : 'No matching aggregate reports were found.') + mappingNote, total && status !== 'healthy' ? (sourceField ? 'Review top failing sources and align legitimate senders.' : 'Review failing records in parsedmarc and align legitimate senders.') : 'Watch for new failing sources.', { period_days: days, total: Math.round(total), passed: Math.round(passed), failed: Math.round(failed), pass_rate: rate, dkim_pass_rate: total ? Math.round(alignedDkim / total * 1000) / 10 : null, spf_pass_rate: total ? Math.round(alignedSpf / total * 1000) / 10 : null, passed_dkim_aligned_rate: passed ? Math.round(passedDkim / passed * 1000) / 10 : null, passed_spf_aligned_rate: passed ? Math.round(passedSpf / passed * 1000) / 10 : null, failed_dkim_aligned_rate: failed ? Math.round(failedDkim / failed * 1000) / 10 : null, failed_spf_aligned_rate: failed ? Math.round(failedSpf / failed * 1000) / 10 : null, reporters: summarizeDmarcReporters(data.hits?.hits || []), reporter_sample_limited: totalHits > 1000, source_field: sourceField, top_failing_sources: sources, timeline });
  } catch (error) { return result('dmarc_reports', 'DMARC reports', 'warning', 'OpenSearch query failed', error.message, 'Verify the OpenSearch environment variables and parsedmarc index.'); }
}

async function reverseDnsName(address) {
  let timeout;
  try {
    const names = await Promise.race([
      dns.reverse(address),
      new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('Reverse DNS timed out')), Math.min(requestTimeoutMs, 3000)); })
    ]);
    return names[0] || null;
  } catch (_) {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function failureReports(domain, config, days) {
  if (!config.enabled) return { available: false, count: 0, reason: 'OpenSearch disabled' };
  try {
    const data = await osRequest(config, '_search', 'POST', { size: 0, query: { bool: { must: [{ range: { arrival_date_utc: { gte: `now-${days}d` } } }, { match_phrase: { reported_domain: domain } }] } } }, config.failure_index);
    return { available: true, count: data.hits?.total?.value || 0, period_days: days, privacy_note: 'Failure-report message samples are not displayed because they can contain personal or confidential content.' };
  } catch (error) { return { available: false, count: 0, error: error.message, period_days: days }; }
}

function smtpOrganization(source, fields = {}) {
  const fieldValue = Array.isArray(fields.organization_name) ? fields.organization_name[0] : fields.organization_name;
  const value = source.organization_name || source.organization || source.org_name || source.report_metadata?.organization_name || source.report_metadata?.org_name || source.report?.organization_name || fieldValue;
  return String(value || '').trim() || 'Reporter name not provided';
}

function summarizeSmtpHits(hits, domain, days) {
  const timeline = new Map(); const failures = new Map(); const organizations = new Map(); const rawSamples = []; let successful = 0; let failed = 0; let reports = 0;
  for (const hit of hits || []) {
    const source = hit._source || hit; const date = String(source.date_begin || source.begin_date || '').slice(0, 10);
    const organization = smtpOrganization(source, hit.fields || {});
    const matchingPolicies = (source.policies || []).filter(policy => String(policy.policy_domain || '').toLowerCase() === domain.toLowerCase());
    if (!matchingPolicies.length) continue;
    if (rawSamples.length < 10) rawSamples.push({ index: hit._index || null, organization_name: source.organization_name ?? null, organization: source.organization ?? null, org_name: source.org_name ?? source.report_metadata?.organization_name ?? source.report_metadata?.org_name ?? null, contact_info: source.contact_info ?? null, report_id: source.report_id ?? null, date_begin: source.date_begin ?? source.begin_date ?? null, date_end: source.date_end ?? source.end_date ?? null, source_fields: Object.keys(source).sort() });
    for (const policy of matchingPolicies) {
      reports += 1; const pass = Number(policy.successful_session_count || policy.summary?.total_successful_session_count || 0); const fail = Number(policy.failed_session_count || policy.summary?.total_failure_session_count || 0);
      successful += pass; failed += fail;
      if (date) { const day = timeline.get(date) || { date, successful: 0, failed: 0 }; day.successful += pass; day.failed += fail; timeline.set(date, day); }
      const reporter = organizations.get(organization) || { name: organization, sessions: 0, reports: 0, domains: new Set() };
      reporter.sessions += pass + fail; reporter.reports += 1;
      const reporterDomain = contactDomain(source.contact_info);
      if (reporterDomain) reporter.domains.add(reporterDomain);
      organizations.set(organization, reporter);
      for (const detail of policy.failure_details || []) { const type = detail.result_type || 'unspecified'; failures.set(type, (failures.get(type) || 0) + Number(detail.failed_session_count || 0)); }
    }
  }
  const total = successful + failed;
  return { available: true, period_days: days, reports, successful, failed, success_rate: total ? Math.round(successful / total * 1000) / 10 : null, timeline: [...timeline.values()].sort((a, b) => a.date.localeCompare(b.date)), failure_types: [...failures].map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count).slice(0, 8), organizations: [...organizations.values()].map(item => ({ ...item, domains: [...item.domains] })).sort((a, b) => b.sessions - a.sessions).slice(0, 8), raw_samples: rawSamples };
}

async function smtpTlsReports(domain, config, days) {
  if (!config.enabled) return { available: false, reports: 0, reason: 'OpenSearch disabled' };
  try {
    const data = await osRequest(config, '_search', 'POST', { size: 500, query: { bool: { must: [{ range: { date_begin: { gte: `now-${days}d` } } }, { match_phrase: { 'policies.policy_domain': domain } }] } }, sort: [{ date_begin: 'desc' }] }, config.smtp_tls_index);
    return summarizeSmtpHits(data.hits?.hits || [], domain, days);
  } catch (error) { return { available: false, reports: 0, error: error.message, period_days: days }; }
}

function domainScore(checks = []) {
  const credits = { critical: 0, warning: 0.55, info: 1, ignored: 1, healthy: 1 };
  if (!checks.length) return 0;
  const total = checks.reduce((sum, check) => {
    const explicit = Number(check?.evidence?.score_credit);
    return sum + (Number.isFinite(explicit) ? Math.max(0, Math.min(1, explicit)) : (credits[check.status] ?? 0));
  }, 0);
  return Math.round(total / checks.length * 100);
}

function summarize(domain, checks, reportSections = {}, metadata = {}) {
  const rank = { healthy: 0, ignored: 0, info: 0, warning: 2, critical: 3 };
  return {
    domain,
    ...metadata,
    status: checks.reduce((a, v) => rank[v.status] > rank[a] ? v.status : a, 'healthy'),
    score: domainScore(checks),
    checks,
    reports: reportSections,
    counts: {
      critical: checks.filter(v => v.status === 'critical').length,
      warning: checks.filter(v => v.status === 'warning').length,
      ignored: checks.filter(v => v.status === 'ignored').length,
      healthy: checks.filter(v => v.status === 'healthy').length
    }
  };
}

function reconcileMtaSts(stsCheck, smtpCheck) {
  const mode = stsCheck?.evidence?.policy?.mode;
  if (!['testing', 'enforce'].includes(mode)) return stsCheck;
  const failedHosts = (smtpCheck?.evidence?.endpoints || []).filter(endpoint => !endpoint.policy_blocked && (!endpoint.starttls_negotiated || endpoint.tls_authorized === false)).map(endpoint => endpoint.host);
  if (!failedHosts.length) return stsCheck;
  return result('mta_sts', 'MTA-STS', mode === 'enforce' ? 'critical' : 'warning', mode === 'enforce' ? 'Enforced policy cannot be validated' : 'Testing policy is not ready to enforce', `${stsCheck.detail} The active SMTP probe found a STARTTLS or certificate-validation failure at ${failedHosts.join(', ')}.`, 'Correct STARTTLS and certificate validation on every MX host before relying on MTA-STS enforcement.', { ...stsCheck.evidence, smtp_validation_failed_hosts: failedHosts });
}

async function checkDomain(entry, config, options = {}) {
  const mailProfile = await resolveSmtpProfile(entry.domain, entry.smtp_profile);
  const noInbound = mailProfile.hosting_type === 'no_inbound';
  const notApplicable = (id, label) => result(id, label, 'info', 'Not applicable', 'This domain is configured not to receive inbound email.', 'No action required while inbound mail remains disabled.', { mail_profile: mailProfile });
  const dm = await dmarc(entry.domain);
  const values = await Promise.all([
    spfCheck(entry.domain, { timeout_ms: requestTimeoutMs, mail_profile: mailProfile }),
    noInbound ? Promise.resolve(notApplicable('mta_sts', 'MTA-STS')) : mtaSts(entry.domain),
    noInbound ? Promise.resolve(notApplicable('tls_rpt', 'TLS reporting')) : tlsRptCheck(entry.domain, { timeout_ms: requestTimeoutMs }),
    smtpDiagnostics(entry.domain, { timeout_ms: requestTimeoutMs, profile: mailProfile, ehlo_hostname: config.smtp_probe_hostname }),
    bimi(entry.domain, dm, entry.bimi_exception),
    dkim(entry.domain, entry.dkim_selectors, mailProfile),
    reports(entry.domain, config.opensearch, entry.report_days),
    failureReports(entry.domain, config.opensearch, entry.report_days),
    smtpTlsReports(entry.domain, config.opensearch, entry.report_days),
    reputationCheck(entry.domain, { timeout_ms: requestTimeoutMs }),
    ...entry.tls_endpoints.map(certificate),
    domainCertificateComponent(entry, config, options)
  ]);
  const [senderPolicy, stsResult, tlsreport, smtpService, brand, keys, aggregate, failures, smtpTls, reputation] = values;
  const certs = values.slice(10, -1);
  const sslCertificates = values.at(-1);
  let sts = reconcileMtaSts(stsResult, smtpService);
  if (!noInbound && isMissingMtaSts(sts)) sts = applyMissingControlException(sts, entry.control_exception?.mta_sts, 'mta_sts_absent');
  return summarize(entry.domain, [dm, senderPolicy, aggregate, keys, sts, tlsreport, smtpService, sslCertificates, ...certs, brand, reputation], { aggregate: aggregate.evidence || {}, failure: failures, smtp_tls: smtpTls, smtp_diagnostics: smtpService.evidence || {} }, { mail_profile: mailProfile });
}
function demo() {
  const aggregate = { period_days: 7, total: 15234, passed: 13985, failed: 1249, pass_rate: 91.8, dkim_pass_rate: 89.7, spf_pass_rate: 96.2, passed_dkim_aligned_rate:97.7,passed_spf_aligned_rate:96.4,failed_dkim_aligned_rate:0,failed_spf_aligned_rate:0, reporters:[{name:'Example Receiver',domain:'example.net',reports:7,messages:10200,last_report:'2026-09-02T23:59:59Z'},{name:'Mailbox Provider',domain:'mail.example.org',reports:6,messages:5034,last_report:'2026-09-02T23:59:59Z'}], timeline: [{date:'2026-08-27',total:1820,failed:180},{date:'2026-08-28',total:2110,failed:220},{date:'2026-08-29',total:1984,failed:175},{date:'2026-08-30',total:2400,failed:164},{date:'2026-08-31',total:2290,failed:190},{date:'2026-09-01',total:2510,failed:200},{date:'2026-09-02',total:2120,failed:120}], top_failing_sources:[{ip:'192.0.2.10',fqdn:'outbound.example.net',network_owner:'Example Mail',messages:620},{ip:'198.51.100.8',fqdn:'relay.example.org',messages:381}] };
  const aggregateCheck = result('dmarc_reports','DMARC reports','critical','91.8% aligned','1,249 messages failed in 7 days.','Review the top failing sources.',aggregate);
  const smtpEndpoint = evaluateSmtpEvidence('mail.example.com', { host:'mail.example.com',port:25,ip_address:'192.0.2.25',ehlo_identity:'[192.0.2.100]',connection_time_ms:7300,transaction_time_ms:7966,reverse_dns:['mail.example.com'],forward_confirmed:true,ptr_matches_host:true,reverse_dns_match:true,banner:'220 mail.example.com ESMTP ready',banner_hostname:'mail.example.com',banner_matches_reverse_dns:true,starttls_advertised:true,starttls_negotiated:true,tls_authorized:true,tls_protocol:'TLSv1.3',tls_cipher:'TLS_AES_256_GCM_SHA384',relay_status:'denied',rcpt_to_code:550,transcript:['S: 220 mail.example.com ESMTP ready','C: EHLO [192.0.2.100]','S: 250-mail.example.com','S: 250 STARTTLS','C: STARTTLS','S: 220 Ready to start TLS','C: EHLO [192.0.2.100]','S: 250 mail.example.com','C: MAIL FROM:<probe@example.com>','S: 250 Sender accepted','C: RCPT TO:<probe@example.net>','S: 550 Relaying denied','C: RSET','S: 250 Reset'] });
  const smtpService = smtpResult('example.com', [{priority:10,exchange:'mail.example.com'}], [smtpEndpoint]);
  const certificateCheckedAt = new Date().toISOString();
  const publicCertificate = sslMonitor.normalizeResult({ common_name:'example.com',subject:'CN=example.com',issuer:'CN=Example Public CA',sans:['example.com','www.example.com'],not_before:'2026-09-01T00:00:00Z',not_after:'2026-12-04T19:00:35Z',days_remaining:59,used_ip:'203.0.113.10',tls_version:'TLS 1.3',cipher_suite:'TLS_AES_128_GCM_SHA256',chain_valid:true,fingerprint:'demo-public-fingerprint' }, { domain:'example.com',checkType:'public',checkedAt:certificateCheckedAt });
  const originCertificate = sslMonitor.normalizeResult({ common_name:'example.com',subject:'CN=example.com',issuer:'CN=Example Origin CA',sans:['example.com'],not_before:'2026-09-28T00:00:00Z',not_after:'2026-12-27T16:39:50Z',days_remaining:82,used_ip:'192.0.2.10',tls_version:'TLS 1.3',cipher_suite:'TLS_AES_128_GCM_SHA256',chain_valid:true,fingerprint:'demo-origin-fingerprint' }, { domain:'example.com',checkType:'origin',originIp:'192.0.2.10',checkedAt:certificateCheckedAt });
  const certificateComponent = sslMonitor.componentResult('example.com', [publicCertificate, originCertificate]);
  const smtpTls = {available:true,reports:4,successful:8200,failed:14,success_rate:99.8,timeline:[{date:'2026-08-30',successful:1800,failed:6},{date:'2026-09-01',successful:3200,failed:5},{date:'2026-09-02',successful:3200,failed:3}],failure_types:[{type:'validation-failure',count:9},{type:'starttls-not-supported',count:5}],organizations:[{name:'Example Reporter',domains:['example.net'],reports:4,sessions:8214}],raw_samples:[{index:'smtp_tls-2026.09',organization_name:'Example Reporter',contact_info:'tls@example.net',report_id:'demo-report',date_begin:'2026-09-01T00:00:00Z',source_fields:['contact_info','date_begin','organization_name','policies','report_id']}] };
  return summarize('example.com', [result('dmarc','DMARC','warning','Quarantine · 25%','Enforcement covers only 25%.','Increase enforcement after resolving legitimate senders.'), result('spf','SPF','healthy','Valid policy · 2/10 lookups','One SPF record is published and ends in -all.','Review the policy when senders change.'), aggregateCheck, result('dkim','DKIM','warning','1/2 selectors healthy','legacy: 1024-bit key','Rotate the legacy key.'), result('mta_sts','MTA-STS','healthy','Enforced','Every MX host is covered.','Rotate the DNS id whenever the policy changes.'), result('tls_rpt','TLS reporting','healthy','1 report destination','Valid TLSRPTv1 policy using mailto.','Review TLS reports.'), smtpService, certificateComponent, result('bimi','BIMI','ignored','Self-asserted logo · Ignored','No mark certificate is published. This review item is ignored permanently.','No action is required while this exception remains active.',{ignored:true,ignore_mode:'permanent',original_status:'warning'}), result('reputation','IP and domain reputation','healthy','No blocklist matches','Three DNS-blocklist checks completed.','Continue monitoring.',{checks:[]})], { aggregate, failure:{available:false,count:0,period_days:7}, smtp_tls:smtpTls, smtp_diagnostics:smtpService.evidence }, { mail_profile: smtpService.evidence.profile });
}

function sendDiscordMessage(content, webhook = discordWebhookUrl()) {
  if (!webhook) return Promise.resolve(false);
  const body = JSON.stringify({ content: String(content || '').slice(0, 1900), allowed_mentions: { parse: [] } });
  return new Promise(resolve => {
    const request = https.request(webhook, {
      method: 'POST',
      timeout: Math.min(requestTimeoutMs, 10000),
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), 'user-agent': `DomainPosture/${APP_VERSION}` }
    }, response => {
      response.resume();
      response.on('end', () => resolve(response.statusCode >= 200 && response.statusCode < 300));
    });
    request.on('timeout', () => { request.destroy(); resolve(false); });
    request.on('error', () => resolve(false));
    request.end(body);
  });
}

function milestoneSeverity(value, milestones) {
  if (value === null || value === undefined) return 0;
  if (typeof value === 'string') return 100;
  const ordered = [...milestones].sort((a, b) => b - a);
  const index = ordered.indexOf(Number(value));
  return index < 0 ? 1 : index + 1;
}

function certificateAlertMessage(domain, certificate, milestone) {
  const title = milestone === 'expired' ? 'SSL Certificate Expired' : milestone === 'invalid' ? 'SSL Certificate Invalid' : milestone === 'check_failed' ? 'SSL Certificate Check Failed' : 'SSL Certificate Expiring Soon';
  const lines = [
    `**DomainPosture: ${title}**`,
    `Domain: ${domain}`,
    `Check: ${certificate.check_type === 'origin' ? 'Origin' : 'Public'}`
  ];
  if (certificate.check_type === 'origin' && certificate.configured_origin_ip) lines.push(`Origin IP: ${certificate.configured_origin_ip}`);
  if (certificate.issuer) lines.push(`Issuer: ${certificate.issuer}`);
  if (certificate.not_after) lines.push(`Expires: ${certificate.not_after}`);
  if (certificate.days_remaining !== null) lines.push(`Days remaining: ${certificate.days_remaining}`);
  if (certificate.error) lines.push(`Issue: ${certificate.error}`);
  return lines.join('\n');
}

async function processNotifications(domainResult, settings, send = sendDiscordMessage, options = {}) {
  const state = options.state || getOperationalState().notifications;
  const webhookReady = options.webhookReady ?? Boolean(discordWebhookUrl());
  const certificates = domainResult.checks.find(check => check.id === 'ssl_certificates')?.evidence?.checks || [];
  for (const certificate of certificates) {
    const key = `${domainResult.domain}:${certificate.check_type}`;
    const previous = state.certificates[key];
    const milestone = sslMonitor.milestoneFor(certificate, settings.ssl_milestones);
    const current = {
      initialized: true,
      active: milestone !== null,
      last_milestone: milestone,
      status: certificate.status,
      fingerprint: certificate.fingerprint || null,
      updated_at: certificate.checked_at
    };
    if (!previous) { state.certificates[key] = current; continue; }
    let message = null;
    if (previous.active && !current.active) {
      message = `**DomainPosture: SSL Certificate Recovered**\nDomain: ${domainResult.domain}\nCheck: ${certificate.check_type === 'origin' ? 'Origin' : 'Public'}${certificate.check_type === 'origin' && certificate.configured_origin_ip ? `\nOrigin IP: ${certificate.configured_origin_ip}` : ''}${certificate.not_after ? `\nExpires: ${certificate.not_after}` : ''}`;
    } else if (current.active && (
      !previous.active ||
      (typeof milestone === 'string' && milestone !== previous.last_milestone) ||
      milestoneSeverity(milestone, settings.ssl_milestones) > milestoneSeverity(previous.last_milestone, settings.ssl_milestones)
    )) {
      message = certificateAlertMessage(domainResult.domain, certificate, milestone);
    }
    if (message && settings.discord_enabled && settings.ssl_enabled && webhookReady) {
      if (await send(message)) state.certificates[key] = current;
    } else {
      state.certificates[key] = current;
    }
  }

  const previousDomain = state.domains[domainResult.domain];
  const attention = ['warning', 'critical'].includes(domainResult.status);
  const currentDomain = { initialized: true, attention, status: domainResult.status, score: domainResult.score, updated_at: new Date().toISOString() };
  if (!previousDomain) { state.domains[domainResult.domain] = currentDomain; return; }
  let domainMessage = null;
  if (!previousDomain.attention && attention) {
    const issues = domainResult.checks.filter(check => ['warning', 'critical'].includes(check.status)).slice(0, 8).map(check => `- ${check.label}: ${check.summary}`);
    domainMessage = `**DomainPosture: Domain Needs Attention**\nDomain: ${domainResult.domain}\nScore: ${domainResult.score}\n\nIssues:\n${issues.join('\n')}`;
  } else if (previousDomain.attention && !attention) {
    domainMessage = `**DomainPosture: Domain Recovered**\nDomain: ${domainResult.domain}\nScore: ${domainResult.score}\nStatus: Healthy`;
  }
  if (domainMessage && settings.discord_enabled && settings.needs_attention_enabled && webhookReady) {
    if (await send(domainMessage)) state.domains[domainResult.domain] = currentDomain;
  } else {
    state.domains[domainResult.domain] = currentDomain;
  }
}

async function refresh(options = {}) {
  if (activeRefresh) return activeRefresh;
  snapshot.refreshing = true;
  activeRefresh = (async () => {
    try {
      const config = process.env.DEMO_MODE === 'true' ? null : settingsConfig();
      let domains;
      if (!config) {
        domains = [demo()];
      } else {
        const entries = options.domain ? config.domains.filter(entry => entry.domain === options.domain) : config.domains;
        if (options.domain && !entries.length) throw new Error('The requested domain is not monitored.');
        const checked = await Promise.all(entries.map(entry => checkDomain(entry, config, { forceCertificates: options.forceCertificates === true })));
        if (options.domain) {
          const replacements = new Map(checked.map(domain => [domain.domain, domain]));
          domains = snapshot.domains.map(domain => replacements.get(domain.domain) || domain);
          for (const domain of checked) if (!domains.some(existing => existing.domain === domain.domain)) domains.push(domain);
        } else domains = checked;
        for (const domain of checked) await processNotifications(domain, config.notifications);
        await saveOperationalState();
      }
      snapshot = {
        version: APP_VERSION,
        generated_at: new Date().toISOString(),
        refreshing: false,
        configuration_required: !domains.length,
        domains,
        summary: {
          critical: domains.reduce((n, d) => n + d.counts.critical, 0),
          warning: domains.reduce((n, d) => n + d.counts.warning, 0),
          ignored: domains.reduce((n, d) => n + (d.counts.ignored || 0), 0),
          healthy: domains.reduce((n, d) => n + d.counts.healthy, 0)
        }
      };
    } catch (error) {
      addDiagnosticEvent('domainposture', 'error', 'Domain checks failed', error.message);
      snapshot = { ...snapshot, generated_at: new Date().toISOString(), refreshing: false, error: error.message };
    } finally { activeRefresh = null; }
    return snapshot;
  })();
  return activeRefresh;
}

function serveBimiLogo(res, requestUrl) {
  const domain = String(requestUrl.searchParams.get('domain') || '').toLowerCase();
  const logo = validDomain(domain) ? bimiLogos.get(domain) : null;
  if (!logo) return json(res, 404, { error: 'No validated BIMI logo is cached for this domain. Run checks again.' });
  res.writeHead(200, {
    'content-type': 'image/svg+xml; charset=utf-8',
    'cache-control': 'private, max-age=300',
    'content-security-policy': "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:",
    'x-content-type-options': 'nosniff',
    etag: `\"${logo.etag}\"`
  });
  res.end(logo.body);
}

function json(res, status, value) { const body = JSON.stringify(value); res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(body); }
function requestJson(req, maxBytes = 65536) { return new Promise((resolve, reject) => { const chunks = []; let size = 0; req.on('data', chunk => { size += chunk.length; if (size > maxBytes) { reject(new Error('Settings request is too large')); req.destroy(); } else chunks.push(chunk); }); req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch (_) { reject(new Error('Settings must be valid JSON')); } }); req.on('error', reject); }); }
function sameOriginRequest(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch (_) { return false; }
}
function staticFile(req, res) { const pathname = req.url.split('?')[0]; const name = ['/', '/domains', '/status', '/settings', '/help'].includes(pathname) ? 'index.html' : pathname.replace(/^\//, ''); const file = path.normalize(path.join(PUBLIC, name)); if (!file.startsWith(PUBLIC)) { res.writeHead(403); return res.end(); } fs.readFile(file, (e, data) => { if (e) { res.writeHead(404); return res.end(); } const type = { '.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml' }[path.extname(file)] || 'application/octet-stream'; res.writeHead(200, { 'content-type': type, 'x-content-type-options':'nosniff' }); res.end(data); }); }
function scheduleRefresh(minutes) { if (refreshTimer) clearInterval(refreshTimer); refreshTimer = setInterval(refresh, Math.max(1, minutes) * 60000); refreshTimer.unref(); }
const server = http.createServer(async (req,res) => {
  const requestUrl = new URL(req.url, 'http://localhost');
  const pathname = requestUrl.pathname;
  if (pathname === '/healthz') return json(res, snapshot.error ? 503 : 200, { ok: !snapshot.error, version: APP_VERSION, uptime_seconds: Math.floor((Date.now()-startedAt)/1000) });
  if (pathname === '/api/status' && req.method === 'GET') return json(res,200,snapshot);
  if (pathname === '/api/system-status' && req.method === 'GET') { try { return json(res, 200, await systemStatus()); } catch (error) { return json(res, 500, { version: APP_VERSION, checked_at: new Date().toISOString(), status: 'critical', checks: [], error: error.message }); } }
  if (pathname === '/api/system-logs' && req.method === 'GET') return json(res, 200, diagnosticLog());
  if (pathname === '/api/service-logs' && req.method === 'GET') {
    const service = requestUrl.searchParams.get('service') || 'domainposture';
    if (!Object.hasOwn(SERVICE_LOG_PATHS, service)) return json(res, 400, { error: 'Choose DomainPosture, OpenSearch, or ParseDMARC.' });
    return json(res, 200, await serviceLog(service));
  }
  if (pathname === '/api/bimi-logo' && req.method === 'GET') return serveBimiLogo(res, requestUrl);
  if (pathname === '/api/refresh' && req.method === 'POST') {
    if (!sameOriginRequest(req)) return json(res, 403, { error: 'Cross-origin requests are not allowed.' });
    if (activeRefresh) await activeRefresh;
    return json(res, 202, await refresh({ forceCertificates: true }));
  }
  const domainCheckMatch = pathname.match(/^\/api\/domains\/([^/]+)\/check$/);
  if (domainCheckMatch && req.method === 'POST') {
    if (!sameOriginRequest(req)) return json(res, 403, { error: 'Cross-origin requests are not allowed.' });
    let domain;
    try { domain = decodeURIComponent(domainCheckMatch[1]).toLowerCase().replace(/\.$/, ''); } catch (_) { return json(res, 400, { error: 'Invalid domain path.' }); }
    if (!validDomain(domain)) return json(res, 400, { error: 'Invalid domain.' });
    try { if (process.env.DEMO_MODE !== 'true' && !getSettings().monitored_domains.includes(domain)) return json(res, 404, { error: 'The requested domain is not monitored.' }); }
    catch (error) { return json(res, 500, { error: error.message }); }
    if (activeRefresh) await activeRefresh;
    return json(res, 202, await refresh({ domain, forceCertificates: true }));
  }
  if (pathname === '/api/settings' && req.method === 'GET') { try { return json(res, 200, publicSettings()); } catch (error) { return json(res, 500, { error: error.message }); } }
  if (pathname === '/api/settings' && req.method === 'PUT') { try { if (!sameOriginRequest(req)) return json(res, 403, { error: 'Cross-origin requests are not allowed.' }); const settings = await saveSettings(await requestJson(req)); if (activeRefresh) await activeRefresh; await refresh(); return json(res, 200, settings); } catch (error) { return json(res, 400, { error: error.message }); } }
  staticFile(req,res);
});
function start() { server.listen(PORT,'0.0.0.0',()=>{ console.log(`DomainPosture listening on :${PORT}`); addDiagnosticEvent('domainposture', 'info', 'DomainPosture started', `Version ${APP_VERSION} is listening on port ${PORT}.`); try { scheduleRefresh(getSettings().refresh_minutes); } catch (_) { scheduleRefresh(15); } refresh(); }); }
if (require.main === module) start();
module.exports = { assignments, envConfig, normalizeSettings, settingsConfig, tags, policyFile, mxMatch, selectSourceField, summarizeDmarcReporters, summarizeSmtpHits, smtpOrganization, parsedmarcIni, parsedmarcConfigurationStatus, overallStatus, systemStatus, diagnosticLog, redactLogText, normalizeBimiExceptions, normalizeControlExceptions, normalizeSmtpProfiles, normalizeCertificateChecks, normalizeNotifications, validDiscordWebhookUrl, discordWebhookConfiguration, activeBimiException, applyMissingControlException, isMissingMtaSts, bimi, globPattern, matchesIndexPattern, unassignedShardSummary, validCron, summarize, domainScore, reconcileMtaSts, smtpDiagnostics, evaluateSmtpEvidence, smtpResult, smtpBannerHostname, smtpCapabilities, validSmtpHostname, smtpTimingTest, smtpProfile, spfCheck, tlsRptCheck, reputationCheck, validateTlsRptRecord, reverseIp, certificate, domainCertificateComponent, processNotifications, sameOriginRequest, refresh, getOperationalState, getSnapshot:()=>snapshot };
