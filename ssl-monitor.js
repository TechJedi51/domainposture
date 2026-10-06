'use strict';

const { execFile } = require('child_process');
const net = require('net');

const SSL_WATCH_PATH = process.env.SSL_WATCH_PATH || '/usr/local/bin/ssl-watch';
const STATUS_RANK = { good: 0, needs_attention: 1, urgent: 2, critical: 3, check_failed: 4, invalid: 5, expired: 6 };
const SCORE_CREDIT = { good: 1, needs_attention: 0.8, urgent: 0.55, critical: 0.25, check_failed: 0.4, invalid: 0, expired: 0 };
const STATUS_LABELS = { good: 'Good', needs_attention: 'Needs attention', urgent: 'Urgent', critical: 'Critical', expired: 'Expired', invalid: 'Invalid', check_failed: 'Check failed' };

function cleanText(value, maximum = 2048) {
  return String(value ?? '').replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, maximum);
}

function finiteNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function validDomain(value) {
  return /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(String(value || ''));
}

function certificateState(output, warningThreshold = 30) {
  if (!output || typeof output !== 'object') return 'check_failed';
  if (output.chain_valid === false || output.name_mismatch === true || output.not_yet_valid === true) return 'invalid';
  if (output.chain_valid !== true) return 'check_failed';
  const days = finiteNumber(output.days_remaining);
  if (days === null || !output.not_after) return 'check_failed';
  if (days < 0) return 'expired';
  if (days <= 7) return 'critical';
  if (days <= 14) return 'urgent';
  if (days <= warningThreshold) return 'needs_attention';
  return 'good';
}

function normalizeResult(output, options = {}) {
  const checkedAt = options.checkedAt || new Date().toISOString();
  const state = certificateState(output, options.warningThreshold);
  const notBefore = Date.parse(output?.not_before);
  const notAfter = Date.parse(output?.not_after);
  return {
    check_type: options.checkType || 'public',
    status: state,
    status_label: STATUS_LABELS[state],
    score_credit: SCORE_CREDIT[state],
    domain: options.domain,
    configured_origin_ip: options.checkType === 'origin' ? options.originIp : null,
    ip_used: cleanText(output?.used_ip || options.originIp || '', 64) || null,
    common_name: cleanText(output?.common_name, 512) || null,
    subject: cleanText(output?.subject, 2048) || null,
    issuer: cleanText(output?.issuer, 2048) || null,
    sans: Array.isArray(output?.sans) ? output.sans.map(value => cleanText(value, 253)).filter(Boolean).slice(0, 200) : [],
    serial: cleanText(output?.serial, 512) || null,
    signature_algorithm: cleanText(output?.signature_algorithm, 128) || null,
    public_key: cleanText(output?.public_key, 128) || null,
    fingerprint: cleanText(output?.fingerprint, 128) || null,
    spki_fingerprint: cleanText(output?.spki_fingerprint, 128) || null,
    not_before: Number.isFinite(notBefore) ? new Date(notBefore).toISOString() : null,
    not_after: Number.isFinite(notAfter) ? new Date(notAfter).toISOString() : null,
    days_remaining: finiteNumber(output?.days_remaining),
    chain_valid: output?.chain_valid === true,
    chain_error: cleanText(output?.chain_error, 2048) || null,
    chain_error_kind: cleanText(output?.chain_error_kind, 128) || null,
    tls_version: cleanText(output?.tls_version, 128) || null,
    cipher_suite: cleanText(output?.cipher_suite, 256) || null,
    checked_at: checkedAt,
    last_successful_check: state === 'check_failed' ? null : checkedAt,
    error: null
  };
}

function failedResult(options, error, previous = null) {
  const checkedAt = options.checkedAt || new Date().toISOString();
  return {
    check_type: options.checkType || 'public',
    status: 'check_failed',
    status_label: STATUS_LABELS.check_failed,
    score_credit: SCORE_CREDIT.check_failed,
    domain: options.domain,
    configured_origin_ip: options.checkType === 'origin' ? options.originIp : null,
    ip_used: options.checkType === 'origin' ? options.originIp : null,
    common_name: null,
    subject: null,
    issuer: null,
    sans: [],
    serial: null,
    signature_algorithm: null,
    public_key: null,
    fingerprint: null,
    spki_fingerprint: null,
    not_before: null,
    not_after: null,
    days_remaining: null,
    chain_valid: false,
    chain_error: null,
    chain_error_kind: null,
    tls_version: null,
    cipher_suite: null,
    checked_at: checkedAt,
    last_successful_check: previous?.last_successful_check || null,
    error: cleanText(error?.message || error || 'ssl-watch could not complete the certificate check.', 2048)
  };
}

function sslWatchArguments(options) {
  const domain = String(options.domain || '').toLowerCase().replace(/\.$/, '');
  if (!validDomain(domain)) throw new Error('Certificate checks require a valid domain name.');
  const port = Number(options.port || 443);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Certificate checks require a valid TCP port.');
  const args = ['-domain', domain, '-port', String(port)];
  if (options.checkType === 'origin') {
    if (!net.isIP(options.originIp)) throw new Error('Origin certificate checks require a valid IPv4 or IPv6 address.');
    args.push('-ipaddr', options.originIp, '-servername', domain);
  }
  args.push('-output', 'json', '-fingerprint', '-timeout', String(Math.max(1, Math.min(60, Math.ceil(Number(options.timeoutMs || 10000) / 1000)))));
  return args;
}

function executeSslWatch(binary, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(binary, args, {
      timeout: Math.max(2000, Number(options.timeoutMs || 10000) + 2000),
      maxBuffer: 1024 * 1024,
      windowsHide: true,
      shell: false
    }, (error, stdout, stderr) => {
      if (error) {
        const message = cleanText(stderr || stdout || error.message);
        const failure = new Error(message || 'ssl-watch execution failed.');
        failure.code = error.code;
        return reject(failure);
      }
      resolve(stdout);
    });
  });
}

async function runCertificateCheck(options = {}) {
  const checkedAt = options.checkedAt || new Date().toISOString();
  const normalizedOptions = { ...options, checkedAt };
  try {
    const args = sslWatchArguments(normalizedOptions);
    const output = await (options.execute || executeSslWatch)(options.binary || SSL_WATCH_PATH, args, normalizedOptions);
    let parsed;
    try { parsed = JSON.parse(String(output || '')); }
    catch (_) { throw new Error('ssl-watch returned invalid JSON.'); }
    if (Array.isArray(parsed)) parsed = parsed[0];
    if (parsed?.error) throw new Error(cleanText(parsed.error));
    return normalizeResult(parsed, normalizedOptions);
  } catch (error) {
    return failedResult(normalizedOptions, error, options.previous);
  }
}

function componentResult(domain, checks) {
  const enabled = checks.filter(Boolean);
  if (!enabled.length) throw new Error(`At least one certificate check must be enabled for ${domain}.`);
  const worst = enabled.reduce((current, item) => STATUS_RANK[item.status] > STATUS_RANK[current.status] ? item : current, enabled[0]);
  const status = ['good'].includes(worst.status) ? 'healthy' : ['needs_attention', 'urgent'].includes(worst.status) ? 'warning' : 'critical';
  const labels = enabled.map(item => `${item.check_type === 'origin' ? 'Origin' : item.check_type === 'public' ? 'Public' : 'Endpoint'}: ${item.status_label}`);
  const detail = labels.join(' · ');
  const action = status === 'healthy'
    ? 'No action required.'
    : worst.status === 'needs_attention' || worst.status === 'urgent' || worst.status === 'critical'
      ? 'Confirm certificate renewal is scheduled and working.'
      : worst.status === 'expired'
        ? 'Renew and deploy the expired certificate immediately.'
        : worst.status === 'invalid'
          ? 'Correct the certificate chain, validity period, SNI, or hostname coverage.'
          : 'Verify network access and that ssl-watch is installed and executable.';
  return {
    id: 'ssl_certificates',
    label: 'SSL/TLS certificates',
    status,
    summary: worst.status === 'good' ? `${enabled.length} enabled check${enabled.length === 1 ? '' : 's'} healthy` : `${worst.check_type === 'origin' ? 'Origin' : 'Public'} certificate: ${worst.status_label}`,
    detail,
    action,
    evidence: {
      score_credit: Math.min(...enabled.map(item => item.score_credit)),
      worst_status: worst.status,
      checks: enabled,
      public: enabled.find(item => item.check_type === 'public') || null,
      origin: enabled.find(item => item.check_type === 'origin') || null
    }
  };
}

function resultIsFresh(result, minutes, now = Date.now()) {
  const checked = Date.parse(result?.checked_at);
  return Number.isFinite(checked) && now - checked < Math.max(1, Number(minutes || 360)) * 60000;
}

function milestoneFor(result, milestones = [30, 14, 7]) {
  if (!result) return null;
  if (['expired', 'invalid', 'check_failed'].includes(result.status)) return result.status;
  const days = finiteNumber(result.days_remaining);
  if (days === null) return null;
  const ordered = [...new Set(milestones.map(Number).filter(Number.isFinite))].sort((a, b) => a - b);
  return ordered.find(value => days <= value) ?? null;
}

module.exports = {
  SSL_WATCH_PATH,
  SCORE_CREDIT,
  STATUS_LABELS,
  validDomain,
  certificateState,
  normalizeResult,
  failedResult,
  sslWatchArguments,
  executeSslWatch,
  runCertificateCheck,
  componentResult,
  resultIsFresh,
  milestoneFor,
  cleanText
};
