'use strict';

const dns = require('dns').promises;
const net = require('net');

function result(id, label, status, summary, detail, action, evidence = {}) {
  return { id, label, status, summary, detail, action, evidence };
}

function dnsMissing(error) {
  return ['ENOTFOUND', 'ENODATA', 'EAI_NONAME', 'NOTFOUND', 'NODATA'].includes(error?.code);
}

function withTimeout(promise, timeoutMs, label = 'DNS lookup') {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error(`${label} timed out`), { code: 'ETIMEOUT' })), Math.max(1, timeoutMs)); })
  ]).finally(() => clearTimeout(timer));
}

function resolverFor(options) {
  if (options.resolver) return options.resolver;
  return new dns.Resolver({ timeout: Math.min(5000, Number(options.timeout_ms || 8000)), tries: 1 });
}

function spfTerms(record) {
  return String(record || '').trim().split(/\s+/).filter(Boolean);
}

function mechanismName(term) {
  return term.replace(/^[+?~-]/, '').split(/[:/=]/, 1)[0].toLowerCase();
}

function mechanismTarget(term) {
  const bare = term.replace(/^[+?~-]/, '');
  const colon = bare.indexOf(':');
  if (colon < 0) return null;
  return bare.slice(colon + 1).split('/')[0].toLowerCase().replace(/\.$/, '');
}

async function inspectSpfDomain(domain, resolver, state, depth = 0, path = new Set()) {
  if (Date.now() >= state.deadline) {
    state.temporaryErrors.push(`${domain}: SPF expansion timed out.`);
    return;
  }
  if (path.has(domain)) {
    state.errors.push(`Recursive SPF reference detected at ${domain}.`);
    return;
  }
  const nextPath = new Set(path); nextPath.add(domain);
  let records;
  try {
    records = (await withTimeout(resolver.resolveTxt(domain), Math.min(5000, state.deadline - Date.now()), `SPF lookup for ${domain}`)).map(parts => parts.join('')).filter(record => /^v=spf1(?:\s|$)/i.test(record.trim()));
  } catch (error) {
    if (dnsMissing(error)) records = [];
    else {
      state.temporaryErrors.push(`${domain}: ${error.message}`);
      return;
    }
  }
  state.records.push({ domain, records });
  if (records.length !== 1) {
    state.errors.push(records.length ? `${domain} publishes multiple SPF records.` : `${domain} does not publish an SPF record.`);
    return;
  }
  const terms = spfTerms(records[0]);
  if (terms[0]?.toLowerCase() !== 'v=spf1') state.errors.push(`${domain}: v=spf1 must be the first term.`);
  const redirects = terms.filter(term => /^redirect=/i.test(term));
  const exps = terms.filter(term => /^exp=/i.test(term));
  if (redirects.length > 1) state.errors.push(`${domain}: redirect appears more than once.`);
  if (exps.length > 1) state.errors.push(`${domain}: exp appears more than once.`);
  const mechanisms = terms.slice(1).filter(term => !/^[a-z][a-z0-9_.-]*=/i.test(term));
  for (const term of mechanisms) {
    const name = mechanismName(term);
    const bare = term.replace(/^[+?~-]/, '');
    if (!['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists'].includes(name)) state.errors.push(`${domain}: unrecognized mechanism “${term}”.`);
    if (['include', 'a', 'mx', 'ptr', 'exists'].includes(name)) state.lookupCount += 1;
    if (name === 'ptr') state.warnings.push(`${domain} uses the deprecated ptr mechanism.`);
    if (name === 'all' && bare.toLowerCase() !== 'all') state.errors.push(`${domain}: all cannot have a value.`);
    if (['include', 'exists'].includes(name) && !mechanismTarget(term)) state.errors.push(`${domain}: ${name} requires a domain.`);
    if (['ip4', 'ip6'].includes(name)) {
      const value = bare.slice(bare.indexOf(':') + 1); const [address, cidr] = value.split('/'); const family = name === 'ip4' ? 4 : 6; const maximum = family === 4 ? 32 : 128;
      if (!bare.includes(':') || net.isIP(address) !== family || (cidr !== undefined && (!/^\d+$/.test(cidr) || Number(cidr) > maximum))) state.errors.push(`${domain}: invalid ${name} mechanism “${term}”.`);
    }
  }
  const allTerms = mechanisms.filter(term => mechanismName(term) === 'all');
  if (depth === 0 && !allTerms.length && !redirects.length) state.warnings.push(`${domain} has no all mechanism or redirect modifier.`);
  if (allTerms.length > 1) state.errors.push(`${domain} contains more than one all mechanism.`);
  if (allTerms.length && mechanisms.indexOf(allTerms[0]) !== mechanisms.length - 1) state.errors.push(`${domain}: all must be the last mechanism.`);
  if (allTerms.length) {
    const qualifier = /^[+?~-]/.test(allTerms[0]) ? allTerms[0][0] : '+';
    if (qualifier === '+') state.errors.push(`${domain} authorizes every sender with +all.`);
    else if (qualifier === '?') state.errors.push(`${domain} uses ?all, which provides no meaningful authorization boundary.`);
    else if (qualifier === '~' && depth === 0) state.warnings.push(`${domain} ends in softfail (~all).`);
    else if (depth === 0) state.hardFail = true;
  }
  const references = mechanisms.filter(term => mechanismName(term) === 'include').map(mechanismTarget).filter(Boolean);
  if (redirects[0]) {
    state.lookupCount += 1;
    const target = redirects[0].slice(redirects[0].indexOf('=') + 1).toLowerCase().replace(/\.$/, '');
    if (target) references.push(target); else state.errors.push(`${domain}: redirect has no target.`);
  }
  const expansions = [];
  for (const target of references) {
    if (target.includes('%{')) {
      state.warnings.push(`${domain} uses a macro-based SPF reference that MailPosture cannot expand statically.`);
      continue;
    }
    if (!/^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(target)) {
      state.errors.push(`${domain}: invalid SPF reference “${target}”.`);
      continue;
    }
    if (state.records.length >= 20) {
      state.errors.push('SPF expansion exceeded the MailPosture safety limit.');
      break;
    }
    expansions.push(inspectSpfDomain(target, resolver, state, depth + 1, nextPath));
  }
  await Promise.all(expansions);
}

async function spfCheck(domain, options = {}) {
  const resolver = resolverFor(options);
  const state = { records: [], errors: [], warnings: [], temporaryErrors: [], lookupCount: 0, hardFail: false, deadline: Date.now() + Number(options.timeout_ms || 8000) };
  await inspectSpfDomain(domain, resolver, state);
  if (state.lookupCount > 10) state.errors.push(`Expanded SPF policy requires at least ${state.lookupCount} DNS-querying terms; the limit is 10.`);
  const evidence = { records: state.records, dns_lookup_terms: state.lookupCount, hard_fail: state.hardFail, warnings: state.warnings, errors: state.errors, temporary_errors: state.temporaryErrors };
  if (state.temporaryErrors.length && !state.records.length) return result('spf', 'SPF', 'warning', 'DNS check unavailable', state.temporaryErrors.join(' '), 'Retry the check and verify DNS resolution from the MailPosture container.', evidence);
  if (state.errors.length) return result('spf', 'SPF', 'critical', 'Invalid policy', state.errors.join(' '), 'Correct the SPF record, then run the check again. Keep recursive DNS-querying terms at 10 or fewer.', evidence);
  if (state.temporaryErrors.length) return result('spf', 'SPF', 'warning', 'Validation incomplete', state.temporaryErrors.join(' '), 'Retry the check and verify DNS resolution from the MailPosture container.', evidence);
  if (state.warnings.length) return result('spf', 'SPF', 'warning', state.hardFail ? 'Valid, with review items' : 'Policy needs review', state.warnings.join(' '), state.hardFail ? 'Review the warnings and confirm every legitimate sender remains authorized.' : 'Move toward -all after confirming every legitimate sender is authorized.', evidence);
  return result('spf', 'SPF', 'healthy', `Valid policy · ${state.lookupCount}/10 lookups`, 'One SPF record is published, its expanded DNS-querying terms are within the RFC limit, and it ends in -all.', 'Review the policy whenever sending services change.', evidence);
}

function validateTlsRptRecord(record) {
  const fields = String(record || '').split(';').map(value => value.trim()).filter(Boolean);
  const errors = [];
  if (fields[0]?.toLowerCase() !== 'v=tlsrptv1') errors.push('v=TLSRPTv1 must be the first field.');
  const ruaFields = fields.filter(field => /^rua=/i.test(field));
  if (ruaFields.length !== 1) errors.push(ruaFields.length ? 'The rua field appears more than once.' : 'The required rua field is missing.');
  const destinations = [];
  if (ruaFields.length === 1) {
    for (const raw of ruaFields[0].slice(ruaFields[0].indexOf('=') + 1).split(',').map(value => value.trim()).filter(Boolean)) {
      try {
        const uri = new URL(raw);
        if (!['mailto:', 'https:'].includes(uri.protocol)) throw new Error('only mailto and https are supported');
        if (uri.protocol === 'mailto:') {
          const address = decodeURIComponent(uri.pathname);
          const at = address.lastIndexOf('@');
          if (at < 1 || !address.slice(at + 1).includes('.')) throw new Error('invalid email address');
          destinations.push({ uri: raw, scheme: 'mailto', domain: address.slice(at + 1).toLowerCase() });
        } else {
          if (!uri.hostname || uri.username || uri.password) throw new Error('invalid HTTPS destination');
          destinations.push({ uri: raw, scheme: 'https', domain: uri.hostname.toLowerCase() });
        }
      } catch (error) { errors.push(`Invalid rua destination “${raw}”: ${error.message}.`); }
    }
    if (!destinations.length) errors.push('The rua field has no usable destinations.');
  }
  for (const field of fields.slice(1)) if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}=\S+$/.test(field)) errors.push(`Malformed field “${field}”.`);
  return { valid: !errors.length, destinations, errors, fields };
}

async function tlsRptCheck(domain, options = {}) {
  const resolver = resolverFor(options);
  let allRecords;
  try { allRecords = (await withTimeout(resolver.resolveTxt(`_smtp._tls.${domain}`), Number(options.timeout_ms || 8000), `TLS-RPT lookup for ${domain}`)).map(parts => parts.join('')); }
  catch (error) {
    return result('tls_rpt', 'TLS reporting', 'warning', 'Not configured', error.message, 'Publish one TLS-RPT TXT record with at least one mailto or HTTPS rua destination.', { records: [] });
  }
  const records = allRecords.filter(value => /^v=tlsrptv1(?:;|$)/i.test(value.trim()));
  if (records.length !== 1) return result('tls_rpt', 'TLS reporting', 'warning', records.length ? 'Multiple policies' : 'Not configured', `Expected exactly one TLSRPTv1 record; found ${records.length}.`, 'Publish exactly one TLS-RPT record at _smtp._tls for this domain.', { records });
  const validation = validateTlsRptRecord(records[0]);
  if (!validation.valid) return result('tls_rpt', 'TLS reporting', 'critical', 'Invalid policy', validation.errors.join(' '), 'Correct the TLS-RPT record syntax and rua destinations.', { record: records[0], ...validation });
  return result('tls_rpt', 'TLS reporting', 'healthy', `${validation.destinations.length} report destination${validation.destinations.length === 1 ? '' : 's'}`, `Valid TLSRPTv1 policy using ${validation.destinations.map(item => item.scheme).join(', ')}.`, 'Review SMTP TLS reports before changing transport policy.', { record: records[0], ...validation });
}

function reverseIp(address) {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(address)) return address.split('.').reverse().join('.');
  if (!address.includes(':')) return null;
  const halves = address.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  if (groups.length !== 8 || groups.some(group => !/^[0-9a-f]{1,4}$/i.test(group))) return null;
  return groups.map(group => group.padStart(4, '0')).join('').split('').reverse().join('.');
}

const REPUTATION_PROVIDERS = [
  { name: 'Spamhaus DBL', type: 'domain', zone: 'dbl.spamhaus.org' },
  { name: 'Spamhaus ZEN', type: 'ip', zone: 'zen.spamhaus.org' },
  { name: 'SpamCop', type: 'ip', zone: 'bl.spamcop.net' }
];

async function queryBlocklist(provider, value, resolver, timeoutMs = 8000) {
  const prefix = provider.type === 'ip' ? reverseIp(value) : value.toLowerCase().replace(/\.$/, '');
  if (!prefix) return { provider: provider.name, target: value, type: provider.type, status: 'unavailable', detail: 'Unsupported address format.' };
  try {
    const answers = await withTimeout(resolver.resolve4(`${prefix}.${provider.zone}`), timeoutMs, `${provider.name} lookup`);
    if (provider.name.startsWith('Spamhaus') && answers.some(answer => answer.startsWith('127.255.255.'))) return { provider: provider.name, target: value, type: provider.type, status: 'unavailable', detail: `Provider access error (${answers.join(', ')}). Use a permitted DNS resolver or Spamhaus DQS.` };
    return { provider: provider.name, target: value, type: provider.type, status: answers.length ? 'listed' : 'clean', answers };
  } catch (error) {
    if (dnsMissing(error)) return { provider: provider.name, target: value, type: provider.type, status: 'clean', answers: [] };
    return { provider: provider.name, target: value, type: provider.type, status: 'unavailable', detail: error.message };
  }
}

async function reputationCheck(domain, options = {}) {
  const resolver = resolverFor(options); const timeoutMs = Number(options.timeout_ms || 8000); const addresses = new Set(options.addresses || []); const mxHosts = new Set();
  if (!addresses.size) {
    try {
      const exchanges = await withTimeout(resolver.resolveMx(domain), timeoutMs, `MX lookup for ${domain}`);
      const addressLookups = [];
      for (const mx of exchanges.slice(0, 10)) {
        const host = mx.exchange.toLowerCase().replace(/\.$/, ''); mxHosts.add(host);
        for (const method of ['resolve4', 'resolve6']) {
          addressLookups.push(withTimeout(resolver[method](host), timeoutMs, `${method} lookup for ${host}`).then(values => { for (const address of values) addresses.add(address); }).catch(() => {}));
        }
      }
      await Promise.all(addressLookups);
    } catch (_) {}
  }
  const targets = [queryBlocklist(REPUTATION_PROVIDERS[0], domain, resolver, timeoutMs)];
  for (const address of [...addresses].slice(0, 20)) for (const provider of REPUTATION_PROVIDERS.filter(item => item.type === 'ip')) targets.push(queryBlocklist(provider, address, resolver, timeoutMs));
  const checks = await Promise.all(targets); const listed = checks.filter(item => item.status === 'listed'); const completed = checks.filter(item => item.status !== 'unavailable');
  const evidence = { scope: 'Monitored domain and receiving MX addresses; outbound sending services can use different addresses.', mx_hosts: [...mxHosts], addresses: [...addresses].slice(0, 20), providers: REPUTATION_PROVIDERS.map(({ name, type, zone }) => ({ name, type, zone })), checks };
  if (listed.length) return result('reputation', 'IP and domain reputation', 'warning', `${listed.length} blocklist match${listed.length === 1 ? '' : 'es'}`, listed.map(item => `${item.target} is listed by ${item.provider}.`).join(' '), 'Open the named provider’s lookup service, verify the listing, correct the underlying cause, and follow that provider’s removal process.', evidence);
  if (!completed.length) return result('reputation', 'IP and domain reputation', 'info', 'Screening unavailable', 'The configured DNS resolver could not query any reputation provider.', 'Allow DNS-blocklist queries or configure a permitted provider service. Do not treat an unavailable result as clean.', evidence);
  const unavailable = checks.length - completed.length;
  return result('reputation', 'IP and domain reputation', unavailable ? 'info' : 'healthy', unavailable ? 'No matches in available lists' : 'No blocklist matches', `${completed.length} of ${checks.length} DNS-blocklist checks completed${unavailable ? `; ${unavailable} could not be queried` : ''}. This is a limited screening, not a deliverability guarantee.`, unavailable ? 'Review unavailable providers and confirm important outbound sending IP addresses separately.' : 'Continue monitoring and confirm outbound sender addresses when they differ from receiving MX addresses.', evidence);
}

module.exports = { spfTerms, mechanismName, validateTlsRptRecord, reverseIp, queryBlocklist, spfCheck, tlsRptCheck, reputationCheck };
