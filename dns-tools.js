'use strict';

const dns = require('dns').promises;
const net = require('net');
const { tlsRptCheck, reputationCheck } = require('./dns-security');
const networkTools = require('./network-tools');
const { isPublicIp } = networkTools;

const LOOKUP_RECORD_TYPES = Object.freeze(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'SOA', 'SRV', 'TLSRPT']);
const MONITOR_RECORD_TYPES = Object.freeze(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TLSRPT']);
const LOOKUP_TOOLS = Object.freeze(['overview', 'dnssec', 'registration', 'srv', 'web', 'asn', 'tcp']);

function validHostname(value) {
  return /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(value);
}

function validSrvName(value) {
  return /^_[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\._(?:tcp|udp)\.(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(value);
}

function normalizeLookupTarget(value) {
  const target = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (net.isIP(target)) return { target, kind: 'ip', family: net.isIP(target) };
  if (validSrvName(target)) return { target, kind: 'srv', family: null };
  if (validHostname(target)) return { target, kind: 'hostname', family: null };
  throw new Error('Enter a valid fully qualified domain name, host name, SRV record name, IPv4 address, or IPv6 address.');
}

function normalizeLookupTool(value) {
  const tool = String(value || 'overview').trim().toLowerCase();
  if (!LOOKUP_TOOLS.includes(tool)) throw new Error('Choose a supported Lookup Center tool.');
  return tool;
}

function dnsMissing(error) {
  return ['ENOTFOUND', 'ENODATA', 'EAI_NONAME', 'NOTFOUND', 'NODATA', 'NXDOMAIN'].includes(error?.code);
}

function withTimeout(promise, timeoutMs, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error(`${label} timed out`), { code: 'ETIMEOUT' })), Math.max(1, timeoutMs)); })
  ]).finally(() => clearTimeout(timer));
}

function resolverFor(options = {}) {
  if (options.resolver) return options.resolver;
  return new dns.Resolver({ timeout: Math.min(5000, Number(options.timeout_ms || 8000)), tries: 1 });
}

function normalizedAddressRecords(values = []) {
  return values.map(value => typeof value === 'string' ? { address: value, ttl: null } : { address: value.address, ttl: Number.isFinite(value.ttl) ? value.ttl : null });
}

function canonicalValues(type, values = []) {
  const normalized = type === 'A' || type === 'AAAA'
    ? values.map(value => value.address)
    : type === 'SOA'
      ? values.map(value => String(value.serial))
      : values.map(value => typeof value === 'string' ? value : JSON.stringify(value));
  return [...new Set(normalized.map(value => String(value).toLowerCase()))].sort();
}

async function resolveRecord(target, type, options = {}) {
  const normalizedTarget = normalizeLookupTarget(target);
  const recordType = String(type || '').toUpperCase();
  const timeoutMs = Number(options.timeout_ms || 8000);
  const resolver = resolverFor(options);
  if (normalizedTarget.kind === 'ip' && recordType !== 'PTR') throw new Error('Only PTR lookup is available for an IP address.');
  if (normalizedTarget.kind === 'srv' && recordType !== 'SRV') throw new Error('Only SRV lookup is available for an SRV record name.');
  if (normalizedTarget.kind === 'hostname' && !LOOKUP_RECORD_TYPES.includes(recordType)) throw new Error(`Unsupported DNS record type: ${recordType || '(empty)'}.`);
  const queriedName = recordType === 'TLSRPT' ? `_smtp._tls.${normalizedTarget.target}` : normalizedTarget.target;
  try {
    let values;
    if (recordType === 'PTR') values = await withTimeout(resolver.reverse(normalizedTarget.target), timeoutMs, `PTR lookup for ${normalizedTarget.target}`);
    else if (recordType === 'A') values = normalizedAddressRecords(await withTimeout(resolver.resolve4(queriedName, { ttl: true }), timeoutMs, `A lookup for ${queriedName}`));
    else if (recordType === 'AAAA') values = normalizedAddressRecords(await withTimeout(resolver.resolve6(queriedName, { ttl: true }), timeoutMs, `AAAA lookup for ${queriedName}`));
    else if (recordType === 'CNAME') values = await withTimeout(resolver.resolveCname(queriedName), timeoutMs, `CNAME lookup for ${queriedName}`);
    else if (recordType === 'MX') values = (await withTimeout(resolver.resolveMx(queriedName), timeoutMs, `MX lookup for ${queriedName}`)).map(value => ({ priority: value.priority, exchange: String(value.exchange || '').toLowerCase().replace(/\.$/, '') })).sort((a, b) => a.priority - b.priority || a.exchange.localeCompare(b.exchange));
    else if (recordType === 'NS') values = await withTimeout(resolver.resolveNs(queriedName), timeoutMs, `NS lookup for ${queriedName}`);
    else if (recordType === 'TXT' || recordType === 'TLSRPT') values = (await withTimeout(resolver.resolveTxt(queriedName), timeoutMs, `${recordType} lookup for ${queriedName}`)).map(parts => parts.join(''));
    else if (recordType === 'CAA') values = await withTimeout(resolver.resolveCaa(queriedName), timeoutMs, `CAA lookup for ${queriedName}`);
    else if (recordType === 'SOA') values = [await withTimeout(resolver.resolveSoa(queriedName), timeoutMs, `SOA lookup for ${queriedName}`)];
    else if (recordType === 'SRV') values = (await withTimeout(resolver.resolveSrv(queriedName), timeoutMs, `SRV lookup for ${queriedName}`)).map(value => ({ priority: value.priority, weight: value.weight, port: value.port, name: String(value.name || '').toLowerCase().replace(/\.$/, '') })).sort((a, b) => a.priority - b.priority || b.weight - a.weight || a.name.localeCompare(b.name));
    else throw new Error(`Unsupported DNS record type: ${recordType || '(empty)'}.`);
    const sorted = [...values].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    return { target: normalizedTarget.target, queried_name: queriedName, type: recordType, status: sorted.length ? 'available' : 'missing', values: sorted, identity: canonicalValues(recordType, sorted), checked_at: new Date().toISOString() };
  } catch (error) {
    if (dnsMissing(error)) return { target: normalizedTarget.target, queried_name: queriedName, type: recordType, status: 'missing', values: [], identity: [], checked_at: new Date().toISOString() };
    return { target: normalizedTarget.target, queried_name: queriedName, type: recordType, status: 'unavailable', values: [], identity: [], error: error.message, checked_at: new Date().toISOString() };
  }
}

async function lookupTarget(value, options = {}) {
  const normalized = normalizeLookupTarget(value);
  const tool = normalizeLookupTool(options.tool);
  const resolver = resolverFor(options);
  const sharedOptions = { ...options, resolver };
  const common = { target: normalized.target, kind: normalized.kind, tool, checked_at: new Date().toISOString() };
  if (tool === 'srv') {
    if (normalized.kind !== 'srv') throw new Error('Enter a complete SRV record name, such as _sip._tcp.example.com.');
    return { ...common, dns: [await resolveRecord(normalized.target, 'SRV', sharedOptions)] };
  }
  if (normalized.kind === 'srv') throw new Error('Choose the SRV record tool for an SRV record name.');
  if (tool === 'dnssec') {
    if (normalized.kind !== 'hostname') throw new Error('DNSSEC validation requires a domain or host name.');
    return { ...common, dnssec: await networkTools.dnssecCheck(normalized.target, sharedOptions) };
  }
  if (tool === 'registration') {
    if (normalized.kind !== 'hostname') throw new Error('Domain registration lookup requires a domain or host name.');
    return { ...common, registration: await networkTools.rdapRegistration(normalized.target, sharedOptions) };
  }
  if (tool === 'web') {
    if (normalized.kind !== 'hostname') throw new Error('HTTP/HTTPS diagnostics require a public domain or host name.');
    return { ...common, web: await networkTools.webDiagnostics(normalized.target, sharedOptions) };
  }
  if (tool === 'asn') {
    const addresses = normalized.kind === 'ip' ? [normalized.target] : await networkTools.publicAddresses(normalized.target, sharedOptions);
    return { ...common, ownership: await networkTools.asnOwnership(addresses, sharedOptions) };
  }
  if (tool === 'tcp') {
    return { ...common, tcp: await networkTools.tcpPortCheck(normalized.target, options.tcp_port, sharedOptions) };
  }
  if (normalized.kind === 'ip') {
    const dnsRecords = [await resolveRecord(normalized.target, 'PTR', sharedOptions)];
    const publicAddresses = isPublicIp(normalized.target) ? [normalized.target] : [];
    const reputation = publicAddresses.length
      ? await reputationCheck('', { ...sharedOptions, addresses: publicAddresses, include_domain: false })
      : { id: 'reputation', label: 'IP reputation', status: 'info', summary: 'Not queried', detail: 'Private, loopback, link-local, multicast, and documentation addresses are not submitted to public blocklists.', action: 'Enter a public IP address to run a reputation lookup.', evidence: { addresses: [normalized.target], checks: [] } };
    return { ...common, dns: dnsRecords, tls_rpt: null, reputation };
  }
  const dnsRecords = await Promise.all(LOOKUP_RECORD_TYPES.filter(type => !['TLSRPT', 'SRV'].includes(type)).map(type => resolveRecord(normalized.target, type, sharedOptions)));
  const addresses = dnsRecords.filter(record => ['A', 'AAAA'].includes(record.type)).flatMap(record => record.values.map(item => item.address)).filter(isPublicIp);
  const [tlsRpt, reputation] = await Promise.all([
    tlsRptCheck(normalized.target, sharedOptions),
    reputationCheck(normalized.target, { ...sharedOptions, addresses, include_domain: true })
  ]);
  return { ...common, dns: dnsRecords, tls_rpt: tlsRpt, reputation };
}

function createLookupCenter(options = {}) {
  const ttlMs = Math.max(1000, Number(options.ttl_ms || 5 * 60000));
  const maxEntries = Math.max(1, Number(options.max_entries || 100));
  const now = options.now || Date.now;
  const execute = options.lookup || lookupTarget;
  const cache = new Map();
  const inFlight = new Map();
  const lookup = (value, toolValue = 'overview', tcpPortValue = null) => {
    const normalized = normalizeLookupTarget(value);
    const tool = normalizeLookupTool(toolValue);
    const tcpPort = tool === 'tcp' ? networkTools.normalizeTcpPort(tcpPortValue) : null;
    const cacheKey = `${normalized.target}|${tool}|${tcpPort || ''}`;
    const cached = cache.get(cacheKey);
    if (cached && now() < cached.expiresAt) return Promise.resolve({ ...cached.result, cached: true });
    if (inFlight.has(cacheKey)) return inFlight.get(cacheKey).then(result => ({ ...result, shared: true }));
    const operation = Promise.resolve().then(() => execute(normalized.target, { ...options, tool, tcp_port: tcpPort })).then(result => {
      cache.set(cacheKey, { result, expiresAt: now() + ttlMs });
      while (cache.size > maxEntries) cache.delete(cache.keys().next().value);
      return { ...result, cached: false };
    }).finally(() => inFlight.delete(cacheKey));
    inFlight.set(cacheKey, operation);
    return operation;
  };
  return { lookup, clear: () => cache.clear() };
}

async function checkDnsMonitors(monitors = [], options = {}) {
  return Promise.all(monitors.map(async monitor => ({ ...monitor, ...(await resolveRecord(monitor.host, monitor.type, options)) })));
}

module.exports = { LOOKUP_RECORD_TYPES, MONITOR_RECORD_TYPES, LOOKUP_TOOLS, validHostname, validSrvName, normalizeLookupTarget, normalizeLookupTool, isPublicIp, canonicalValues, resolveRecord, lookupTarget, createLookupCenter, checkDnsMonitors };
