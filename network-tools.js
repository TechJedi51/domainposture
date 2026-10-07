'use strict';

const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const net = require('net');
const { reverseIp } = require('./dns-security');

const ALLOWED_TCP_PORTS = Object.freeze([22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 8080, 8443]);
const DNSSEC_ENDPOINT = 'https://dns.google/resolve';
const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
let rdapBootstrapCache = null;

function isPublicIp(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const [a, b, c] = address.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 0 && c === 0) || (a === 192 && b === 0 && c === 2) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113));
  }
  if (family === 6) {
    const normalized = address.toLowerCase();
    const mappedIpv4 = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)?.[1];
    if (mappedIpv4) return isPublicIp(mappedIpv4);
    return !(normalized === '::' || normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') || /^fe[89ab]/.test(normalized) || normalized.startsWith('ff') || normalized.startsWith('2001:db8:'));
  }
  return false;
}

function withTimeout(promise, timeoutMs, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out.`)), Math.max(1, timeoutMs)); })
  ]).finally(() => clearTimeout(timer));
}

function normalizeTcpPort(value) {
  if (value === undefined || value === null || value === '') return null;
  const port = Number(value);
  if (!Number.isInteger(port) || !ALLOWED_TCP_PORTS.includes(port)) throw new Error(`Choose an allowed TCP port: ${ALLOWED_TCP_PORTS.join(', ')}.`);
  return port;
}

async function publicAddresses(hostname, options = {}) {
  if (net.isIP(hostname)) return isPublicIp(hostname) ? [hostname] : [];
  const operation = options.addressLookup
    ? options.addressLookup(hostname, { all: true, verbatim: true })
    : dns.lookup(hostname, { all: true, verbatim: true });
  const values = await withTimeout(Promise.resolve(operation), Number(options.timeout_ms || 8000), `Address lookup for ${hostname}`);
  return [...new Set(values.map(value => typeof value === 'string' ? value : value.address).filter(isPublicIp))].sort((left, right) => net.isIP(left) - net.isIP(right));
}

function responseBody(response) {
  return response && Object.hasOwn(response, 'body') ? response.body : response;
}

async function requestJsonHttps(input, options = {}, redirects = 4) {
  const url = input instanceof URL ? input : new URL(input);
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) throw new Error('External lookup services must use standard HTTPS.');
  const addresses = await publicAddresses(url.hostname, options);
  if (!addresses.length) throw new Error(`External lookup service ${url.hostname} did not resolve to a public address.`);
  const address = addresses[0];
  return new Promise((resolve, reject) => {
    const request = https.request({
      hostname: url.hostname, port: 443, path: `${url.pathname}${url.search}`, method: 'GET', servername: url.hostname,
      headers: { accept: 'application/json, application/rdap+json', 'user-agent': 'DomainPosture Lookup Center' },
      lookup: (_hostname, lookupOptions, callback) => lookupOptions?.all ? callback(null, [{ address, family: net.isIP(address) }]) : callback(null, address, net.isIP(address))
    }, response => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
        response.resume();
        if (!redirects) return reject(new Error('External lookup redirected too many times.'));
        let next;
        try { next = new URL(response.headers.location, url); } catch (error) { return reject(error); }
        return requestJsonHttps(next, options, redirects - 1).then(resolve, reject);
      }
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => {
        body += chunk;
        if (body.length > 1024 * 1024) request.destroy(new Error('External lookup response exceeded 1 MB.'));
      });
      response.on('end', () => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          const error = new Error(`External lookup returned HTTP ${response.statusCode}.`);
          error.statusCode = response.statusCode;
          return reject(error);
        }
        try { resolve({ body: JSON.parse(body), url: url.toString() }); }
        catch (_) { reject(new Error('External lookup returned invalid JSON.')); }
      });
    });
    request.setTimeout(Number(options.timeout_ms || 8000), () => request.destroy(new Error(`External lookup for ${url.hostname} timed out.`)));
    request.on('error', reject);
    request.end();
  });
}

async function dnssecCheck(target, options = {}) {
  const requestJson = options.requestJson || requestJsonHttps;
  const query = async type => {
    const url = new URL(DNSSEC_ENDPOINT);
    url.searchParams.set('name', target);
    url.searchParams.set('type', type);
    url.searchParams.set('cd', '0');
    url.searchParams.set('do', '1');
    url.searchParams.set('edns_client_subnet', '0.0.0.0/0');
    return responseBody(await requestJson(url, options));
  };
  try {
    const [validation, dnskey, ds] = await Promise.all([query('SOA'), query('DNSKEY'), query('DS')]);
    const records = (response, type) => (response?.Answer || []).filter(answer => Number(answer.type) === type).map(answer => ({ type: answer.type, ttl: answer.TTL, data: answer.data }));
    const evidence = { authenticated_data: validation?.AD === true, response_status: Number(validation?.Status), dnskey: records(dnskey, 48), ds: records(ds, 43), provider: 'Google Public DNS' };
    if (validation?.AD === true) return { status: 'healthy', summary: 'DNSSEC validated', detail: 'Google Public DNS authenticated the DNS response with DNSSEC.', evidence };
    if (Number(validation?.Status) === 2) return { status: 'warning', summary: 'DNSSEC validation failed', detail: validation.Comment || 'The validating resolver returned SERVFAIL. Review the DNSSEC chain and authoritative DNS service.', evidence };
    if (evidence.dnskey.length || evidence.ds.length) return { status: 'warning', summary: 'DNSSEC records not validated', detail: 'DNSSEC records were found, but the response did not validate as authenticated data.', evidence };
    return { status: 'info', summary: 'No DNSSEC validation', detail: 'The validating resolver did not authenticate this DNS response.', evidence };
  } catch (error) {
    return { status: 'info', summary: 'DNSSEC lookup unavailable', detail: error.message, evidence: { authenticated_data: false, dnskey: [], ds: [], provider: 'Google Public DNS' } };
  }
}

function rdapEntityName(entity) {
  const fields = Array.isArray(entity?.vcardArray?.[1]) ? entity.vcardArray[1] : [];
  for (const name of ['fn', 'org']) {
    const field = fields.find(item => Array.isArray(item) && item[0] === name);
    if (field?.[3]) return Array.isArray(field[3]) ? field[3].filter(Boolean).join(' ') : String(field[3]);
  }
  return null;
}

async function rdapBootstrap(options = {}) {
  const now = options.now ? options.now() : Date.now();
  if (!options.requestJson && rdapBootstrapCache && now < rdapBootstrapCache.expires_at) return rdapBootstrapCache.value;
  const requestJson = options.requestJson || requestJsonHttps;
  const value = responseBody(await requestJson(new URL(RDAP_BOOTSTRAP_URL), options));
  if (!Array.isArray(value?.services)) throw new Error('IANA returned an invalid RDAP bootstrap document.');
  if (!options.requestJson) rdapBootstrapCache = { value, expires_at: now + 24 * 60 * 60 * 1000 };
  return value;
}

function rdapEvent(events, action) {
  return events?.find(event => String(event.eventAction || '').toLowerCase() === action)?.eventDate || null;
}

async function rdapRegistration(target, options = {}) {
  try {
    const bootstrap = await rdapBootstrap(options);
    const labels = target.split('.');
    const tld = labels.at(-1);
    const service = bootstrap.services.find(entry => Array.isArray(entry?.[0]) && entry[0].some(value => String(value).toLowerCase() === tld));
    const bases = Array.isArray(service?.[1]) ? service[1].filter(value => String(value).startsWith('https://')) : [];
    if (!bases.length) return { status: 'info', summary: 'No RDAP service listed', detail: `IANA does not list an HTTPS RDAP service for .${tld}.`, source: RDAP_BOOTSTRAP_URL };
    const requestJson = options.requestJson || requestJsonHttps;
    let lastError;
    for (let index = 0; index < labels.length - 1; index += 1) {
      const candidate = labels.slice(index).join('.');
      for (const base of bases) {
        const url = new URL(`domain/${encodeURIComponent(candidate)}`, base.endsWith('/') ? base : `${base}/`);
        try {
          const response = await requestJson(url, options);
          const document = responseBody(response);
          if (document?.objectClassName !== 'domain') continue;
          const registrarEntity = document.entities?.find(entity => entity.roles?.includes('registrar'));
          const events = document.events || [];
          return {
            status: 'healthy', summary: document.ldhName || candidate, detail: 'Current registration data returned by the registry RDAP service.',
            domain: document.ldhName || candidate, handle: document.handle || null, registrar: rdapEntityName(registrarEntity), statuses: document.status || [],
            registered_at: rdapEvent(events, 'registration'), expires_at: rdapEvent(events, 'expiration'), changed_at: rdapEvent(events, 'last changed'),
            nameservers: (document.nameservers || []).map(item => item.ldhName).filter(Boolean), source: response?.url || url.toString()
          };
        } catch (error) {
          lastError = error;
          if (error.statusCode === 404) break;
          if (error.statusCode === 429) throw error;
        }
      }
    }
    return { status: 'info', summary: lastError?.statusCode === 404 ? 'Registration not found' : 'RDAP lookup unavailable', detail: lastError?.message || 'The registry RDAP service did not return registration data.', source: RDAP_BOOTSTRAP_URL };
  } catch (error) {
    return { status: 'info', summary: 'RDAP lookup unavailable', detail: error.message, source: RDAP_BOOTSTRAP_URL };
  }
}

function txtRecord(value) {
  return Array.isArray(value) ? value.join('') : String(value || '');
}

async function asnOwnership(addresses, options = {}) {
  const resolver = options.resolver || new dns.Resolver({ timeout: Math.min(5000, Number(options.timeout_ms || 8000)), tries: 1 });
  const publicTargets = [...new Set(addresses)].filter(isPublicIp).slice(0, 10);
  const records = await Promise.all(publicTargets.map(async address => {
    const reverse = reverseIp(address);
    const zone = net.isIP(address) === 6 ? 'origin6.asn.cymru.com' : 'origin.asn.cymru.com';
    try {
      const answers = await withTimeout(resolver.resolveTxt(`${reverse}.${zone}`), Number(options.timeout_ms || 8000), `ASN lookup for ${address}`);
      const origin = txtRecord(answers[0]).split('|').map(value => value.trim());
      const asn = origin[0]?.split(/\s+/)[0];
      let name = null;
      if (asn) {
        try {
          const names = await withTimeout(resolver.resolveTxt(`AS${asn}.asn.cymru.com`), Number(options.timeout_ms || 8000), `ASN name lookup for AS${asn}`);
          name = txtRecord(names[0]).split('|').map(value => value.trim())[4] || null;
        } catch (_) {}
      }
      return { address, status: asn ? 'available' : 'unavailable', asn: asn ? `AS${asn}` : null, prefix: origin[1] || null, country: origin[2] || null, registry: origin[3] || null, allocated_at: origin[4] || null, name };
    } catch (error) { return { address, status: 'unavailable', error: error.message }; }
  }));
  const available = records.filter(record => record.status === 'available').length;
  return { status: available ? 'healthy' : 'info', summary: available ? `${available} address owner${available === 1 ? '' : 's'} identified` : 'ASN ownership unavailable', detail: available ? 'BGP origin and registry data supplied by Team Cymru’s community DNS service.' : 'No public address could be mapped to an origin ASN.', records, provider: 'Team Cymru' };
}

async function requestWebHead(input, options = {}, redirects = 3) {
  const url = input instanceof URL ? input : new URL(input);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || (url.port && !['80', '443'].includes(url.port))) throw new Error('Web diagnostics permit standard HTTP and HTTPS endpoints only.');
  const addresses = await publicAddresses(url.hostname, options);
  if (!addresses.length) throw new Error(`${url.hostname} did not resolve to a public address.`);
  const address = addresses[0];
  const transport = url.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const request = transport.request({
      hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80), path: `${url.pathname}${url.search}`, method: 'HEAD', servername: url.protocol === 'https:' ? url.hostname : undefined,
      headers: { 'user-agent': 'DomainPosture Lookup Center' }, lookup: (_hostname, lookupOptions, callback) => lookupOptions?.all ? callback(null, [{ address, family: net.isIP(address) }]) : callback(null, address, net.isIP(address))
    }, response => {
      const entry = { url: url.toString(), status_code: response.statusCode, location: response.headers.location || null };
      response.resume();
      if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
        if (!redirects) return reject(new Error('Web endpoint redirected too many times.'));
        let next;
        try { next = new URL(response.headers.location, url); } catch (error) { return reject(error); }
        return requestWebHead(next, options, redirects - 1).then(result => resolve({ ...result, redirects: [entry, ...(result.redirects || [])] }), reject);
      }
      resolve({ status: 'available', url: url.toString(), status_code: response.statusCode, response_time_ms: Date.now() - started, redirects: [], headers: { strict_transport_security: response.headers['strict-transport-security'] || null, content_security_policy: response.headers['content-security-policy'] || null, x_content_type_options: response.headers['x-content-type-options'] || null, referrer_policy: response.headers['referrer-policy'] || null } });
    });
    request.setTimeout(Number(options.timeout_ms || 8000), () => request.destroy(new Error(`${url.protocol.slice(0, -1).toUpperCase()} request timed out.`)));
    request.on('error', reject);
    request.end();
  });
}

async function webDiagnostics(target, options = {}) {
  const probe = options.webProbe || requestWebHead;
  const results = await Promise.all(['https', 'http'].map(async scheme => {
    try { return { scheme, ...(await probe(new URL(`${scheme}://${target}/`), options)) }; }
    catch (error) { return { scheme, status: 'unavailable', error: error.message, redirects: [] }; }
  }));
  const available = results.filter(result => result.status === 'available');
  const httpsAvailable = available.some(result => result.scheme === 'https');
  const errorResponses = available.filter(result => Number(result.status_code) >= 400);
  const status = !available.length ? 'info' : !httpsAvailable || errorResponses.length ? 'warning' : 'healthy';
  const summary = !available.length ? 'Web endpoints unavailable' : errorResponses.length ? `${errorResponses.length} endpoint response${errorResponses.length === 1 ? '' : 's'} need review` : !httpsAvailable ? 'HTTPS endpoint unavailable' : `${available.length}/2 web endpoints responded`;
  return { status, summary, detail: 'HEAD requests check status, redirect handling, timing, and selected response security headers without downloading page content.', results };
}

async function tcpPortCheck(target, portValue, options = {}) {
  const port = normalizeTcpPort(portValue);
  if (!port) throw new Error('Choose a TCP port to test.');
  const addresses = options.resolveAddresses ? await options.resolveAddresses(target) : await publicAddresses(target, options);
  const address = addresses.find(isPublicIp);
  if (!address) return { status: 'info', summary: `TCP ${port} not tested`, detail: 'The target did not resolve to a public address.', port, address: null };
  const started = Date.now();
  if (options.connectTcp) return options.connectTcp({ target, address, port, started });
  return new Promise(resolve => {
    const socket = net.createConnection({ host: address, port });
    let settled = false;
    const finish = result => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, address, response_time_ms: Date.now() - started, ...result });
    };
    socket.setTimeout(Math.min(5000, Number(options.timeout_ms || 8000)), () => finish({ status: 'warning', summary: `TCP ${port} timed out`, detail: 'No connection response was received before the safety timeout.' }));
    socket.once('connect', () => finish({ status: 'healthy', summary: `TCP ${port} is reachable`, detail: 'A TCP connection opened successfully. No application data was sent.' }));
    socket.once('error', error => finish({ status: error.code === 'ECONNREFUSED' ? 'warning' : 'info', summary: error.code === 'ECONNREFUSED' ? `TCP ${port} refused the connection` : `TCP ${port} check unavailable`, detail: error.message }));
  });
}

module.exports = { ALLOWED_TCP_PORTS, isPublicIp, normalizeTcpPort, publicAddresses, requestJsonHttps, dnssecCheck, rdapRegistration, asnOwnership, requestWebHead, webDiagnostics, tcpPortCheck };
