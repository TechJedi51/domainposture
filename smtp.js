'use strict';

const net = require('net');
const tls = require('tls');
const dns = require('dns').promises;

const STATUS_RANK = { healthy: 0, info: 0, warning: 1, critical: 2 };
const CONNECTION_WARNING_MS = 5000;
const CONNECTION_CRITICAL_MS = 15000;
const TRANSACTION_WARNING_MS = 5000;
const TRANSACTION_CRITICAL_MS = 15000;
const PROVIDER_LABELS = { kerio: 'Kerio Connect', google: 'Google Workspace', microsoft: 'Microsoft 365', hover: 'Hover Mail', icloud: 'iCloud Mail', self_hosted: 'Self-hosted', other: 'Other provider', none: 'None' };
const PROVIDERS = new Set(['auto', 'kerio', 'google', 'microsoft', 'hover', 'icloud', 'self_hosted', 'other']);

function normalizedHost(value) {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '');
}

function normalizedIp(value) {
  return String(value || '').replace(/^::ffff:/, '').toLowerCase();
}

function validHostname(value) {
  return /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(normalizedHost(value));
}

function detectedProvider(mxRecords = []) {
  const hosts = mxRecords.map(record => normalizedHost(record.exchange));
  if (hosts.some(host => host === 'smtp.google.com' || host.endsWith('.google.com'))) return 'google';
  if (hosts.some(host => host.endsWith('.mail.protection.outlook.com'))) return 'microsoft';
  if (hosts.some(host => host.endsWith('.hostedemail.com'))) return 'hover';
  if (hosts.some(host => host.endsWith('.mail.icloud.com'))) return 'icloud';
  return 'other';
}

function smtpProfile(domain, configured = {}, mxRecords = []) {
  const requestedHosting = ['auto', 'self_hosted', 'managed', 'no_inbound'].includes(configured.hosting_type) ? configured.hosting_type : 'auto';
  const requestedProvider = PROVIDERS.has(configured.provider) ? configured.provider : 'auto';
  const detected = detectedProvider(mxRecords);
  const domainHost = normalizedHost(domain);
  const ownMx = mxRecords.length > 0 && mxRecords.every(record => {
    const host = normalizedHost(record.exchange);
    return host === domainHost || host.endsWith(`.${domainHost}`);
  });
  const detectedHosting = detected !== 'other' || !ownMx ? 'managed' : 'self_hosted';
  const selectedProviderHosting = ['kerio', 'self_hosted'].includes(requestedProvider) ? 'self_hosted' : requestedProvider === 'auto' ? null : 'managed';
  const hostingType = requestedHosting === 'auto' ? selectedProviderHosting || detectedHosting : requestedHosting;
  const provider = hostingType === 'no_inbound'
    ? 'none'
    : requestedProvider !== 'auto'
      ? requestedProvider
      : hostingType === 'self_hosted'
        ? 'self_hosted'
        : detected;
  const relayContext = ['auto', 'external', 'internal'].includes(configured.relay_context) ? configured.relay_context : 'auto';
  const expectedHostname = validHostname(configured.expected_hostname) ? normalizedHost(configured.expected_hostname) : null;
  return {
    requested_hosting_type: requestedHosting,
    hosting_type: hostingType,
    hosting_type_label: hostingType === 'managed' ? 'Managed provider' : hostingType === 'self_hosted' ? 'Self-hosted' : hostingType === 'no_inbound' ? 'No inbound mail' : 'Automatic',
    hosting_source: requestedHosting === 'auto' && requestedProvider === 'auto' ? 'auto_detected' : 'selected',
    requested_provider: requestedProvider,
    provider: provider,
    provider_label: PROVIDER_LABELS[provider] || PROVIDER_LABELS.other,
    provider_source: requestedProvider === 'auto' ? 'auto_detected' : 'selected',
    expected_hostname: expectedHostname,
    relay_context: relayContext
  };
}

async function resolveSmtpProfile(domain, configured = {}, resolver = dns) {
  let records = [];
  try { records = await resolver.resolveMx(domain); } catch (_) {}
  return smtpProfile(domain, configured, records.filter(record => normalizedHost(record.exchange) && normalizedHost(record.exchange) !== '.'));
}

function safeLine(value) {
  return String(value || '').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '').slice(0, 1000);
}

function addTranscript(transcript, prefix, value) {
  if (transcript.length < 120) transcript.push(`${prefix}: ${safeLine(value)}`);
}

function responseReader(socket, timeoutMs, transcript) {
  let buffer = '';
  let current = [];
  let currentCode = null;
  const responses = [];
  const waiters = [];

  const deliver = response => {
    const waiter = waiters.shift();
    if (waiter) {
      clearTimeout(waiter.timer);
      waiter.resolve(response);
    } else responses.push(response);
  };

  const fail = error => {
    while (waiters.length) {
      const waiter = waiters.shift();
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
  };

  const onData = chunk => {
    buffer += chunk.toString('utf8');
    if (buffer.length > 65536) return fail(new Error('SMTP response exceeded the safety limit'));
    while (buffer.includes('\n')) {
      const index = buffer.indexOf('\n');
      const line = buffer.slice(0, index).replace(/\r$/, '');
      buffer = buffer.slice(index + 1);
      addTranscript(transcript, 'S', line);
      const match = line.match(/^(\d{3})([- ])(.*)$/);
      if (!match) continue;
      if (currentCode === null) currentCode = Number(match[1]);
      current.push(line);
      if (Number(match[1]) === currentCode && match[2] === ' ') {
        deliver({ code: currentCode, lines: current });
        current = [];
        currentCode = null;
      }
    }
  };

  const onError = error => fail(error);
  const onClose = () => fail(new Error('SMTP connection closed unexpectedly'));
  socket.on('data', onData);
  socket.on('error', onError);
  socket.on('close', onClose);

  return {
    read() {
      if (responses.length) return Promise.resolve(responses.shift());
      return new Promise((resolve, reject) => {
        const waiter = { resolve, reject, timer: null };
        waiter.timer = setTimeout(() => {
          const index = waiters.indexOf(waiter);
          if (index >= 0) waiters.splice(index, 1);
          reject(new Error('SMTP response timed out'));
        }, timeoutMs);
        waiters.push(waiter);
      });
    },
    async command(command) {
      addTranscript(transcript, 'C', command);
      await new Promise((resolve, reject) => socket.write(`${command}\r\n`, error => error ? reject(error) : resolve()));
      return this.read();
    },
    cleanup() {
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
      fail(new Error('SMTP response reader closed'));
    }
  };
}

function connect(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    const timer = setTimeout(() => socket.destroy(new Error('SMTP connection timed out')), timeoutMs);
    const cleanup = () => {
      clearTimeout(timer);
      socket.off('connect', onConnect);
      socket.off('error', onError);
    };
    const onConnect = () => { cleanup(); resolve(socket); };
    const onError = error => { cleanup(); reject(error); };
    socket.once('connect', onConnect);
    socket.once('error', onError);
  });
}

function upgradeTls(socket, host, timeoutMs) {
  return new Promise((resolve, reject) => {
    const secure = tls.connect({ socket, servername: host, rejectUnauthorized: false });
    const timer = setTimeout(() => secure.destroy(new Error('SMTP STARTTLS negotiation timed out')), timeoutMs);
    const cleanup = () => {
      clearTimeout(timer);
      secure.off('secureConnect', onSecure);
      secure.off('error', onError);
    };
    const onSecure = () => { cleanup(); resolve(secure); };
    const onError = error => { cleanup(); reject(error); };
    secure.once('secureConnect', onSecure);
    secure.once('error', onError);
  });
}

function smtpClientIdentity(configured, localAddress) {
  if (validHostname(configured)) return normalizedHost(configured);
  const address = normalizedIp(localAddress);
  return net.isIP(address) === 6 ? `[IPv6:${address}]` : net.isIP(address) === 4 ? `[${address}]` : '[127.0.0.1]';
}

function smtpBannerHostname(lines) {
  const match = String(lines?.[0] || '').match(/^220[- ]([^\s]+)/i);
  const candidate = normalizedHost(match?.[1]?.replace(/^\[|\]$/g, ''));
  return validHostname(candidate) ? candidate : null;
}

function smtpCapabilities(lines) {
  return (lines || []).map(line => String(line).replace(/^250[- ]/i, '').trim().split(/\s+/)[0].toUpperCase()).filter(Boolean);
}

function policyBlock(response) {
  const detail = (response?.lines || []).join(' ');
  return response?.code >= 400 && /(?:access denied|blocked|not permitted|policy rejection|client host rejected)/i.test(detail)
    ? { code: response.code, detail: safeLine(detail) }
    : null;
}

async function reverseIdentity(ip, resolver = dns) {
  const identity = { reverse_dns: [], forward_confirmed: false };
  if (!ip) return identity;
  try { identity.reverse_dns = (await resolver.reverse(normalizedIp(ip))).map(normalizedHost).filter(Boolean); }
  catch (_) { return identity; }
  for (const hostname of identity.reverse_dns) {
    try {
      const addresses = await resolver.lookup(hostname, { all: true });
      if (addresses.some(address => normalizedIp(address.address) === normalizedIp(ip))) {
        identity.forward_confirmed = true;
        break;
      }
    } catch (_) {}
  }
  return identity;
}

async function probeSmtp(host, options = {}) {
  const port = Number(options.port || 25);
  const timeoutMs = Math.max(1000, Number(options.timeout_ms || 8000));
  const transcript = [];
  const started = Date.now();
  const evidence = { host: normalizedHost(host), port, transcript, relay_probe: 'No message content was transmitted.' };
  let socket;
  let reader;
  try {
    socket = await connect(evidence.host, port, timeoutMs);
    socket.setNoDelay(true);
    evidence.tcp_connection_ms = Date.now() - started;
    evidence.ip_address = normalizedIp(socket.remoteAddress);
    evidence.ehlo_identity = smtpClientIdentity(options.ehlo_hostname, socket.localAddress);
    reader = responseReader(socket, timeoutMs, transcript);
    const greeting = await reader.read();
    evidence.connection_time_ms = Date.now() - started;
    evidence.greeting_code = greeting.code;
    evidence.banner = safeLine(greeting.lines[0]);
    evidence.banner_hostname = smtpBannerHostname(greeting.lines);
    if (greeting.code !== 220) throw new Error(`SMTP greeting returned ${greeting.code}`);

    let hello = await reader.command(`EHLO ${evidence.ehlo_identity}`);
    if (hello.code >= 500) hello = await reader.command(`HELO ${evidence.ehlo_identity}`);
    evidence.ehlo_code = hello.code;
    evidence.capabilities = smtpCapabilities(hello.lines);
    evidence.starttls_advertised = evidence.capabilities.includes('STARTTLS');

    if (evidence.starttls_advertised) {
      const starttls = await reader.command('STARTTLS');
      evidence.starttls_code = starttls.code;
      const blocked = policyBlock(starttls);
      if (blocked) Object.assign(evidence, { policy_blocked: true, policy_blocked_command: 'STARTTLS', policy_response_code: blocked.code, policy_response: blocked.detail });
      if (starttls.code === 220) {
        reader.cleanup();
        socket = await upgradeTls(socket, evidence.host, timeoutMs);
        evidence.starttls_negotiated = true;
        evidence.tls_authorized = socket.authorized;
        evidence.tls_authorization_error = socket.authorizationError || null;
        evidence.tls_protocol = socket.getProtocol();
        evidence.tls_cipher = socket.getCipher()?.name || null;
        const certificate = socket.getPeerCertificate();
        evidence.certificate_valid_to = certificate.valid_to ? new Date(certificate.valid_to).toISOString() : null;
        reader = responseReader(socket, timeoutMs, transcript);
        hello = await reader.command(`EHLO ${evidence.ehlo_identity}`);
        evidence.secure_ehlo_code = hello.code;
      }
    }

    if (!evidence.policy_blocked && (!evidence.starttls_advertised || evidence.starttls_negotiated)) {
      const mail = await reader.command('MAIL FROM:<probe@example.com>');
      evidence.mail_from_code = mail.code;
      const blocked = policyBlock(mail);
      if (blocked) Object.assign(evidence, { policy_blocked: true, policy_blocked_command: 'MAIL FROM', policy_response_code: blocked.code, policy_response: blocked.detail });
      if (mail.code >= 200 && mail.code < 300) {
        const recipient = await reader.command('RCPT TO:<probe@example.net>');
        evidence.rcpt_to_code = recipient.code;
        evidence.relay_status = recipient.code >= 200 && recipient.code < 300 ? 'potential' : recipient.code >= 500 ? 'denied' : 'inconclusive';
        await reader.command('RSET').catch(() => null);
      } else evidence.relay_status = 'inconclusive';
    } else {
      evidence.relay_status = 'inconclusive';
      evidence.relay_probe_skipped = evidence.policy_blocked ? 'The server blocked the monitoring source.' : 'STARTTLS could not be negotiated.';
    }
    evidence.transaction_time_ms = Date.now() - started;

    await reader.command('QUIT').catch(() => null);
  } catch (error) {
    evidence.error = safeLine(error.message);
    evidence.transaction_time_ms ||= Date.now() - started;
    evidence.starttls_negotiated ||= false;
    evidence.relay_status ||= 'inconclusive';
  } finally {
    reader?.cleanup();
    socket?.destroy();
  }
  Object.assign(evidence, await reverseIdentity(evidence.ip_address, options.resolver || dns));
  evidence.ptr_matches_host = evidence.reverse_dns.includes(evidence.host);
  evidence.reverse_dns_match = evidence.ptr_matches_host && evidence.forward_confirmed;
  evidence.banner_matches_reverse_dns = Boolean(evidence.banner_hostname && evidence.reverse_dns.includes(evidence.banner_hostname));
  return evidence;
}

function timingTest(label, milliseconds, warningMs, criticalMs) {
  if (!Number.isFinite(milliseconds)) return { label, status: 'critical', value: 'Unavailable', detail: 'The SMTP timing could not be measured.' };
  const seconds = `${(milliseconds / 1000).toFixed(3)} seconds`;
  const status = milliseconds >= criticalMs ? 'critical' : milliseconds >= warningMs ? 'warning' : 'healthy';
  return { label, status, value: seconds, detail: status === 'healthy' ? `Completed in less than ${(warningMs / 1000).toFixed(0)} seconds.` : `${status === 'critical' ? 'Critical' : 'Warning'}: slower than ${(status === 'critical' ? criticalMs : warningMs) / 1000} seconds.` };
}

function advisoryTimingTest(label, milliseconds, warningMs, criticalMs) {
  const test = timingTest(label, milliseconds, warningMs, criticalMs);
  if (!['warning', 'critical'].includes(test.status)) return test;
  return { ...test, status: 'info', value: `Advisory — ${test.value}`, detail: `${test.detail} Timing from one monitoring location is not a protocol failure.` };
}

function evaluateSmtpEvidence(host, evidence, configuredProfile = {}) {
  const profile = configuredProfile.hosting_type && configuredProfile.requested_hosting_type
    ? configuredProfile
    : smtpProfile(host, configuredProfile, [{ exchange: host }]);
  const managed = profile.hosting_type === 'managed';
  const ptr = evidence.reverse_dns?.[0] || null;
  const ptrMatchesHost = evidence.ptr_matches_host ?? evidence.reverse_dns?.includes(normalizedHost(host));
  const expectedHostname = profile.expected_hostname || normalizedHost(host);
  const reverseDnsTest = !ptr
    ? { label: 'SMTP Reverse DNS', status: managed ? 'info' : 'warning', value: managed ? 'Advisory — No PTR record observed' : 'Review — No PTR record', detail: `No PTR record was found for the connected address.${managed ? ' Reverse DNS on shared infrastructure is controlled by the mail provider.' : ''}` }
    : evidence.forward_confirmed
      ? ptrMatchesHost || managed || evidence.reverse_dns.includes(expectedHostname)
        ? { label: 'SMTP Reverse DNS', status: 'healthy', value: managed && !ptrMatchesHost ? 'OK — Provider PTR is forward-confirmed' : `OK — ${evidence.ip_address} resolves to ${ptr}`, detail: managed && !ptrMatchesHost ? `PTR record ${ptr} resolves back to the connected address. It does not need to equal the customer-facing MX name on shared infrastructure.` : `PTR record ${ptr} resolves back to the connected address.` }
        : { label: 'SMTP Reverse DNS', status: 'warning', value: 'Review — PTR differs from expected server identity', detail: `PTR records: ${evidence.reverse_dns.join(', ')}. Expected ${expectedHostname} for this self-hosted service.` }
      : { label: 'SMTP Reverse DNS', status: managed ? 'info' : 'warning', value: managed ? 'Advisory — PTR is not forward-confirmed' : 'Review — PTR is not forward-confirmed', detail: `PTR records: ${evidence.reverse_dns.join(', ')}. Their address records did not include the connected address.${managed ? ' The provider controls this shared infrastructure.' : ''}` };
  const bannerValid = Boolean(evidence.banner_hostname) || /^220[- ]\[(?:IPv6:)?[^\]]+\]/i.test(evidence.banner || '');
  const bannerAligned = Boolean(evidence.banner_hostname && (evidence.banner_hostname === expectedHostname || evidence.reverse_dns?.includes(evidence.banner_hostname)));
  const bannerTest = !bannerValid
    ? { label: 'SMTP Banner Check', status: managed ? 'info' : 'warning', value: managed ? 'Advisory — Provider greeting identity is nonstandard' : 'Review — Invalid server identity', detail: `The SMTP greeting did not contain a valid hostname or address literal: ${evidence.banner || 'not available'}.${managed ? ' The managed provider controls this identity; STARTTLS and certificate validation remain the security checks.' : ''}` }
    : managed || bannerAligned
      ? { label: 'SMTP Banner Check', status: 'healthy', value: managed && !bannerAligned ? 'OK — Valid provider SMTP identity' : 'OK — Valid and aligned SMTP identity', detail: managed && !bannerAligned ? `Banner host ${evidence.banner_hostname || 'address literal'} is valid. A shared provider banner does not need to equal the customer-facing MX name.` : `Banner host: ${evidence.banner_hostname || 'address literal'}.` }
      : { label: 'SMTP Banner Check', status: 'warning', value: 'Review — Banner differs from expected identity', detail: `Banner host: ${evidence.banner_hostname}; expected ${expectedHostname} or a forward-confirmed PTR name.` };
  const blockedDetail = evidence.policy_response || 'The server rejected commands from the monitoring source address.';
  const tests = [
    advisoryTimingTest('SMTP Connection Time', evidence.connection_time_ms, CONNECTION_WARNING_MS, CONNECTION_CRITICAL_MS),
    advisoryTimingTest('SMTP Transaction Time', evidence.transaction_time_ms, TRANSACTION_WARNING_MS, TRANSACTION_CRITICAL_MS),
    reverseDnsTest,
    { label: 'SMTP Valid Hostname', status: ptr && validHostname(ptr) ? 'healthy' : 'warning', value: ptr && validHostname(ptr) ? 'OK — Reverse DNS is a valid hostname' : 'Review', detail: ptr && validHostname(ptr) ? `${ptr} is a valid fully qualified host name.` : ptr ? `${ptr} is not a valid fully qualified host name.` : 'A reverse-DNS host name was not available.' },
    bannerTest,
    { label: 'SMTP TLS', status: evidence.policy_blocked && !evidence.starttls_negotiated ? 'info' : evidence.starttls_negotiated && evidence.tls_authorized ? 'healthy' : evidence.starttls_negotiated ? 'warning' : 'critical', value: evidence.policy_blocked && !evidence.starttls_negotiated ? 'Not tested — Server policy blocked the probe' : evidence.starttls_negotiated ? evidence.tls_authorized ? 'OK — STARTTLS negotiated with a trusted certificate' : 'Review — STARTTLS certificate is not trusted' : 'Failed — STARTTLS was not negotiated', detail: evidence.policy_blocked && !evidence.starttls_negotiated ? `${blockedDetail} This does not demonstrate a TLS failure for other senders.` : evidence.starttls_negotiated ? `${evidence.tls_protocol || 'TLS'}${evidence.tls_cipher ? ` using ${evidence.tls_cipher}` : ''}${evidence.tls_authorization_error ? `; ${evidence.tls_authorization_error}` : ''}.` : evidence.starttls_advertised ? `The server advertised STARTTLS but negotiation failed${evidence.error ? `: ${evidence.error}` : '.'}` : 'The server did not advertise STARTTLS.' },
    { label: 'SMTP Open Relay', status: evidence.policy_blocked ? 'info' : evidence.relay_status === 'denied' ? 'healthy' : evidence.relay_status === 'potential' && profile.relay_context === 'external' ? 'critical' : evidence.relay_status === 'potential' && profile.relay_context === 'internal' ? 'info' : 'warning', value: evidence.policy_blocked ? 'Not tested — Server policy blocked the probe' : evidence.relay_status === 'denied' ? 'OK — Relay attempt denied' : evidence.relay_status === 'potential' && profile.relay_context === 'external' ? 'Failed — External relay recipient accepted' : evidence.relay_status === 'potential' ? 'External verification required — Recipient accepted' : 'Inconclusive', detail: evidence.policy_blocked ? `${blockedDetail} The external-recipient command was not reached. No DATA command or message content was sent.` : evidence.relay_status === 'potential' ? `The server accepted an unauthenticated recipient outside the tested domain from DomainPosture’s ${profile.relay_context === 'external' ? 'configured external, untrusted' : profile.relay_context === 'internal' ? 'configured internal, trusted' : 'current'} network location. ${profile.relay_context === 'external' ? 'Restrict unauthenticated relaying immediately.' : 'This does not prove that the service relays from the public internet.'} No DATA command or message content was sent.` : evidence.relay_status === 'denied' ? `The external recipient was rejected with SMTP ${evidence.rcpt_to_code}.` : 'The server did not reach a definitive external-recipient decision. No DATA command or message content was sent.' }
  ];
  if (managed && tests[3].status === 'warning') tests[3] = { ...tests[3], status: 'info', value: ptr ? 'Advisory — Provider PTR hostname is nonstandard' : 'Advisory — Provider PTR unavailable', detail: ptr ? `${ptr} is provider-controlled and does not affect MX routing or certificate validation.` : 'A reverse-DNS hostname was not available from this location. The managed provider controls the SMTP server identity.' };
  if (evidence.error && !evidence.greeting_code) {
    tests[0] = { label: 'SMTP Connection Time', status: 'critical', value: 'Connection failed', detail: evidence.error };
    tests[1] = { label: 'SMTP Transaction Time', status: 'info', value: 'Not run', detail: 'The SMTP transaction could not start because the greeting was not received.' };
    tests[4] = { label: 'SMTP Banner Check', status: 'info', value: 'Not run', detail: 'No SMTP greeting was available.' };
    tests[5] = { label: 'SMTP TLS', status: 'info', value: 'Not run', detail: 'STARTTLS could not be tested without an SMTP greeting.' };
    tests[6] = { label: 'SMTP Open Relay', status: 'info', value: 'Not run', detail: 'The relay-safety probe could not start. No message content was sent.' };
  }
  let status = tests.reduce((current, test) => STATUS_RANK[test.status] > STATUS_RANK[current] ? test.status : current, 'healthy');
  if (status === 'healthy' && tests.some(test => test.status === 'info')) status = 'info';
  return { ...evidence, host: normalizedHost(host), status, tests, profile };
}

function smtpResult(domain, mxRecords, endpoints, profile = smtpProfile(domain, {}, mxRecords)) {
  if (!mxRecords.length) return { id: 'smtp_service', label: 'SMTP service', status: 'warning', summary: 'No MX hosts configured', detail: 'No SMTP server could be selected from the domain’s MX records.', action: 'Publish an MX record or confirm that this domain intentionally does not receive email.', evidence: { domain, mx: [], endpoints: [] } };
  let status = endpoints.reduce((current, endpoint) => STATUS_RANK[endpoint.status] > STATUS_RANK[current] ? endpoint.status : current, 'healthy');
  if (status === 'healthy' && endpoints.some(endpoint => endpoint.status === 'info')) status = 'info';
  const affected = endpoints.filter(endpoint => endpoint.status !== 'healthy');
  const summary = status === 'healthy' ? `${endpoints.length} MX host${endpoints.length === 1 ? '' : 's'} ready` : status === 'info' ? `${affected.length} MX host${affected.length === 1 ? '' : 's'} not fully tested` : `${affected.length} of ${endpoints.length} MX host${endpoints.length === 1 ? '' : 's'} need${affected.length === 1 ? 's' : ''} attention`;
  const detail = status === 'healthy' ? 'Connection, SMTP greeting, STARTTLS, and relay-safety checks passed.' : affected.map(endpoint => `${endpoint.host}: ${endpoint.tests.filter(test => status === 'info' ? test.status === 'info' : ['warning', 'critical'].includes(test.status)).map(test => test.label).join(', ')}`).join(' · ');
  const action = endpoints.some(endpoint => endpoint.tests[0]?.status === 'critical') ? 'Confirm that the MX host is reachable on TCP port 25 and review its SMTP service and network logs.' : endpoints.some(endpoint => !endpoint.policy_blocked && (!endpoint.starttls_negotiated || endpoint.tls_authorized === false)) ? 'Correct STARTTLS or certificate trust on the affected MX host, then run checks again. Managed-provider certificate failures still prevent safe MTA-STS enforcement.' : endpoints.some(endpoint => endpoint.relay_status === 'potential' && profile.relay_context === 'external') ? 'Restrict unauthenticated relaying immediately, then repeat the test from an external untrusted address.' : endpoints.some(endpoint => endpoint.policy_blocked) ? 'The receiving service blocked this monitoring source. Use a permitted external probe address and rely on SMTP TLS reports for production delivery evidence.' : endpoints.some(endpoint => endpoint.relay_status === 'potential') ? 'Repeat the relay test from a network outside your organization. If an external probe also accepts the recipient, restrict unauthenticated relaying immediately.' : 'Review the affected SMTP identity or protocol result. Provider-owned PTR and banner names are informational when they are otherwise valid.';
  return { id: 'smtp_service', label: 'SMTP service', status, summary, detail, action, evidence: { domain, profile, mx: mxRecords, endpoints, relay_probe_safety: 'Uses reserved example.com/example.net addresses and stops before DATA; no message content is transmitted.' } };
}

async function smtpDiagnostics(domain, options = {}) {
  try {
    const resolver = options.resolver || dns;
    let resolvedMx = [];
    try { resolvedMx = await resolver.resolveMx(domain); } catch (error) {
      if (options.profile?.hosting_type !== 'no_inbound') throw error;
    }
    const nullMx = resolvedMx.some(record => String(record.exchange || '').trim() === '.');
    const mxRecords = resolvedMx.sort((a, b) => a.priority - b.priority).filter(record => normalizedHost(record.exchange) && normalizedHost(record.exchange) !== '.');
    const profile = options.profile?.requested_hosting_type ? options.profile : smtpProfile(domain, options.profile || {}, mxRecords);
    if (profile.hosting_type === 'no_inbound') {
      if (mxRecords.length) return { id: 'smtp_service', label: 'SMTP service', status: 'warning', summary: 'Inbound mail disabled but MX hosts exist', detail: 'This domain is configured as not receiving mail, but it publishes active mail exchangers.', action: 'Remove the MX hosts and publish a Null MX record, or change the DomainPosture hosting type.', evidence: { domain, profile, mx: mxRecords, endpoints: [] } };
      return { id: 'smtp_service', label: 'SMTP service', status: nullMx ? 'healthy' : 'info', summary: nullMx ? 'Inbound mail intentionally disabled' : 'No inbound mail expected', detail: nullMx ? 'A standards-based Null MX record is published.' : 'No MX hosts were found. DomainPosture is configured not to expect inbound mail for this domain.', action: nullMx ? 'No action required.' : 'Publish a Null MX record to state explicitly that this domain does not receive mail.', evidence: { domain, profile, mx: [], endpoints: [], null_mx: nullMx } };
    }
    const unique = [...new Map(mxRecords.map(record => [normalizedHost(record.exchange), { priority: record.priority, exchange: normalizedHost(record.exchange) }])).values()].slice(0, 10);
    const probe = options.probe || probeSmtp;
    const endpoints = await Promise.all(unique.map(async record => evaluateSmtpEvidence(record.exchange, await probe(record.exchange, { timeout_ms: options.timeout_ms, resolver, ehlo_hostname: options.ehlo_hostname }), profile)));
    return smtpResult(domain, unique, endpoints, profile);
  } catch (error) {
    return { id: 'smtp_service', label: 'SMTP service', status: 'critical', summary: 'SMTP check failed', detail: safeLine(error.message), action: 'Verify the domain’s MX records and confirm that DomainPosture can reach TCP port 25.', evidence: { domain, error: safeLine(error.message), endpoints: [] } };
  }
}

module.exports = { smtpDiagnostics, probeSmtp, evaluateSmtpEvidence, smtpResult, smtpBannerHostname, smtpCapabilities, validHostname, timingTest, smtpProfile, resolveSmtpProfile, detectedProvider, smtpClientIdentity };
