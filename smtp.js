'use strict';

const net = require('net');
const tls = require('tls');
const dns = require('dns').promises;

const STATUS_RANK = { healthy: 0, info: 0, warning: 1, critical: 2 };
const CONNECTION_WARNING_MS = 5000;
const CONNECTION_CRITICAL_MS = 15000;
const TRANSACTION_WARNING_MS = 5000;
const TRANSACTION_CRITICAL_MS = 15000;

function normalizedHost(value) {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '');
}

function normalizedIp(value) {
  return String(value || '').replace(/^::ffff:/, '').toLowerCase();
}

function validHostname(value) {
  return /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(normalizedHost(value));
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
    reader = responseReader(socket, timeoutMs, transcript);
    const greeting = await reader.read();
    evidence.connection_time_ms = Date.now() - started;
    evidence.greeting_code = greeting.code;
    evidence.banner = safeLine(greeting.lines[0]);
    evidence.banner_hostname = smtpBannerHostname(greeting.lines);
    if (greeting.code !== 220) throw new Error(`SMTP greeting returned ${greeting.code}`);

    let hello = await reader.command('EHLO mailposture.invalid');
    if (hello.code >= 500) hello = await reader.command('HELO mailposture.invalid');
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
        hello = await reader.command('EHLO mailposture.invalid');
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

function evaluateSmtpEvidence(host, evidence) {
  const ptr = evidence.reverse_dns?.[0] || null;
  const ptrMatchesHost = evidence.ptr_matches_host ?? evidence.reverse_dns?.includes(normalizedHost(host));
  const reverseDnsTest = !ptr
    ? { label: 'SMTP Reverse DNS', status: 'warning', value: 'Review — No PTR record', detail: 'No PTR record was found for the connected address.' }
    : ptrMatchesHost && evidence.forward_confirmed
      ? { label: 'SMTP Reverse DNS', status: 'healthy', value: `OK — ${evidence.ip_address} resolves to ${host}`, detail: `PTR record ${ptr} matches the MX host and resolves back to the connected address.` }
      : ptrMatchesHost
        ? { label: 'SMTP Reverse DNS', status: 'info', value: 'PTR matches MX; forward confirmation unavailable', detail: `PTR record ${ptr} matches the MX host, but its current address records did not include the connected address. This can occur with a shared or load-balanced mail service.` }
        : { label: 'SMTP Reverse DNS', status: 'warning', value: 'Review — PTR does not match MX host', detail: `PTR records: ${evidence.reverse_dns.join(', ')}${evidence.forward_confirmed ? '' : '; forward confirmation also failed'}.` };
  const blockedDetail = evidence.policy_response || 'The server rejected commands from the monitoring source address.';
  const tests = [
    timingTest('SMTP Connection Time', evidence.connection_time_ms, CONNECTION_WARNING_MS, CONNECTION_CRITICAL_MS),
    timingTest('SMTP Transaction Time', evidence.transaction_time_ms, TRANSACTION_WARNING_MS, TRANSACTION_CRITICAL_MS),
    reverseDnsTest,
    { label: 'SMTP Valid Hostname', status: ptr && validHostname(ptr) ? 'healthy' : 'warning', value: ptr && validHostname(ptr) ? 'OK — Reverse DNS is a valid hostname' : 'Review', detail: ptr && validHostname(ptr) ? `${ptr} is a valid fully qualified host name.` : ptr ? `${ptr} is not a valid fully qualified host name.` : 'A reverse-DNS host name was not available.' },
    { label: 'SMTP Banner Check', status: evidence.banner_matches_reverse_dns ? 'healthy' : 'warning', value: evidence.banner_matches_reverse_dns ? 'OK — Reverse DNS matches SMTP banner' : 'Review', detail: `Banner host: ${evidence.banner_hostname || 'not identified'}; reverse DNS: ${ptr || 'not found'}.` },
    { label: 'SMTP TLS', status: evidence.policy_blocked && !evidence.starttls_negotiated ? 'info' : evidence.starttls_negotiated && evidence.tls_authorized ? 'healthy' : evidence.starttls_negotiated ? 'warning' : 'critical', value: evidence.policy_blocked && !evidence.starttls_negotiated ? 'Not tested — Server policy blocked the probe' : evidence.starttls_negotiated ? evidence.tls_authorized ? 'OK — STARTTLS negotiated with a trusted certificate' : 'Review — STARTTLS certificate is not trusted' : 'Failed — STARTTLS was not negotiated', detail: evidence.policy_blocked && !evidence.starttls_negotiated ? `${blockedDetail} This does not demonstrate a TLS failure for other senders.` : evidence.starttls_negotiated ? `${evidence.tls_protocol || 'TLS'}${evidence.tls_cipher ? ` using ${evidence.tls_cipher}` : ''}${evidence.tls_authorization_error ? `; ${evidence.tls_authorization_error}` : ''}.` : evidence.starttls_advertised ? `The server advertised STARTTLS but negotiation failed${evidence.error ? `: ${evidence.error}` : '.'}` : 'The server did not advertise STARTTLS.' },
    { label: 'SMTP Open Relay', status: evidence.policy_blocked ? 'info' : evidence.relay_status === 'denied' ? 'healthy' : 'warning', value: evidence.policy_blocked ? 'Not tested — Server policy blocked the probe' : evidence.relay_status === 'denied' ? 'OK — Relay attempt denied' : evidence.relay_status === 'potential' ? 'External verification required — Recipient accepted' : 'Inconclusive', detail: evidence.policy_blocked ? `${blockedDetail} The external-recipient command was not reached. No DATA command or message content was sent.` : evidence.relay_status === 'potential' ? 'The server accepted an unauthenticated recipient outside the tested domain from MailPosture’s network location. This can be expected when the server trusts the local network and does not prove that it is open to the internet. No DATA command or message content was sent.' : evidence.relay_status === 'denied' ? `The external recipient was rejected with SMTP ${evidence.rcpt_to_code}.` : 'The server did not reach a definitive external-recipient decision. No DATA command or message content was sent.' }
  ];
  if (evidence.error && !evidence.greeting_code) {
    tests[0] = { label: 'SMTP Connection Time', status: 'critical', value: 'Connection failed', detail: evidence.error };
    tests[1] = { label: 'SMTP Transaction Time', status: 'info', value: 'Not run', detail: 'The SMTP transaction could not start because the greeting was not received.' };
    tests[4] = { label: 'SMTP Banner Check', status: 'info', value: 'Not run', detail: 'No SMTP greeting was available.' };
    tests[5] = { label: 'SMTP TLS', status: 'info', value: 'Not run', detail: 'STARTTLS could not be tested without an SMTP greeting.' };
    tests[6] = { label: 'SMTP Open Relay', status: 'info', value: 'Not run', detail: 'The relay-safety probe could not start. No message content was sent.' };
  }
  let status = tests.reduce((current, test) => STATUS_RANK[test.status] > STATUS_RANK[current] ? test.status : current, 'healthy');
  if (status === 'healthy' && tests.some(test => test.status === 'info')) status = 'info';
  return { ...evidence, host: normalizedHost(host), status, tests };
}

function smtpResult(domain, mxRecords, endpoints) {
  if (!mxRecords.length) return { id: 'smtp_service', label: 'SMTP service', status: 'warning', summary: 'No MX hosts configured', detail: 'No SMTP server could be selected from the domain’s MX records.', action: 'Publish an MX record or confirm that this domain intentionally does not receive email.', evidence: { domain, mx: [], endpoints: [] } };
  let status = endpoints.reduce((current, endpoint) => STATUS_RANK[endpoint.status] > STATUS_RANK[current] ? endpoint.status : current, 'healthy');
  if (status === 'healthy' && endpoints.some(endpoint => endpoint.status === 'info')) status = 'info';
  const affected = endpoints.filter(endpoint => endpoint.status !== 'healthy');
  const summary = status === 'healthy' ? `${endpoints.length} MX host${endpoints.length === 1 ? '' : 's'} ready` : status === 'info' ? `${affected.length} MX host${affected.length === 1 ? '' : 's'} not fully tested` : `${affected.length} of ${endpoints.length} MX host${endpoints.length === 1 ? '' : 's'} need${affected.length === 1 ? 's' : ''} attention`;
  const detail = status === 'healthy' ? 'Connection, identity, STARTTLS, and relay-safety checks passed.' : affected.map(endpoint => `${endpoint.host}: ${endpoint.tests.filter(test => status === 'info' ? test.status === 'info' : ['warning', 'critical'].includes(test.status)).map(test => test.label).join(', ')}`).join(' · ');
  const action = endpoints.some(endpoint => endpoint.policy_blocked) ? 'Run MailPosture from a permitted static address or another external monitoring location. The receiving service blocked this probe source; this does not show that normal mail delivery or STARTTLS is broken.' : endpoints.some(endpoint => endpoint.tests[0]?.status === 'critical') ? 'Confirm that the MX host is reachable on TCP port 25 and review its SMTP service and network logs.' : endpoints.some(endpoint => !endpoint.starttls_negotiated || endpoint.tls_authorized === false) ? 'Correct STARTTLS or certificate trust on the affected MX host, then run checks again.' : endpoints.some(endpoint => ['warning', 'critical'].includes(endpoint.tests[0]?.status) || ['warning', 'critical'].includes(endpoint.tests[1]?.status)) ? 'Review SMTP service load, DNS, network latency, and connection filtering on the affected host.' : endpoints.some(endpoint => endpoint.relay_status === 'potential') ? 'Repeat the relay test from a network outside your organization. If an external probe also accepts the recipient, restrict unauthenticated relaying immediately.' : 'Correct reverse DNS or the SMTP greeting so the connected address, PTR record, and banner use the intended host name.';
  return { id: 'smtp_service', label: 'SMTP service', status, summary, detail, action, evidence: { domain, mx: mxRecords, endpoints, relay_probe_safety: 'Uses reserved example.com/example.net addresses and stops before DATA; no message content is transmitted.' } };
}

async function smtpDiagnostics(domain, options = {}) {
  try {
    const resolver = options.resolver || dns;
    const mxRecords = (await resolver.resolveMx(domain)).sort((a, b) => a.priority - b.priority).filter(record => normalizedHost(record.exchange) && record.exchange !== '.');
    const unique = [...new Map(mxRecords.map(record => [normalizedHost(record.exchange), { priority: record.priority, exchange: normalizedHost(record.exchange) }])).values()].slice(0, 10);
    const probe = options.probe || probeSmtp;
    const endpoints = await Promise.all(unique.map(async record => evaluateSmtpEvidence(record.exchange, await probe(record.exchange, { timeout_ms: options.timeout_ms, resolver }))));
    return smtpResult(domain, unique, endpoints);
  } catch (error) {
    return { id: 'smtp_service', label: 'SMTP service', status: 'critical', summary: 'SMTP check failed', detail: safeLine(error.message), action: 'Verify the domain’s MX records and confirm that MailPosture can reach TCP port 25.', evidence: { domain, error: safeLine(error.message), endpoints: [] } };
  }
}

module.exports = { smtpDiagnostics, probeSmtp, evaluateSmtpEvidence, smtpResult, smtpBannerHostname, smtpCapabilities, validHostname, timingTest };
