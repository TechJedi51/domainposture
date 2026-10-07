'use strict';

const $ = selector => document.querySelector(selector);
const storedDomainSort = localStorage.getItem('domainposture-domain-sort') || localStorage.getItem('mailposture-domain-sort');
const state = { data: null, system: null, logs: [], serviceLogs: null, selected: 0, settings: null, settingsLoaded: false, editor: null, route: '/', domainSort: storedDomainSort === 'alphabetical' ? 'alphabetical' : 'priority', editingDiscordWebhook: false, backgroundRefreshTimer: null };
const names = { critical: 'Needs action', warning: 'Review', healthy: 'Healthy', info: 'Info', ignored: 'Ignored' };
const themeQuery = matchMedia('(prefers-color-scheme: dark)');
const esc = value => String(value ?? '').replace(/[&<>'"]/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character]);
const clone = value => JSON.parse(JSON.stringify(value));
const number = value => new Intl.NumberFormat().format(Math.round(Number(value || 0)));
const hostingLabels = { auto: 'Automatic', self_hosted: 'Self-hosted', managed: 'Managed provider', no_inbound: 'No inbound mail' };
const providerLabels = { auto: 'Automatic', kerio: 'Kerio Connect', google: 'Google Workspace', microsoft: 'Microsoft 365', hover: 'Hover Mail', icloud: 'iCloud Mail', self_hosted: 'Self-hosted', other: 'Other provider', none: 'None' };

function mailProfileValues(profile = {}) {
  const requestedHosting = profile.requested_hosting_type || profile.hosting_type || 'auto';
  const requestedProvider = profile.requested_provider || profile.provider || 'auto';
  const hostingSource = profile.hosting_source || (requestedHosting === 'auto' ? 'auto_detected' : 'selected');
  const providerSource = profile.provider_source || (requestedProvider === 'auto' ? 'auto_detected' : 'selected');
  return {
    hosting: profile.hosting_type_label || hostingLabels[profile.hosting_type] || 'Unknown',
    hostingSource: hostingSource === 'selected' ? 'Selected' : 'Auto-detected',
    provider: profile.provider_label || providerLabels[profile.provider] || 'Unknown',
    providerSource: providerSource === 'selected' ? 'Selected' : 'Auto-detected'
  };
}

function mailProfileText(profile) {
  const value = mailProfileValues(profile);
  return `Hosting type: ${value.hosting} (${value.hostingSource}) · Provider: ${value.provider} (${value.providerSource})`;
}

function mailProfileMarkup(profile) {
  const value = mailProfileValues(profile);
  return `<div class="mail-profile-summary"><span><small>Hosting type · ${esc(value.hostingSource)}</small><strong>${esc(value.hosting)}</strong></span><span><small>Provider · ${esc(value.providerSource)}</small><strong>${esc(value.provider)}</strong></span></div>`;
}

function statusSymbol(status, label = names[status] || status) {
  return `<span class="status-symbol ${esc(status)}" role="img" aria-label="${esc(label)}"></span>`;
}

function ago(value) {
  if (!value) return 'Starting checks…';
  const seconds = Math.max(0, Math.round((Date.now() - new Date(value)) / 1000));
  return seconds < 10 ? 'Updated just now' : seconds < 60 ? `Updated ${seconds}s ago` : `Updated ${Math.floor(seconds / 60)}m ago`;
}

function score(domain) {
  if (Number.isFinite(Number(domain.score))) return Number(domain.score);
  const weights = { critical: 0, warning: .55, info: 1, ignored: 1, healthy: 1 };
  return domain.checks.length ? Math.round(domain.checks.reduce((total, check) => total + weights[check.status], 0) / domain.checks.length * 100) : 0;
}

function issuesFor(domain) {
  return domain.checks.filter(check => ['critical', 'warning'].includes(check.status)).sort((a, b) => (a.status === b.status ? 0 : a.status === 'critical' ? -1 : 1));
}

function renderDomainMenu() {
  const menu = $('#domain-menu-list');
  if (!menu) return;
  const domains = (state.data?.domains || []).map((domain, index) => ({ domain, index }));
  const rank = { critical: 0, warning: 1, info: 2, ignored: 2, healthy: 3 };
  domains.sort((a, b) => state.domainSort === 'alphabetical'
    ? a.domain.domain.localeCompare(b.domain.domain)
    : (rank[a.domain.status] ?? 4) - (rank[b.domain.status] ?? 4) || a.domain.domain.localeCompare(b.domain.domain));
  menu.innerHTML = domains.length
    ? domains.map(({ domain, index }) => `<button type="button" role="menuitem" data-menu-domain="${index}"${index === state.selected ? ' aria-current="true"' : ''}>${statusSymbol(domain.status)}<span>${esc(domain.domain)}</span><small>${esc(names[domain.status] || domain.status)}</small></button>`).join('')
    : '<a href="/settings" data-route="/settings" role="menuitem">Add a monitored domain</a>';
}

function setDomainSort(mode, persist = true) {
  state.domainSort = mode === 'alphabetical' ? 'alphabetical' : 'priority';
  if (persist) localStorage.setItem('domainposture-domain-sort', state.domainSort);
  document.querySelectorAll('input[name="domain-sort"]').forEach(input => { input.checked = input.value === state.domainSort; });
  renderDomainMenu();
}

function tlsEndpoint(check, domain) {
  if (check.label !== 'TLS certificate') return '';
  return `${check.evidence?.host || domain}:${check.evidence?.port || '—'}`;
}

function trendChart(points, successKey, failureKey, label) {
  if (!points?.length) return '<p class="report-empty">No daily trend is available for this period.</p>';
  const hasFailures = points.some(point => Number(point[failureKey] || 0) > 0);
  const maximum = Math.max(1, ...points.map(point => Number(point[successKey] || 0) + Number(point[failureKey] || 0)));
  const columns = points.map(point => {
    const success = Number(point[successKey] || 0); const failed = Number(point[failureKey] || 0);
    const successHeight = Math.max(success ? 2 : 0, success / maximum * 100); const failedHeight = Math.max(failed ? 2 : 0, failed / maximum * 100);
    const date = new Date(`${String(point.date).slice(0, 10)}T00:00:00`).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    return `<span class="chart-column" title="${esc(date)}: ${number(success)} successful, ${number(failed)} failed">${success ? `<i class="chart-bar" style="height:${successHeight}%"></i>` : ''}${failed ? `<i class="chart-bar failed" style="height:${failedHeight}%"></i>` : ''}</span>`;
  }).join('');
  return `<div class="chart" role="img" aria-label="${esc(label)}">${columns}</div><div class="chart-legend"><span><i></i>Successful</span>${hasFailures ? '<span class="failed"><i></i>Failed</span>' : ''}</div>`;
}

function rankedList(items, nameKey, valueKey, emptyText) {
  if (!items?.length) return `<p class="report-empty">${esc(emptyText)}</p>`;
  const maximum = Math.max(1, ...items.map(item => Number(item[valueKey] || 0)));
  return `<ol class="ranked-list">${items.map(item => `<li><span>${esc(item[nameKey])}</span><strong>${number(item[valueKey])}</strong><span class="rank-bar"><i style="width:${Number(item[valueKey] || 0) / maximum * 100}%"></i></span></li>`).join('')}</ol>`;
}

function sourceList(items) {
  if (!items?.length) return '<p class="report-empty">No failing sources were reported.</p>';
  const maximum = Math.max(1, ...items.map(item => Number(item.messages || 0)));
  return `<ol class="ranked-list source-list">${items.map(item => `<li><span class="source-identity"><strong>${esc(item.ip)}</strong>${item.fqdn ? `<small>${esc(item.fqdn)}</small>` : '<small>No reverse-DNS name found</small>'}${item.network_owner ? `<small>${esc(item.network_owner)}</small>` : ''}</span><strong>${number(item.messages)}</strong><span class="rank-bar"><i style="width:${Number(item.messages || 0) / maximum * 100}%"></i></span></li>`).join('')}</ol>`;
}

function reportId(id) { return id ? ` id="${esc(id)}" tabindex="-1"` : ''; }

function aggregateCard(report, wide = false, id = '') {
  if (!report?.total) return `<article${reportId(id)} class="report-card ${wide ? 'wide' : ''}"><div class="report-card-header"><div><h3>DMARC aggregate reports</h3><p>Authentication results reported by receiving email services.</p></div></div><p class="report-empty">No aggregate report data was found for this period.</p></article>`;
  const passed = Math.max(0, Number(report.total) - Number(report.failed || 0));
  return `<article${reportId(id)} class="report-card ${wide ? 'wide' : ''}"><div class="report-card-header"><div><h3>DMARC aggregate reports</h3><p>${number(report.total)} messages observed over ${number(report.period_days)} days</p></div><span class="report-value">${report.pass_rate ?? '—'}%</span></div><div class="alignment-table"><div class="alignment-heading"><span>Result</span><span>Messages</span><span>DKIM aligned</span><span>SPF aligned</span></div><div><strong>Failed DMARC</strong><span>${number(report.failed)}</span><span>${report.failed_dkim_aligned_rate ?? '—'}%</span><span>${report.failed_spf_aligned_rate ?? '—'}%</span></div><div><strong>Passed DMARC</strong><span>${number(report.passed ?? passed)}</span><span>${report.passed_dkim_aligned_rate ?? '—'}%</span><span>${report.passed_spf_aligned_rate ?? '—'}%</span></div></div><p class="report-explanation">Each alignment percentage uses only the messages in its row. DMARC passes when SPF or DKIM aligns, so the two percentages can overlap. The failed count is separate from optional, message-level RUF report files.</p>${trendChart((report.timeline || []).map(item => ({...item, passed: Math.max(0, item.total - item.failed)})), 'passed', 'failed', `Stacked DMARC daily results: ${number(passed)} successful and ${number(report.failed)} failed`)}</article>`;
}

function smtpTlsCard(report, id = '', wide = false) {
  if (!report?.available || (!report.successful && !report.failed)) return `<article${reportId(id)} class="report-card${wide ? ' wide' : ''}"><div class="report-card-header"><div><h3>SMTP TLS reports</h3><p>Transport security results reported by sending services.</p></div></div><p class="report-empty">No SMTP TLS report data was found for this period.</p></article>`;
  return `<article${reportId(id)} class="report-card${wide ? ' wide' : ''}"><div class="report-card-header"><div><h3>SMTP TLS reports</h3><p>${number(report.reports)} reported policies</p></div><span class="report-value">${report.success_rate ?? '—'}%</span></div><div class="metric-row"><div class="metric"><strong>${number(report.successful)}</strong><span>Successful sessions</span></div><div class="metric"><strong>${number(report.failed)}</strong><span>Failed sessions</span></div><div class="metric"><strong>${number(report.failure_types?.length)}</strong><span>Failure types</span></div></div>${trendChart(report.timeline, 'successful', 'failed', `SMTP TLS daily results: ${number(report.successful)} successful and ${number(report.failed)} failed`)}</article>`;
}

function failureCard(report, id = '') {
  const explanation = report?.available
    ? `${number(report.count)} optional individual report file${Number(report.count) === 1 ? '' : 's'} received. This is a file count, not the number of messages that failed DMARC.`
    : 'No individual-report index has been created. This usually means no provider has sent an optional RUF report; it is not evidence that report processing failed.';
  return `<article${reportId(id)} class="report-card"><div class="report-card-header"><div><h3>Individual DMARC failure reports (RUF)</h3><p>Optional, message-level reports sent by some receiving providers</p></div><span class="report-value">${report?.available ? number(report.count) : '0'}</span></div><p class="report-explanation">${esc(explanation)} Aggregate reports above remain the authoritative count of messages that failed DMARC.</p><p class="privacy-note">${esc(report?.privacy_note || (report?.error ? 'No matching index is available yet.' : '') || 'Message samples are not displayed because they may contain personal or confidential content.')}</p></article>`;
}

function reporterList(items, valueKey, valueLabel, emptyText) {
  if (!items?.length) return `<p class="report-empty">${esc(emptyText)}</p>`;
  return `<ol class="reporter-list">${items.map(item => `<li><span><strong>${esc(item.name)}</strong>${item.domain ? `<small>${esc(item.domain)}</small>` : item.domains?.length ? `<small>${esc(item.domains.join(', '))}</small>` : '<small>Reporter domain not provided</small>'}</span><b>${number(item[valueKey])}<small>${esc(valueLabel)}</small></b></li>`).join('')}</ol>`;
}

function dmarcReportersCard(report, id = '') {
  const limited = report?.reporter_sample_limited ? '<p class="privacy-note">The list is based on the 1,000 most recent matching OpenSearch documents.</p>' : '';
  return `<article${reportId(id)} class="report-card wide"><div class="report-card-header"><div><h3>DMARC reports</h3><p>Receiving services and reporter domains that supplied aggregate reports</p></div></div>${reporterList(report?.reporters, 'reports', 'reports', 'No DMARC reporting services were found for this period.')}${limited}</article>`;
}

function reportingOrganizationsCard(report, id = '') {
  const organizations = report?.organizations || [];
  const samples = report?.raw_samples || [];
  const raw = samples.length || organizations.length ? `<details class="raw-data"><summary>Show reporter source fields</summary><p>These limited samples show the exact organization-related fields stored by parsedmarc. Message content and policy details are excluded.</p><pre>${esc(JSON.stringify({ normalized_organizations: organizations, source_samples: samples }, null, 2))}</pre></details>` : '';
  const missingName = organizations.some(item => item.name === 'Reporter name not provided');
  return `<article${reportId(id)} class="report-card"><div class="report-card-header"><div><h3>Top TLS reporting organizations</h3><p>Sending services and reporter domains that supplied TLS-RPT data</p></div></div><p class="report-explanation">Each value is the number of reported SMTP delivery sessions, not messages. ${missingName ? '“Reporter name not provided” means the stored report did not contain a recognized organization-name field; open the source fields below to verify what parsedmarc saved.' : 'The source fields below let you verify what parsedmarc stored.'}</p>${reporterList(organizations, 'sessions', 'sessions', 'No TLS reporting organizations were found.')}${raw}</article>`;
}

function smtpDiagnosticsCard(report, id = '') {
  const endpoints = report?.endpoints || [];
  if (!endpoints.length) return `<article${reportId(id)} class="report-card wide"><div class="report-card-header"><div><h3>MX endpoint results</h3><p>Live checks of the domain’s published MX hosts on TCP port 25.</p></div></div><p class="report-empty">No SMTP diagnostic results are available.</p></article>`;
  const endpointCards = endpoints.map(endpoint => {
    const tests = (endpoint.tests || []).map(test => `<div class="smtp-test ${esc(test.status)}"><span>${statusSymbol(test.status)}</span><div><strong>${esc(test.label)}</strong><small>${esc(test.detail)}</small></div><b>${esc(test.value)}</b></div>`).join('');
    const transcript = endpoint.transcript?.length ? `<details class="smtp-transcript"><summary>Session transcript</summary><p>The probe uses reserved example addresses and stops before DATA. No message content is sent.</p><pre>${esc(endpoint.transcript.join('\n'))}</pre></details>` : '';
    const probeNote = endpoint.rate_limited && endpoint.next_probe_at ? ` · Next probe after ${new Date(endpoint.next_probe_at).toLocaleString()}` : endpoint.probe_cached ? ' · Reused cached probe' : endpoint.probe_shared ? ' · Shared probe result' : '';
    return `<section class="smtp-endpoint"><div class="smtp-endpoint-heading"><div><strong>${esc(endpoint.host)}:${number(endpoint.port || 25)}</strong><span>${esc(endpoint.ip_address || 'Address unavailable')}${esc(probeNote)}</span></div><span class="state ${esc(endpoint.status)}">${esc(names[endpoint.status] || endpoint.status)}</span></div><div class="smtp-tests">${tests}</div>${transcript}</section>`;
  }).join('');
  const profile = report.profile || {};
  return `<article${reportId(id)} class="report-card wide"><div class="report-card-header"><div><h3>MX endpoint results</h3><p>Connection, SMTP identity, STARTTLS, and relay protection for each published MX host.</p></div></div>${mailProfileMarkup(profile)}<p class="report-explanation">PTR and banner names on managed infrastructure may differ from the customer-facing MX name. Slow timing from this single monitoring location is advisory. The relay probe never sends DATA or message content; acceptance is conclusive only from a configured external, untrusted location.</p><div class="smtp-endpoints">${endpointCards}</div></article>`;
}

function dnsValue(value) {
  if (typeof value === 'string') return value;
  if (value?.address) return `${value.address}${value.ttl !== null && value.ttl !== undefined ? ` · TTL ${value.ttl}s` : ''}`;
  if (value?.exchange) return `${value.priority} ${value.exchange}`;
  if (value?.nsname) return `${value.nsname} · ${value.hostmaster} · serial ${value.serial} · refresh ${value.refresh}s · retry ${value.retry}s · expire ${value.expire}s · minimum ${value.minttl}s`;
  if (value?.critical !== undefined && value?.issue) return `${value.critical} ${value.issue} ${value.value}`;
  return JSON.stringify(value);
}

function dnsMonitoringCard(report) {
  const records = report?.records || [];
  if (!records.length) return '';
  const rows = records.map(record => {
    const stateLabel = { baseline: 'Baseline saved', unchanged: 'Unchanged', pending: `Change pending ${record.confirmations_observed || 1}/${report.confirmation_runs || 2}`, changed: 'Change confirmed', notification_failed: 'Notification retry pending', unavailable: 'Lookup unavailable' }[record.change_state] || (record.status === 'missing' ? 'No record' : 'Observed');
    const stateClass = record.change_state === 'unavailable' || record.change_state === 'notification_failed' ? 'warning' : record.change_state === 'changed' || record.change_state === 'pending' ? 'info' : 'healthy';
    const values = record.status === 'unavailable' ? record.error : record.values?.length ? record.values.map(dnsValue).join(' · ') : 'No record published';
    return `<div class="dns-monitor-row"><span>${statusSymbol(stateClass)}</span><div><strong>${esc(record.host)} <b>${esc(record.type)}</b></strong><small>${esc(values)}</small></div><em class="state ${stateClass}">${esc(stateLabel)}</em></div>`;
  }).join('');
  return `<article class="report-card wide dns-monitoring-card"><div class="report-card-header"><div><h3>DNS change monitoring</h3><p>Operational record baselines and confirmed changes. These results do not affect the posture score.</p></div></div><div class="dns-monitor-rows">${rows}</div></article>`;
}

function detailCards(reports, configuredSections = {}, dnsMonitoringEnabled = false) {
  const sections = { domain_certificates: true, additional_tls: true, smtp: true, dkim: true, mail_security: true, bimi: true, ...configuredSections };
  const mailReports = sections.mail_security ? `${aggregateCard(reports?.aggregate, true, 'report-dmarc')}${smtpTlsCard(reports?.smtp_tls, 'report-smtp-tls', true)}<article id="report-dmarc-sources" tabindex="-1" class="report-card"><div class="report-card-header"><div><h3>Top failing DMARC sources</h3><p>Source addresses producing the most failed messages, with reverse-DNS names when available</p></div></div>${sourceList(reports?.aggregate?.top_failing_sources)}</article>${reportingOrganizationsCard(reports?.smtp_tls, 'report-smtp-tls-organizations')}${failureCard(reports?.failure, 'report-dmarc-failure')}<article id="report-smtp-tls-failures" tabindex="-1" class="report-card"><div class="report-card-header"><div><h3>SMTP TLS failure types</h3><p>Transport problems reported by sending services</p></div></div>${rankedList(reports?.smtp_tls?.failure_types, 'type', 'count', 'No SMTP TLS failure types were reported.')}</article>${dmarcReportersCard(reports?.aggregate, 'report-dmarc-reporters')}` : '';
  const smtpReports = sections.smtp ? `<div class="report-subheading wide"><small>Live service check</small><h3>SMTP server diagnostics</h3></div>${smtpDiagnosticsCard(reports?.smtp_diagnostics, 'report-smtp-diagnostics')}` : '';
  const dnsMonitoring = dnsMonitoringCard(reports?.dns_monitoring);
  const labels = { domain_certificates: 'Domain certificates', additional_tls: 'Additional TLS endpoints', smtp: 'Mail hosting and SMTP probes', dkim: 'DKIM selectors', mail_security: 'Mail security review exceptions', bimi: 'BIMI review exceptions' };
  const disabled = `${Object.entries(labels).filter(([key]) => !sections[key]).map(([, label]) => `<li>${esc(label)}</li>`).join('')}${dnsMonitoringEnabled ? '' : '<li>DNS change monitoring <small>Non-scored</small></li>'}`;
  const empty = mailReports || smtpReports || dnsMonitoring ? '' : '<div class="empty-state wide"><h3>No Report Center checks are enabled</h3><p>Enable mail security, SMTP probes, or DNS change monitoring in this domain’s settings to show report information here.</p></div>';
  const disabledSection = disabled ? `<section class="disabled-checks wide"><small>Domain configuration</small><h3>Checks switched off</h3><p>Scored checks are excluded from the Domain Score. All listed checks are omitted from the Report Center.</p><ul>${disabled}</ul></section>` : '';
  return `${mailReports}${smtpReports}${dnsMonitoring}${empty}${disabledSection}`;
}

function organizationReports(domains) {
  const aggregate = { total: 0, passed: 0, failed: 0, period_days: 0, timeline: [], top_failing_sources: [], reporters: [] }; const smtp = { available: false, reports: 0, successful: 0, failed: 0, timeline: [], failure_types: [], organizations: [], raw_samples: [] }; let failures = 0; let failureAvailable = false;
  const days = new Map(); const tlsDays = new Map(); const sources = new Map(); const types = new Map(); const organizations = new Map(); const reporters = new Map(); let passedDkim = 0; let passedSpf = 0; let failedDkim = 0; let failedSpf = 0;
  for (const domain of domains) {
    const a = domain.reports?.aggregate || {}; const aPassed = Number(a.passed ?? Math.max(0, Number(a.total || 0) - Number(a.failed || 0))); const aFailed = Number(a.failed || 0); aggregate.total += Number(a.total || 0); aggregate.passed += aPassed; aggregate.failed += aFailed; aggregate.period_days = Math.max(aggregate.period_days, Number(a.period_days || 0)); passedDkim += Number(a.passed_dkim_aligned_rate || 0) * aPassed; passedSpf += Number(a.passed_spf_aligned_rate || 0) * aPassed; failedDkim += Number(a.failed_dkim_aligned_rate || 0) * aFailed; failedSpf += Number(a.failed_spf_aligned_rate || 0) * aFailed;
    for (const point of a.timeline || []) { const key = String(point.date).slice(0,10); const day = days.get(key) || {date:key,total:0,failed:0}; day.total += Number(point.total || 0); day.failed += Number(point.failed || 0); days.set(key,day); }
    for (const item of a.top_failing_sources || []) { const current = sources.get(item.ip) || { ...item, messages: 0 }; current.messages += Number(item.messages || 0); if (!current.fqdn && item.fqdn) current.fqdn = item.fqdn; if (!current.network_owner && item.network_owner) current.network_owner = item.network_owner; sources.set(item.ip, current); }
    for (const item of a.reporters || []) { const key = `${item.name}|${item.domain || ''}`; const current = reporters.get(key) || { ...item, reports: 0, messages: 0 }; current.reports += Number(item.reports || 0); current.messages += Number(item.messages || 0); if (item.last_report && (!current.last_report || item.last_report > current.last_report)) current.last_report = item.last_report; reporters.set(key, current); }
    const t = domain.reports?.smtp_tls || {}; if (t.available) smtp.available = true; smtp.reports += Number(t.reports || 0); smtp.successful += Number(t.successful || 0); smtp.failed += Number(t.failed || 0);
    for (const point of t.timeline || []) { const key = String(point.date).slice(0,10); const day = tlsDays.get(key) || {date:key,successful:0,failed:0}; day.successful += Number(point.successful || 0); day.failed += Number(point.failed || 0); tlsDays.set(key,day); }
    for (const item of t.failure_types || []) types.set(item.type, (types.get(item.type) || 0) + Number(item.count || 0));
    for (const item of t.organizations || []) { const current = organizations.get(item.name) || { name: item.name, sessions: 0, reports: 0, domains: new Set() }; current.sessions += Number(item.sessions || 0); current.reports += Number(item.reports || 0); for (const value of item.domains || []) current.domains.add(value); organizations.set(item.name, current); }
    for (const sample of t.raw_samples || []) if (smtp.raw_samples.length < 20) smtp.raw_samples.push({ domain: domain.domain, ...sample });
    const f = domain.reports?.failure || {}; if (f.available) failureAvailable = true; failures += Number(f.count || 0);
  }
  aggregate.pass_rate = aggregate.total ? Math.round(aggregate.passed / aggregate.total * 1000) / 10 : null; aggregate.passed_dkim_aligned_rate = aggregate.passed ? Math.round(passedDkim / aggregate.passed * 10) / 10 : null; aggregate.passed_spf_aligned_rate = aggregate.passed ? Math.round(passedSpf / aggregate.passed * 10) / 10 : null; aggregate.failed_dkim_aligned_rate = aggregate.failed ? Math.round(failedDkim / aggregate.failed * 10) / 10 : null; aggregate.failed_spf_aligned_rate = aggregate.failed ? Math.round(failedSpf / aggregate.failed * 10) / 10 : null; aggregate.timeline = [...days.values()].sort((a,b)=>a.date.localeCompare(b.date)); aggregate.top_failing_sources = [...sources.values()].sort((a,b)=>b.messages-a.messages).slice(0,8); aggregate.reporters = [...reporters.values()].sort((a,b)=>b.messages-a.messages);
  const tlsTotal = smtp.successful + smtp.failed; smtp.success_rate = tlsTotal ? Math.round(smtp.successful / tlsTotal * 1000) / 10 : null; smtp.timeline = [...tlsDays.values()].sort((a,b)=>a.date.localeCompare(b.date)); smtp.failure_types = [...types].map(([type,count])=>({type,count})).sort((a,b)=>b.count-a.count).slice(0,8); smtp.organizations = [...organizations.values()].map(item=>({...item,domains:[...item.domains]})).sort((a,b)=>b.sessions-a.sessions).slice(0,8);
  return { aggregate, smtp_tls: smtp, failure: { available: failureAvailable, count: failures, privacy_note: 'Counts only. Message samples remain private.' } };
}

function setTheme(mode, persist = true) {
  const normalized = ['light', 'dark', 'system'].includes(mode) ? mode : 'system';
  const resolved = normalized === 'system' ? (themeQuery.matches ? 'dark' : 'light') : normalized;
  document.documentElement.dataset.themeMode = normalized;
  document.documentElement.dataset.theme = resolved;
  document.querySelector('meta[name="theme-color"]').content = resolved === 'dark' ? '#07111b' : '#f4f7fb';
  if (persist) localStorage.setItem('domainposture-theme', normalized);
  document.querySelectorAll('input[name="theme"]').forEach(input => { input.checked = input.value === normalized; });
}

function renderDashboard() {
  const data = state.data;
  if (!data) return;
  if (data.error && !data.domains.length) {
    $('#master-score').innerHTML = '<span>Unavailable</span>';
    $('#domain-scores').innerHTML = `<div class="error">${esc(data.error)}</div>`;
    $('#master-attention').innerHTML = '';
    $('#organization-reports').innerHTML = '';
    return;
  }
  if (!data.domains.length) {
    $('#master-score').innerHTML = '<strong>—</strong><span>No domains configured</span>';
    $('#domain-scores').innerHTML = '<div class="empty-state"><h3>Add your first domain</h3><p>Configure a domain, its DKIM selectors, and its TLS certificate endpoints.</p><a href="/settings" data-route="/settings">Open Settings →</a></div>';
    $('#master-attention').innerHTML = '<div class="clear">There are no domains to evaluate.</div>';
    $('#organization-reports').innerHTML = '<div class="empty-state"><h3>No report data yet</h3><p>Add a domain and connect a report source.</p></div>';
    $('#master-issue-count').textContent = '0 open';
    return;
  }
  const domainScores = data.domains.map(score);
  const master = Math.round(domainScores.reduce((total, value) => total + value, 0) / domainScores.length);
  const issueCount = data.domains.reduce((total, domain) => total + issuesFor(domain).length, 0);
  const masterStatus = data.domains.some(domain => domain.status === 'critical') ? 'critical' : data.domains.some(domain => domain.status === 'warning') ? 'warning' : 'healthy';
  $('#master-score').innerHTML = `<span class="score-watermark status-symbol ${masterStatus}" aria-hidden="true"></span><div class="score-content"><strong>${master}</strong><span>Master score out of 100</span><div class="bar"><i style="width:${master}%"></i></div></div>`;
  $('#domain-scores').innerHTML = data.domains.map((domain, index) => {
    const value = domainScores[index];
    const ignored = domain.counts.ignored ? ` · ${domain.counts.ignored} ignored` : '';
    return `<button class="domain-score-card" data-open-domain="${index}"><div class="domain-score-top"><span>${statusSymbol(domain.status)}${esc(domain.domain)}</span><span class="state ${domain.status}">${names[domain.status]}</span></div><span class="domain-mail-host">${esc(mailProfileText(domain.mail_profile || {}))}</span><strong>${value}</strong><div class="bar"><i style="width:${value}%"></i></div><p>${domain.counts.critical} critical · ${domain.counts.warning} review${ignored}</p></button>`;
  }).join('');
  $('#master-issue-count').textContent = issueCount ? `${issueCount} open` : 'Clear';
  $('#master-attention').innerHTML = issueCount ? data.domains.map((domain, domainIndex) => {
    const issues = issuesFor(domain);
    if (!issues.length) return '';
    return `<section class="attention-group"><div class="attention-group-heading"><h3>${esc(domain.domain)}</h3><button data-open-domain="${domainIndex}">View domain →</button></div>${issues.map(check => `<article class="issue ${check.status}"><span class="issue-status">${statusSymbol(check.status)}</span><span class="control">${esc(check.label)}</span><div><h3>${esc(check.summary)}</h3><p>${esc(check.action)}</p></div><button class="view" data-dashboard-check="${esc(check.id)}" data-domain-index="${domainIndex}">View →</button></article>`).join('')}</section>`;
  }).join('') : '<div class="clear">No immediate actions. Every configured control passed its threshold.</div>';
  const reports = organizationReports(data.domains);
  $('#organization-reports').innerHTML = `${aggregateCard(reports.aggregate)}${smtpTlsCard(reports.smtp_tls)}${dmarcReportersCard(reports.aggregate)}${failureCard(reports.failure)}${reportingOrganizationsCard(reports.smtp_tls)}`;
}

function certificateResultMarkup(certificate) {
  if (!certificate) return '';
  const type = certificate.check_type === 'origin' ? 'Origin' : 'Public';
  const expires = certificate.not_after ? new Date(certificate.not_after).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : 'Unavailable';
  const checked = certificate.checked_at ? new Date(certificate.checked_at).toLocaleString() : 'Not checked';
  const days = Number.isFinite(Number(certificate.days_remaining)) ? `${number(certificate.days_remaining)} days` : '—';
  return `<section class="certificate-result ${esc(certificate.status)}"><div class="certificate-result-heading"><strong>${esc(type)}</strong><span>${esc(certificate.status_label || certificate.status)}</span></div><dl><div><dt>Expires</dt><dd>${esc(expires)}</dd></div><div><dt>Days remaining</dt><dd>${esc(days)}</dd></div><div><dt>Issuer</dt><dd>${esc(certificate.issuer || 'Unavailable')}</dd></div><div><dt>IP used</dt><dd>${esc(certificate.ip_used || 'Unavailable')}</dd></div><div><dt>Checked</dt><dd>${esc(checked)}</dd></div>${certificate.error ? `<div class="certificate-error"><dt>Issue</dt><dd>${esc(certificate.error)}</dd></div>` : ''}</dl></section>`;
}

function certificateControlCard(check, domain) {
  const certificates = check.evidence?.checks || [];
  return `<article class="card certificate-control ${esc(check.status)}"><div class="card-content"><div class="card-top"><span class="label">${esc(check.label)}</span><span class="state ${esc(check.status)}">${esc(names[check.status])}</span></div><h3>${esc(check.summary)}</h3><p>${esc(check.detail)}</p><div class="certificate-results">${certificates.map(certificateResultMarkup).join('')}</div><div class="certificate-actions"><button type="button" class="secondary" data-check="${esc(check.id)}">View details</button><button type="button" data-check-now="${esc(domain)}">Check Now</button></div></div></article>`;
}

function renderDomain() {
  const data = state.data;
  if (!data) return;
  $('#updated').textContent = ago(data.generated_at);
  if (data.error && !data.domains.length) {
    $('#hero').innerHTML = '<div><small>Configuration needed</small><h1>Check the saved settings.</h1></div>';
    $('#checks').innerHTML = '';
    $('#attention').innerHTML = `<div class="error">${esc(data.error)}</div>`;
    $('#domain-issue-count').textContent = 'Unavailable';
    $('#domain-reports').innerHTML = '';
    return;
  }
  if (!data.domains.length) {
    $('#hero').innerHTML = '<div><small>Configuration needed</small><h1>Add your first domain.</h1><p>Open Settings to choose the domain, mail controls, and certificate paths.</p><a class="primary-link" href="/settings" data-route="/settings">Open Settings →</a></div>';
    $('#checks').innerHTML = '';
    $('#attention').innerHTML = '<div class="clear">No domains are configured yet.</div>';
    $('#domain-issue-count').textContent = 'Clear';
    $('#domain-reports').innerHTML = '';
    return;
  }
  if (state.selected >= data.domains.length) state.selected = 0;
  const domain = data.domains[state.selected];
  const issues = issuesFor(domain);
  const posture = score(domain);
  const issueHeading = domain.counts.critical ? `${domain.counts.critical} issue${domain.counts.critical === 1 ? ' needs' : 's need'} attention.` : domain.counts.warning ? 'Protected, with room to improve.' : 'Domain controls look solid.';
  $('#hero').innerHTML = `<div><small>${esc(domain.domain)} · Current posture</small><h1>${issueHeading}</h1><p>Live policy, certificate, and observed authentication results, translated into the next useful action.</p>${mailProfileMarkup(domain.mail_profile || {})}<button type="button" class="hero-check-now" data-check-now="${esc(domain.domain)}">Check Now</button></div><div class="score"><span class="score-watermark status-symbol ${esc(domain.status)}" aria-hidden="true"></span><div class="score-content"><strong>${posture}</strong><span>Domain Score out of 100</span><div class="bar"><i style="width:${posture}%"></i></div></div></div>`;
  $('#domain-issue-count').textContent = issues.length ? `${issues.length} open` : 'Clear';
  $('#attention').innerHTML = issues.length ? issues.map(check => `<article class="issue ${check.status}"><span class="issue-status">${statusSymbol(check.status)}</span><span class="control">${esc(check.label)}</span><div><h3>${esc(check.summary)}</h3><p>${esc(check.action)}</p></div><button class="view" data-check="${esc(check.id)}">View →</button></article>`).join('') : '<div class="clear">No immediate actions. Every configured control passed its threshold.</div>';
  renderDomainMenu();
  $('#checks').innerHTML = domain.checks.map(check => {
    if (check.id === 'ssl_certificates') return certificateControlCard(check, domain.domain);
    const endpoint = tlsEndpoint(check, domain.domain);
    const days = check.label === 'TLS certificate' && Number.isFinite(Number(check.evidence?.days_remaining)) ? Number(check.evidence.days_remaining) : null;
    const bimiLogo = check.id === 'bimi' && check.evidence?.logo_available ? `<img class="bimi-logo" src="/api/bimi-logo?domain=${encodeURIComponent(domain.domain)}" alt="BIMI logo for ${esc(domain.domain)}">` : '';
    return `<button class="card ${esc(check.status)}${days === null ? '' : ' tls-card'}${bimiLogo ? ' bimi-card' : ''}" data-check="${esc(check.id)}">${days === null ? '' : `<span class="certificate-days" aria-hidden="true">${number(days)}</span>`}<div class="card-content"><div class="card-top"><span><span class="label">${esc(check.label)}</span>${endpoint ? `<span class="card-context">${esc(endpoint)}</span>` : ''}</span><span class="state ${check.status}">${names[check.status]}</span></div>${bimiLogo}<h3>${esc(check.summary)}</h3><p>${esc(check.detail)}</p></div></button>`;
  }).join('');
  $('#domain-reports').innerHTML = detailCards(domain.reports, domain.check_sections, domain.dns_monitoring_enabled);
}

function renderStatus() {
  if (!state.data) return;
  $('#version').textContent = `v${state.data.version || 'unknown'}`;
  $('#updated').textContent = ago(state.data.generated_at);
  renderDashboard();
  renderDomain();
  renderDomainMenu();
}

function systemSettingsSection(check) {
  if (check.id === 'opensearch') return check.evidence?.nodes === 1 && check.evidence?.actual_cluster_status === 'yellow' ? 'parsedmarc' : 'opensearch';
  if (check.id === 'report_indices' || check.id.startsWith('parsedmarc')) return 'parsedmarc';
  return null;
}

function systemCheckDetails(check) {
  if (check.id === 'opensearch' && check.evidence?.unassigned_breakdown?.length) {
    return `<div class="system-breakdown"><strong>Unassigned shard breakdown</strong><ul>${check.evidence.unassigned_breakdown.map(group => `<li><span>${esc(group.category)}</span><b>${number(group.unassigned_shards)} shard${Number(group.unassigned_shards) === 1 ? '' : 's'} across ${number(group.index_count)} index${Number(group.index_count) === 1 ? '' : 'es'} · ${number(group.primary_shards)} primary, ${number(group.replica_shards)} replica</b></li>`).join('')}</ul>${check.evidence.affected_report_shards === 0 ? '<p>No DomainPosture report shard is affected.</p>' : `<p>${number(check.evidence.affected_report_shards)} report shard${Number(check.evidence.affected_report_shards) === 1 ? ' is' : 's are'} affected.</p>`}</div>`;
  }
  if (check.id === 'report_indices' && check.evidence?.patterns) {
    const patterns = check.evidence.patterns.map(item => {
      const summary = item.available ? `${number(item.count)} documents` : item.type === 'failure' ? 'No optional reports received' : 'Unavailable';
      const contents = item.indexes?.length
        ? `<div class="index-rows">${item.indexes.map(index => `<div><code>${esc(index.name)}</code><span>${esc(index.health || 'unknown')} · ${number(index.documents)} documents · ${number(index.primary_shards)} primary · ${number(index.replicas)} replica</span></div>`).join('')}</div>`
        : `<p>${item.type === 'failure' ? 'OpenSearch has no matching index. This is normal until a provider sends the first optional RUF report.' : esc(item.error || 'No matching index has been created yet.')}</p>`;
      return `<details class="index-pattern"><summary><span><b>${esc(item.label)}</b><code>${esc(item.pattern)}</code></span><em>${summary}</em></summary>${contents}</details>`;
    }).join('');
    const rufDomains = check.evidence.ruf_domains?.length ? `<details class="ruf-domains"><summary>Domains publishing a RUF destination</summary><div>${check.evidence.ruf_domains.map(item => `<p><strong>${esc(item.domain)}</strong><span>${item.destination ? esc(item.destination) : 'No ruf tag published'}</span></p>`).join('')}</div></details>` : '';
    return `<div class="index-patterns"><strong>Scope: ${esc(check.evidence.scope || 'All domains')}</strong>${patterns}${rufDomains}</div>`;
  }
  return '';
}

function renderSystemStatus() {
  const data = state.system;
  if (!data) return;
  const indicator = $('#system-status-indicator');
  const indicatorStatus = data.status || 'warning';
  indicator.innerHTML = `<span class="status-symbol ${esc(indicatorStatus)}" aria-hidden="true"></span>`;
  indicator.setAttribute('aria-label', `System Status: ${names[indicatorStatus] || 'Unavailable'}`);
  indicator.title = `System Status: ${names[indicatorStatus] || 'Unavailable'}`;
  $('#system-status-updated').textContent = data.checked_at ? `Checked ${new Date(data.checked_at).toLocaleString()}` : 'Check unavailable';
  if (data.error) {
    $('#system-status-summary').innerHTML = `${statusSymbol('critical')}<div><strong>Unavailable</strong><span>System checks could not be completed.</span></div>`;
    $('#system-status-checks').innerHTML = `<div class="error">${esc(data.error)}</div>`;
    return;
  }
  const status = data.status || 'warning';
  const counts = (data.checks || []).reduce((totals, check) => ({ ...totals, [check.status]: (totals[check.status] || 0) + 1 }), {});
  $('#system-status-summary').innerHTML = `${statusSymbol(status)}<div><strong>${names[status] || 'Unavailable'}</strong><span>${counts.critical || 0} need action · ${counts.warning || 0} review · ${counts.info || 0} informational · ${counts.healthy || 0} healthy</span></div>`;
  $('#system-status-checks').innerHTML = (data.checks || []).map(check => {
    const section = systemSettingsSection(check);
    const structuredDetails = systemCheckDetails(check);
    const technicalDetails = Object.keys(check.evidence || {}).length ? `<details class="system-evidence"><summary>Show technical details</summary><pre>${esc(JSON.stringify(check.evidence, null, 2))}</pre></details>` : '';
    return `<article class="system-status-card ${esc(check.status)}"><div class="system-status-card-heading">${statusSymbol(check.status)}<div><span class="state ${esc(check.status)}">${esc(names[check.status] || check.status)}</span><h3>${esc(check.label)}</h3></div></div>${check.evidence?.scope ? `<span class="system-scope">${esc(check.evidence.scope)}</span>` : ''}<strong>${esc(check.summary)}</strong><p>${esc(check.detail)}</p>${structuredDetails}${check.status !== 'healthy' ? `<div class="system-action"><span>${check.status === 'info' ? 'Guidance' : 'Next action'}</span><p>${esc(check.action)}</p>${section && check.status !== 'info' ? `<button type="button" data-system-settings="${section}">Open Settings →</button>` : ''}</div>` : ''}${technicalDetails}</article>`;
  }).join('') || '<div class="clear">No system checks were returned.</div>';
}

function renderSystemLogs() {
  const container = $('#system-log');
  if (!container) return;
  const service = $('#log-service')?.value || 'all';
  const events = (state.logs || []).filter(event => service === 'all' || event.service === service);
  container.innerHTML = events.length ? events.map(event => `<article class="log-entry ${esc(event.level)}"><time datetime="${esc(event.timestamp)}">${esc(new Date(event.timestamp).toLocaleString())}</time><span>${statusSymbol(event.level === 'error' ? 'critical' : event.level === 'warning' ? 'warning' : 'healthy', event.level)}</span><strong>${esc(event.service)}</strong><div><h3>${esc(event.message)}</h3>${event.detail ? `<p>${esc(event.detail)}</p>` : ''}</div></article>`).join('') : '<div class="clear">No diagnostic changes have been recorded for this service during the current DomainPosture session.</div>';
}

async function loadSystemLogs() {
  try {
    const response = await fetch('/api/system-logs', { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Unable to load diagnostics');
    state.logs = data.events || [];
  } catch (error) {
    state.logs = [{ timestamp: new Date().toISOString(), service: 'domainposture', level: 'error', message: 'Diagnostic log unavailable', detail: error.message }];
  }
  renderSystemLogs();
}

function renderServiceLogs() {
  const container = $('#service-log');
  if (!container) return;
  const data = state.serviceLogs;
  if (!data) return;
  if (!data.available) {
    container.innerHTML = `<div class="clear">${esc(data.reason || 'No service log is available.')}</div>`;
    return;
  }
  container.innerHTML = (data.files || []).map(file => `<article class="service-log-file"><div><strong>${esc(file.name)}</strong><span>${file.updated_at ? `Updated ${esc(new Date(file.updated_at).toLocaleString())}` : ''}</span></div><pre>${esc(file.content || 'The log file is empty.')}</pre></article>`).join('');
}

async function loadServiceLogs() {
  const service = $('#service-log-service')?.value || 'domainposture';
  const container = $('#service-log');
  if (container) container.innerHTML = '<div class="clear">Loading service log…</div>';
  try {
    const response = await fetch(`/api/service-logs?service=${encodeURIComponent(service)}`, { cache: 'no-store' });
    state.serviceLogs = await response.json();
    if (!response.ok) throw new Error(state.serviceLogs.error || 'Unable to load the service log');
  } catch (error) {
    state.serviceLogs = { service, available: false, reason: error.message };
  }
  renderServiceLogs();
}

async function loadSystemStatus() {
  try {
    const response = await fetch('/api/system-status', { cache: 'no-store' });
    state.system = await response.json();
    if (!response.ok && !state.system.error) state.system.error = 'System checks could not be completed.';
  } catch (error) {
    state.system = { status: 'critical', checks: [], error: error.message, checked_at: new Date().toISOString() };
  }
  renderSystemStatus();
  await loadSystemLogs();
  await loadServiceLogs();
}

function detail(id) {
  const domain = state.data?.domains[state.selected];
  const check = domain?.checks.find(value => value.id === id);
  if (!check) return;
  const endpoint = tlsEndpoint(check, domain.domain);
  const destination = reportDestination(check);
  $('#detail').innerHTML = `<div class="detail"><span class="state ${check.status}">${names[check.status]}</span><h2>${esc(check.label)}</h2><p class="detail-domain">${esc(domain.domain)}${endpoint ? ` · ${esc(endpoint)}` : ''}</p><p class="summary">${esc(check.summary)}</p><div class="block"><h3>What this means</h3><p>${esc(check.detail)}</p></div><div class="block action"><h3>Next action</h3><p>${esc(check.action)}</p></div><a class="primary-link report-link" href="#${esc(destination.id)}" data-report-target="${esc(destination.id)}">${esc(destination.label)} →</a>${Object.keys(check.evidence || {}).length ? `<div class="block"><h3>Evidence</h3><pre>${esc(JSON.stringify(check.evidence, null, 2))}</pre></div>` : ''}</div>`;
  $('#detail-dialog').showModal();
}

function reportDestination(check) {
  if (check.id === 'dmarc_reports' || check.id === 'dmarc' || check.id === 'spf' || check.id === 'dkim') return { id: 'report-dmarc', label: 'View DMARC reports' };
  if (check.id === 'smtp_service') return { id: 'report-smtp-diagnostics', label: 'View SMTP diagnostics' };
  if (check.id === 'tls_rpt' || check.id === 'mta_sts' || check.id.startsWith('tls_')) return { id: 'report-smtp-tls', label: 'View SMTP TLS reports' };
  return { id: 'report-center', label: 'View domain reports' };
}

async function loadStatus() {
  try {
    const response = await fetch('/api/status', { cache: 'no-store' });
    state.data = await response.json();
    renderStatus();
  } catch (error) {
    $('#domain-scores').innerHTML = `<div class="error">${esc(error.message)}</div>`;
    $('#attention').innerHTML = `<div class="error">${esc(error.message)}</div>`;
  }
}

function renderLookupResults(result) {
  const recordCards = (result.dns || []).map(record => {
    const available = record.status === 'available';
    const value = record.status === 'unavailable' ? record.error : available ? record.values.map(dnsValue).join('\n') : 'No record found';
    return `<article class="lookup-card ${record.status}"><div><strong>${esc(record.type)}</strong><span>${esc(record.queried_name)}</span></div><pre>${esc(value)}</pre></article>`;
  }).join('');
  const tls = result.tls_rpt ? `<article class="lookup-summary-card ${esc(result.tls_rpt.status)}"><div>${statusSymbol(result.tls_rpt.status)}</div><section><small>TLS-RPT validation</small><h2>${esc(result.tls_rpt.summary)}</h2><p>${esc(result.tls_rpt.detail)}</p>${result.tls_rpt.evidence?.record ? `<pre>${esc(result.tls_rpt.evidence.record)}</pre>` : ''}</section></article>` : '';
  const reputation = result.reputation || {};
  const reputationChecks = (reputation.evidence?.checks || []).map(check => `<div class="lookup-reputation-row"><span>${statusSymbol(check.status === 'listed' ? 'warning' : check.status === 'clean' ? 'healthy' : 'info')}</span><strong>${esc(check.provider)}</strong><code>${esc(check.target)}</code><em>${esc(check.status)}</em></div>`).join('');
  const reputationCard = `<article class="lookup-summary-card ${esc(reputation.status || 'info')}"><div>${statusSymbol(reputation.status || 'info')}</div><section><small>Reputation screening</small><h2>${esc(reputation.summary || 'Unavailable')}</h2><p>${esc(reputation.detail || '')}</p>${reputationChecks ? `<div class="lookup-reputation">${reputationChecks}</div>` : ''}</section></article>`;
  $('#lookup-results').innerHTML = `<div class="lookup-result-heading"><div><small>Lookup result</small><h2>${esc(result.target)}</h2></div><span>${result.cached ? 'Cached result' : result.shared ? 'Shared active lookup' : `Checked ${new Date(result.checked_at).toLocaleString()}`}</span></div><div class="lookup-summary-grid">${tls}${reputationCard}</div><div class="lookup-record-grid">${recordCards}</div>`;
}

async function runLookup(event) {
  event.preventDefault();
  const button = $('#lookup-form button[type="submit"]');
  const message = $('#lookup-message');
  button.disabled = true;
  button.textContent = 'Looking up…';
  message.textContent = 'Querying DNS and available reputation providers…';
  $('#lookup-results').innerHTML = '<div class="clear">Running lookup…</div>';
  try {
    const response = await fetch('/api/tools/lookup', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ target: $('#lookup-target').value.trim() }) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to complete the lookup.');
    renderLookupResults(result);
    message.textContent = result.cached ? 'A recent cached result is shown.' : 'Lookup complete. An unavailable provider is not treated as a clean result.';
  } catch (error) {
    $('#lookup-results').innerHTML = `<div class="error">${esc(error.message)}</div>`;
    message.textContent = 'Lookup failed.';
  } finally {
    button.disabled = false;
    button.textContent = 'Run lookup';
  }
}

function followBackgroundRefresh(previousGeneratedAt, attempt = 0) {
  clearTimeout(state.backgroundRefreshTimer);
  state.backgroundRefreshTimer = setTimeout(async () => {
    await loadStatus();
    if (attempt < 60 && (state.data?.refreshing || state.data?.generated_at === previousGeneratedAt)) followBackgroundRefresh(previousGeneratedAt, attempt + 1);
  }, 1000);
}

function renderSettingsDomains() {
  const settings = state.settings;
  if (!settings) return;
  $('#settings-domain-list').innerHTML = settings.monitored_domains.length ? settings.monitored_domains.map((domain, index) => {
    const selectors = settings.dkim_selectors[domain] || [];
    const endpoints = settings.tls_endpoints[domain] || [];
    const dnsMonitors = settings.dns_monitors?.[domain] || [];
    const dnsMonitoringEnabled = settings.dns_monitoring_enabled?.[domain] === true;
    const smtpProfile = settings.smtp_profiles?.[domain] || { hosting_type: 'auto', provider: 'auto' };
    const sections = { domain_certificates: true, additional_tls: true, smtp: true, dkim: true, mail_security: true, bimi: true, ...(settings.check_sections?.[domain] || {}) };
    const certificate = settings.certificate_checks?.[domain] || { check_public: true, check_origin: false, origin_ip: '' };
    const configured = settings.bimi_exceptions?.[domain] || {};
    const exceptions = [configured.self_asserted || (configured.mode ? configured : null), configured.no_logo].filter(value => value?.mode);
    const controlExceptions = Object.values(settings.control_exceptions?.[domain] || {}).filter(value => value?.mode);
    const active = [...exceptions, ...controlExceptions].filter(value => value.mode === 'permanent' || (value.mode === 'until' && new Date(value.expires_at) > new Date()));
    const exceptionNote = active.length ? ` · ${active.length} review exception${active.length === 1 ? '' : 's'}` : '';
    const detectedProfile = state.data?.domains?.find(item => item.domain === domain)?.mail_profile;
    const mailNote = !sections.smtp ? 'SMTP probes off' : detectedProfile ? mailProfileText(detectedProfile) : `Hosting type: ${hostingLabels[smtpProfile.hosting_type] || 'Automatic'} (${smtpProfile.hosting_type === 'auto' ? 'Auto-detected' : 'Selected'}) · Provider: ${providerLabels[smtpProfile.provider] || 'Automatic'} (${smtpProfile.provider === 'auto' ? 'Auto-detected' : 'Selected'})`;
    const certificateNote = sections.domain_certificates ? `${certificate.check_public ? 'Public certificate' : ''}${certificate.check_public && certificate.check_origin ? ' + ' : ''}${certificate.check_origin ? `Origin certificate (${certificate.origin_ip})` : ''}` : 'Certificate checks off';
    const enabledCount = Object.values(sections).filter(Boolean).length;
    const dnsNote = dnsMonitoringEnabled ? `${dnsMonitors.length} DNS record monitor${dnsMonitors.length === 1 ? '' : 's'}` : `DNS monitoring off${dnsMonitors.length ? ` (${dnsMonitors.length} saved)` : ''}`;
    return `<div class="editable-row"><div><strong>${esc(domain)}</strong><span>${enabledCount} of 6 scored sections enabled · ${esc(mailNote)} · ${esc(certificateNote)} · ${selectors.length} DKIM selector${selectors.length === 1 ? '' : 's'} · ${endpoints.length} additional TLS endpoint${endpoints.length === 1 ? '' : 's'} · ${esc(dnsNote)}${esc(exceptionNote)}</span></div><div class="row-actions"><button class="symbol-button" type="button" data-edit-domain="${index}" aria-label="Edit ${esc(domain)}" title="Edit domain">✎</button><button class="symbol-button danger-symbol" type="button" data-remove-domain="${index}" aria-label="Remove ${esc(domain)}" title="Remove domain">−</button></div></div>`;
  }).join('') : '<div class="empty-list"><p>No domains are configured.</p><button type="button" data-add-domain>Add a domain</button></div>';
}

function renderSecretsKeySettings(settings = state.settings) {
  const key = settings?.secrets_key || {};
  const createButton = $('#create-secrets-key');
  const rotateButton = $('#rotate-secrets-key');
  const status = $('#secrets-key-status');
  status.className = 'settings-note status-line';
  if (key.configured) {
    const source = key.source === 'managed' ? 'DomainPosture' : key.source === 'external' ? 'an external Docker secret' : 'the deployment environment';
    status.innerHTML = `<span class="dot healthy" aria-hidden="true"></span><span>An encryption key is configured and provided by ${source}.</span>`;
    createButton.hidden = true;
    rotateButton.hidden = !key.can_rotate;
  } else {
    status.innerHTML = '<span class="dot critical" aria-hidden="true"></span><span>No encryption key is configured. Create one before saving a Discord webhook or report-mailbox password.</span>';
    createButton.hidden = !key.can_generate;
    rotateButton.hidden = true;
  }
}

function renderDiscordWebhookSettings(settings = state.settings) {
  const source = settings?.notifications?.discord_webhook_source;
  const configured = Boolean(settings?.notifications?.discord_webhook_configured);
  const status = $('#discord-webhook-status');
  const message = source === 'settings'
    ? 'A webhook is saved in DomainPosture.'
    : source === 'environment'
      ? 'A webhook from the deployment environment is active.'
      : 'No Discord webhook is configured.';
  status.innerHTML = `<span class="dot ${configured ? 'healthy' : 'critical'}" aria-hidden="true"></span><span>${message}</span>`;
  $('#discord-webhook-field').hidden = configured && !state.editingDiscordWebhook;
  $('#change-discord-webhook').hidden = !configured || state.editingDiscordWebhook;
  $('#test-discord-webhook').disabled = !configured;
}

async function loadSettings() {
  const response = await fetch('/api/settings', { cache: 'no-store' });
  const settings = await response.json();
  if (!response.ok) throw new Error(settings.error || 'Unable to load settings');
  state.settings = clone(settings);
  renderSecretsKeySettings(settings);
  $('#report-days').value = settings.report_days;
  $('#refresh-minutes').value = settings.refresh_minutes;
  $('#certificate-check-minutes').value = settings.certificate_check_minutes;
  $('#request-timeout').value = settings.request_timeout_ms;
  $('#smtp-probe-cooldown').value = settings.smtp_probe_cooldown_minutes;
  $('#discord-enabled').checked = settings.notifications.discord_enabled;
  $('#ssl-notifications-enabled').checked = settings.notifications.ssl_enabled;
  $('#attention-notifications-enabled').checked = settings.notifications.needs_attention_enabled;
  $('#dns-notifications-enabled').checked = settings.notifications.dns_changes_enabled;
  $('#ssl-warning-threshold').value = settings.notifications.ssl_warning_threshold;
  $('#dns-change-confirmations').value = settings.dns_change_confirmations;
  $('#discord-webhook').value = '';
  state.editingDiscordWebhook = false;
  renderDiscordWebhookSettings(settings);
  $('#smtp-probe-hostname').value = settings.smtp_probe_hostname || '';
  $('#report-source').value = settings.report_source;
  $('#opensearch-url').value = settings.opensearch_url;
  $('#opensearch-username').value = settings.opensearch_username;
  $('#opensearch-verify-tls').checked = settings.opensearch_verify_tls;
  $('#aggregate-index').value = settings.opensearch_aggregate_index;
  $('#failure-index').value = settings.opensearch_failure_index;
  $('#smtp-tls-index').value = settings.opensearch_smtp_tls_index;
  $('#mailbox-enabled').checked = settings.mailbox.enabled;
  $('#imap-host').value = settings.mailbox.host;
  $('#imap-port').value = settings.mailbox.port;
  $('#imap-username').value = settings.mailbox.username;
  $('#imap-password').value = '';
  $('#imap-ssl').checked = settings.mailbox.ssl;
  $('#reports-folder').value = settings.mailbox.reports_folder;
  $('#archive-folder').value = settings.mailbox.archive_folder;
  $('#pm-watch').checked = settings.mailbox.watch;
  $('#imap-password-status').textContent = settings.mailbox.password_set ? 'A password is saved. Leave this blank to keep it.' : 'No password is saved.';
  const pm = settings.parsedmarc;
  $('#pm-save-aggregate').checked = pm.general.save_aggregate;
  $('#pm-save-failure').checked = pm.general.save_failure;
  $('#pm-save-smtp-tls').checked = pm.general.save_smtp_tls;
  $('#pm-strip-attachments').checked = pm.general.strip_attachment_payloads;
  $('#pm-offline').checked = pm.general.offline;
  $('#pm-local-files').checked = pm.general.always_use_local_files;
  $('#pm-silent').checked = pm.general.silent;
  $('#pm-warnings').checked = pm.general.warnings;
  $('#pm-verbose').checked = pm.general.verbose;
  $('#pm-debug').checked = pm.general.debug;
  $('#pm-fail-output').checked = pm.general.fail_on_output_error;
  $('#pm-n-procs').value = pm.general.n_procs;
  $('#pm-dns-timeout').value = pm.general.dns_timeout;
  $('#pm-dns-retries').value = pm.general.dns_retries;
  $('#pm-test').checked = pm.mailbox.test;
  $('#pm-delete').checked = pm.mailbox.delete;
  $('#pm-delete-aggregate').checked = pm.mailbox.delete_aggregate;
  $('#pm-delete-failure').checked = pm.mailbox.delete_failure;
  $('#pm-delete-smtp-tls').checked = pm.mailbox.delete_smtp_tls;
  $('#pm-delete-invalid').checked = pm.mailbox.delete_invalid;
  $('#pm-batch-size').value = pm.mailbox.batch_size;
  $('#pm-check-timeout').value = pm.mailbox.check_timeout;
  $('#pm-max-unsaved').value = pm.mailbox.max_unsaved_retries;
  $('#pm-since').value = pm.mailbox.since;
  $('#pm-imap-skip-verify').checked = pm.imap.skip_certificate_verification;
  $('#pm-imap-timeout').value = pm.imap.timeout;
  $('#pm-imap-max-retries').value = pm.imap.max_retries;
  $('#pm-os-timeout').value = pm.opensearch.timeout;
  $('#pm-monthly-indexes').checked = pm.opensearch.monthly_indexes;
  $('#pm-shards').value = pm.opensearch.number_of_shards;
  $('#pm-replicas').value = pm.opensearch.number_of_replicas;
  $('#snapshots-enabled').checked = settings.snapshots.enabled;
  $('#snapshot-cron').value = settings.snapshots.cron;
  $('#snapshot-delete-cron').value = settings.snapshots.delete_cron;
  $('#snapshot-timezone').value = settings.snapshots.timezone;
  $('#snapshot-retention').value = settings.snapshots.retention_days;
  $('#snapshot-min').value = settings.snapshots.min_count;
  $('#snapshot-max').value = settings.snapshots.max_count;
  setTheme(localStorage.getItem('domainposture-theme') || localStorage.getItem('mailposture-theme') || 'system', false);
  renderSettingsDomains();
  updateSettingsVisibility();
  state.settingsLoaded = true;
}

function updateSettingsVisibility() {
  const source = $('#report-source').value;
  $('#opensearch-fields').hidden = source === 'disabled';
  $('#snapshot-panel').hidden = source !== 'standalone';
  $('#mailbox-fields').hidden = !$('#mailbox-enabled').checked;
  $('#snapshot-fields').hidden = !$('#snapshots-enabled').checked;
  const archive = $('#archive-folder').value.trim() || 'Archive';
  $('#archive-preview').textContent = `${archive}/Aggregate · ${archive}/Failure · ${archive}/Invalid · ${archive}/SMTP-TLS · ${archive}/Unsaved`;
  $('#smtp-tls-folder').textContent = `${archive}/SMTP-TLS`;
}

function selectSettingsTab(name, focus = false) {
  const tabs = [...document.querySelectorAll('[data-settings-tab]')];
  const selected = tabs.find(tab => tab.dataset.settingsTab === name) || tabs[0];
  tabs.forEach(tab => {
    const active = tab === selected;
    tab.setAttribute('aria-selected', String(active));
    tab.tabIndex = active ? 0 : -1;
    $(`#settings-panel-${tab.dataset.settingsTab}`).hidden = !active;
  });
  if (focus) selected.focus();
}

function renderEditorLists() {
  const editor = state.editor;
  $('#selector-list').innerHTML = editor.selectors.length ? editor.selectors.map((selector, index) => `<div class="editable-row small-row"><code>${esc(selector)}</code><div class="row-actions"><button class="symbol-button" type="button" data-edit-selector="${index}" aria-label="Edit selector ${esc(selector)}" title="Edit selector">✎</button><button class="symbol-button danger-symbol" type="button" data-remove-selector="${index}" aria-label="Remove selector ${esc(selector)}" title="Remove selector">−</button></div></div>`).join('') : '<p class="empty-inline">No selectors added.</p>';
  $('#endpoint-list').innerHTML = editor.endpoints.length ? editor.endpoints.map((endpoint, index) => `<div class="editable-row small-row"><code>${esc(endpoint.host)}:${endpoint.port}</code><div class="row-actions"><button class="symbol-button" type="button" data-edit-endpoint="${index}" aria-label="Edit endpoint ${esc(endpoint.host)} port ${endpoint.port}" title="Edit endpoint">✎</button><button class="symbol-button danger-symbol" type="button" data-remove-endpoint="${index}" aria-label="Remove endpoint ${esc(endpoint.host)} port ${endpoint.port}" title="Remove endpoint">−</button></div></div>`).join('') : '<p class="empty-inline">No TLS certificates added.</p>';
  $('#dns-monitor-list').innerHTML = editor.dnsMonitors.length ? editor.dnsMonitors.map((monitor, index) => `<div class="editable-row small-row"><code>${esc(monitor.host)} ${esc(monitor.type)}</code><div class="row-actions"><button class="symbol-button" type="button" data-edit-dns-monitor="${index}" aria-label="Edit ${esc(monitor.host)} ${esc(monitor.type)} monitor" title="Edit DNS monitor">✎</button><button class="symbol-button danger-symbol" type="button" data-remove-dns-monitor="${index}" aria-label="Remove ${esc(monitor.host)} ${esc(monitor.type)} monitor" title="Remove DNS monitor">−</button></div></div>`).join('') : '<p class="empty-inline">No DNS records are monitored.</p>';
}

function openDomainEditor(index = null) {
  const domain = index === null ? '' : state.settings.monitored_domains[index];
  const configured = clone(state.settings.bimi_exceptions?.[domain] || {});
  const exceptions = { self_asserted: configured.self_asserted || (configured.mode ? configured : null), no_logo: configured.no_logo || null };
  const controlExceptions = clone(state.settings.control_exceptions?.[domain] || {});
  const smtpProfile = clone(state.settings.smtp_profiles?.[domain] || { hosting_type: 'auto', provider: 'auto', expected_hostname: '', relay_context: 'auto' });
  const certificateChecks = clone(state.settings.certificate_checks?.[domain] || { check_public: true, check_origin: false, origin_ip: '' });
  const checkSections = clone(state.settings.check_sections?.[domain] || { domain_certificates: true, additional_tls: true, smtp: true, dkim: true, mail_security: true, bimi: true });
  state.editor = {
    index,
    originalDomain: domain,
    selectors: clone(state.settings.dkim_selectors[domain] || []),
    endpoints: clone(state.settings.tls_endpoints[domain] || []),
    dnsMonitors: clone(state.settings.dns_monitors?.[domain] || []),
    certificateChecks,
    checkSections,
    smtpProfile,
    bimiExceptionsOriginal: exceptions,
    bimiExceptionDirty: { self_asserted: false, no_logo: false },
    controlExceptionsOriginal: { mta_sts: controlExceptions.mta_sts || null, tls_certificates: controlExceptions.tls_certificates || null },
    controlExceptionDirty: { mta_sts: false },
    editingSelector: null,
    editingEndpoint: null,
    editingDnsMonitor: null
  };
  $('#domain-editor-title').textContent = index === null ? 'Add domain' : 'Edit domain';
  $('#domain-name').value = domain;
  $('#smtp-hosting-type').value = smtpProfile.hosting_type || 'auto';
  $('#smtp-provider').value = smtpProfile.provider || 'auto';
  $('#smtp-expected-host').value = smtpProfile.expected_hostname || '';
  $('#smtp-relay-context').value = smtpProfile.relay_context || 'auto';
  $('#check-public-certificate').checked = certificateChecks.check_public !== false;
  $('#check-origin-certificate').checked = certificateChecks.check_origin === true;
  $('#section-domain-certificates').checked = checkSections.domain_certificates !== false;
  $('#section-additional-tls').checked = checkSections.additional_tls !== false;
  $('#section-smtp').checked = checkSections.smtp !== false;
  $('#section-dkim').checked = checkSections.dkim !== false;
  $('#section-mail-security').checked = checkSections.mail_security !== false;
  $('#section-bimi').checked = checkSections.bimi !== false;
  $('#origin-ip').value = certificateChecks.origin_ip || '';
  $('#selector-input').value = '';
  $('#selector-add').textContent = '＋';
  $('#endpoint-host').value = '';
  $('#endpoint-port').value = '443';
  $('#endpoint-add').textContent = '＋';
  $('#dns-monitoring-enabled').checked = state.settings.dns_monitoring_enabled?.[domain] === true;
  $('#dns-monitor-host').value = domain;
  $('#dns-monitor-type').value = 'A';
  $('#dns-monitor-add').textContent = '＋';
  setBimiExceptionFields('self_asserted', '#bimi-ignore-mode', '#bimi-ignore-months');
  setBimiExceptionFields('no_logo', '#bimi-no-logo-ignore-mode', '#bimi-no-logo-ignore-months');
  setControlExceptionFields('mta_sts', '#mta-sts-ignore-mode', '#mta-sts-ignore-months');
  $('#domain-message').textContent = '';
  renderEditorLists();
  updateBimiIgnoreVisibility();
  updateControlIgnoreVisibility();
  updateMailHostingFields();
  updateOriginCertificateVisibility();
  updateDomainSectionVisibility();
  updateDnsMonitoringVisibility();
  $('#domain-dialog').showModal();
}

function updateDomainSectionVisibility() {
  const sections = {
    domain_certificates: '#section-domain-certificates',
    additional_tls: '#section-additional-tls',
    smtp: '#section-smtp',
    dkim: '#section-dkim',
    mail_security: '#section-mail-security',
    bimi: '#section-bimi'
  };
  for (const [name, selector] of Object.entries(sections)) {
    const content = document.querySelector(`[data-section-settings="${name}"]`);
    if (content) content.hidden = !$(selector).checked;
  }
}

function updateOriginCertificateVisibility() {
  $('#origin-ip-field').hidden = !$('#check-origin-certificate').checked;
}

function updateDnsMonitoringVisibility() {
  $('#dns-monitoring-settings').hidden = !$('#dns-monitoring-enabled').checked;
}

function updateMailHostingFields() {
  const type = $('#smtp-hosting-type').value;
  $('#smtp-provider').disabled = type === 'no_inbound';
  $('#smtp-expected-host-field').hidden = type === 'no_inbound';
}

function setBimiExceptionFields(kind, modeSelector, monthsSelector) {
  const exception = state.editor.bimiExceptionsOriginal[kind];
  const expiration = exception?.mode === 'until' ? new Date(exception.expires_at) : null;
  const active = exception?.mode === 'permanent' || (expiration instanceof Date && Number.isFinite(expiration.valueOf()) && expiration > new Date());
  $(modeSelector).value = active && exception.mode === 'permanent' ? 'permanent' : active && exception.mode === 'until' ? 'temporary' : 'none';
  $(monthsSelector).value = active && exception?.mode === 'until' ? Math.max(1, Math.ceil((expiration - Date.now()) / 2629800000)) : 6;
}

function updateBimiIgnoreVisibility() {
  for (const item of [{ kind: 'self_asserted', mode: '#bimi-ignore-mode', field: '#bimi-ignore-months-field', note: '#bimi-ignore-expiration' }, { kind: 'no_logo', mode: '#bimi-no-logo-ignore-mode', field: '#bimi-no-logo-ignore-months-field', note: '#bimi-no-logo-ignore-expiration' }]) {
    const temporary = $(item.mode).value === 'temporary'; $(item.field).hidden = !temporary;
    const original = state.editor?.bimiExceptionsOriginal?.[item.kind]; const note = $(item.note);
    if (!temporary) note.textContent = '';
    else if (!state.editor?.bimiExceptionDirty?.[item.kind] && original?.mode === 'until') { const expires = new Date(original.expires_at); note.textContent = expires > new Date() ? `Current exception expires ${expires.toLocaleDateString()}.` : `The previous exception expired ${expires.toLocaleDateString()}. Saving renews it.`; }
    else note.textContent = 'The exception period begins when Settings are saved.';
  }
}

function bimiExceptionFromFields(kind, modeSelector, monthsSelector) {
  const mode = $(modeSelector).value;
  if (mode === 'none') return null;
  if (mode === 'permanent') return { mode: 'permanent' };
  const months = Number($(monthsSelector).value);
  if (!Number.isInteger(months) || months < 1 || months > 120) throw new Error('Enter each BIMI exception period as a number between 1 and 120 months.');
  const original = state.editor.bimiExceptionsOriginal[kind];
  if (!state.editor.bimiExceptionDirty[kind] && original?.mode === 'until') return clone(original);
  const expires = new Date(); expires.setUTCMonth(expires.getUTCMonth() + months); return { mode: 'until', expires_at: expires.toISOString() };
}

function setControlExceptionFields(kind, modeSelector, monthsSelector) {
  const exception = state.editor.controlExceptionsOriginal[kind];
  const expiration = exception?.mode === 'until' ? new Date(exception.expires_at) : null;
  const active = exception?.mode === 'permanent' || (expiration instanceof Date && Number.isFinite(expiration.valueOf()) && expiration > new Date());
  $(modeSelector).value = active && exception.mode === 'permanent' ? 'permanent' : active && exception.mode === 'until' ? 'temporary' : 'none';
  $(monthsSelector).value = active && exception?.mode === 'until' ? Math.max(1, Math.ceil((expiration - Date.now()) / 2629800000)) : 6;
}

function updateControlIgnoreVisibility() {
  for (const item of [{ kind: 'mta_sts', mode: '#mta-sts-ignore-mode', field: '#mta-sts-ignore-months-field', note: '#mta-sts-ignore-expiration' }]) {
    const temporary = $(item.mode).value === 'temporary'; $(item.field).hidden = !temporary;
    const original = state.editor?.controlExceptionsOriginal?.[item.kind]; const note = $(item.note);
    if (!temporary) note.textContent = '';
    else if (!state.editor?.controlExceptionDirty?.[item.kind] && original?.mode === 'until') { const expires = new Date(original.expires_at); note.textContent = expires > new Date() ? `Current exception expires ${expires.toLocaleDateString()}.` : `The previous exception expired ${expires.toLocaleDateString()}. Saving renews it.`; }
    else note.textContent = 'The exception period begins when Settings are saved.';
  }
}

function controlExceptionFromFields(kind, modeSelector, monthsSelector) {
  const mode = $(modeSelector).value;
  if (mode === 'none') return null;
  if (mode === 'permanent') return { mode: 'permanent' };
  const months = Number($(monthsSelector).value);
  if (!Number.isInteger(months) || months < 1 || months > 120) throw new Error('Enter each mail-security exception period as a number between 1 and 120 months.');
  const original = state.editor.controlExceptionsOriginal[kind];
  if (!state.editor.controlExceptionDirty[kind] && original?.mode === 'until') return clone(original);
  const expires = new Date(); expires.setUTCMonth(expires.getUTCMonth() + months); return { mode: 'until', expires_at: expires.toISOString() };
}

function addSelector() {
  const selector = $('#selector-input').value.trim();
  if (!/^[a-z0-9_-]{1,63}$/i.test(selector)) return showDomainError('Enter a valid selector using letters, numbers, hyphens, or underscores.');
  const duplicate = state.editor.selectors.findIndex((value, index) => value.toLowerCase() === selector.toLowerCase() && index !== state.editor.editingSelector);
  if (duplicate >= 0) return showDomainError('That selector is already listed.');
  if (state.editor.editingSelector === null) state.editor.selectors.push(selector);
  else state.editor.selectors[state.editor.editingSelector] = selector;
  state.editor.editingSelector = null;
  $('#selector-input').value = '';
  $('#selector-add').textContent = '＋';
  showDomainError('');
  renderEditorLists();
}

function addEndpoint() {
  const host = $('#endpoint-host').value.trim().toLowerCase().replace(/\.$/, '');
  const port = Number($('#endpoint-port').value);
  if (!/^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(host)) return showDomainError('Enter a valid TLS host name.');
  if (!Number.isInteger(port) || port < 1 || port > 65535) return showDomainError('Enter a TLS port between 1 and 65535.');
  const duplicate = state.editor.endpoints.findIndex((value, index) => value.host === host && value.port === port && index !== state.editor.editingEndpoint);
  if (duplicate >= 0) return showDomainError('That TLS endpoint is already listed.');
  const endpoint = { host, port };
  if (state.editor.editingEndpoint === null) state.editor.endpoints.push(endpoint);
  else state.editor.endpoints[state.editor.editingEndpoint] = endpoint;
  state.editor.editingEndpoint = null;
  $('#endpoint-host').value = '';
  $('#endpoint-port').value = '443';
  $('#endpoint-add').textContent = '＋';
  showDomainError('');
  renderEditorLists();
}

function addDnsMonitor() {
  const host = $('#dns-monitor-host').value.trim().toLowerCase().replace(/\.$/, '');
  const type = $('#dns-monitor-type').value;
  if (!/^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(host)) return showDomainError('Enter a valid fully qualified host name for DNS monitoring.');
  if (state.editor.dnsMonitors.length >= 20 && state.editor.editingDnsMonitor === null) return showDomainError('DNS monitoring is limited to 20 records per domain.');
  const duplicate = state.editor.dnsMonitors.findIndex((value, index) => value.host === host && value.type === type && index !== state.editor.editingDnsMonitor);
  if (duplicate >= 0) return showDomainError('That DNS record is already monitored.');
  const monitor = { host, type };
  if (state.editor.editingDnsMonitor === null) state.editor.dnsMonitors.push(monitor);
  else state.editor.dnsMonitors[state.editor.editingDnsMonitor] = monitor;
  state.editor.editingDnsMonitor = null;
  $('#dns-monitor-host').value = '';
  $('#dns-monitor-type').value = 'A';
  $('#dns-monitor-add').textContent = '＋';
  showDomainError('');
  renderEditorLists();
}

function showDomainError(message) { $('#domain-message').textContent = message; }

function saveDomain(event) {
  event.preventDefault();
  const domain = $('#domain-name').value.trim().toLowerCase().replace(/\.$/, '');
  const valid = /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(domain);
  if (!valid) return showDomainError('Enter a valid domain name.');
  const duplicate = state.settings.monitored_domains.findIndex((value, index) => value === domain && index !== state.editor.index);
  if (duplicate >= 0) return showDomainError('That domain is already monitored.');
  const checkPublic = $('#check-public-certificate').checked;
  const checkOrigin = $('#check-origin-certificate').checked;
  const checkSections = {
    domain_certificates: $('#section-domain-certificates').checked,
    additional_tls: $('#section-additional-tls').checked,
    smtp: $('#section-smtp').checked,
    dkim: $('#section-dkim').checked,
    mail_security: $('#section-mail-security').checked,
    bimi: $('#section-bimi').checked
  };
  if (!Object.values(checkSections).some(Boolean)) return showDomainError('Enable at least one check section for this domain.');
  const originIp = $('#origin-ip').value.trim();
  if (checkSections.domain_certificates && !checkPublic && !checkOrigin) return showDomainError('Enable at least one certificate check, or switch off Domain certificates.');
  const looksLikeIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(originIp) && originIp.split('.').every(part => Number(part) <= 255);
  const looksLikeIpv6 = /^[0-9a-f:]+$/i.test(originIp) && originIp.includes(':');
  if (checkSections.domain_certificates && checkOrigin && !looksLikeIpv4 && !looksLikeIpv6) return showDomainError('Enter a valid origin IPv4 or IPv6 address.');
  if ($('#dns-monitoring-enabled').checked && !state.editor.dnsMonitors.length) return showDomainError('Add at least one DNS record to monitor, or switch off DNS change monitoring.');
  const expectedHostname = $('#smtp-expected-host').value.trim().toLowerCase().replace(/\.$/, '');
  if (expectedHostname && !/^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(expectedHostname)) return showDomainError('Enter a valid expected SMTP hostname or leave it blank.');
  let selfAssertedException; let noLogoException; let mtaStsException;
  try {
    selfAssertedException = bimiExceptionFromFields('self_asserted', '#bimi-ignore-mode', '#bimi-ignore-months');
    noLogoException = bimiExceptionFromFields('no_logo', '#bimi-no-logo-ignore-mode', '#bimi-no-logo-ignore-months');
    mtaStsException = controlExceptionFromFields('mta_sts', '#mta-sts-ignore-mode', '#mta-sts-ignore-months');
  }
  catch (error) { return showDomainError(error.message); }
  const oldDomain = state.editor.originalDomain;
  if (state.editor.index === null) state.settings.monitored_domains.push(domain);
  else state.settings.monitored_domains[state.editor.index] = domain;
  if (oldDomain && oldDomain !== domain) {
    delete state.settings.dkim_selectors[oldDomain];
    delete state.settings.tls_endpoints[oldDomain];
    if (state.settings.certificate_checks) delete state.settings.certificate_checks[oldDomain];
    if (state.settings.check_sections) delete state.settings.check_sections[oldDomain];
    if (state.settings.smtp_profiles) delete state.settings.smtp_profiles[oldDomain];
    if (state.settings.bimi_exceptions) delete state.settings.bimi_exceptions[oldDomain];
    if (state.settings.control_exceptions) delete state.settings.control_exceptions[oldDomain];
    if (state.settings.dns_monitoring_enabled) delete state.settings.dns_monitoring_enabled[oldDomain];
    if (state.settings.dns_monitors) delete state.settings.dns_monitors[oldDomain];
  }
  state.settings.dkim_selectors[domain] = clone(state.editor.selectors);
  state.settings.tls_endpoints[domain] = clone(state.editor.endpoints);
  state.settings.certificate_checks ||= {};
  state.settings.certificate_checks[domain] = { check_public: checkPublic, check_origin: checkOrigin, origin_ip: checkOrigin ? originIp : '' };
  state.settings.check_sections ||= {};
  state.settings.check_sections[domain] = checkSections;
  state.settings.smtp_profiles ||= {};
  state.settings.smtp_profiles[domain] = { hosting_type: $('#smtp-hosting-type').value, provider: $('#smtp-provider').disabled ? 'auto' : $('#smtp-provider').value, expected_hostname: expectedHostname, relay_context: $('#smtp-relay-context').value };
  state.settings.bimi_exceptions ||= {};
  if (selfAssertedException || noLogoException) state.settings.bimi_exceptions[domain] = { ...(selfAssertedException ? { self_asserted: selfAssertedException } : {}), ...(noLogoException ? { no_logo: noLogoException } : {}) };
  else delete state.settings.bimi_exceptions[domain];
  state.settings.control_exceptions ||= {};
  const legacyTlsCertificateException = state.editor.controlExceptionsOriginal.tls_certificates;
  if (mtaStsException || legacyTlsCertificateException) state.settings.control_exceptions[domain] = { ...(mtaStsException ? { mta_sts: mtaStsException } : {}), ...(legacyTlsCertificateException ? { tls_certificates: legacyTlsCertificateException } : {}) };
  else delete state.settings.control_exceptions[domain];
  state.settings.dns_monitoring_enabled ||= {};
  state.settings.dns_monitoring_enabled[domain] = $('#dns-monitoring-enabled').checked;
  state.settings.dns_monitors ||= {};
  state.settings.dns_monitors[domain] = clone(state.editor.dnsMonitors);
  $('#domain-dialog').close();
  renderSettingsDomains();
  $('#settings-message').textContent = 'Domain changes are ready. Save settings to apply them.';
  $('#settings-message').className = 'pending';
}

async function saveSettings(event) {
  event.preventDefault();
  const button = $('#settings-form button[type="submit"]');
  const message = $('#settings-message');
  if (!state.settings?.monitored_domains.length) { message.textContent = 'Add at least one monitored domain.'; message.className = 'failure'; return; }
  button.disabled = true;
  button.textContent = 'Saving…';
  message.className = '';
  const previousGeneratedAt = state.data?.generated_at || null;
  try {
    const body = {
      ...state.settings,
      report_days: Number($('#report-days').value),
      refresh_minutes: Number($('#refresh-minutes').value),
      certificate_check_minutes: Number($('#certificate-check-minutes').value),
      request_timeout_ms: Number($('#request-timeout').value),
      smtp_probe_cooldown_minutes: Number($('#smtp-probe-cooldown').value),
      dns_change_confirmations: Number($('#dns-change-confirmations').value),
      notifications: {
        discord_enabled: $('#discord-enabled').checked,
        ssl_enabled: $('#ssl-notifications-enabled').checked,
        needs_attention_enabled: $('#attention-notifications-enabled').checked,
        dns_changes_enabled: $('#dns-notifications-enabled').checked,
        ssl_warning_threshold: Number($('#ssl-warning-threshold').value),
        discord_webhook: $('#discord-webhook').value.trim()
      },
      smtp_probe_hostname: $('#smtp-probe-hostname').value.trim(),
      report_source: $('#report-source').value,
      opensearch_url: $('#opensearch-url').value.trim(),
      opensearch_username: $('#opensearch-username').value.trim(),
      opensearch_verify_tls: $('#opensearch-verify-tls').checked,
      opensearch_aggregate_index: $('#aggregate-index').value.trim(),
      opensearch_failure_index: $('#failure-index').value.trim(),
      opensearch_smtp_tls_index: $('#smtp-tls-index').value.trim(),
      mailbox: {
        ...state.settings.mailbox,
        enabled: $('#mailbox-enabled').checked,
        host: $('#imap-host').value.trim(),
        port: Number($('#imap-port').value),
        username: $('#imap-username').value.trim(),
        password: $('#imap-password').value,
        ssl: $('#imap-ssl').checked,
        reports_folder: $('#reports-folder').value.trim(),
        archive_folder: $('#archive-folder').value.trim(),
        watch: $('#pm-watch').checked
      },
      parsedmarc: {
        general: {
          save_aggregate: $('#pm-save-aggregate').checked,
          save_failure: $('#pm-save-failure').checked,
          save_smtp_tls: $('#pm-save-smtp-tls').checked,
          strip_attachment_payloads: $('#pm-strip-attachments').checked,
          offline: $('#pm-offline').checked,
          always_use_local_files: $('#pm-local-files').checked,
          silent: $('#pm-silent').checked,
          warnings: $('#pm-warnings').checked,
          verbose: $('#pm-verbose').checked,
          debug: $('#pm-debug').checked,
          fail_on_output_error: $('#pm-fail-output').checked,
          n_procs: Number($('#pm-n-procs').value),
          dns_timeout: Number($('#pm-dns-timeout').value),
          dns_retries: Number($('#pm-dns-retries').value)
        },
        mailbox: {
          test: $('#pm-test').checked,
          delete: $('#pm-delete').checked,
          delete_aggregate: $('#pm-delete-aggregate').checked,
          delete_failure: $('#pm-delete-failure').checked,
          delete_smtp_tls: $('#pm-delete-smtp-tls').checked,
          delete_invalid: $('#pm-delete-invalid').checked,
          batch_size: Number($('#pm-batch-size').value),
          check_timeout: Number($('#pm-check-timeout').value),
          max_unsaved_retries: Number($('#pm-max-unsaved').value),
          since: $('#pm-since').value.trim()
        },
        imap: {
          skip_certificate_verification: $('#pm-imap-skip-verify').checked,
          timeout: Number($('#pm-imap-timeout').value),
          max_retries: Number($('#pm-imap-max-retries').value)
        },
        opensearch: {
          timeout: Number($('#pm-os-timeout').value),
          monthly_indexes: $('#pm-monthly-indexes').checked,
          number_of_shards: Number($('#pm-shards').value),
          number_of_replicas: Number($('#pm-replicas').value)
        }
      },
      snapshots: {
        enabled: $('#snapshots-enabled').checked,
        cron: $('#snapshot-cron').value.trim(),
        delete_cron: $('#snapshot-delete-cron').value.trim(),
        timezone: $('#snapshot-timezone').value.trim(),
        retention_days: Number($('#snapshot-retention').value),
        min_count: Number($('#snapshot-min').value),
        max_count: Number($('#snapshot-max').value)
      }
    };
    const response = await fetch('/api/settings', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to save settings');
    state.settings = clone(result);
    renderSecretsKeySettings(result);
    $('#discord-webhook').value = '';
    state.editingDiscordWebhook = false;
    renderDiscordWebhookSettings(result);
    $('#imap-password').value = '';
    $('#imap-password-status').textContent = result.mailbox.password_set ? 'A password is saved. Leave this blank to keep it.' : 'No password is saved.';
    const savedMessage = result.snapshot_notice || (result.parsedmarc_reload_automatic
      ? `Settings saved. parsedmarc will reload the active configuration within ${result.parsedmarc_reload_seconds} seconds.`
      : result.report_source === 'external'
        ? 'Settings saved and parsedmarc configuration written. Restart the external parsedmarc service to apply it.'
        : 'Settings saved. Historical report collection is disabled.');
    message.textContent = `${savedMessage} Monitoring checks are refreshing in the background.`;
    message.className = result.snapshot_notice ? 'pending' : 'success';
    renderSettingsDomains();
    followBackgroundRefresh(previousGeneratedAt);
  } catch (error) {
    message.textContent = error.message;
    message.className = 'failure';
  } finally {
    button.disabled = false;
    button.textContent = 'Save settings';
  }
}

function normalizedRoute(pathname) {
  return ['/', '/domains', '/tools', '/status', '/settings', '/help'].includes(pathname) ? pathname : '/';
}

async function showRoute(pathname, push = false) {
  const route = normalizedRoute(pathname);
  state.route = route;
  $('#domain-menu-list').hidden = true;
  $('#domain-menu-button').setAttribute('aria-expanded', 'false');
  document.title = `${{ '/': 'Dashboard', '/domains': 'Domains', '/tools': 'Lookup Center', '/status': 'System Status', '/settings': 'Settings', '/help': 'Help' }[route]} · DomainPosture`;
  if (push) history.pushState({}, '', route);
  const viewByRoute = { '/': '#dashboard-view', '/domains': '#domains-view', '/tools': '#tools-view', '/status': '#system-status-view', '/settings': '#settings-view', '/help': '#help-view' };
  Object.values(viewByRoute).forEach(selector => { $(selector).hidden = selector !== viewByRoute[route]; });
  const quiet = ['/tools', '/settings', '/help'].includes(route);
  $('#refresh').hidden = quiet;
  $('#updated').hidden = quiet;
  document.querySelectorAll('[data-route]').forEach(link => {
    const active = link.getAttribute('href') === route;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
  });
  $('#domain-menu-button').classList.toggle('active', route === '/domains');
  if (route === '/settings' && !state.settingsLoaded) {
    try { await loadSettings(); } catch (error) { $('#settings-message').textContent = error.message; $('#settings-message').className = 'failure'; }
  }
  if (route === '/') renderDashboard();
  if (route === '/domains') renderDomain();
  if (route === '/status') await loadSystemStatus();
}

$('#refresh').onclick = async () => {
  const button = $('#refresh');
  const label = button.querySelector('.toolbar-label');
  button.disabled = true;
  label.textContent = 'Checking…';
  try {
    state.data = await fetch('/api/refresh', { method: 'POST' }).then(response => response.json());
    renderStatus();
    await loadSystemStatus();
  } finally {
    button.disabled = false;
    label.textContent = 'Run checks';
  }
};

$('#settings-form').addEventListener('submit', saveSettings);
$('#domain-form').addEventListener('submit', saveDomain);
$('#lookup-form').addEventListener('submit', runLookup);
document.querySelectorAll('input[type="checkbox"]').forEach(input => input.setAttribute('role', 'switch'));
function showSecretsRecoveryKey(result, rotated = false) {
  state.settings.secrets_key = { configured: true, source: result.source, can_generate: false, can_rotate: result.source === 'managed' };
  renderSecretsKeySettings();
  $('#secrets-key-kicker').textContent = rotated ? 'Rotated recovery key' : 'One-time recovery key';
  $('#secrets-key-title').textContent = rotated ? 'Save the new key now' : 'Save this key now';
  $('#secrets-key-description').textContent = rotated
    ? 'Your saved settings remain available and now use this new key. This key will not be shown again. Save it in 1Password or another secure password manager. Keep the previous key only while you still need to restore backups encrypted with it.'
    : 'This key will not be shown again. Save it in 1Password or another secure password manager. You will need it to recover encrypted settings from a backup.';
  $('#generated-secrets-key').value = result.key;
  $('#copy-secrets-key-status').textContent = '';
  $('#secrets-key-dialog').showModal();
  $('#copy-secrets-key').focus();
}
$('#create-secrets-key').onclick = async () => {
  const button = $('#create-secrets-key');
  button.disabled = true;
  button.textContent = 'Creating…';
  try {
    const response = await fetch('/api/secrets-key', { method: 'POST' });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to create the encryption key.');
    showSecretsRecoveryKey(result);
  } catch (error) {
    $('#secrets-key-status').innerHTML = `<span class="dot critical" aria-hidden="true"></span><span>${esc(error.message)}</span>`;
    $('#secrets-key-status').className = 'settings-note status-line failure';
  } finally {
    button.disabled = false;
    button.textContent = 'Create encryption key';
  }
};
$('#rotate-secrets-key').onclick = async () => {
  if (!confirm('Rotate the DomainPosture encryption key now? Saved passwords and webhooks will be re-encrypted and preserved. Save the new recovery key when it appears.')) return;
  const button = $('#rotate-secrets-key');
  button.disabled = true;
  button.textContent = 'Rotating…';
  try {
    const response = await fetch('/api/secrets-key/rotate', { method: 'POST' });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to rotate the encryption key.');
    showSecretsRecoveryKey(result, true);
  } catch (error) {
    $('#secrets-key-status').innerHTML = `<span class="dot critical" aria-hidden="true"></span><span>${esc(error.message)}</span>`;
    $('#secrets-key-status').className = 'settings-note status-line failure';
  } finally {
    button.disabled = false;
    button.textContent = 'Rotate encryption key';
  }
};
$('#change-discord-webhook').onclick = () => {
  state.editingDiscordWebhook = true;
  renderDiscordWebhookSettings();
  $('#discord-webhook').focus();
};
$('#test-discord-webhook').onclick = async () => {
  const button = $('#test-discord-webhook');
  button.disabled = true;
  button.textContent = 'Sending…';
  try {
    const response = await fetch('/api/notifications/discord/test', { method: 'POST' });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to send the test notification.');
    $('#discord-webhook-status').innerHTML = '<span class="dot healthy" aria-hidden="true"></span><span>A webhook is configured. Test notification sent.</span>';
  } catch (error) {
    $('#discord-webhook-status').innerHTML = `<span class="dot critical" aria-hidden="true"></span><span>${esc(error.message)}</span>`;
  } finally {
    button.textContent = 'Test notification';
    button.disabled = !state.settings?.notifications?.discord_webhook_configured;
  }
};
$('#copy-secrets-key').onclick = async () => {
  const field = $('#generated-secrets-key');
  try {
    await navigator.clipboard.writeText(field.value);
    $('#copy-secrets-key-status').textContent = 'Key copied. Save it in your password manager before continuing.';
  } catch (_) {
    field.select();
    $('#copy-secrets-key-status').textContent = 'Copy was unavailable. The key is selected so you can copy it manually.';
  }
};
$('#close-secrets-key').onclick = () => {
  $('#secrets-key-dialog').close();
  $('#generated-secrets-key').value = '';
  $('#copy-secrets-key-status').textContent = '';
};
$('#secrets-key-dialog').addEventListener('cancel', event => {
  event.preventDefault();
  $('#copy-secrets-key-status').textContent = 'Save the key, then choose “I saved it securely.”';
});
$('#add-domain').onclick = () => openDomainEditor();
$('#selector-add').onclick = addSelector;
$('#endpoint-add').onclick = addEndpoint;
$('#dns-monitor-add').onclick = addDnsMonitor;
document.querySelectorAll('.domain-cancel').forEach(button => { button.onclick = () => $('#domain-dialog').close(); });
document.querySelectorAll('input[name="theme"]').forEach(input => { input.onchange = () => setTheme(input.value); });
document.querySelectorAll('input[name="domain-sort"]').forEach(input => { input.onchange = () => setDomainSort(input.value); });
$('#domain-menu-button').onclick = event => {
  event.stopPropagation();
  const menu = $('#domain-menu-list');
  const opening = menu.hidden;
  menu.hidden = !opening;
  $('#domain-menu-button').setAttribute('aria-expanded', String(opening));
  if (opening) menu.querySelector('[aria-current="true"],button,a')?.focus();
};
$('#report-source').onchange = updateSettingsVisibility;
$('#mailbox-enabled').onchange = updateSettingsVisibility;
$('#snapshots-enabled').onchange = updateSettingsVisibility;
$('#check-origin-certificate').onchange = updateOriginCertificateVisibility;
$('#dns-monitoring-enabled').onchange = updateDnsMonitoringVisibility;
['#section-domain-certificates', '#section-additional-tls', '#section-smtp', '#section-dkim', '#section-mail-security', '#section-bimi'].forEach(selector => {
  $(selector).onchange = updateDomainSectionVisibility;
});
$('#archive-folder').oninput = updateSettingsVisibility;
$('#bimi-ignore-mode').onchange = () => { state.editor.bimiExceptionDirty.self_asserted = true; updateBimiIgnoreVisibility(); };
$('#bimi-ignore-months').oninput = () => { state.editor.bimiExceptionDirty.self_asserted = true; updateBimiIgnoreVisibility(); };
$('#bimi-no-logo-ignore-mode').onchange = () => { state.editor.bimiExceptionDirty.no_logo = true; updateBimiIgnoreVisibility(); };
$('#bimi-no-logo-ignore-months').oninput = () => { state.editor.bimiExceptionDirty.no_logo = true; updateBimiIgnoreVisibility(); };
$('#mta-sts-ignore-mode').onchange = () => { state.editor.controlExceptionDirty.mta_sts = true; updateControlIgnoreVisibility(); };
$('#mta-sts-ignore-months').oninput = () => { state.editor.controlExceptionDirty.mta_sts = true; updateControlIgnoreVisibility(); };
$('#smtp-hosting-type').onchange = updateMailHostingFields;
$('#log-service').onchange = renderSystemLogs;
$('#service-log-service').onchange = loadServiceLogs;
$('#refresh-service-log').onclick = loadServiceLogs;
$('#pm-delete').onchange = event => {
  ['#pm-delete-aggregate', '#pm-delete-failure', '#pm-delete-smtp-tls', '#pm-delete-invalid'].forEach(selector => { $(selector).checked = event.target.checked; });
};
document.querySelectorAll('[data-settings-tab]').forEach(tab => {
  tab.onclick = () => selectSettingsTab(tab.dataset.settingsTab);
  tab.onkeydown = event => {
    const tabs = [...document.querySelectorAll('[data-settings-tab]')];
    const current = tabs.indexOf(tab);
    let next = null;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (current + 1) % tabs.length;
    if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (current - 1 + tabs.length) % tabs.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = tabs.length - 1;
    if (next !== null) { event.preventDefault(); selectSettingsTab(tabs[next].dataset.settingsTab, true); }
  };
});
themeQuery.addEventListener?.('change', () => { if ((localStorage.getItem('domainposture-theme') || localStorage.getItem('mailposture-theme') || 'system') === 'system') setTheme('system', false); });

document.onclick = async event => {
  if (!event.target.closest('.domain-menu')) {
    $('#domain-menu-list').hidden = true;
    $('#domain-menu-button').setAttribute('aria-expanded', 'false');
  }
  const route = event.target.closest('[data-route]');
  if (route) { event.preventDefault(); showRoute(route.getAttribute('href'), true); return; }
  const systemSettings = event.target.closest('[data-system-settings]');
  if (systemSettings) { showRoute('/settings', true).then(() => selectSettingsTab(systemSettings.dataset.systemSettings)); return; }
  const reportLink = event.target.closest('[data-report-target]');
  if (reportLink) {
    event.preventDefault();
    const targetId = reportLink.dataset.reportTarget;
    $('#detail-dialog').close();
    requestAnimationFrame(() => {
      const target = document.getElementById(targetId) || $('#report-center');
      target?.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
      target?.focus({ preventScroll: true });
    });
    return;
  }
  const openDomain = event.target.closest('[data-open-domain]');
  if (openDomain) { state.selected = Number(openDomain.dataset.openDomain); showRoute('/domains', true); return; }
  const menuDomain = event.target.closest('[data-menu-domain]');
  if (menuDomain) {
    state.selected = Number(menuDomain.dataset.menuDomain);
    $('#domain-menu-list').hidden = true;
    $('#domain-menu-button').setAttribute('aria-expanded', 'false');
    showRoute('/domains', true);
    return;
  }
  const domain = event.target.closest('[data-domain]');
  if (domain) { state.selected = Number(domain.dataset.domain); renderDomain(); return; }
  const dashboardCheck = event.target.closest('[data-dashboard-check]');
  if (dashboardCheck) { state.selected = Number(dashboardCheck.dataset.domainIndex); detail(dashboardCheck.dataset.dashboardCheck); return; }
  const checkNow = event.target.closest('[data-check-now]');
  if (checkNow) {
    const original = checkNow.textContent;
    checkNow.disabled = true;
    checkNow.textContent = 'Checking…';
    try {
      const response = await fetch(`/api/domains/${encodeURIComponent(checkNow.dataset.checkNow)}/check`, { method: 'POST' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Unable to check this domain.');
      state.data = data;
      renderStatus();
      await loadSystemStatus();
    } catch (error) {
      window.alert(error.message);
    } finally {
      checkNow.disabled = false;
      checkNow.textContent = original;
    }
    return;
  }
  const check = event.target.closest('[data-check]');
  if (check) { detail(check.dataset.check); return; }
  if (event.target.closest('[data-add-domain]')) { openDomainEditor(); return; }
  const editDomain = event.target.closest('[data-edit-domain]');
  if (editDomain) { openDomainEditor(Number(editDomain.dataset.editDomain)); return; }
  const removeDomain = event.target.closest('[data-remove-domain]');
  if (removeDomain) {
    const index = Number(removeDomain.dataset.removeDomain);
    const removed = state.settings.monitored_domains.splice(index, 1)[0];
    delete state.settings.dkim_selectors[removed];
    delete state.settings.tls_endpoints[removed];
    if (state.settings.smtp_profiles) delete state.settings.smtp_profiles[removed];
    if (state.settings.certificate_checks) delete state.settings.certificate_checks[removed];
    if (state.settings.check_sections) delete state.settings.check_sections[removed];
    if (state.settings.bimi_exceptions) delete state.settings.bimi_exceptions[removed];
    if (state.settings.control_exceptions) delete state.settings.control_exceptions[removed];
    if (state.settings.dns_monitoring_enabled) delete state.settings.dns_monitoring_enabled[removed];
    if (state.settings.dns_monitors) delete state.settings.dns_monitors[removed];
    renderSettingsDomains();
    $('#settings-message').textContent = `${removed} was removed. Save settings to apply this change.`;
    $('#settings-message').className = 'pending';
    return;
  }
  const editSelector = event.target.closest('[data-edit-selector]');
  if (editSelector) {
    const index = Number(editSelector.dataset.editSelector);
    state.editor.editingSelector = index;
    $('#selector-input').value = state.editor.selectors[index];
    $('#selector-input').focus();
    $('#selector-add').textContent = '✓';
    return;
  }
  const removeSelector = event.target.closest('[data-remove-selector]');
  if (removeSelector) { state.editor.selectors.splice(Number(removeSelector.dataset.removeSelector), 1); state.editor.editingSelector = null; $('#selector-input').value = ''; $('#selector-add').textContent = '＋'; renderEditorLists(); return; }
  const editEndpoint = event.target.closest('[data-edit-endpoint]');
  if (editEndpoint) {
    const index = Number(editEndpoint.dataset.editEndpoint);
    const endpoint = state.editor.endpoints[index];
    state.editor.editingEndpoint = index;
    $('#endpoint-host').value = endpoint.host;
    $('#endpoint-port').value = endpoint.port;
    $('#endpoint-host').focus();
    $('#endpoint-add').textContent = '✓';
    return;
  }
  const removeEndpoint = event.target.closest('[data-remove-endpoint]');
  if (removeEndpoint) { state.editor.endpoints.splice(Number(removeEndpoint.dataset.removeEndpoint), 1); state.editor.editingEndpoint = null; $('#endpoint-host').value = ''; $('#endpoint-port').value = '443'; $('#endpoint-add').textContent = '＋'; renderEditorLists(); return; }
  const editDnsMonitor = event.target.closest('[data-edit-dns-monitor]');
  if (editDnsMonitor) {
    const index = Number(editDnsMonitor.dataset.editDnsMonitor);
    const monitor = state.editor.dnsMonitors[index];
    state.editor.editingDnsMonitor = index;
    $('#dns-monitor-host').value = monitor.host;
    $('#dns-monitor-type').value = monitor.type;
    $('#dns-monitor-host').focus();
    $('#dns-monitor-add').textContent = '✓';
    return;
  }
  const removeDnsMonitor = event.target.closest('[data-remove-dns-monitor]');
  if (removeDnsMonitor) { state.editor.dnsMonitors.splice(Number(removeDnsMonitor.dataset.removeDnsMonitor), 1); state.editor.editingDnsMonitor = null; $('#dns-monitor-host').value = ''; $('#dns-monitor-type').value = 'A'; $('#dns-monitor-add').textContent = '＋'; renderEditorLists(); }
};

window.onpopstate = () => showRoute(location.pathname);
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && !$('#domain-menu-list').hidden) {
    $('#domain-menu-list').hidden = true;
    $('#domain-menu-button').setAttribute('aria-expanded', 'false');
    $('#domain-menu-button').focus();
  }
});
$('#detail-dialog .close').onclick = () => $('#detail-dialog').close();
$('#detail-dialog').onclick = event => { if (event.target === $('#detail-dialog')) $('#detail-dialog').close(); };
$('#domain-dialog').onclick = event => { if (event.target === $('#domain-dialog')) $('#domain-dialog').close(); };
$('#selector-input').onkeydown = event => { if (event.key === 'Enter') { event.preventDefault(); addSelector(); } };
$('#endpoint-host').onkeydown = event => { if (event.key === 'Enter') { event.preventDefault(); addEndpoint(); } };
$('#endpoint-port').onkeydown = event => { if (event.key === 'Enter') { event.preventDefault(); addEndpoint(); } };
$('#dns-monitor-host').onkeydown = event => { if (event.key === 'Enter') { event.preventDefault(); addDnsMonitor(); } };

setTheme(localStorage.getItem('domainposture-theme') || localStorage.getItem('mailposture-theme') || 'system', false);
setDomainSort(state.domainSort, false);
showRoute(location.pathname);
loadStatus();
loadSystemStatus();
setInterval(() => { if (state.data) $('#updated').textContent = ago(state.data.generated_at); }, 15000);
