# DomainPosture

DomainPosture 3.0.0 is a focused domain-health dashboard. It combines the existing email posture checks and report analysis with public and origin SSL/TLS certificate monitoring. Add a domain, keep public certificate monitoring enabled, optionally add an origin IP, and DomainPosture schedules and explains the checks.

The application evolved in place from MailPosture. Existing domains, settings, report data, ParseDMARC configuration, OpenSearch data, snapshots, and Docker volumes remain usable. Some legacy internal names are intentionally retained where renaming them would risk data loss; see [Upgrading from MailPosture](#upgrading-from-mailposture).

## What it checks

- SPF, DKIM, DMARC, BIMI, MTA-STS, and TLS reporting DNS and policy controls
- DMARC aggregate and optional failure-report data from OpenSearch
- SMTP TLS report data from OpenSearch
- Live MX SMTP reachability, greeting, STARTTLS, certificate trust, and relay behavior
- Limited IP and domain reputation signals
- Public HTTPS certificates resolved through normal DNS
- Optional origin HTTPS certificates reached at a specific IPv4 or IPv6 address while using the domain for SNI and hostname validation

The dashboard translates those checks into **Healthy**, **Needs Attention**, and **Critical** states and a 0–100 Domain Score. It is not a general-purpose infrastructure monitoring system.

## Architecture

DomainPosture remains a small Node.js service with a static browser interface. Settings and operational state are JSON files under `/data`; there is no SQL database. ParseDMARC and OpenSearch remain separate services.

Two Compose configurations are included:

- `docker-compose.yml` connects DomainPosture to existing ParseDMARC and OpenSearch services.
- `compose.standalone.yml` runs DomainPosture, the official ParseDMARC image, and OpenSearch together.

The container includes `ssl-watch` v1.17.2 as `/usr/local/bin/ssl-watch`. It is copied from the upstream image in a multi-stage build. The final Alpine image installs the CA trust store and verifies that the executable is present during the build. `ssl-watch` remains a short-lived CLI process; no extra daemon or privileged container is introduced.

## Certificate monitoring

Each domain has these settings in the existing Add/Edit Domain dialog:

- **Check Public Certificate** — enabled by default
- **Check Origin Certificate** — disabled by default
- **Origin IP** — shown and required only when origin checking is enabled

At least one certificate path must be enabled. Domain names and IPv4/IPv6 addresses are validated in the browser and again on the server.

### Public and origin checks

The public path uses normal DNS resolution:

```text
ssl-watch -domain example.com -port 443 -output json -fingerprint
```

The origin path connects to the configured IP while retaining the domain for both SNI and hostname verification:

```text
ssl-watch -domain example.com -port 443 -ipaddr 192.0.2.10 -servername example.com -output json -fingerprint
```

TLS verification is not disabled. The app invokes the executable directly with an argument array, never through a shell, and does not accept arbitrary CLI options.

Public and origin results are cached and stored independently. The dashboard shows the check type, status, expiration, remaining days, issuer, IP used, and check time. Technical details include the common name, subject, SANs, fingerprints, validity dates, chain result, TLS version, cipher, last successful check, and a bounded error message.

Statuses are:

| Certificate condition | Display state | Score credit |
|---|---:|---:|
| Valid, more than 30 days | Good | 1.00 |
| Valid, 15–30 days | Needs attention | 0.80 |
| Valid, 8–14 days | Urgent | 0.55 |
| Valid, 0–7 days | Critical | 0.25 |
| Check failed | Check failed | 0.40 |
| Expired or invalid | Expired / Invalid | 0.00 |

The warning threshold is configurable from 7 to 365 days. The default is 30 days; 14-day and 7-day milestones remain fixed.

DNS failures, timeouts, refused connections, invalid JSON, and missing executables become **Check failed** results. An untrusted chain, name mismatch, or not-yet-valid certificate becomes **Invalid** when reported by ssl-watch. Errors are returned as data and do not expose stack traces in the interface.

## Domain Score

The previous scoring model gave every displayed posture check equal weight: Healthy, Informational, or Ignored received full credit; Warning received 0.55; and Critical received 0. The score was the average credit scaled to 100.

Version 3.0.0 preserves that model. All enabled public and origin certificate paths are consolidated into one `SSL/TLS certificates` component, and that component uses the worst enabled path's credit from the table above. A disabled path has no effect. This makes certificate health meaningful without allowing two certificate paths to overwhelm the existing email controls.

With ten healthy existing components plus the certificate component, representative scores are:

| Worst enabled certificate state | Domain Score |
|---|---:|
| Good | 100 |
| 20 days | 98 |
| 10 days | 96 |
| 5 days | 93 |
| Expired or invalid | 91 |

The certificate card shows each enabled path separately so the reason for any score reduction is visible.

## Scheduling and Check Now

The existing application refresh scheduler remains authoritative. The default application refresh is every 15 minutes. Certificate results have their own six-hour freshness interval (`360` minutes), so ordinary refreshes reuse stored results until they are due.

**Check Now** on a domain runs every check for that domain and forces all its enabled certificate paths to run immediately. The global refresh action also forces certificate checks. Normal page rendering only reads the current snapshot and never runs ssl-watch synchronously.

The certificate interval can be changed under **Settings → Monitoring behavior** from 5 minutes to 7 days.

## Discord notifications

Enter the webhook under **Settings → Monitored domains → Discord notifications**. DomainPosture stores it in `/data/secrets.json` with the report-mailbox password and never returns its value to the browser. Leave the field blank to keep the current value, or select **Remove the webhook saved in DomainPosture** to delete it.

For deployments that manage secrets outside the application, the environment variable remains supported as a fallback:

```text
DOMAINPOSTURE_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
```

Only HTTPS Discord webhook URLs with an approved Discord host and `/api/webhooks/<id>/<token>` path are accepted. A webhook saved through Settings takes precedence over the environment fallback. The URL is never returned by the API, placed in HTML, or written to logs; the Settings screen reports only whether it is saved in DomainPosture, supplied by the environment, or not configured.

Notification controls are available in Settings for:

- all Discord notifications
- certificate notifications
- the certificate warning threshold
- domain Needs Attention notifications

Notification state is persisted in `/data/domainposture-state.json`. Public and origin paths have independent state. DomainPosture sends one certificate message when a path first crosses the 30-day, 14-day, or 7-day milestone, or becomes expired, invalid, or unavailable. It does not repeat the same state on later scans. A return to a non-actionable state sends one recovery message and resets the milestone sequence for the next certificate.

The existing domain status is reused for domain notifications. A transition from Healthy to Warning or Critical sends one **Domain Needs Attention** message with the score and actionable checks. Remaining in that state does not send duplicates. Returning to Healthy sends one **Domain Recovered** message.

The first observed state establishes a baseline and does not generate an alert storm after an upgrade.

## Installation

### Prepare the environment

Copy the example without committing the resulting secret file:

```sh
cp env.example .env
```

Set at least the image and OpenSearch values appropriate to the selected Compose file. For the standalone stack, set `ROOT`, `OPENSEARCH_PASSWORD`, and `OPENSEARCH_INITIAL_ADMIN_PASSWORD` to deployment-specific values.

### Existing report services

```sh
docker compose -f docker-compose.yml pull
docker compose -f docker-compose.yml up -d
```

This configuration joins the existing external `monitoring` and `proxy` networks. Override `MONITORING_NETWORK` or `PROXY_NETWORK` when those network names differ.

### Standalone stack

```sh
docker compose -f compose.standalone.yml pull
docker compose -f compose.standalone.yml up -d
```

The standalone stack has a private backend network and joins only the external proxy network. Port 8080 is exposed to the Docker networks but is not published to the host. Keep authentication and TLS termination at the reverse proxy; DomainPosture does not include its own login.

After deployment, open Settings, add domains and DKIM selectors, configure optional origin certificates, and save. For the standalone stack, also configure the report mailbox. ParseDMARC reloads automatically when its generated configuration changes.

## Environment variables

The web interface manages domains, certificate paths, report history, refresh intervals, notification switches, the Discord webhook, mailbox options, and most OpenSearch settings. The OpenSearch password and storage locations remain deployment environment variables.

| Variable | Purpose |
|---|---|
| `DOMAINPOSTURE_IMAGE` | DomainPosture container image |
| `DOMAINPOSTURE_DISCORD_WEBHOOK` | Optional Discord webhook fallback when none is saved in Settings |
| `DOMAINPOSTURE_SETTINGS_PATH` | Optional standalone host path mounted at `/data` |
| `DOMAINPOSTURE_DATA_VOLUME` | Optional Docker volume name for `/data` in the lightweight stack |
| `OPENSEARCH_URL` | Existing OpenSearch URL |
| `OPENSEARCH_INDEX` | DMARC aggregate index pattern |
| `OPENSEARCH_FAILURE_INDEX` | Optional DMARC failure/RUF index patterns |
| `OPENSEARCH_SMTP_TLS_INDEX` | SMTP TLS report index pattern |
| `OPENSEARCH_USERNAME` | OpenSearch user |
| `OPENSEARCH_PASSWORD` | OpenSearch password secret |
| `OPENSEARCH_VERIFY_TLS` | Verify HTTPS OpenSearch certificates |
| `OPENSEARCH_INITIAL_ADMIN_PASSWORD` | Standalone OpenSearch administrator secret |
| `ROOT` | Parent directory for standalone persistent data |
| `OPENSEARCH_DATA_PATH` | Optional existing OpenSearch data path |
| `OPENSEARCH_SNAPSHOT_PATH` | Optional existing snapshot repository path |
| `PROXY_NETWORK` | Existing reverse-proxy Docker network |
| `MONITORING_NETWORK` | Existing monitoring Docker network for the lightweight stack |
| `SERVICE_LOGS_ENABLED` | Enable bounded, redacted service-log views when matching read-only mounts exist |

Runtime overrides used mainly for development are `PORT`, `APP_VERSION`, `SSL_WATCH_PATH`, `DOMAINPOSTURE_SETTINGS_FILE`, `DOMAINPOSTURE_SECRETS_FILE`, `DOMAINPOSTURE_STATE_PATH`, and `PARSEDMARC_CONFIG_PATH`.

Deprecated `MAILPOSTURE_IMAGE`, `MAILPOSTURE_DISCORD_WEBHOOK`, `MAILPOSTURE_SETTINGS_PATH`, `MAILPOSTURE_DATA_VOLUME`, `MAILPOSTURE_DEPLOYMENT_MODE`, and `MAILPOSTURE_LOG_PATH` remain accepted as fallbacks. Prefer the `DOMAINPOSTURE_` names for new deployments.

## Upgrading from MailPosture

1. Back up the existing `/data` volume or `${ROOT}/mailposture` directory and the OpenSearch snapshot repository.
2. Do not delete or recreate Docker volumes, OpenSearch data, or the report mailbox.
3. Pull or build the DomainPosture 3.0.0 image.
4. Keep the existing `mailposture_data` volume or legacy host path during the first upgrade. The supplied Compose defaults do this automatically.
5. Replace product-specific environment variables with their `DOMAINPOSTURE_` equivalents when convenient; the old names remain fallbacks.
6. Start the updated stack and confirm `/healthz`, **System Status**, the saved domain list, report counts, and a manual certificate check.
7. Configure origin certificate paths only after confirming their intended IP addresses.

Settings are normalized from schema 7 to schema 8 when loaded. Existing domain and report settings are preserved. Every existing domain receives public certificate monitoring enabled and origin monitoring disabled unless certificate settings already exist. Saving Settings writes the normalized schema atomically. The new operational state file is additive and does not replace prior settings or report data.

The Compose project and service keys, default standalone paths, snapshot repository name, internal ParseDMARC runtime path, internal OpenSearch policy name, compatibility network aliases, and named diagnostic volumes still contain `mailposture`. They are deliberately retained so Compose can recreate the existing service in place and reuse its data. The container name, primary network alias, user-facing branding, preferred environment variables, package metadata, and new files use DomainPosture.

Rollback is to stop the 3.0.0 containers and restart the prior image against the untouched volume backup. The prior release ignores the additive certificate and notification fields, but restoring the pre-upgrade settings backup is the safest rollback.

## Data and privacy

- `/data/settings.json` stores application configuration.
- `/data/secrets.json` stores the report-mailbox password and optional Discord webhook with restrictive file permissions.
- `/data/domainposture-state.json` stores certificate cache and notification transition state.
- ParseDMARC writes normalized reports to OpenSearch and controls mailbox archive/delete behavior.
- DomainPosture shows RUF counts but intentionally does not display potentially sensitive report samples.
- SMTP relay probes use reserved example addresses, stop before `DATA`, and never send message content.
- BIMI SVGs are validated and served through a sandboxed same-origin response.
- Service log views use a fixed service list, bounded reads, and redaction as defense in depth. Review logs before sharing them.

The application writes settings, operational state, generated ParseDMARC configuration, logs when enabled, and OpenSearch snapshot policy configuration. It does not modify DNS. The container uses a read-only root filesystem, drops Linux capabilities, has no Docker socket, and uses `/data` as its writable application mount.

## Health and troubleshooting

`GET /healthz` returns the application version and process health. **System Status** checks storage, the ssl-watch executable, OpenSearch, report indexes, generated ParseDMARC configuration, and the collector heartbeat.

If a certificate check fails:

1. Open **System Status** and confirm `/usr/local/bin/ssl-watch` is available.
2. Confirm the container has outbound TCP access to port 443 and a current CA trust store.
3. For a public check, verify the domain resolves from inside the container.
4. For an origin check, verify the IP is correct and accepts TLS on 443 for the configured SNI name.
5. Do not disable verification to hide a chain or hostname problem.
6. Select **Check Now** after correcting the issue.

If Discord is not sending messages, confirm Settings reports a saved or environment webhook, the notification switches are enabled, and the container can reach Discord. Existing actionable states do not alert immediately after an upgrade because the first scan establishes the deduplication baseline.

## Development and verification

```sh
npm test
node --check server.js
node --check ssl-monitor.js
node --check public/app.js
```

The test suite covers settings migration, public/origin argument construction, input rejection, JSON normalization, distinct cached paths, status thresholds, score contribution, forced and scheduled-cache behavior, Discord webhook validation and precedence, notification milestones, deduplication, recovery, UI wiring, and existing email posture behavior.

The integration follows the current upstream [ssl-watch documentation](https://github.com/idesyatov/ssl-watch) and pins version 1.17.2. Its MIT attribution is retained in `THIRD_PARTY_NOTICES.md`. The project uses semantic versioning; this DomainPosture feature release is `3.0.0`.

## Repository rename

The repository was renamed in place from `TechJedi51/mailposture` to `TechJedi51/domainposture`. GitHub redirects the former repository URL, but existing local clones should update their `origin` URL explicitly. The image workflow derives its GHCR name from the repository slug, so future releases publish `ghcr.io/techjedi51/domainposture`.
