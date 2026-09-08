# MailPosture with Dockhand

MailPosture is a generic, management-focused status page for SPF, DMARC aggregate and failure reports, SMTP TLS reports, live SMTP service diagnostics, DKIM, MTA-STS, TLS certificates, BIMI, and limited IP/domain reputation screening. It contains no user-specific domain configuration. Operational settings are entered in the web interface and saved in persistent storage; Dockhand supplies deployment secrets and storage paths.

## Included files

```text
mailposture/
├── .github/workflows/       # Tests and publishes the image to GHCR
├── docker-compose.yml
├── compose.standalone.yml
├── Dockerfile
├── .env.example
├── server.js
├── smtp.js
├── dns-security.js
├── public/
└── test/
```

Use `docker-compose.yml` when parsedmarc and OpenSearch already exist. Use `compose.standalone.yml` to deploy MailPosture, the official `ghcr.io/domainaware/parsedmarc` image, and OpenSearch together. They remain separate containers so each service can be upgraded, restarted, secured, and backed up independently.

## Interface

- **Dashboard** shows the organization-wide score, domain scores, open issues, stacked aggregate DMARC trends, optional DMARC failure-report counts, and stacked SMTP TLS results.
- **Domains** shows the detailed status, report center, attention queue, SMTP diagnostics, evidence, and control matrix for one domain at a time.
- **System Status** directly checks MailPosture storage and refreshes, OpenSearch authentication and cluster health, report indexes, the generated ParseDMARC configuration, and the bundled collector heartbeat. It includes both a privacy-safe operational event log and bounded, redacted service-log views for the standalone MailPosture, OpenSearch, and ParseDMARC services.
- **Settings** separates monitored domains, appearance, OpenSearch, and parsedmarc configuration into accessible tabs with keyboard navigation.
- **Help** explains setup, every check, and the terminology used by the application.

## Settings screen

After the first deployment, select the gear button in MailPosture. The Monitored domains, Appearance, OpenSearch, and parsedmarc tabs make room for each service's related options.

### Domains

Select the plus button to add a domain. Use the edit button beside a domain to change its name; select its inbound-mail hosting type and provider; identify whether relay probes run from a trusted or external network; or manage its DKIM selectors and TLS certificate endpoints. Automatic provider detection recognizes Google Workspace, Microsoft 365, Hover Mail, iCloud Mail, and self-hosted MX names. Kerio Connect can be selected for a self-hosted domain because its product identity cannot be determined reliably from public DNS. Domain removal remains pending until **Save settings** is selected.

The domain dashboard, domain cards, Settings list, and SMTP diagnostics show the effective hosting type and provider. Each value is labeled **Auto-detected** or **Selected** so operators can distinguish DNS-derived classification from an explicit configuration choice.

Add every domain that appears after the `@` in an organization-managed From address.

### DKIM selectors

Edit a domain, then add each active selector by its label, such as `selector1` or `google`. An omitted domain receives a visible “No selectors configured” warning. DKIM selectors cannot be discovered reliably from DNS.

### TLS certificate endpoints

Edit a domain, then add each endpoint as a host and port, such as `mta-sts.example.com` on port `443` or `mail.example.com` on port `465`.

Direct TLS endpoints such as HTTPS 443, SMTP 465, and IMAP 993 are supported. MailPosture also discovers every monitored domain’s published MX hosts and probes SMTP on TCP port 25. It checks reachability and the SMTP greeting, negotiates STARTTLS before testing the mail envelope, validates certificate trust against the MX hostname, and checks whether an unauthenticated external recipient is rejected. Reverse DNS, banner alignment, and timing from one location remain visible as supporting diagnostics; valid provider-owned identities and slow single-location timing are informational rather than protocol failures. Results reflect MailPosture’s network location, and the container must be allowed outbound TCP port 25. When the receiving provider blocks the monitoring source address, TLS and relay checks are labeled **Not tested** rather than failed. The relay probe uses reserved example addresses and stops before `DATA`; it never submits message content. If the recipient is accepted, the result is critical only when the domain is configured to identify this installation as external and untrusted. Otherwise MailPosture requests external verification.

Under **Monitoring behavior**, optionally provide a public SMTP probe hostname whose A/AAAA and PTR records identify this MailPosture installation. When it is blank, MailPosture uses the local connection address as an SMTP address literal instead of claiming an unresolvable hostname.

The Domains button opens a status-aware menu. Under **Settings → Appearance**, choose whether that menu lists domains by priority—needs action, review, then healthy—or alphabetically. This preference is stored in the current browser with the color-mode preference.

### Report source

Choose **Bundled services** with `compose.standalone.yml`, **External OpenSearch** when an existing parsedmarc/OpenSearch deployment supplies the data, or **Live checks only** to disable historical reporting. The OpenSearch password remains a Dockhand secret and is never returned to the browser.

### Report mailbox

One mailbox is normally sufficient for every monitored domain. Point each domain's DMARC `rua` and TLS-RPT `rua` address—or aliases for those addresses—to the same account. parsedmarc watches the configured incoming folder and sorts messages below the configured archive folder:

```text
Archive/
├── Aggregate
├── Failure
├── Invalid
├── SMTP-TLS
└── Unsaved
```

Saving Settings writes `/data/parsedmarc/config.ini`. The standalone Compose file mounts that generated file at parsedmarc's active `/etc/parsedmarc/config.ini` path and reloads parsedmarc automatically within 10 seconds when it changes. An external parsedmarc deployment must mount the same generated directory—or copy the file to its configured path—and must be restarted by its own service manager.

The standalone stack also uses the small `parsedmarc_status` Docker volume for a runtime heartbeat. MailPosture reads this volume but cannot modify it. ParseDMARC updates it while waiting, running, reloading, or after an unexpected exit. This provides process visibility without granting MailPosture access to the Docker socket. External ParseDMARC deployments remain observable through configuration and OpenSearch report checks, but their process state is reported as unavailable unless they provide a compatible heartbeat.

`Archive/SMTP-TLS` contains the original TLS-RPT messages after parsedmarc processes them. MailPosture does not read or parse that folder. It reads the normalized documents that parsedmarc writes to the configured `smtp_tls*` OpenSearch index, which prevents duplicate processing and mailbox conflicts.

DMARC aggregate failures and DMARC failure reports are different measurements. Aggregate reports count messages that failed DMARC. Failure reports, also called RUF or forensic reports, are optional individual reports that many receivers do not send. It is therefore normal for an aggregate report to show failed messages while the RUF report count is zero. MailPosture shows only RUF counts because those reports may contain personal or confidential message data.

The aggregate report card separates messages that passed DMARC from messages that failed it. DKIM-aligned and SPF-aligned percentages use only the messages in their respective row. Because DMARC needs either aligned DKIM or aligned SPF, those percentages can overlap. The DMARC reports list identifies the receiving organizations and reporter domains found in the 1,000 most recent matching OpenSearch documents; totals and alignment rates still use all matching documents in the selected period.

TLS reporting organizations are the outside mail providers that sent TLS-RPT data about delivery attempts to a monitored domain. Their values count SMTP sessions, not email messages. MailPosture recognizes current and legacy parsedmarc organization fields. When a report has no recognized name, the interface says **Reporter name not provided** and provides a limited raw-field view so you can verify what was stored without exposing policy details or message content.

The SPF check validates that exactly one SPF policy is published, expands static `include` and `redirect` references, checks the RFC limit of 10 DNS-querying terms, flags recursive references and malformed IP networks, and distinguishes `-all`, `~all`, and unsafe catch-all policies. DNS timeouts produce an incomplete or unavailable result instead of a false pass.

The TLS-RPT check looks up `_smtp._tls.<domain>`, requires exactly one `v=TLSRPTv1` record, and validates each `rua` destination as a `mailto` or HTTPS URI. This DNS policy check is separate from the report history collected by parsedmarc.

The reputation check performs a limited DNS-based screen of the monitored domain through Spamhaus DBL and the domain's receiving MX addresses through Spamhaus ZEN and SpamCop. It does not replace a deliverability service, and receiving MX addresses are often different from outbound sending addresses. Provider access failures are shown as unavailable and never as clean. Verify a reported listing with the named provider before remediation; DNS blocklists have their own access and removal policies.

Top failing DMARC sources include the source IP address and, when available, parsedmarc's saved host name, base domain, and network owner. If no saved host name exists, MailPosture attempts a bounded reverse-DNS lookup. A PTR name is supporting context and is not proof that the named organization authorized the traffic.

When BIMI publishes a safe SVG logo over HTTPS and passes validation, MailPosture displays it on the BIMI control card through a same-origin, sandboxed image response. Remote logo markup is not inserted into the page. A domain editor can independently ignore an intentionally self-asserted logo or intentionally absent logo permanently or for 1–120 months. The BIMI card remains visible and labeled **Ignored**; invalid records, unsafe logos, and unmet DMARC prerequisites are never suppressed.

The parsedmarc tab manages the general, mailbox, IMAP, and OpenSearch options used by the bundled IMAP-to-OpenSearch pipeline. Monthly indexes are enabled by default for new configurations to avoid creating a large number of small report indexes. For a single OpenSearch node, use one shard and zero replicas. Less common outputs and collectors, including Kafka, S3, Splunk, Gmail API, and Microsoft Graph, remain advanced file-based configuration. MailPosture does not parse, move, or delete report messages itself; parsedmarc performs the configured mailbox actions.

### System Status troubleshooting

A yellow OpenSearch cluster is expected when a single-node cluster has replica shards configured because OpenSearch will not place a replica on the same node as its primary. MailPosture inspects every unassigned shard and separates report indexes, OpenSearch security audit logs, internal indexes, and other indexes. When all unassigned shards are replicas and no MailPosture report shard is affected, the application reports the pipeline as operational while preserving the actual yellow cluster state in its evidence. Set **Replicas** to `0` under **Settings → ParseDMARC → OpenSearch output** for new report indexes. Existing indexes and OpenSearch-created audit/internal indexes require their own `index.number_of_replicas` setting or an appropriate cluster default. Multi-node clusters should normally retain replicas.

The Report indexes card has **All domains** scope because its patterns query shared cluster indexes, not one selected domain. Each pattern appears on its own line and can be expanded to show the matching physical indexes, health, document count, primary shards, and replicas. An unavailable aggregate or SMTP TLS pattern means OpenSearch has no matching index yet; confirm that the report type is enabled and matching messages reach the mailbox. A missing individual DMARC failure (RUF) index is informational, not an error, because many providers never send these optional reports.

The in-app **Event history** is intentionally limited to state changes detected by MailPosture. Its entries are historical, so a brief failure remains visible after the current status cards show that the service recovered. The standalone Compose file also writes or mounts bounded service logs from MailPosture, OpenSearch, and ParseDMARC. MailPosture exposes only a fixed service list, reads the volumes without write access, limits the number and size of files returned, and redacts common password, token, secret, and authorization labels. This is defense in depth, not a guarantee that logs contain no sensitive metadata. Review logs before sharing them. External deployments leave service-log viewing disabled unless equivalent read-only mounts are configured.

The standalone OpenSearch health check waits for cluster status **yellow** or **green**. A red cluster can still answer its HTTP endpoint, but it is not marked healthy and dependent services do not start until primary shards are available or the health-check retries are exhausted.

Failure reports can contain message headers or content. MailPosture shows counts but intentionally does not display those samples.

### OpenSearch snapshots

The standalone stack mounts `${ROOT}/mailposture/opensearch/snapshots` by default and MailPosture registers it as the `mailposture` file-system repository. Set `OPENSEARCH_SNAPSHOT_PATH` to reuse an existing absolute host path instead. Saving an enabled snapshot schedule creates or updates OpenSearch's native `mailposture` snapshot policy using the configured creation cron, cleanup cron, time zone, age, and count limits.

The snapshot directory is on the same host by default. Copy it to separate storage to protect against host or disk failure.

## 1. Create the local repository

Download and extract the supplied archive, then run:

```bash
cd /path/to/mailposture
git init
git branch -M main
git add .
git status
git commit -m "Add generic MailPosture stack"
```

The repository contains only examples. You do not need to edit any file before pushing it.

## 2. Push it to GitHub

With GitHub CLI:

```bash
gh auth login
gh repo create mailposture --private --source=. --remote=origin --push
```

Alternatively, create an empty private `mailposture` repository on GitHub. Do not initialize it with extra files, then run:

```bash
git remote add origin git@github.com:YOUR_GITHUB_USERNAME/mailposture.git
git push -u origin main
```

## 3. Let GitHub build the image

The first push to `main` starts **Test and publish container image** under the repository's **Actions** tab. The workflow:

- runs the application tests;
- builds `linux/amd64` and `linux/arm64` images;
- publishes `ghcr.io/OWNER/REPOSITORY:latest`;
- also publishes an immutable `sha-...` tag;
- publishes version tags when a tag such as `v2.1.0` is pushed.

No registry password is required in the workflow. GitHub's temporary `GITHUB_TOKEN` publishes the image to the repository's GHCR package.

Wait for the workflow to finish successfully before the first Dockhand deployment.

### Public or private image

For the simplest homelab deployment, open the package from the repository's **Packages** section and make the container package public. The source repository can remain private.

To keep the image private, create a GitHub token that can read packages. In Dockhand, open **Settings → Registries** and add:

```text
Registry: ghcr.io
Username: your GitHub username
Password: a token with read:packages access
```

## 4. Create the Git stack in Dockhand

1. Add credentials for the private GitHub repository under **Settings → Git**.
2. Create a new Git-backed stack and choose the target Docker environment.
3. Select the repository and the `main` branch.
4. Set **Compose file path** to `compose.standalone.yml` for a complete deployment, or `docker-compose.yml` when using an existing OpenSearch service.
5. Set **Context directory** to the repository root (`.` or blank).
6. Leave **Build images on deploy** disabled; GitHub has already built the image.
7. Enable **Re-pull images** so Dockhand refreshes the `latest` tag.
8. Add the variables below in Dockhand's environment-variable panel.
9. Deploy.

### Required Dockhand variables

```dotenv
MAILPOSTURE_IMAGE=ghcr.io/your-github-username/mailposture:latest
ROOT=/srv/docker-data
OPENSEARCH_INITIAL_ADMIN_PASSWORD=your-strong-opensearch-password
```

Mark the OpenSearch password as a secret. For the lightweight Compose file, provide the same value as `OPENSEARCH_PASSWORD` instead of `OPENSEARCH_INITIAL_ADMIN_PASSWORD`.

### Optional Dockhand variables

```dotenv
TZ=America/Los_Angeles
OPENSEARCH_URL=http://parsedmarc-opensearch:9200
OPENSEARCH_INDEX=dmarc_aggregate*
OPENSEARCH_FAILURE_INDEX=dmarc_failure*,dmarc_forensic*
OPENSEARCH_SMTP_TLS_INDEX=smtp_tls*
OPENSEARCH_USERNAME=admin
OPENSEARCH_VERIFY_TLS=false
MONITORING_NETWORK=monitoring
PROXY_NETWORK=proxy
MAILPOSTURE_DATA_VOLUME=mailposture_data
OPENSEARCH_VERSION=2
PARSEDMARC_VERSION=latest
OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g
OPENSEARCH_LOG_VOLUME=mailposture_opensearch_logs
MAILPOSTURE_SETTINGS_PATH=/srv/docker-data/mailposture
OPENSEARCH_DATA_PATH=/srv/docker-data/parsedmarc/opensearch/data
OPENSEARCH_SNAPSHOT_PATH=/srv/docker-data/parsedmarc/opensearch/snapshots
```

The Compose files provide defaults for optional values. The three `*_PATH` variables are migration overrides: set them to absolute host paths to reuse MailPosture settings, OpenSearch data, or an existing snapshot repository, and omit them for the new default folders. Do not run snapshot jobs from two OpenSearch clusters against the same repository. The Settings screen can override the OpenSearch URL, username, index patterns, and certificate verification behavior. The password remains an environment secret.

Use the lowercase owner and repository path shown on the GitHub package page for `MAILPOSTURE_IMAGE`.

## Versioning

MailPosture uses semantic versioning:

- Bug fixes increment the third number, such as `1.1.2` to `1.1.3`.
- Features increment the second number and reset the third number to zero, such as `1.2.1` to `1.3.0`.
- Incompatible changes increment the first number.

This feature release is version `2.1.0`.

## 5. Reverse proxy

The lightweight stack joins the existing external `monitoring` and `proxy` networks. The standalone stack creates its own private `mailposture-backend` network and joins only the existing external `proxy` network. Set `MONITORING_NETWORK` or `PROXY_NETWORK` to use different existing network names without editing the repository.

Point the reverse proxy at:

```text
http://mailposture:8080
```

Keep authentication at the reverse proxy. MailPosture intentionally does not have a built-in login, and port 8080 is not published to the host.

## 6. Local testing

Copy the sample environment file and replace its example values locally:

```bash
cp .env.example .env
docker compose config
docker compose pull
docker compose up -d
```

Open MailPosture, select the Settings button, add the monitored domains and their selectors and endpoints, then save. With the standalone stack, also enter the report mailbox and enable snapshots. parsedmarc starts after the first valid mailbox configuration is saved and reloads automatically after later changes. Appearance preference is stored in the browser because it is specific to each device.

`.env` is excluded by `.gitignore`. It must never be committed.

For temporary direct browser access, add the following under the service in a local, uncommitted override file:

```yaml
ports:
  - "127.0.0.1:8080:8080"
```

## Updating the application

Repository changes are deployed with:

```bash
git add .
git commit -m "Update MailPosture"
git push
```

Wait for **Test and publish container image** to complete, then manually deploy or sync the stack in Dockhand. Dockhand will pull the refreshed `latest` image; it will not build locally.

### Optional automatic deployment after the image is ready

A normal GitHub push webhook can reach Dockhand before GHCR has finished building the new image. The included workflow can instead call Dockhand only after publishing succeeds.

After creating the Dockhand Git stack:

1. Configure a webhook secret in that stack and copy its unique webhook URL.
2. In the GitHub repository, open **Settings → Secrets and variables → Actions**.
3. Add `DOCKHAND_WEBHOOK_URL` containing the full Dockhand stack webhook URL.
4. Add `DOCKHAND_WEBHOOK_SECRET` containing the matching secret.
5. Do not add a separate push webhook for this stack.

On later pushes, GitHub tests and publishes the image first, then signs a deployment request with HMAC-SHA256 and sends it to Dockhand. If either secret is absent, this step is skipped and manual deployment remains available.

## Standalone persistent folders

Create these folders before the first standalone deployment and grant the container users access appropriate to your Docker host:

```text
${ROOT}/mailposture/
├── settings/
│   ├── settings.json
│   ├── secrets.json
│   └── parsedmarc/config.ini
└── opensearch/
    ├── data/
    └── snapshots/
```

Do not place this mutable data inside Dockhand's Git checkout. Do not commit `settings.json`, `secrets.json`, `config.ini`, OpenSearch data, or snapshots.

To keep the data from the stack shown in this guide without copying it, set these Dockhand variables to the actual absolute paths represented by your current `${ROOT}` value:

```dotenv
MAILPOSTURE_SETTINGS_PATH=/your/current/root/mailposture
OPENSEARCH_DATA_PATH=/your/current/root/parsedmarc/opensearch/data
OPENSEARCH_SNAPSHOT_PATH=/your/current/root/parsedmarc/opensearch/snapshots
```

Stop the old parsedmarc and OpenSearch services before starting the standalone stack against those paths. A data directory or snapshot repository must never be opened concurrently by two OpenSearch containers.

## Verification

```bash
npm test
```

MailPosture never writes to DNS or mailboxes. In standalone mode it writes its own settings, secrets, and generated parsedmarc configuration, and it manages the OpenSearch snapshot repository and policy. Its root filesystem remains read-only, `/data` is the only writable application mount, and the container has no Linux capabilities or Docker socket access.
