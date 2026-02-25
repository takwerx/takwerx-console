# infra-TAK

Emergency Services Tactical Infrastructure Management Platform.

One clone. One password. One URL. Manage everything from your browser.

## What Is This?

A unified web console for deploying and managing TAK ecosystem infrastructure:

- **TAK Server** — Upload your .deb/.rpm, configure, deploy, manage CoreConfig — all from the browser
- **Authentik** — Identity provider with automated LDAP configuration for TAK Server auth
- **TAK Portal** — User and certificate management portal with auto-configured Authentik + TAK Server integration
- **Caddy SSL** — Let's Encrypt certificates and reverse proxy management
- **CloudTAK** — Browser-based TAK client
- **MediaMTX** — Video streaming server for real-time feeds
- **Node-RED** — Flow-based automation engine, protected behind Authentik forward auth
- **Email Relay** — Outbound email for notifications and alerts
- **Guard Dog** — Network monitoring and intrusion detection *(in development)*

No more SSH. No more editing XML by hand. No more running scripts and hoping.

## Quick Start

```bash
git clone https://github.com/takwerx/infra-TAK.git
cd infra-TAK
chmod +x start.sh
sudo ./start.sh
```

The script will:
1. Detect your OS (Ubuntu 22.04, Rocky 9)
2. Install Python dependencies
3. Ask you to set an admin password
4. Ask if you're using a domain name or IP address
5. Start the web console

Then open your browser to the URL shown and log in.

## Deployment Order

Deploy services in this order — each step auto-configures the next:

```
1. Caddy SSL         Set your FQDN, get Let's Encrypt certs (recommended first if using a domain)
         ↓
2. TAK Server        Upload .deb, deploy, configure ports + certs
         ↓
3. Authentik         Identity provider + LDAP outpost (automated deploy)
                     Auto-patches CoreConfig.xml with LDAP auth block
         ↓
4. TAK Portal        User/cert management portal
                     Auto-configures Authentik URL, API token, TAK Server certs
         ↓
5. Anything else     CloudTAK, Node-RED, MediaMTX, Email Relay — any order
```

**TAK Server must be deployed before Authentik.** Authentik auto-configures LDAP auth in CoreConfig.xml and restarts TAK Server. TAK Portal auto-detects the Authentik bootstrap token and TAK Server certificates — zero manual configuration required. After TAK Portal, the remaining services can be deployed in any order from the Marketplace.

## What Gets Automated

**Authentik Deploy (~7 minutes):**
Bootstrap credentials generated, LDAP blueprint installed, Docker Compose patched with standalone LDAP container, API polled for outpost token, CoreConfig.xml patched with LDAP auth block, TAK Server restarted.

**TAK Portal Deploy (~4 minutes):**
Repository cloned, container built, TAK Server certs (admin.p12, tak-ca.pem) copied into container, settings.json auto-configured with Authentik URL/token and TAK Server connection, forward auth configured in Caddy, 2-minute sync wait for Authentik outpost.

After deployment, create users in TAK Portal — they flow through Authentik → LDAP → TAK Server automatically.

## Requirements

- Ubuntu 22.04 LTS or Rocky Linux 9 (fresh installation recommended)
- Root access
- 8GB+ RAM recommended for TAK Server
- Internet connection for initial setup
- TAK Server .deb or .rpm package from [tak.gov](https://tak.gov)

## Architecture

```
start.sh                    ← One CLI command to launch everything
├── app.py                  ← Flask web application (HTTPS on :5001)
├── uploads/                ← Uploaded .deb/.rpm packages
└── .config/                ← Auth + settings (gitignored)
```

## Ports

| Service | Port | Description |
|---------|------|-------------|
| TAK-infra Console | 5001 | Management web UI |
| TAK Server | 8089 | ATAK/TAKAware connections (TLS) |
| TAK Server | 8443 | WebGUI (cert auth) |
| TAK Server | 8446 | WebGUI (Let's Encrypt, password auth) |
| Authentik | 9090 | Identity provider |
| LDAP | 389 | LDAP auth for TAK Server |
| TAK Portal | 3000 | User management portal |

## Access Modes

**IP Address Mode** — Self-signed certificate, works anywhere (field deployments, no DNS needed)

**FQDN Mode** — Caddy + Let's Encrypt for proper SSL. Required for ATAK Android QR enrollment. Can upgrade from IP mode through the web console without SSH.

## QR Code Enrollment

| Client | Status | Notes |
|--------|--------|-------|
| ATAK (Android) | ✅ Working | Requires FQDN mode with Let's Encrypt |
| TAKAware (iOS) | ✅ Working | Works in both IP and FQDN mode |

## Security

- Password required before any access (set during `./start.sh`)
- HTTPS from the start (self-signed or Let's Encrypt)
- Session-based authentication
- All config files are 600 permissions
- Authentik bootstrap credentials auto-generated per deployment

---

## Changelog

### v0.1.7-alpha — 2026-02-24

**Node-RED Authentik Integration**
Node-RED is now protected behind Authentik forward auth at `console.{fqdn}/nodered/`. Requires Authentik login — same flow as TAK Portal.

**Bug Fix: Node-RED proxy provider was never created**
The provider creation payload used `authentication_flow` instead of `authorization_flow` (typo). Every POST returned 400 validation error, not "duplicate" — so the provider was never created. Also added the missing `invalidation_flow` field.

**Bug Fix: Orphaned Node-RED application**
Previous failed deploys created the application with no provider linked. The deploy now PATCHes the existing application to link the provider if it already exists.

**Bug Fix: Update mechanism didn't restart the service**
Clicking "Update Now" ran `git pull` but never restarted `takwerx-console`. Users saw "Updated!" but the old code kept running. The update now triggers a delayed `systemctl restart` after responding.

---

### v0.1.6 — 2026-02-22

**Rebranding:** Project renamed from `takwerx-console` to `tak-infra`. The console interface is now a component within the broader TAK-infra platform.

**Bug Fix: Console not loading after fresh deploy**
The auto-generated Caddyfile was missing the `tls` directive in the console reverse proxy transport block. Since the Flask app runs on HTTPS, Caddy was unable to forward requests to it, causing browsers to spin indefinitely. The TAK Server block already had the correct configuration — the console block now matches.

- `app.py`: Added `tls` to console Caddy transport block

---

### v0.1.5-alpha — 2026-02-21

**LDAP Authentication Fixed**
Authentik blueprint was setting `authentication_flow` instead of `authorization_flow` on the LDAP provider. This was the root cause of "Flow does not apply to current user" errors on every deploy since LDAP was introduced.

**Duplicate LDAP Provider Removed**
A second LDAP provider was being created via API after the blueprint, pointing to the wrong authentication flow. The API block has been removed. The deploy now waits for the blueprint worker to create the correct provider and injects its token directly.

**Token Injection Retry Loop**
LDAP outpost token fetch now retries indefinitely at 5-second intervals instead of timing out. No more manual token injection required after deploy.

**Caddy Reverse Proxy Redirect Fix**
TAK Server behind a reverse proxy was sending `Location: 127.0.0.1:8446` redirects back to the browser after login. Caddy now rewrites these headers to the correct FQDN automatically.

**TAK Portal Forward Auth**
Forward auth and invalidation flow lookups now retry indefinitely. TAK Portal deploy waits 2 minutes after completion for Authentik's embedded outpost to fully sync. Public paths bypass forward auth to support self-service enrollment.

**UX Improvements**
Deploy logs for Authentik and TAK Portal persist after completion. Completion screens show direct launch buttons for each service.

---

### v0.1.4-alpha — 2026-02-18

**GitHub Update Checker**
Switched from Releases API to Tags API — the previous implementation hit `/releases/latest` which returns 404 unless a Release is manually created on GitHub. Now uses `/tags` with semver sorting and 1-hour cache.

**Deploy State Reset**
TAK Server, Authentik, and TAK Portal pages now clear the `deploy_done` flag when services are running. Previously, refreshing after a deploy would keep showing the log instead of the running state.

**CoreConfig LDAP Auth**
`default="ldap"` preserved in the auth block — required for TAK Portal QR code enrollment.

---

### v0.1.3-alpha — 2026-02-18

**CoreConfig LDAP Auth**
`default="ldap"` preserved and File auth listed before LDAP in the auth block.

**Deploy State Reset**
All three module pages (TAK Server, Authentik, TAK Portal) now reset deploy state correctly on refresh.

---

### v0.1.2-alpha — 2026-02-17

**CoreConfig Auth Default Fix**
Changed `default` from `ldap` to `file` to fix `webadmin` access on port 8446. Password auth uses flat file, LDAP users still authenticate via the LDAP block, x509 cert auth still routes groups through LDAP.

**TAK Portal Container Log Cleanup**
Filtered `npm error`, `SIGTERM`, and `command failed` messages from container log display — these were cosmetic restart noise with no functional impact.

**Console Cross-Navigation**
Added links between Authentik, TAK Portal, and TAK Server pages.

---

### v0.1.1-alpha — 2026-02-17

**Authentik Module — Automated Deploy**
Full 10-step automated deployment: bootstrap credentials, LDAP blueprint, Docker Compose patching, API-driven token retrieval, CoreConfig.xml auto-patch, TAK Server restart. Smart API polling handles the full 503 → 403 → 200 startup progression.

**TAK Portal Module — Automated Deploy**
6-step automated deployment: repository clone, container build, TAK Server certificate copy, settings.json auto-configuration.

**Console UI**
Cross-service navigation between all module pages. Real-time step-by-step deploy logging.

---

### v0.1.0-alpha — 2026-02-16

Initial release.

- Services dashboard with live TAK Server process monitoring (Messaging, API, Config, Plugin Manager, Retention)
- Live server log streaming with color-coded ERROR/WARN highlighting
- Certificates page with file browser and direct download
- Deployment improvements: countdown timers, unattended-upgrades detection, cancel button, log reconnection
- Upload management: duplicate detection, cancellation, remove button
- Ubuntu 22.04 support

---

## License

MIT

## Credits

Built by [TAKWERX](https://github.com/takwerx) for emergency services.
