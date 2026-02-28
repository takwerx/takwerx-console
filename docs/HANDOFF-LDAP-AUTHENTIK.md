# infra-TAK Technical Handoff Document

## 0. Current Session State (Last Updated: 2026-02-23)

**This section is the single source of truth.** Update it when server state changes. This doc is a living handoff between machines -- only describe what is true right now.

### What's Deployed on the Server
- **Caddy** -- running, TLS for subdomains
- **Authentik** -- running (server, worker, postgres, redis, LDAP outpost)
- **TAK Server** -- running (systemd), CoreConfig.xml has LDAP block (clean stanza matching TAK Portal reference + adminGroup)
- **TAK Portal** -- running (Docker)
- **Email Relay** -- running, SMTP + recovery flow auto-configured in Authentik
- **MediaMTX** -- NOT YET TESTED on this deploy (LDAP overlay code is in repo, needs deploy + verification)

### What Works (Verified on Fresh VPS 2026-02-23)
- All services deploy and run (Authentik-first deployment order verified on fresh VPS)
- Authentik SSO via Caddy forward_auth (infratak, takportal, nodered, mediamtx subdomains)
- Password recovery flow (forgot username or password -> email -> reset -> login)
- TAK Server 8443 (cert auth), 8446 (password auth via LDAP, admin console works for webadmin)
- LDAP user authentication -- CoreConfig patched with clean stanza, webadmin login on 8446 confirmed
- TAK Portal user creation -> Authentik user creation -> QR enrollment -> TAK client connects with no issues
- **No user-profile.pref popup** -- fixed by stripping extra LDAP attributes (style, ldapSecurityType, groupObjectClass, userObjectClass, matchGroupInChain, roleAttribute)
- **Authentik SMTP auto-configuration** -- Email Relay deploy auto-configures Postfix inet_interfaces, mynetworks, firewall rules (ufw/firewalld) for Docker-to-host port 25
- **App access policies** -- auto-created on Authentik deploy: "Allow authentik Admins" (group membership) bound to admin-only apps; "Allow MediaMTX users" (expression policy for vid_* groups) bound to MediaMTX; TAK Portal open to all authenticated users
- **"TAK clients" terminology** -- universal across UI, logs, and docs (no more "ATAK enrollment")

### What's New in This Build (Changes Since Last Session)
1. **Authentik SMTP/firewall automation** -- `_configure_authentik_smtp_and_recovery` now auto-configures Postfix `inet_interfaces = all`, `mynetworks` with Docker subnets (172.16.0.0/12), and UFW/firewalld rules for port 25 on deploy
2. **App access policies** -- `_ensure_app_access_policies` creates and binds policies automatically:
   - `Allow authentik Admins` (group membership) -> infra-TAK, Node-RED, LDAP
   - `Allow MediaMTX users` (expression: admins OR vid_admin/vid_private/vid_public) -> MediaMTX
   - TAK Portal left unbound (all authenticated users see it)
3. **MediaMTX LDAP overlay** -- `mediamtx_ldap_overlay.py` patches vanilla editor at deploy time when Authentik detected: Authentik header auth, Stream Access page at /stream-access, sidebar injection. NOT YET TESTED.
4. **LDAP stanza cleanup** -- Stripped `style="DS"`, `ldapSecurityType="simple"`, `groupObjectClass`, `userObjectClass`, `matchGroupInChain`, `roleAttribute` from CoreConfig LDAP block. Kept `adminGroup="ROLE_ADMIN"` (required for admin console access). Matches TAK Portal reference stanza. Fixed user-profile.pref phantom popup.
5. **MediaMTX deploy bugfix** -- Clone dir was deleted before editor file was copied; moved cleanup after copy+patching
6. **Universal "TAK clients" terminology** -- Replaced "ATAK enrollment" everywhere

### What Still Needs Testing
- **MediaMTX LDAP overlay** -- Deploy MediaMTX on the current VPS and verify:
  - No local login page (Authentik header auth should auto-authenticate)
  - Sidebar shows "Stream Access" instead of "Web Users"
  - `/stream-access` page loads, shows Authentik users
  - Group badge toggles work (add/remove users from vid_admin, vid_private, vid_public)
  - Viewer role (vid_public/vid_private user) only sees Active Streams tab

### What's Broken (Only list if verified broken right now)
- *(None currently)*

### What To Do Next
1. **Deploy MediaMTX** on current VPS and verify LDAP overlay end-to-end
2. After MediaMTX verified: begin **two-server TAK Server module** (Server 1 = DB via SSH, Server 2 = Core local)

### What's Next / Work in Progress
- **Next up**: Two-server TAK Server deployment (single UI flow, user picks 1 or 2 server, uploads core + database debs)
- **Planned / Backlog**: Cloudflare Tunnel module for travel NUC/Pi deployments, Pi optimization, systemd service rename from `takwerx-console` to `infra-tak` (deferred to first non-alpha release)
- **TAK Portal request-access page**: Justin building a public-facing request-access page (not behind Authentik) for TAK Portal. Future enhancement: at approval time, optionally assign vid_* groups for MediaMTX stream access in one step.
- **Blocked / Waiting on**: Nothing

### Key Files Changed
- `app.py` -- SMTP/firewall automation, app access policies, MediaMTX LDAP overlay deploy logic, LDAP stanza cleanup, MediaMTX deploy bugfix
- `mediamtx_ldap_overlay.py` -- NEW: Authentik header auth + Stream Access page + API routes for vid_* group management
- `docs/COMMANDS.md` -- NEW: Copy-paste commands and troubleshooting guide
- `docs/email-template-user-created-without-password.html` -- NEW: Ready-to-paste TAK Portal email template
- `docs/MEDIAMTX-TAKPORTAL-ACCESS.md` -- Updated to reflect implemented Stream Access page
- `README.md`, `TESTING.md`, `docs/HANDOFF-LDAP-AUTHENTIK.md` -- Updated terminology

### Server Access
```bash
# Pull latest code and restart console
cd ~/infra-TAK && git pull origin dev && sudo systemctl restart takwerx-console

# Verify LDAP is in CoreConfig (the real check -- must say OK)
grep -q 'adm_ldapservice' /opt/tak/CoreConfig.xml && echo OK || echo FAIL

# Revert CoreConfig to pre-LDAP state (if LDAP breaks 8446 login)
sudo cp /opt/tak/CoreConfig.xml.pre-ldap.bak /opt/tak/CoreConfig.xml && sudo systemctl restart takserver

# Check LDAP outpost logs
docker logs authentik-ldap-1 --since 2m 2>&1

# Check LDAP outpost config
TOKEN=$(grep AUTHENTIK_BOOTSTRAP_TOKEN ~/authentik/.env | cut -d= -f2)
curl -s "http://127.0.0.1:9090/api/v3/outposts/instances/?search=LDAP" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Check LDAP flow authentication setting
curl -s "http://127.0.0.1:9090/api/v3/flows/instances/?slug=ldap-authentication-flow" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | grep authentication
```

---

## 1. Project Overview

| Field | Value |
|---|---|
| **Project name** | infra-TAK |
| **Version** | 0.1.7-alpha |
| **Purpose** | Unified web console for deploying and managing TAK ecosystem infrastructure (TAK Server, Authentik SSO, LDAP, Caddy reverse proxy, TAK Portal, Node-RED, MediaMTX, CloudTAK, Email Relay) |
| **Intended users** | System administrators deploying TAK (Team Awareness Kit) infrastructure |
| **Operating environment** | Ubuntu 22.04/24.04 or Rocky Linux 9, single VPS, accessible via `https://<ip>:5001` (backdoor) or `https://infratak.<fqdn>` (behind Authentik) |
| **Current completion status** | Alpha. All modules deploy. LDAP authentication working. App access policies automated. MediaMTX LDAP overlay built (needs testing). Two-server deployment planned. |

---

## 2. System Architecture

### High-Level Components

```
+-----------------------------------------------------------------+
|  Caddy (reverse proxy, TLS termination, forward_auth)            |
|  - infratak.<fqdn>  -> Flask app :5001 (via Authentik)           |
|  - authentik.<fqdn> -> Authentik :9090                           |
|  - tak.<fqdn>       -> TAK Server :8446                          |
|  - takportal.<fqdn> -> TAK Portal :3000 (via Authentik)          |
|  - nodered.<fqdn>   -> Node-RED :1880 (via Authentik)            |
|  - stream.<fqdn>    -> MediaMTX :5080 (via Authentik)            |
|  - map.<fqdn>       -> CloudTAK :5000                            |
+-----------------------------------------------------------------+
         |
+---------+--------------------------------------------+
|  Authentik (SSO / IdP)                                |
|  - Server + Worker + PostgreSQL + Redis (Docker)      |
|  - Embedded Outpost (proxy provider, forward_auth)    |
|  - LDAP Outpost (Docker, port 389->3389)              |
|  - Policies: Allow authentik Admins (group membership)|
|              Allow MediaMTX users (expression)        |
+---------+--------------------------------------------+
         | LDAP bind (port 389)
+---------+--------------------------------------------+
|  TAK Server (systemd, /opt/tak)                       |
|  - CoreConfig.xml -> <auth default="ldap">            |
|  - Service account: adm_ldapservice                   |
|  - User auth: cn={username},ou=users,dc=takldap       |
|  - Ports: 8089 (TLS / TAK clients), 8443 (cert),     |
|           8446 (pw)                                   |
+---------+--------------------------------------------+
         |
+---------+--------------------------------------------+
|  MediaMTX (systemd, /opt/mediamtx-webeditor)          |
|  - With Authentik: LDAP overlay auto-applied          |
|    - Auth via X-Authentik-* headers (no local login)  |
|    - Stream Access page at /stream-access             |
|    - vid_admin -> full console                        |
|    - vid_private/vid_public -> Active Streams only    |
|  - Without Authentik: vanilla editor (local login)    |
+------------------------------------------------------+
```

### App Access Policy Model

| App | Who sees the tile | Policy |
|---|---|---|
| TAK Portal | All authenticated users | No binding (open) |
| MediaMTX | authentik Admins + vid_admin + vid_private + vid_public | Expression: Allow MediaMTX users |
| infra-TAK, Node-RED, LDAP | authentik Admins only | Group membership: Allow authentik Admins |

### LDAP Group Namespaces

| Prefix | Used by | Purpose |
|---|---|---|
| `tak_` | TAK Server, TAK Portal, TAK clients | Missions, roles, agency groups |
| `vid_` | MediaMTX | Stream access (vid_admin, vid_private, vid_public) |
| `authentik-` | TAK Portal agencies | Agency admin groups (e.g. authentik-HCSO-AgencyAdmin) |

TAK Portal only shows `tak_*` groups. MediaMTX Stream Access only shows `vid_*` groups. The prefixes keep the namespaces separate.

### Data Flow: User Authentication via TAK client

1. User created in TAK Portal -> Authentik API creates user
2. User scans QR code in TAK client -> client connects to TAK Server :8089
3. TAK Server authenticates via LDAP (`LdapAuthenticator.java`)
4. TAK Server binds as service account -> `cn=adm_ldapservice,ou=users,dc=takldap`
5. TAK Server binds as user -> `cn={username},ou=users,dc=takldap` with user's password
6. LDAP outpost executes `ldap-authentication-flow` against Authentik core
7. If flow succeeds -> user authenticated -> TAK Server grants access

### External Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| Python 3 / Flask | Latest | Web console backend |
| Docker / Docker Compose | 29.x | Authentik, TAK Portal, Node-RED, CloudTAK |
| Caddy | Latest | Reverse proxy, auto-TLS, forward_auth |
| Authentik | 2025.12.4 | SSO, LDAP provider, proxy provider |
| TAK Server | 5.6-RELEASE-6 | CoT server, installed via .deb |
| Postfix | System | Email relay for password recovery |
| psutil | Latest | System metrics |

---

## 3. Development Environment

| Field | Value |
|---|---|
| **Language** | Python 3 (Flask), Jinja2 templates (inline in app.py), JavaScript (inline), YAML (blueprints) |
| **Framework** | Flask |
| **Platform** | Linux (Ubuntu 22.04/24.04, Rocky Linux 9) |
| **Build tools** | None (single-file app). `start.sh` bootstraps venv + systemd |
| **Config** | `.config/settings.json`, `.config/auth.json`, `.config/ssl/` |
| **Key constraint** | Entire app is a single 523KB `app.py` file with inline HTML/JS/CSS templates |

---

## 4. Design Decisions and Rationale

### 4.1 Single-file architecture (`app.py`)

- **Decision**: Everything in one file -- routes, templates, deploy logic, API calls
- **Why**: Simplifies deployment (just `git pull && restart`), no build step
- **Tradeoff**: File is 8500+ lines, difficult to navigate and debug
- **Risk**: Merge conflicts, hard for multiple developers

### 4.2 LDAP Blueprint vs API-only approach

- **Decision**: Use Authentik blueprints (`tak-ldap-setup.yaml`) to create LDAP provider, flow, outpost, and service account
- **Why**: Blueprints are idempotent and run on Authentik startup
- **Alternatives considered**: Pure API calls (used as fallback)
- **Tradeoff**: Blueprint behavior can be opaque; `state: created` only creates once, `state: present` updates every restart
- **Risk**: Blueprint errors are logged in worker but not surfaced to the user. The `search_full_directory` permission format causes a `ValueError` in recent Authentik versions

### 4.3 LDAP flow authentication setting

- **Decision**: The `ldap-authentication-flow` uses `authentication: none` (was `require_outpost`)
- **Why**: `require_outpost` caused "Flow does not apply to current user" -- the outpost was not recognized when executing user binds. The flow is only reachable via LDAP on port 389, so `none` adds no security risk.
- **Implementation**: Blueprint has `authentication: none`; "Connect TAK Server to LDAP" runs `_ensure_ldap_flow_authentication_none()` which PATCHes the live flow and restarts the LDAP outpost

### 4.4 LDAP outpost token injection

- **Decision**: Docker-compose starts LDAP with `AUTHENTIK_TOKEN: placeholder`, then Step 11 injects the real token and recreates the container
- **Why**: The real token doesn't exist until after Authentik is running and the blueprint creates the outpost
- **Risk**: If token injection fails, the LDAP outpost runs with an invalid token and stays unhealthy

### 4.5 Caddy forward_auth pattern

- **Decision**: Caddy uses `forward_auth 127.0.0.1:9090` with Authentik's embedded outpost
- **Why**: Native Caddy integration, no separate proxy container needed
- **Pattern**: `/outpost.goauthentik.io/*` routes must come before `forward_auth` in Caddy's `route` block
- **Backdoor**: `infratak.<fqdn>/login*` skips `forward_auth` so the console password login always works

### 4.6 Service account in authentik Admins group

- **Decision**: `adm_ldapservice` is added to the `authentik Admins` group (superuser)
- **Why**: Workaround for Authentik bug where `search_full_directory` permission doesn't work reliably
- **Risk**: Overprivileged service account

### 4.7 CoreConfig LDAP stanza -- matches TAK Portal reference

- **Decision**: The `<ldap>` element uses only the attributes from TAK Portal's known-good reference, plus `adminGroup="ROLE_ADMIN"`
- **Why**: Extra attributes (`style="DS"`, `ldapSecurityType="simple"`, `groupObjectClass`, `userObjectClass`, `matchGroupInChain`, `roleAttribute`) caused a phantom `user-profile.pref` push to TAK clients on connect. Stripping them fixed the issue. `adminGroup="ROLE_ADMIN"` is required for webadmin to access the admin console (without it, everyone gets WebTAK).
- **Reference stanza** (TAK Portal project `docs/authentik-tak-server.md`):
  ```xml
  <ldap url="ldap://..." userstring="cn={username},ou=users,dc=takldap"
    updateinterval="60" groupprefix="cn=tak_"
    groupNameExtractorRegex="cn=tak_(.*?)(?:,|$)"
    serviceAccountDN="cn=adm_ldapservice,ou=users,dc=takldap"
    serviceAccountCredential="..." groupBaseRDN="ou=groups,dc=takldap"
    userBaseRDN="ou=users,dc=takldap" dnAttributeName="DN" nameAttr="CN"/>
  ```
- **Our addition**: `adminGroup="ROLE_ADMIN"` appended (TAK Portal doesn't need it because their users access admin via cert auth on 8443, not LDAP on 8446)

### 4.8 CoreConfig auth block structure

- **Decision**: The `<auth>` block uses `<ldap .../>` before `<File .../>` (not the other way around)
- **Why**: Matches the known-good CoreConfig from a working deployment. Reversing the order caused issues.
- **Critical attributes on `<auth>`**: `x509groups="true"`, `x509useGroupCache="true"`, `x509useGroupCacheDefaultActive="true"`, `x509checkRevocation="true"` -- without these, TAK clients get disconnected when webadmin logs into 8446

### 4.9 CoreConfig LDAP detection

- **Decision**: Check for substring `adm_ldapservice` in CoreConfig, not `serviceAccountDN="cn=adm_ldapservice"`
- **Why**: The full attribute value is `serviceAccountDN="cn=adm_ldapservice,ou=users,dc=takldap"` -- checking for `serviceAccountDN="cn=adm_ldapservice"` (with closing `"`) never matches because `"` follows `dc=takldap`, not `adm_ldapservice`. This bug caused false negatives.

### 4.10 MediaMTX LDAP overlay (deploy-time patching)

- **Decision**: Keep one branch on the MediaMTX repo (vanilla editor). infra-TAK applies `mediamtx_ldap_overlay.py` at deploy time when Authentik is detected.
- **Why**: Standalone MediaMTX users get the vanilla editor unchanged. infra-TAK users get Authentik header auth + Stream Access page without maintaining a separate LDAP branch.
- **Implementation**: Copy overlay file, inject gated import (`LDAP_ENABLED` env var) before `app.run()`, set env vars in systemd service.

### 4.11 App access policies (automated)

- **Decision**: Auto-create and bind Authentik policies during Authentik deploy
- **Why**: Regular users should only see TAK Portal tile. Admins see everything. MediaMTX visible to vid_* group members.
- **Implementation**: `_ensure_app_access_policies()` creates "Allow authentik Admins" (group membership) and "Allow MediaMTX users" (expression policy checking vid_admin OR vid_private OR vid_public OR authentik Admins). Idempotent -- safe to run on every deploy.

---

## 5. Problems Encountered During Development

| # | Problem | Root Cause | Resolution |
|---|---|---|---|
| 1 | Recovery flow redirects to "Welcome to Authentik" | Wrong stage bindings | Rewrote to fetch ALL bindings, filter client-side |
| 2 | "When no user fields are selected..." (HTTP 400) | Creating separate identification stage | Reuse `default-authentication-identification` |
| 3 | "Forgot password?" link not showing | recovery_flow set on wrong stage | Set on `default-authentication-identification` |
| 4 | infratak bypasses Authentik login | route block missing forward_auth | Removed specific route; generic route handles all |
| 5 | LDAP service account path mismatch | path defaults to service-accounts | Added `path: users` to blueprint and API |
| 6 | ldapsearch always returns error 49 | Authentik LDAP outpost incompatibility | Check outpost Docker logs instead |
| 7 | "Flow does not apply to current user" | authentication: require_outpost | Changed to authentication: none |
| 8 | LDAP outpost unhealthy after deploy | Token still "placeholder" | Moved LDAP start to after token injection |
| 9 | search_full_directory ValueError | Authentik 2025.x permission format change | Service account in Admins group (workaround) |
| 10 | CoreConfig patch not applying | Regex required exact whitespace | Replaced with str.find() span replacement |
| 11 | CoreConfig LDAP detection false negative | Substring check matched wrong part | Check for `adm_ldapservice` substring only |
| 12 | webadmin not in LDAP after Authentik-first | Only created when /opt/tak existed | Added to Connect flow regardless of order |
| 13 | user-profile.pref phantom popup | Extra LDAP attributes (style, roleAttribute, etc.) | Stripped to match TAK Portal reference stanza |
| 14 | webadmin gets WebTAK not admin console | adminGroup="ROLE_ADMIN" was stripped | Added adminGroup back (the only extra attr needed) |
| 15 | Authentik not sending recovery emails | Postfix inet_interfaces=localhost, firewall blocking Docker | Auto-configure inet_interfaces=all, mynetworks, ufw/firewalld rules |
| 16 | MediaMTX editor not found at deploy | Clone dir deleted before file copied | Moved cleanup after copy+patching |

---

## 6. Patterns and Methods That Worked Well

### 6.1 Non-destructive flow binding management
Fetch ALL bindings across all flows, filter client-side. Only delete bindings on the target flow that shouldn't be there.

### 6.2 Outpost log verification
`docker logs authentik-ldap-1 --since Xs` for "authenticated" strings is the only reliable LDAP bind verification.

### 6.3 Idempotent API calls with fallback
POST to create -> catch 400 -> GET to find existing -> PATCH to update. Used for providers, applications, users, groups, and policies.

### 6.4 Blueprint + API redundancy
Blueprint creates resources on startup. API code also creates/ensures them. System works regardless of blueprint success.

### 6.5 Pre-LDAP backup
`CoreConfig.xml.pre-ldap.bak` created before patching. Only created once (won't overwrite).

### 6.6 TAK Portal reference as source of truth
LDAP stanza matches TAK Portal's `docs/authentik-tak-server.md` exactly (plus adminGroup). Any deviation causes issues.

### 6.7 Substring matching for config detection
Match unique substring (`adm_ldapservice`) rather than full `key="value"` pattern.

---

## 7. Known Limitations and Technical Debt

### HIGH

- `search_full_directory` permission throws `ValueError` in Authentik 2025.x blueprints -- workaround is superuser via Admins group
- Single 523KB `app.py` file
- No automated tests
- No CI/CD pipeline

### MEDIUM

- LDAP `bind_mode: cached` and `search_mode: cached` -- cache behavior during outpost recreation poorly understood
- Hardcoded LDAP base DN `DC=takldap` and group prefix `tak_`
- Inline HTML/JS/CSS in Python strings
- systemd service still named `takwerx-console`

### LOW

- Browser cache causes stale UI
- No rate limiting or CSRF protection beyond Flask session

---

## 8. Configuration and Setup Instructions

### Fresh Deployment

```bash
git clone -b dev https://github.com/takwerx/infra-TAK.git ~/infra-TAK
cd ~/infra-TAK && chmod +x start.sh && sudo ./start.sh
```

### Deployment Order (Authentik-first, verified 2026-02-23)

1. **Caddy** -- set FQDN and TLS
2. **Authentik** -- auto-creates recovery flow, LDAP, apps, access policies
3. **Email Relay** -- auto-configures Authentik SMTP + Postfix + firewall
4. **TAK Server** -- upload .deb and deploy
5. **Connect TAK Server to LDAP** -- button on TAK Server page
6. **TAK Portal** -- deploy
7. **MediaMTX** -- deploy (auto-applies LDAP overlay when Authentik present)
8. **Node-RED, CloudTAK** -- as needed

---

## 9. Critical Knowledge Transfer Notes

### Hidden Assumptions

- TAK Server is a **systemd service**, NOT Docker. `sudo systemctl restart takserver` after CoreConfig changes.
- LDAP outpost maps host port **389->3389** (not 389->389).
- `authentik_host` in LDAP outpost config = `http://authentik-server-1:9000/` (Docker internal). Embedded outpost = public URL. These are DIFFERENT.
- The LDAP stanza MUST match TAK Portal's reference. Extra attributes cause phantom device profile pushes.

### Gotchas

- **`ldapsearch` CLI is UNRELIABLE** against Authentik's LDAP outpost. Use Docker logs.
- **Authentik blueprints with `state: present`** re-apply on every restart. API changes get overwritten.
- **Browser cache** aggressively caches Authentik login pages. Hard refresh often needed.
- **`flow__pk` API filter on bindings is broken**. Always fetch all and filter client-side.
- **CoreConfig `.pre-ldap.bak`** is only created once. Don't overwrite.
- **Never check for `serviceAccountDN="cn=adm_ldapservice"`** (with closing quote). Check for `adm_ldapservice` substring.
- **CoreConfig auth block element order**: `<ldap .../>` before `<File .../>`.

### Edge-Case Logic That Must Not Be Removed

- `_ensure_authentik_recovery_flow`: Client-side binding filter (`target == recovery_flow_pk`) is critical
- `_ensure_authentik_ldap_service_account`: `path: 'users'` patch is required
- `generate_caddyfile`: `/login*` route without `forward_auth` is the backdoor
- `_coreconfig_has_ldap`: Must check `adm_ldapservice` substring, NOT full attribute
- `_apply_ldap_to_coreconfig`: Uses `str.find()` NOT regex. `<ldap>` before `<File>`.
- `_ensure_authentik_webadmin`: Must run during Connect flow regardless of deploy order
- `_ensure_app_access_policies`: Runs after all apps created in Authentik deploy. Idempotent.
