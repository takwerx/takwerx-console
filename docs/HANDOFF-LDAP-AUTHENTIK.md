# infra-TAK Technical Handoff Document

## 0. Current Session State (Last Updated: 2026-02-27)

**This section is the single source of truth.** Update it when server state changes. This doc is a living handoff between machines — only describe what is true right now.

### What's Deployed on the Server
- **Caddy** — running, TLS for subdomains
- **Authentik** — running (server, worker, postgres, redis, LDAP outpost)
- **TAK Server** — running (systemd), CoreConfig.xml has LDAP block (verified via `grep adm_ldapservice /opt/tak/CoreConfig.xml`)
- **TAK Portal** — running (Docker)
- **Email Relay** — running, SMTP + recovery flow configured in Authentik

### What Works
- All services deploy and run (Authentik-first deployment order verified on fresh VPS)
- Authentik SSO via Caddy forward_auth (infratak, takportal, nodered, mediamtx)
- Password recovery flow (forgot password → email → reset → login)
- TAK Server 8443 (cert auth), 8446 (password auth via LDAP)
- LDAP user authentication — CoreConfig patched, webadmin login on 8446 confirmed working against LDAP
- TAK Portal user creation → Authentik user creation
- "Connect TAK Server to LDAP" button: ensures flow auth=none, service account, webadmin in LDAP, CoreConfig patch, TAK Server restart

### What's Fixed (Previously Broken, Now Resolved)
- **"Flow does not apply to current user"** — Blueprint uses `authentication: none` on `ldap-authentication-flow`. Connect button runs `_ensure_ldap_flow_authentication_none()` to PATCH the live flow and restart the LDAP outpost.
- **CoreConfig patch not applying** — Was caused by two bugs: (1) regex required exactly 4 spaces before `<auth>` (didn't match TAK Server's actual indentation), (2) `_coreconfig_has_ldap()` checked for `serviceAccountDN="cn=adm_ldapservice"` which is never a substring of the actual value `serviceAccountDN="cn=adm_ldapservice,ou=users,dc=takldap"` (the `"` comes after `dc=takldap`, not after `adm_ldapservice`). Fixed: uses `str.find()` instead of regex, checks for `adm_ldapservice` substring.
- **Auth block child order** — Was generating `<File>` then `<ldap>`, but known-good CoreConfig has `<ldap>` then `<File>`. Fixed to match known-good structure.
- **`ldapsearch` not installed** — `_ensure_ldapsearch()` now auto-installs `ldap-utils` (Debian) or `openldap-clients` (RHEL) if missing. `_test_ldap_bind()` gracefully handles missing binary.
- **webadmin not in LDAP after Authentik-first deploy** — `_ensure_authentik_webadmin()` creates webadmin user in Authentik with `path=users` and `tak_ROLE_ADMIN` group during Connect flow.

### What's Broken (Only list if verified broken right now)
- *(None currently — update when a test confirms a failure)*
- **Note**: Device profiles prompt appeared during registration on 5.6 — needs investigation (may be a TAK Server 5.6 default, not an infra-TAK issue)

### What To Do Next (This Session)
1. Fresh VPS rebuild to verify end-to-end flow clean (tear down and rebuild)
2. After rebuild: enroll a TAK client, verify LDAP user auth end-to-end (QR → client connect → confirm no disconnect when webadmin logs into 8446)
3. Build two-server deployment support in TAK Server module

### What's Next / Work in Progress
- **In progress**: Two-server TAK Server deployment (Server 1 = DB via SSH, Server 2 = Core local). Plan agreed, building tomorrow.
- **Planned / Backlog**: Cloudflare Tunnel module for travel NUC/Pi deployments, Pi optimization, systemd service rename from `takwerx-console` to `infra-tak` (deferred to first non-alpha release)
- **Blocked / Waiting on**: Nothing
- **Ready to test**: Full Authentik-first deploy flow on fresh VPS (all LDAP/CoreConfig fixes pushed to dev)

### Server Access
```bash
# Pull latest code and restart console
cd ~/infra-TAK && git pull origin dev && sudo systemctl restart takwerx-console

# Verify LDAP is in CoreConfig (the real check — must say OK)
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
| **Current completion status** | Alpha. All modules deploy. LDAP authentication working (Authentik-first and TAK-first deploy orders both supported). Two-server deployment planned. |

---

## 2. System Architecture

### High-Level Components

```
┌─────────────────────────────────────────────────────────────┐
│  Caddy (reverse proxy, TLS termination, forward_auth)       │
│  - infratak.<fqdn>  → Flask app :5001 (via Authentik)       │
│  - authentik.<fqdn> → Authentik :9090                       │
│  - tak.<fqdn>       → TAK Server :8446                      │
│  - takportal.<fqdn> → TAK Portal :3000 (via Authentik)      │
│  - nodered.<fqdn>   → Node-RED :1880 (via Authentik)        │
│  - stream.<fqdn>    → MediaMTX :5080 (via Authentik)        │
│  - map.<fqdn>       → CloudTAK :5000                        │
└─────────────────────────────────────────────────────────────┘
         │
┌────────┴──────────────────────────────────────────┐
│  Authentik (SSO / IdP)                             │
│  - Server + Worker + PostgreSQL + Redis (Docker)   │
│  - Embedded Outpost (proxy provider, forward_auth) │
│  - LDAP Outpost (Docker, port 389→3389)            │
│  - Blueprints: tak-ldap-setup.yaml,                │
│                tak-embedded-outpost.yaml            │
└────────┬──────────────────────────────────────────┘
         │ LDAP bind (port 389)
┌────────┴──────────────────────────────────────────┐
│  TAK Server (systemd, /opt/tak)                    │
│  - CoreConfig.xml → <auth default="ldap">          │
│  - Service account: adm_ldapservice                │
│  - User auth: cn={username},ou=users,dc=takldap    │
│  - Ports: 8089 (TLS / TAK clients), 8443 (cert), 8446 (pw) │
└───────────────────────────────────────────────────┘
```

### Data Flow: User Authentication via TAK client

1. User created in TAK Portal → Authentik API creates user
2. User scans QR code in TAK client → client connects to TAK Server :8089
3. TAK Server authenticates via LDAP (`LdapAuthenticator.java`)
4. TAK Server binds as service account → `cn=adm_ldapservice,ou=users,dc=takldap`
5. TAK Server binds as user → `cn={username},ou=users,dc=takldap` with user's password
6. LDAP outpost executes `ldap-authentication-flow` against Authentik core
7. If flow succeeds → user authenticated → TAK Server grants access

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

- **Decision**: Everything in one file — routes, templates, deploy logic, API calls
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
- **Why**: `require_outpost` caused "Flow does not apply to current user" — the outpost was not recognized when executing user binds. The flow is only reachable via LDAP on port 389, so `none` adds no security risk.
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

### 4.7 CoreConfig auth block structure

- **Decision**: The `<auth>` block uses `<ldap .../>` before `<File .../>` (not the other way around)
- **Why**: Matches the known-good CoreConfig from a working deployment. Reversing the order caused issues.
- **Critical attributes**: `x509groups="true"`, `x509useGroupCache="true"`, `x509useGroupCacheDefaultActive="true"`, `updateinterval="60"` — without these, the admin GUI is slow, and TAK clients get disconnected when webadmin logs into 8446

### 4.8 CoreConfig LDAP detection

- **Decision**: Check for substring `adm_ldapservice` in CoreConfig, not `serviceAccountDN="cn=adm_ldapservice"`
- **Why**: The full attribute value is `serviceAccountDN="cn=adm_ldapservice,ou=users,dc=takldap"` — checking for `serviceAccountDN="cn=adm_ldapservice"` (with closing `"`) never matches because `"` follows `dc=takldap`, not `adm_ldapservice`. This bug caused false negatives for hours.

---

## 5. Problems Encountered During Development

| # | Problem | Root Cause | Symptoms | Resolution | Prevention Strategy |
|---|---|---|---|---|---|
| 1 | Recovery flow redirects to "Welcome to Authentik" | `_ensure_authentik_recovery_flow` was binding wrong stages and deleting stages from other flows | After clicking password reset email, user sees generic welcome page | Rewrote function to fetch ALL bindings, filter client-side by `target == recovery_flow_pk`, only delete extraneous bindings on the recovery flow | Always filter bindings client-side; never trust `flow__pk` API filter |
| 2 | "When no user fields are selected, at least one source must be selected" (HTTP 400) | Creating a separate "Recovery Identification" stage without `user_fields` | Configure Authentik fails with validation error | Reuse `default-authentication-identification` stage instead of creating a new one; include `user_fields` in PATCH body | Reuse existing default stages where possible |
| 3 | "Forgot password?" link not showing | `recovery_flow` was set on wrong identification stage; also browser cache | Link absent from login page | Set `recovery_flow` on `default-authentication-identification`; hard refresh browser | Always target the default identification stage |
| 4 | `infratak.<fqdn>` bypasses Authentik login | A `route /` block directly proxied to Flask without `forward_auth` | Accessing infratak.fqdn showed console without login | Removed specific `route /` block; generic `route { ... }` with `forward_auth` handles all paths | Only two routes for infratak: `/login*` (no auth) and `{ ... }` (auth) |
| 5 | LDAP service account path mismatch | `type: service_account` defaults `path` to `service-accounts`, giving DN `ou=service-accounts` | `ldapsearch` returns "Invalid credentials (49)" because bind DN uses `ou=users` | Added `path: users` to blueprint and API creation; PATCH existing users' path | Always explicitly set `path: users` for any user that needs LDAP bind via `ou=users` |
| 6 | `ldapsearch` CLI always returns error 49 | Authentik LDAP outpost incompatibility with `ldapsearch` CLI tool | `ldapsearch` fails but outpost logs show "authenticated from session" | Changed verification to check outpost Docker logs for "authenticated" instead of `ldapsearch` exit code | Never use `ldapsearch` exit code as verification against Authentik's LDAP outpost |
| 7 | "Flow does not apply to current user" | `ldap-authentication-flow` had `authentication: require_outpost`; outpost not recognized for user binds | TAK Server got `LDAP error code 49` for user binds | Blueprint changed to `authentication: none`; Connect button runs `_ensure_ldap_flow_authentication_none()` to PATCH flow + restart outpost | Blueprint and Connect button both ensure flow has `authentication: none` |
| 8 | LDAP outpost unhealthy after deploy | LDAP container started with `AUTHENTIK_TOKEN: placeholder` before real token was available | Outpost stays unhealthy, 403 errors | Moved LDAP start to after token injection (Step 11) | Never start LDAP outpost before injecting real token |
| 9 | `search_full_directory` permission ValueError | Authentik 2025.x changed permission format to require `app_label.codename` | Blueprint apply fails silently in worker logs | Added service account to `authentik Admins` group as workaround | Monitor Authentik changelog for permission API changes |
| 10 | JavaScript syntax errors in templates | Missing function declarations, unclosed try/catch blocks in inline JS | Browser console errors; buttons don't work | Fixed `connectLdap()` try/catch, wrapped `showAkPassword` in proper function declaration | Lint inline JavaScript; consider extracting to separate files |
| 11 | File upload "nothing happens" | Browser doesn't fire `change` event if file input value unchanged | User selects files but upload doesn't start | Clear `input.value = ''` in onclick before triggering file dialog | Always reset file input value before opening dialog |
| 12 | `add_user` API wrong body format | Used `{"user": uid}` instead of `{"pk": uid}` | Service account not added to Admins group | Changed to `{"pk": uid}` per Authentik API docs | Check Authentik API schema for exact field names |
| 13 | No feedback after LDAP connect | Button disappeared after click with no success/error indication | User doesn't know if operation succeeded | Added alert() popup on success, green status banner when connected | Always provide explicit success/failure feedback for destructive operations |
| 14 | CoreConfig backup overwritten | Multiple LDAP connect attempts overwrote the pre-LDAP backup with an already-patched version | Can't revert to pre-LDAP state | Only create backup if `.pre-ldap.bak` doesn't already exist | Check existence before creating backup |
| 15 | CoreConfig patch regex too strict | Regex `r'    <auth[^>]*>.*?</auth>'` required exactly 4 spaces before `<auth>` | Patch silently failed when TAK Server used different indentation; returned false "success" | Replaced regex with `str.find('<auth')` / `str.find('</auth>')` span replacement — no regex | Never use whitespace-dependent regex on XML files you don't control |
| 16 | CoreConfig LDAP detection false negative | Checked for `serviceAccountDN="cn=adm_ldapservice"` — the `"` after `adm_ldapservice` never matches because the actual value continues with `,ou=users,dc=takldap"` | `_coreconfig_has_ldap()` always returned False; Connect button kept appearing; CLI grep said FAIL when LDAP was actually there | Changed all checks to look for `adm_ldapservice` substring | When checking for attribute presence, match the unique part of the value, not the full `key="value"` |
| 17 | Auth block child element order wrong | Generated `<File>` then `<ldap>` but known-good CoreConfig has `<ldap>` then `<File>` | Potential XML parsing differences in TAK Server | Matched known-good CoreConfig structure exactly: `<ldap .../>` first, `<File .../>` second | Always compare generated config against a verified working file |
| 18 | `ldapsearch` binary missing on fresh VPS | `ldap-utils` / `openldap-clients` not installed by default on minimal Ubuntu | `[Errno 2] No such file or directory: 'ldapsearch'` crashed the Connect flow | Added `_ensure_ldapsearch()` to auto-install; `_test_ldap_bind()` gracefully handles missing binary | Auto-install CLI dependencies before using them |
| 19 | webadmin not created in Authentik-first deploy | `run_authentik_deploy` only created webadmin when `/opt/tak` existed (TAK-first); Authentik-first skipped it | 8446 login failed after LDAP patch because webadmin only existed in local file auth, not LDAP | Added `_ensure_authentik_webadmin()` to Connect flow — creates webadmin in Authentik with correct group/path | Connect flow must be self-contained: create all required users regardless of deploy order |

---

## 6. Patterns and Methods That Worked Well

### 6.1 Non-destructive flow binding management
The recovery flow function fetches ALL bindings across all flows, then filters client-side. It only deletes bindings that are on the recovery flow but shouldn't be, and only adds missing ones. This prevents accidentally breaking the authentication flow.

### 6.2 Outpost log verification
Checking `docker logs authentik-ldap-1 --since Xs` for "authenticated" strings is the only reliable way to verify LDAP binds against Authentik's outpost. `ldapsearch` CLI exit codes are unreliable.

### 6.3 Idempotent API calls with fallback
Pattern: POST to create → catch 400 → GET to find existing → PATCH to update. Used consistently for providers, applications, users, and groups.

### 6.4 Blueprint + API redundancy
The blueprint creates resources on Authentik startup. The API code also creates/ensures them. This redundancy means the system works regardless of whether the blueprint applied successfully.

### 6.5 Pre-LDAP backup
`CoreConfig.xml.pre-ldap.bak` is created before patching, enabling clean revert: `sudo cp /opt/tak/CoreConfig.xml.pre-ldap.bak /opt/tak/CoreConfig.xml && sudo systemctl restart takserver`

### 6.6 Known-good CoreConfig as reference
Always compare generated XML against a verified working CoreConfig. The known-good file was provided by the user from a working deployment and used to fix auth block structure (element order, attribute order).

### 6.7 Substring matching for config detection
When checking if a config file contains a specific block, match the unique substring (`adm_ldapservice`) rather than a full `key="value"` pattern that may not be a valid substring of the actual attribute.

---

## 7. Known Limitations and Technical Debt

### HIGH

- `search_full_directory` permission throws `ValueError` in Authentik 2025.x blueprints — workaround is superuser via Admins group (overprivileged)
- Single 523KB `app.py` file — extremely difficult to maintain, debug, and review
- No automated tests
- Commit messages are inconsistent ("new", "n" for many commits)
- No CI/CD pipeline

### MEDIUM

- LDAP `bind_mode: cached` and `search_mode: cached` — cache behavior during outpost recreation is poorly understood
- Hardcoded LDAP base DN `DC=takldap` throughout — not configurable
- Hardcoded LDAP group prefix `tak_` — not configurable
- `adminGroup="ROLE_ADMIN"` hardcoded in CoreConfig LDAP block
- Inline HTML/JS/CSS in Python strings — no syntax highlighting, no linting, no minification
- No HTTPS for LDAP (uses `ldapSecurityType="simple"`)
- systemd service still named `takwerx-console` (rename deferred to first non-alpha release)

### LOW

- Browser cache causes stale UI (recovery link, login page)
- `Session cookie domain` handling has edge cases between IP and FQDN access
- No rate limiting on API endpoints
- No CSRF protection beyond Flask session
- Device profiles prompt appearing during registration on TAK Server 5.6 (needs investigation)

---

## 8. Configuration and Setup Instructions

### Fresh Deployment

```bash
# 1. Clone repository
git clone -b dev https://github.com/takwerx/infra-TAK.git ~/infra-TAK

# 2. Run setup (creates venv, installs deps, generates certs, starts systemd service)
cd ~/infra-TAK && sudo bash start.sh

# 3. Access console
# Via IP (backdoor): https://<server-ip>:5001
# Set admin password on first access
```

### Deployment Order (Both orders work — Authentik-first verified on fresh VPS 2026-02-27)

**Option A: TAK Server first (original order)**
1. **Caddy** — reverse proxy + TLS
2. **TAK Server** — deploy via console UI (upload .deb/.rpm)
3. **Authentik** — deploy via console UI (auto-patches CoreConfig with LDAP if TAK Server exists)
4. **Email Relay** — deploy, then "Configure Authentik" (SMTP + recovery flow)
5. **TAK Portal** — deploy via console UI
6. **Node-RED, MediaMTX, CloudTAK** — deploy as needed

**Option B: Authentik first (verified working)**
1. **Caddy** — reverse proxy + TLS
2. **Authentik** — deploy via console UI
3. **Email Relay** — deploy, then "Configure Authentik" (SMTP + recovery flow)
4. **TAK Server** — deploy via console UI (upload .deb/.rpm)
5. **Connect TAK Server to LDAP** — button on TAK Server page (patches CoreConfig, creates webadmin in LDAP)
6. **TAK Portal** — deploy via console UI
7. **Node-RED, MediaMTX, CloudTAK** — deploy as needed

### Environment Variables (in `~/authentik/.env`)

| Variable | Purpose |
|---|---|
| `AUTHENTIK_BOOTSTRAP_TOKEN` | API token for Authentik admin operations |
| `AUTHENTIK_BOOTSTRAP_PASSWORD` | Initial akadmin password |
| `AUTHENTIK_BOOTSTRAP_LDAPSERVICE_USERNAME` | LDAP service account username (default: `adm_ldapservice`) |
| `AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD` | LDAP service account password (auto-generated) |
| `AUTHENTIK_BOOTSTRAP_LDAP_BASEDN` | LDAP base DN (default: `DC=takldap`) |
| `AUTHENTIK_BOOTSTRAP_LDAP_AUTHENTIK_HOST` | Internal Docker URL for LDAP outpost → Authentik core (must be `http://authentik-server-1:9000/`) |
| `AUTHENTIK_HOST` | Public URL for embedded outpost (e.g., `https://authentik.<fqdn>`) |

### Common Setup Errors

| Error | Cause | Fix |
|---|---|---|
| "Request has been denied" on login | Recovery flow function accidentally deleted auth flow bindings | Fixed in code; if recurring, check `default-authentication-flow` bindings in Authentik admin |
| LDAP outpost unhealthy | Token still "placeholder" | Check `docker exec authentik-ldap-1 env \| grep TOKEN` — if it says "placeholder", re-run Authentik deploy |
| Port 389 not listening | LDAP container not started or crashed | `cd ~/authentik && docker compose up -d ldap && docker logs authentik-ldap-1` |
| 8446 WebGUI login fails after LDAP | webadmin not in Authentik/LDAP | Run "Connect TAK Server to LDAP" again (creates webadmin in Authentik) |
| CoreConfig shows no LDAP after Connect says success | Old bug: substring check was wrong | Fixed: now checks for `adm_ldapservice` substring. Verify: `grep -q adm_ldapservice /opt/tak/CoreConfig.xml && echo OK` |
| TAK clients kicked when webadmin logs into 8446 | CoreConfig missing x509 cache attributes | Fixed: auth block includes `x509groups`, `x509useGroupCache`, `x509useGroupCacheDefaultActive`, `updateinterval="60"` |

---

## 9. Operational Workflow

### Console Access
- **Backdoor**: `https://<ip>:5001/login` — always works, uses console admin password
- **Domain**: `https://infratak.<fqdn>` — behind Authentik when deployed; `/login` path bypasses Authentik

### Module Deployment
1. Navigate to module page in sidebar
2. Click "Deploy" button
3. Real-time deployment log streams to UI
4. Module status updates automatically

### LDAP Connection Flow
1. Deploy TAK Server → Deploy Authentik (or reverse order)
2. TAK Server page shows "Connect TAK Server to LDAP" button (only when CoreConfig lacks LDAP)
3. Button calls `POST /api/takserver/connect-ldap`
4. Backend (in order): (1) `_ensure_ldap_flow_authentication_none()` — PATCH flow to `authentication: none`, restart LDAP outpost; (2) `_ensure_authentik_ldap_service_account()` — service account + bind verification; (3) `_ensure_authentik_webadmin()` — webadmin user in Authentik/LDAP; (4) `_apply_ldap_to_coreconfig()` — find `<auth>...</auth>` by string search (no regex), splice in known-good LDAP block, write via `sudo cp`, verify with `grep`, restart TAK Server
5. Green status banner shows "LDAP Connected to Authentik"

### Verification
```bash
# CoreConfig has LDAP (the definitive check)
grep -q 'adm_ldapservice' /opt/tak/CoreConfig.xml && echo OK || echo FAIL

# Then test 8446 login as webadmin in browser
# Both must pass to confirm LDAP is working
```

### Key API Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /api/takserver/connect-ldap` | LDAP flow fix + service account + webadmin sync + CoreConfig patch |
| `POST /api/takserver/control` | Start/stop/restart TAK Server |
| `POST /api/takportal/control` | Start/stop/restart/update TAK Portal |
| `POST /api/authentik/configure` | Configure SMTP + recovery flow |
| `POST /api/caddy/save` | Regenerate and reload Caddyfile |

---

## 10. Future Roadmap / Recommended Improvements

### COMPLETED — LDAP User Authentication
- Blueprint uses `authentication: none` on `ldap-authentication-flow`
- "Connect TAK Server to LDAP" runs full setup: flow fix, service account, webadmin, CoreConfig patch
- Both Authentik-first and TAK-first deploy orders work
- CoreConfig detection and patching use reliable substring matching (no regex)

### SHORT-TERM (Next)
- **Two-server TAK Server deployment**: Single UI flow — user picks 1-server or 2-server, uploads core + database `.deb` files, provides DB server IP + SSH credentials. infra-TAK SSHes into Server 1 (DB) to install `takserver-database`, then installs `takserver-core` locally on Server 2, patches CoreConfig `<connection>` to remote DB. (Server 1 = DB, Server 2 = Core per official TAK Server guide numbering.)
- **Cloudflare Tunnel module**: For travel NUC/Pi deployments — install `cloudflared`, configure tunnel to TAK ports, stable FQDN from any network, no VPN required on clients
- **Verify end-to-end on fresh VPS**: Enroll a TAK client, confirm no disconnect when webadmin uses 8446

### MEDIUM-TERM

- **Refactor app.py**: Split into modules (routes, templates, services, deploy logic)
- **Add tests**: At minimum, test LDAP bind verification, CoreConfig patching, Caddyfile generation
- **Fix `search_full_directory` permission**: Track Authentik issue for proper `app_label.codename` format
- **Make LDAP configurable**: Base DN, group prefix, admin group should be in settings.json
- **Extract inline templates**: Move HTML/JS/CSS to separate files
- **Add proper logging**: Replace `plog()` with Python logging module
- **Commit message standards**: Enforce conventional commits
- **Rename systemd service**: `takwerx-console` → `infra-tak` (first non-alpha release, tell users to start fresh)

### LONG-TERM

- **CI/CD pipeline**: Automated testing, linting, deployment
- **Pi optimization**: Test on Pi 4 8GB, document `takserver-noplugins`, Java heap tuning, SSD recommendation
- **Penetration testing**: See TESTING.md for planned approach
- **TLS for LDAP**: Switch from `ldapSecurityType="simple"` to LDAPS on port 636
- **Reduce service account privileges**: Find alternative to Admins group workaround

---

## 11. Critical Knowledge Transfer Notes

### Hidden Assumptions

- TAK Server is a **systemd service**, not Docker. `systemctl restart takserver` is required after CoreConfig changes.
- The LDAP outpost container maps host port **389→3389** (not 389→389).
- `authentik_host` in the LDAP outpost config MUST be `http://authentik-server-1:9000/` (Docker internal name). NOT `localhost`, NOT the public domain.
- The embedded outpost `authentik_host` MUST be the public URL (`https://authentik.<fqdn>`). These are DIFFERENT from the LDAP outpost's `authentik_host`.
- The app runs as root (via systemd), so writing to `/opt/tak/CoreConfig.xml` uses `sudo cp` from a temp file in the app directory for reliability.

### Gotchas

- **`ldapsearch` CLI is UNRELIABLE against Authentik's LDAP outpost**. It returns error 49 even when the outpost successfully authenticates the user. The outpost logs are the source of truth.
- **`ldapsearch` may not be installed** on minimal Ubuntu. `_ensure_ldapsearch()` auto-installs it. If it's still missing, the bind test skips it gracefully.
- **Authentik blueprints with `state: present` re-apply on every restart**. API changes to resources managed by blueprints will be overwritten. Change the blueprint source in `app.py` to make persistent changes.
- **Authentik blueprints with `state: created` only apply once**. If the initial creation fails, the blueprint won't retry.
- **Browser cache** aggressively caches Authentik login pages. Hard refresh (Ctrl+Shift+R) is often needed after flow changes.
- **`flow__pk` API filter on bindings is broken** in Authentik. Always fetch all bindings and filter client-side.
- **`set_password` API returns 204 (success) but the password may not be usable via LDAP** if the authentication flow rejects the user for non-password reasons.
- **CoreConfig.xml `.pre-ldap.bak`** is only created once. If it gets overwritten with an LDAP-patched version, manual recovery is needed.
- **Never check for `serviceAccountDN="cn=adm_ldapservice"`** (with closing quote) — it's not a valid substring. Check for `adm_ldapservice` instead.
- **CoreConfig auth block element order matters**: `<ldap .../>` must come before `<File .../>` to match the known-good structure.
- **SMTP and Authentik config are intentionally separate steps** — user may change email providers and only needs to update Authentik, not redeploy.

### Edge-Case Logic That Must Not Be Removed

- `_ensure_authentik_recovery_flow`: The client-side binding filter (`target == recovery_flow_pk`) is critical. Do not revert to server-side `flow__pk` filter.
- `_ensure_authentik_ldap_service_account`: The `path: 'users'` patch is required. Without it, service accounts get DN `ou=service-accounts` which doesn't match CoreConfig's bind DN.
- `generate_caddyfile`: The `/login*` route without `forward_auth` is the backdoor. Removing it locks out the admin if Authentik is down.
- `_test_ldap_bind`: Must check Docker outpost logs, not `ldapsearch` exit code.
- `_coreconfig_has_ldap`: Must check for `adm_ldapservice` substring, NOT `serviceAccountDN="cn=adm_ldapservice"`.
- `_apply_ldap_to_coreconfig`: Uses `str.find()` span replacement, NOT regex. The auth block must have `<ldap>` before `<File>`.
- `_ensure_authentik_webadmin`: Must run during Connect flow regardless of deploy order. Creates webadmin in Authentik with `path=users` and `tak_ROLE_ADMIN` group.

---

## 12. File-Level Breakdown

### `app.py` (~8700 lines)

| Line Range | Section | Purpose |
|---|---|---|
| 1-90 | Flask setup | App config, session, cookie domain, imports |
| 90-127 | Config management | `load_settings()`, `save_settings()`, `load_auth()` |
| 128-210 | Module detection | `detect_modules()` — checks installed services |
| 210-685 | Console routes | Dashboard, settings, update, metrics |
| 688-865 | Caddy | `generate_caddyfile()` — reverse proxy config generation |
| 865-1190 | TAK Server | Deploy, upload, status, control routes |
| 1190-1690 | TAK Portal | Deploy, control, update, uninstall routes |
| 1690-2460 | Certs/Misc | Certificate management, various utility routes |
| 2460-2995 | CloudTAK | Deploy, control routes |
| 2995-3080 | Email Relay | Deploy, Authentik SMTP config |
| 3082-3308 | Recovery Flow | `_ensure_authentik_recovery_flow()` |
| 3308-3660 | Authentik Apps | `_ensure_authentik_nodered_app()`, `_ensure_authentik_console_app()` |
| 3660-3900 | Node-RED | Deploy, control routes |
| 3900-5010 | MediaMTX | Deploy, config, control routes |
| 5010-5100 | TAK Portal Template | HTML/CSS/JS for TAK Portal page |
| 5100-5600 | Authentik Template | HTML/CSS/JS for Authentik page |
| 5600-5810 | LDAP Blueprint | `tak-ldap-setup.yaml` content |
| 5810-6580 | Authentik Deploy | `run_authentik_deploy()` (Steps 1-12) |
| 6580-6950 | Authentik Templates | HTML for LDAP status, configuration |
| ~6980 | LDAP Detection | `_coreconfig_has_ldap()` — checks for `adm_ldapservice` substring |
| ~6990-7020 | LDAP Utilities | `_ensure_ldapsearch()`, `_test_ldap_bind()` |
| ~7020-7100 | LDAP Flow Fix | `_ensure_ldap_flow_authentication_none()` |
| ~7100-7200 | LDAP Service Account | `_ensure_authentik_ldap_service_account()` |
| ~7200-7270 | CoreConfig Patch | `_apply_ldap_to_coreconfig()` — str.find() span replacement |
| ~7270-7340 | WebAdmin Sync | `_ensure_authentik_webadmin()` |
| ~7340-7370 | Connect Endpoint | `takserver_connect_ldap()` — orchestrates all LDAP steps |
| ~7370-7830 | TAK Server Deploy | `run_takserver_deploy()` (Steps 1-9) |
| ~7830-8700 | TAK Server Template | HTML/CSS/JS for TAK Server page + remaining templates |

### `start.sh` (~320 lines)

- OS detection and dependency installation
- Python venv creation
- First-time password setup
- SSL certificate generation
- Systemd service creation and start
- Branding: "infra-TAK — Team Awareness Kit Infrastructure Platform"

### `fix-console-after-pull.sh` (1KB)

- Fixes CONFIG_DIR path in systemd after `git pull` changes working directory

### `reset-console-password.sh` (1.3KB)

- Resets admin password from CLI

### Blueprint: `tak-ldap-setup.yaml` (generated at deploy time)

- Creates `adm_ldapservice` user (service_account, path=users)
- Creates `ldap-authentication-flow` with `authentication: none`, identification → password → login stages
- Creates LDAP provider (base_dn=DC=takldap, bind_mode=cached)
- Creates LDAP application
- Creates LDAP outpost (type=ldap)
- Grants `search_full_directory` permission to service account

### Blueprint: `tak-embedded-outpost.yaml` (generated at deploy time)

- Sets `authentik_host` on the embedded (proxy) outpost to the public Authentik URL
