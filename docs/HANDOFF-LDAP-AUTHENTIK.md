# infra-TAK Technical Handoff Document

## 0. Current Session State (Last Updated: 2026-02-27)

### What's Deployed on the Server Right Now
- **Caddy** — running, TLS working for all subdomains
- **Authentik** — running (server, worker, postgres, redis, LDAP outpost all healthy)
- **TAK Server** — running (systemd), CoreConfig.xml HAS the LDAP block patched in
- **TAK Portal** — running (Docker, healthy)
- **Email Relay** — running, SMTP configured in Authentik, password recovery flow works end-to-end

### What Works
- All services deploy and run
- Authentik SSO via Caddy forward_auth (infratak, takportal, nodered, mediamtx subdomains)
- Password recovery flow (forgot password → email → reset → login)
- Service account LDAP bind (`adm_ldapservice`) — works from cache
- TAK Server 8443 (cert auth) and 8446 (password auth with file-based users)
- TAK Portal user creation → Authentik user creation
- "LDAP Connected to Authentik" status banner shows on TAK Server page

### What's Broken — THE BLOCKER
**ATAK users cannot authenticate via LDAP.** When a user created in TAK Portal tries to connect via ATAK (scans QR code), TAK Server tries to authenticate them via LDAP and gets `error code 49 - Invalid Credentials`.

**Root cause**: The `ldap-authentication-flow` in the Authentik blueprint has `authentication: require_outpost`. When the LDAP outpost tries to execute this flow for a real user bind, Authentik rejects it with "Flow does not apply to current user." The service account only works because it was cached during outpost startup.

**LDAP outpost logs show**:
```
{"bindDN":"cn=ajjohanssoncacor,ou=users,dc=takldap","error":"Flow does not apply to current user.","event":"failed to execute flow"}
```

**TAK Server logs show**:
```
javax.naming.AuthenticationException: [LDAP: error code 49 - Invalid Credentials]
  at com.bbn.marti.groups.LdapAuthenticator.connect(LdapAuthenticator.java:328)
```

### What To Do Next
1. **In `app.py` (~line 5660)**: Change `authentication: require_outpost` to `authentication: none` in the `ldap-authentication-flow` blueprint YAML
2. **In `_ensure_authentik_ldap_service_account()` (~line 7003)**: Add an API call to PATCH the existing `ldap-authentication-flow` to `authentication: none` (so it fixes existing deployments without redeploying Authentik)
3. **Restart the LDAP outpost** after the flow change
4. **Test with a real user** (not just the service account) — create user in TAK Portal, scan QR in ATAK, verify TAK Server authenticates via LDAP
5. After LDAP works: deploy CloudTAK, then Node-RED, then MediaMTX (in that order)

### Things Already Tried That Didn't Fix It
- Changing `bind_mode` from `cached` to `direct` — same error
- Changing `search_mode` from `cached` to `direct` — same error  
- PATCH `authentication: none` on the flow via API alone (without restarting outpost) — same error
- Force-recreating the LDAP outpost — same error
- The API PATCH may have succeeded but the outpost was returning cached flow data; the fix likely needs BOTH the API change AND a full outpost restart together

### Server Access
```bash
# Pull latest code and restart console
cd ~/infra-TAK && git pull && sudo systemctl restart takwerx-console

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
| **Current completion status** | Alpha. All modules deploy. **CRITICAL BLOCKER**: LDAP user authentication fails when Authentik is deployed before TAK Server. Service account bind works; user binds fail with "Flow does not apply to current user." |

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
│  - Ports: 8089 (TLS/ATAK), 8443 (cert), 8446 (pw) │
└───────────────────────────────────────────────────┘
```

### Data Flow: User Authentication via ATAK

1. User created in TAK Portal → Authentik API creates user
2. User scans QR code in ATAK → ATAK connects to TAK Server :8089
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

### 4.3 `authentication: require_outpost` on LDAP flow

- **Decision**: The `ldap-authentication-flow` uses `authentication: require_outpost`
- **Why**: Security — only the LDAP outpost should execute this flow
- **THIS IS THE CURRENT BLOCKER**: The outpost is not being recognized as an outpost when executing user binds, causing "Flow does not apply to current user"
- **Attempted fixes**: Changing `bind_mode` from `cached` to `direct`, changing `authentication` to `none` — neither fully resolved the issue
- **Recommended fix**: See Section 10

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
| 7 | **CURRENT BLOCKER**: "Flow does not apply to current user" | `ldap-authentication-flow` has `authentication: require_outpost` but outpost isn't recognized when executing user binds | TAK Server gets `LDAP error code 49` for all user binds; service account works from cache | **UNRESOLVED** — see Section 10 | See Section 10 |
| 8 | LDAP outpost unhealthy after deploy | LDAP container started with `AUTHENTIK_TOKEN: placeholder` before real token was available | Outpost stays unhealthy, 403 errors | Moved LDAP start to after token injection (Step 11) | Never start LDAP outpost before injecting real token |
| 9 | `search_full_directory` permission ValueError | Authentik 2025.x changed permission format to require `app_label.codename` | Blueprint apply fails silently in worker logs | Added service account to `authentik Admins` group as workaround | Monitor Authentik changelog for permission API changes |
| 10 | JavaScript syntax errors in templates | Missing function declarations, unclosed try/catch blocks in inline JS | Browser console errors; buttons don't work | Fixed `connectLdap()` try/catch, wrapped `showAkPassword` in proper function declaration | Lint inline JavaScript; consider extracting to separate files |
| 11 | File upload "nothing happens" | Browser doesn't fire `change` event if file input value unchanged | User selects files but upload doesn't start | Clear `input.value = ''` in onclick before triggering file dialog | Always reset file input value before opening dialog |
| 12 | `add_user` API wrong body format | Used `{"user": uid}` instead of `{"pk": uid}` | Service account not added to Admins group | Changed to `{"pk": uid}` per Authentik API docs | Check Authentik API schema for exact field names |
| 13 | No feedback after LDAP connect | Button disappeared after click with no success/error indication | User doesn't know if operation succeeded | Added alert() popup on success, green status banner when connected | Always provide explicit success/failure feedback for destructive operations |
| 14 | CoreConfig backup overwritten | Multiple LDAP connect attempts overwrote the pre-LDAP backup with an already-patched version | Can't revert to pre-LDAP state | Only create backup if `.pre-ldap.bak` doesn't already exist | Check existence before creating backup |

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

---

## 7. Known Limitations and Technical Debt

### CRITICAL

- **LDAP user authentication broken when Authentik deployed before TAK Server**: The `ldap-authentication-flow` with `authentication: require_outpost` rejects user binds. Service account bind works from cache. This is the primary blocker for the Authentik-first deployment order.

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

### LOW

- Browser cache causes stale UI (recovery link, login page)
- `Session cookie domain` handling has edge cases between IP and FQDN access
- No rate limiting on API endpoints
- No CSRF protection beyond Flask session

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

### Deployment Order (RECOMMENDED — the order that previously worked)

1. **Caddy** — reverse proxy + TLS
2. **TAK Server** — deploy via console UI (upload .deb/.rpm)
3. **Authentik** — deploy via console UI (creates LDAP blueprint, outpost, service account)
4. **Email Relay** — deploy, then "Configure Authentik" (SMTP + recovery flow)
5. **TAK Portal** — deploy via console UI
6. **Connect TAK Server to LDAP** — button on TAK Server page
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
| 8446 WebGUI login fails | CoreConfig has LDAP but LDAP bind is broken | Revert: `sudo cp /opt/tak/CoreConfig.xml.pre-ldap.bak /opt/tak/CoreConfig.xml && sudo systemctl restart takserver` |

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
1. Deploy TAK Server → Deploy Authentik
2. TAK Server page shows "Connect TAK Server to LDAP" button
3. Button calls `POST /api/takserver/connect-ldap`
4. Backend: ensures service account → verifies bind → patches CoreConfig → restarts TAK Server
5. Green status banner shows "LDAP Connected to Authentik"

### Key API Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /api/takserver/connect-ldap` | One-shot LDAP setup + CoreConfig patch |
| `POST /api/takserver/control` | Start/stop/restart TAK Server |
| `POST /api/takportal/control` | Start/stop/restart/update TAK Portal |
| `POST /api/authentik/configure` | Configure SMTP + recovery flow |
| `POST /api/caddy/save` | Regenerate and reload Caddyfile |

---

## 10. Future Roadmap / Recommended Improvements

### IMMEDIATE — Fix LDAP User Authentication (BLOCKER)

**Problem**: `ldap-authentication-flow` has `authentication: require_outpost`. The LDAP outpost is not recognized as an outpost when executing user bind flows, causing "Flow does not apply to current user."

**Root cause hypothesis**: The outpost authenticates to Authentik core using its `AUTHENTIK_TOKEN`. When processing a user bind, the outpost calls the flow executor API. If the outpost's token doesn't have the correct scope or the outpost isn't registered as an "outpost" identity, the `require_outpost` check fails.

**Recommended investigation steps**:
1. Check if the LDAP outpost token is valid: `curl -s http://127.0.0.1:9090/api/v3/core/tokens/?identifier=<token-identifier> -H "Authorization: Bearer $AK_TOKEN"` 
2. Check the outpost's managed field and status in Authentik admin → Outposts
3. Try changing the flow to `authentication: none` AND recreating the LDAP outpost (both changes together)
4. Compare with the deployment where TAK Server was deployed first — in that case, did the blueprint apply before or after the outpost token was injected?
5. Check Authentik version-specific behavior for `require_outpost` — it may require the outpost to present its token in a specific header format
6. **Most promising fix**: Change the blueprint to use `authentication: none` on the `ldap-authentication-flow`. The LDAP outpost is the only consumer of this flow (it's not exposed to web users), so `require_outpost` adds no real security benefit. The flow is only reachable via the LDAP protocol, which is only exposed on port 389.
7. After changing the blueprint, delete the existing flow in Authentik admin (or PATCH via API to `authentication: none`), then restart Authentik so the blueprint re-creates it with the correct setting

**Why previous attempts failed**:
- Changing `authentication: none` via API was tried but the outpost may have been returning cached flow data
- The outpost needs to be fully restarted after the flow changes
- The blueprint has `state: present` which re-applies on every Authentik restart — if you only change via API without changing the blueprint, the blueprint will overwrite it

**The fix must change BOTH**:
1. The blueprint YAML in `app.py` (line ~5660): change `authentication: require_outpost` to `authentication: none`
2. PATCH the existing flow via API after changing the blueprint
3. Restart the LDAP outpost

### MEDIUM-TERM

- **Refactor app.py**: Split into modules (routes, templates, services, deploy logic)
- **Add tests**: At minimum, test LDAP bind verification, CoreConfig patching, Caddyfile generation
- **Fix `search_full_directory` permission**: Track Authentik issue for proper `app_label.codename` format
- **Make LDAP configurable**: Base DN, group prefix, admin group should be in settings.json
- **Extract inline templates**: Move HTML/JS/CSS to separate files
- **Add proper logging**: Replace `plog()` with Python logging module
- **Commit message standards**: Enforce conventional commits

### LONG-TERM

- **CI/CD pipeline**: Automated testing, linting, deployment
- **Multi-server support**: Currently assumes single VPS
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

### Gotchas

- **`ldapsearch` CLI is UNRELIABLE against Authentik's LDAP outpost**. It returns error 49 even when the outpost successfully authenticates the user. The outpost logs are the source of truth.
- **Authentik blueprints with `state: present` re-apply on every restart**. API changes to resources managed by blueprints will be overwritten. Change the blueprint source in `app.py` to make persistent changes.
- **Authentik blueprints with `state: created` only apply once**. If the initial creation fails, the blueprint won't retry.
- **Browser cache** aggressively caches Authentik login pages. Hard refresh (Ctrl+Shift+R) is often needed after flow changes.
- **`flow__pk` API filter on bindings is broken** in Authentik. Always fetch all bindings and filter client-side.
- **`set_password` API returns 204 (success) but the password may not be usable via LDAP** if the authentication flow rejects the user for non-password reasons.
- **CoreConfig.xml `.pre-ldap.bak`** is only created once. If it gets overwritten with an LDAP-patched version, manual recovery is needed.

### Edge-Case Logic That Must Not Be Removed

- `_ensure_authentik_recovery_flow`: The client-side binding filter (`target == recovery_flow_pk`) is critical. Do not revert to server-side `flow__pk` filter.
- `_ensure_authentik_ldap_service_account`: The `path: 'users'` patch is required. Without it, service accounts get DN `ou=service-accounts` which doesn't match CoreConfig's bind DN.
- `generate_caddyfile`: The `/login*` route without `forward_auth` is the backdoor. Removing it locks out the admin if Authentik is down.
- `_test_ldap_bind`: Must check Docker outpost logs, not `ldapsearch` exit code.

---

## 12. File-Level Breakdown

### `app.py` (523KB, ~8500 lines)

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
| 6950-7000 | LDAP Detection | `_coreconfig_has_ldap()` |
| 7000-7090 | LDAP Service Account | `_test_ldap_bind()`, `_ensure_authentik_ldap_service_account()` |
| 7090-7160 | LDAP CoreConfig | `_apply_ldap_to_coreconfig()`, `takserver_connect_ldap()` |
| 7160-8100 | TAK Server Template | HTML/CSS/JS for TAK Server page |
| 8100-8450 | Remaining Templates | Misc pages, footer, main block |

### `start.sh` (10KB)

- OS detection and dependency installation
- Python venv creation
- First-time password setup
- SSL certificate generation
- Systemd service creation and start

### `fix-console-after-pull.sh` (1KB)

- Fixes CONFIG_DIR path in systemd after `git pull` changes working directory

### `reset-console-password.sh` (1.3KB)

- Resets admin password from CLI

### Blueprint: `tak-ldap-setup.yaml` (generated at deploy time)

- Creates `adm_ldapservice` user (service_account, path=users)
- Creates `ldap-authentication-flow` with identification → password → login stages
- Creates LDAP provider (base_dn=DC=takldap, bind_mode=cached)
- Creates LDAP application
- Creates LDAP outpost (type=ldap)
- Grants `search_full_directory` permission to service account

### Blueprint: `tak-embedded-outpost.yaml` (generated at deploy time)

- Sets `authentik_host` on the embedded (proxy) outpost to the public Authentik URL
