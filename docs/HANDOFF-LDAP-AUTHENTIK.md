# infra-TAK Technical Handoff Document

## 0. Current Session State (Last Updated: 2026-03-02)

**This section is the single source of truth.** Update it when server state changes. This doc is a living handoff between machines -- only describe what is true right now.

### LDAP Bind Issue — RESOLVED

**Status:** LDAP bind is WORKING. Service account bind, user search, and TAK Server LDAP authentication all confirmed functional.

**Server:** `root@responder` (190.102.110.224)

**Root Cause (Authentik 2026.2.0 breaking change):**

In Authentik 2026.2.0, the LDAP outpost reads the provider's `authorization_flow` as its `bind_flow_slug` — this is the flow used for LDAP bind operations. The `authentication_flow` field is NOT used by the outpost for binds.

We had `authorization_flow` set to `default-provider-authorization-implicit-consent` (a consent-only flow with no identification/password/login stages). The outpost ran this flow for every bind, which never created an authenticated session. The follow-up `/api/v3/core/users/me/` call got 403 "Authentication credentials were not provided" because no session existed.

**Fix:** Set `authorization_flow` on the LDAP provider to `ldap-authentication-flow` (the same flow used for `authentication_flow`). This flow has identification, password, and user login stages, so a proper session is created during bind.

**What was also fixed along the way:**
- Added "Allow LDAP Access" expression policy (`return True`) to the LDAP application (needed because `policy_engine_mode: any` with 0 bindings = deny all)
- LDAP outpost image updated from 2025.12.4 to 2026.2.0 to match the server version
- `AUTHENTIK_COOKIE_DOMAIN` restored to `.test.takwerx.com` (required for SSO across subdomains)

**What was wrong (root cause identified and partially fixed):**

The Authentik blueprint (`~/authentik/blueprints/tak-ldap-setup.yaml`) defined LDAP flow stages with two properties that caused an infinite recursion loop in the LDAP outpost:

1. **`configure_flow: !Find [authentik_flows.flow, [slug, default-password-change]]`** on the password stage (`ldap-authentication-password`) — When the outpost executed the password stage, it triggered a redirect to the password-change flow, which looped back infinitely.
2. **`password_stage: !KeyOf ldap-authentication-password`** on the identification stage (`ldap-identification-stage`) — This embedded the password stage inside the identification stage, creating a double-password pattern that confused the LDAP outpost's flow executor.

Because the blueprint uses `state: present`, Authentik re-applied these broken stage configurations on **every restart**, overwriting any API-level fixes.

**What has been fixed (in app.py on local machine):**

The blueprint definition in `app.py` (lines ~6340-6364) has been updated:
- Removed `configure_flow: !Find [authentik_flows.flow, [slug, default-password-change]]` from the password stage
- Removed `password_stage: !KeyOf ldap-authentication-password` from the identification stage
- Removed `authentik.sources.ldap.auth.LDAPBackend` from password stage backends (not needed)
- Removed `- email` from identification stage `user_fields` (LDAP only needs username)

**What has been done on the live server:**

1. Blueprint file on server (`~/authentik/blueprints/tak-ldap-setup.yaml`) was updated via `sed` — the four problematic lines were removed. Verified clean.
2. The original blueprint stages (`ldap-identification-stage`, `ldap-authentication-password`, `ldap-authentication-login`) were no longer in the API (had been deleted during debugging). They should be recreated by blueprint reconciliation on Authentik restart.
3. Three manually-created API stages (`ldap-identification`, `ldap-password`, `ldap-login`) were cleaned up (deleted via API).
4. Authentik server + worker were restarted. Blueprint should have reconciled and recreated stages.
5. LDAP outpost was force-recreated (`docker compose up -d --force-recreate ldap`).
6. Password was set via API for user pk=54.
7. `adm_ldapservice` (pk=54) **is confirmed in `authentik Admins` group** (verified via API, the group has users [4, 49, 54]).

**What still fails and needs investigation:**

```
ldap_bind: Insufficient access (50)
```
Outpost log: `"Access denied for user"` (NOT "exceeded stage recursion depth" — that's fixed).

This means the password stage succeeded (the user was authenticated) but the LDAP provider/application denied access. Possible causes to investigate:

1. **Flow bindings may be broken** — When Step 4 ran (`Verify LDAP flow now has the blueprint's stages`), the output was EMPTY — meaning the flow has NO stage bindings. The blueprint may not have recreated them properly because we also manually deleted and created bindings via API earlier, leaving the flow in an inconsistent state. **Check first:** `curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9090/api/v3/flows/bindings/?target=3e3c6348-439d-4cae-8818-28a3c64fdfae&ordering=order"` and verify 3 bindings exist (identification order 10, password order 15, login order 20).

2. **`search_full_directory` permission not assigned** — The blueprint assigns this permission via `permissions: [{permission: search_full_directory, user: !KeyOf ldap-service-account}]` on the LDAP provider model. But user pk=54 was created via API (not blueprint), so `!KeyOf ldap-service-account` may reference a stale/different user object. The RBAC assign API returned HTTP 405 when we tried manually. Being in `authentik Admins` (superuser group) should bypass this, but may not for LDAP provider access specifically.

3. **LDAP application policy binding** — There's a policy "Allow authentik Admins" bound to the LDAP application. If this binding got corrupted or deleted during our debugging, the application would deny access. Check: `curl -s -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:9090/api/v3/core/applications/?search=LDAP'` and verify the app exists and has correct provider.

4. **Stale outpost configuration** — The outpost may have cached the old flow (with broken stages). Even after `--force-recreate`, if Authentik server hasn't fully reconciled the blueprint, the outpost gets stale data. Try: restart authentik server+worker, wait 60s, then recreate LDAP outpost.

**Fix applied (2026-03-01):**

`_ensure_ldap_flow_authentication_none()` in app.py now ensures the 3 stage bindings exist when the flow exists but has none (e.g. after manual deletion during debugging). When you run "Connect TAK Server to LDAP" in infra-TAK, it will:
1. Patch authentication to none
2. Check bindings count — if < 3, find stages by name and create bindings via API
3. Force-recreate LDAP outpost (`docker compose up -d --force-recreate ldap`)

**To fix on live server:** Run "Connect TAK Server to LDAP" from the TAK Server page in infra-TAK. Or run the diagnostic script: `./scripts/ldap-diagnose-and-fix.sh` (from repo root on server).

**If bindings still empty after Connect:** Trigger blueprint reconciliation: `cd ~/authentik && docker compose restart worker && sleep 45`, then run Connect again.

**Diagnostic commands (run from `~/authentik`):**

```bash
TOKEN=$(grep AUTHENTIK_BOOTSTRAP_TOKEN ~/authentik/.env | cut -d= -f2)

# 1. Check flow bindings (should show 3 stages)
echo "=== Flow bindings ==="
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/api/v3/flows/bindings/?target=3e3c6348-439d-4cae-8818-28a3c64fdfae&ordering=order" | \
  python3 -c "import sys,json; r=json.loads(sys.stdin.read())['results']; [print(f'  order={b[\"order\"]} stage={b.get(\"stage_obj\",{}).get(\"name\",\"?\")}') for b in r]"

# 2. Check LDAP application + provider
echo "=== LDAP app ==="
curl -s -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:9090/api/v3/core/applications/?search=LDAP' | \
  python3 -c "import sys,json; r=json.loads(sys.stdin.read())['results']; [print(f'  name={a[\"name\"]} provider={a.get(\"provider\")} slug={a[\"slug\"]}') for a in r]"

# 3. Check LDAP provider details
echo "=== LDAP provider ==="
curl -s -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:9090/api/v3/providers/ldap/?search=LDAP' | \
  python3 -c "import sys,json; r=json.loads(sys.stdin.read())['results']; [print(f'  pk={p[\"pk\"]} name={p[\"name\"]} auth_flow={p.get(\"authorization_flow\")} bind_mode={p.get(\"bind_mode\")}') for p in r]"

# 4. Check user
echo "=== User ==="
curl -s -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:9090/api/v3/core/users/54/' | \
  python3 -c "import sys,json; u=json.loads(sys.stdin.read()); print(f'  pk={u[\"pk\"]} username={u[\"username\"]} active={u[\"is_active\"]} groups={[g[\"name\"] for g in u.get(\"groups_obj\",[])]}')"

# 5. Check outpost logs
echo "=== Recent LDAP outpost logs ==="
docker compose logs ldap --tail=10 --no-log-prefix 2>/dev/null

# 6. Test bind
LDAP_PASS=$(grep AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD ~/authentik/.env | cut -d= -f2-)
echo "=== Bind test ==="
ldapsearch -x -H ldap://127.0.0.1:389 -D 'cn=adm_ldapservice,ou=users,dc=takldap' -w "$LDAP_PASS" -b 'dc=takldap' -s base '(objectClass=*)' 2>&1 | head -5
```

### What's Deployed on the Server
- **Caddy** -- running, TLS for subdomains
- **Authentik** -- running (server, worker, postgres, redis, LDAP outpost). Blueprint file has been fixed (configure_flow and password_stage removed).
- **TAK Server** -- STOPPED (`sudo systemctl stop takserver` — stopped during LDAP debugging to prevent connection flooding)
- **TAK Portal** -- running (Docker)
- **Email Relay** -- running, SMTP + recovery flow auto-configured in Authentik
- **MediaMTX** -- running (LDAP overlay deployed, stream visibility, share links, themed viewer all working)

### What Works (Verified)
- All services deploy and run (Authentik-first deployment order verified on fresh VPS)
- Authentik SSO via Caddy forward_auth (infratak, takportal, nodered, mediamtx subdomains)
- Password recovery flow (forgot username or password -> email -> reset -> login)
- TAK Server 8443 (cert auth), 8446 (password auth via LDAP, admin console works for webadmin)
- TAK Portal user creation -> Authentik user creation
- **No user-profile.pref popup** -- fixed by stripping extra LDAP attributes
- **Authentik SMTP auto-configuration** -- Email Relay deploy auto-configures Postfix inet_interfaces, mynetworks, firewall rules
- **App access policies** -- auto-created on Authentik deploy
- **MediaMTX LDAP overlay** -- fully working: Authentik header auth, Web Users page, stream visibility (public/private), tokenized share links, themed viewer page, self-healing overlay
- **TAK Portal dashboard metrics** -- working (requires full TAK_URL with `:8443/Marti`)
- **TAK Portal email auto-config** -- pulls SMTP settings from Email Relay module if deployed
- **TAK Portal group filtering** -- `GROUPS_HIDDEN_PREFIXES` hides `vid_` and `tak_ROLE_` groups

### What's Broken (Verified)
- **LDAP bind fails with "Insufficient access (50)"** — See CRITICAL section above. This blocks TAK Server LDAP auth and QR registration.

### Changes Made to app.py in This Session

1. **Blueprint fix (CRITICAL)** — Removed `configure_flow`, `password_stage`, `LDAPBackend`, and `email` user field from `tak-ldap-setup.yaml` blueprint definition (lines ~6340-6364). This fixes the root cause of `exceeded stage recursion depth`.

2. **Blueprint password line removal (prior session)** — Removed `password: !Context password` from the `authentik_core.user` model in the blueprint. This prevented Authentik from overwriting the service account password on every restart.

3. **LDAP verification block** — Added comprehensive LDAP verification at end of `run_authentik_deploy` (ensures `authentication: none`, resets password, verifies bind).

4. **TAK Portal email auto-config** — `_portal_email_settings()` helper populates email settings from Email Relay config.

5. **TAK Portal TAK_URL fix** — Includes `:8443/Marti` when FQDN is set.

6. **Self-healing MediaMTX overlay** — `ensure_overlay.py` re-injects overlay on service start if upstream updates overwrite it.

### Key Files Changed
- `app.py` — Blueprint fix (configure_flow/password_stage removed), LDAP verification, TAK Portal email/URL fixes, MediaMTX self-healing overlay
- `mediamtx_ldap_overlay.py` — Stream visibility, share links, themed viewer, External Sources UI, Admin Active Streams UI

### Server Access
```bash
# SSH
ssh root@63.250.55.132

# Pull latest code and restart console
cd ~/infra-TAK && git pull origin dev && sudo systemctl restart takwerx-console

# Run LDAP diagnostic script (run from repo root)
./scripts/ldap-diagnose-and-fix.sh

# Fix LDAP bindings: Use infra-TAK UI → TAK Server → Connect TAK Server to LDAP
# Or manually: the Connect button runs _ensure_ldap_flow_authentication_none() which now recreates missing bindings

# Start TAK Server (currently stopped)
sudo systemctl start takserver

# Check LDAP outpost logs
cd ~/authentik && docker compose logs ldap --tail=20 --no-log-prefix

# Test LDAP bind
LDAP_PASS=$(grep AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD ~/authentik/.env | cut -d= -f2-)
ldapsearch -x -H ldap://127.0.0.1:389 -D 'cn=adm_ldapservice,ou=users,dc=takldap' -w "$LDAP_PASS" -b 'dc=takldap' -s base '(objectClass=*)'
```

### Application visibility (authentik.fqdn)
- **Admins** (users in group *authentik Admins*): see all applications (infra-TAK, Node-RED, TAK Portal, MediaMTX, LDAP, etc.).
- **Regular users**: see only **TAK Portal** and **MediaMTX** (stream). infra-TAK and Node-RED are not listed and are not accessible (proxy returns 403 if they try the URL directly).

---

## 1. Project Overview

| Field | Value |
|---|---|
| **Project name** | infra-TAK |
| **Version** | 0.1.7-alpha |
| **Purpose** | Unified web console for deploying and managing TAK ecosystem infrastructure (TAK Server, Authentik SSO, LDAP, Caddy reverse proxy, TAK Portal, Node-RED, MediaMTX, CloudTAK, Email Relay) |
| **Intended users** | System administrators deploying TAK (Team Awareness Kit) infrastructure |
| **Operating environment** | Ubuntu 22.04/24.04 or Rocky Linux 9, single VPS, accessible via `https://<ip>:5001` (backdoor) or `https://infratak.<fqdn>` (behind Authentik) |
| **Current completion status** | Alpha. All modules deploy. LDAP blueprint fixed in code. Active LDAP bind access issue on live server. |

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
|    - Web Users page at /stream-access                 |
|    - Stream visibility: public/private toggle         |
|    - Tokenized share links (4h/8h/12h/24h TTL)       |
|    - Themed viewer page (/viewer)                     |
|    - vid_private/vid_public -> Active Streams only    |
|  - Without Authentik: vanilla editor (local login)    |
+------------------------------------------------------+
```

### App Access Policy Model

| App | Who sees the tile | Policy |
|---|---|---|
| TAK Portal | All authenticated users | No binding (open) |
| MediaMTX | authentik Admins + vid_private + vid_public | Expression: Allow MediaMTX users |
| infra-TAK, Node-RED, LDAP | authentik Admins only | Group membership: Allow authentik Admins |

### LDAP Group Namespaces

| Prefix | Used by | Purpose |
|---|---|---|
| `tak_` | TAK Server, TAK Portal, TAK clients | Missions, roles, agency groups |
| `vid_` | MediaMTX | Stream access (vid_private, vid_public) |
| `authentik-` | TAK Portal agencies | Agency admin groups |

TAK Portal hides `vid_*` and `tak_ROLE_*` groups via `GROUPS_HIDDEN_PREFIXES`. MediaMTX Web Users only shows `vid_*` groups.

### Data Flow: User Authentication via TAK client

1. User created in TAK Portal -> Authentik API creates user
2. User scans QR code in TAK client -> client connects to TAK Server :8089
3. TAK Server authenticates via LDAP (`LdapAuthenticator.java`)
4. TAK Server binds as service account -> `cn=adm_ldapservice,ou=users,dc=takldap`
5. TAK Server binds as user -> `cn={username},ou=users,dc=takldap` with user's password
6. LDAP outpost executes `ldap-authentication-flow` against Authentik core
7. If flow succeeds -> user authenticated -> TAK Server grants access

### LDAP Authentication Flow (Blueprint-Defined)

The `ldap-authentication-flow` is defined in `tak-ldap-setup.yaml` blueprint with:
- `authentication: none` (required — `require_outpost` causes "Flow does not apply" errors)
- 3 stages:
  - **order 10**: `ldap-identification-stage` — `user_fields: [username]`, NO `password_stage` (CRITICAL: having `password_stage` causes recursion)
  - **order 15**: `ldap-authentication-password` — backends: `[InbuiltBackend, TokenBackend]`, NO `configure_flow` (CRITICAL: having `configure_flow` causes recursion)
  - **order 20**: `ldap-authentication-login` — simple user login stage
- LDAP provider: `bind_mode: cached`, `search_mode: cached`, `mfa_support: false`

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
| **Key constraint** | Entire app is a single ~550KB `app.py` file with inline HTML/JS/CSS templates |

---

## 4. Design Decisions and Rationale

### 4.1 Single-file architecture (`app.py`)

- **Decision**: Everything in one file -- routes, templates, deploy logic, API calls
- **Why**: Simplifies deployment (just `git pull && restart`), no build step
- **Tradeoff**: File is 9000+ lines, difficult to navigate and debug
- **Risk**: Merge conflicts, hard for multiple developers

### 4.2 LDAP Blueprint vs API-only approach

- **Decision**: Use Authentik blueprints (`tak-ldap-setup.yaml`) to create LDAP provider, flow, outpost, and service account
- **Why**: Blueprints are idempotent and run on Authentik startup
- **Alternatives considered**: Pure API calls (used as fallback)
- **Tradeoff**: Blueprint behavior can be opaque; `state: created` only creates once, `state: present` updates every restart
- **CRITICAL LESSON**: Blueprint `state: present` OVERWRITES API changes on every Authentik restart. Any manual API fix to stages/bindings will be lost. The blueprint file itself must be correct.

### 4.3 LDAP flow stage design (CRITICAL — learned the hard way)

- **Decision**: LDAP flow stages must NOT have `configure_flow` or embedded `password_stage`
- **Why**: The LDAP outpost executes flows programmatically (not via browser). When the password stage has a `configure_flow`, a failed password check redirects to the password-change flow, which loops back. When the identification stage has `password_stage` embedded, it creates a double-password collection pattern. Both cause `exceeded stage recursion depth` in the outpost.
- **Symptoms**: Outpost logs show `"error":"exceeded stage recursion depth","event":"failed to execute flow"`. The bind returns `Invalid credentials (49)`.
- **Why it was hidden**: `bind_mode: cached` means the outpost caches successful bind sessions. When the flow worked once (before the recursion bug was triggered), the cache masked the problem. Only when caches expired or were cleared (restart, recreate) did the actual broken flow execution surface.
- **Resolution**: Removed `configure_flow` and `password_stage` from the blueprint. Also removed `LDAPBackend` (not needed) and `email` from user_fields (LDAP uses username only).

### 4.4 LDAP flow authentication setting

- **Decision**: The `ldap-authentication-flow` uses `authentication: none` (was `require_outpost`)
- **Why**: `require_outpost` caused "Flow does not apply to current user" -- the outpost was not recognized when executing user binds. The flow is only reachable via LDAP on port 389, so `none` adds no security risk.
- **Implementation**: Blueprint has `authentication: none`; "Connect TAK Server to LDAP" runs `_ensure_ldap_flow_authentication_none()` which PATCHes the live flow and restarts the LDAP outpost

### 4.5 LDAP outpost token injection

- **Decision**: Docker-compose starts LDAP with `AUTHENTIK_TOKEN: placeholder`, then Step 11 injects the real token and recreates the container
- **Why**: The real token doesn't exist until after Authentik is running and the blueprint creates the outpost
- **Risk**: If token injection fails, the LDAP outpost runs with an invalid token and stays unhealthy

### 4.6 Caddy forward_auth pattern

- **Decision**: Caddy uses `forward_auth 127.0.0.1:9090` with Authentik's embedded outpost
- **Why**: Native Caddy integration, no separate proxy container needed
- **Pattern**: `/outpost.goauthentik.io/*` routes must come before `forward_auth` in Caddy's `route` block
- **Backdoor**: `infratak.<fqdn>/login*` skips `forward_auth` so the console password login always works
- **MediaMTX bypasses**: `/watch/*`, `/hls-proxy/*`, `/shared/*`, `/shared-hls/*` bypass `forward_auth` on the stream subdomain for public/shared stream access

### 4.7 Service account in authentik Admins group

- **Decision**: `adm_ldapservice` is added to the `authentik Admins` group (superuser)
- **Why**: Workaround for Authentik bug where `search_full_directory` permission doesn't work reliably
- **Risk**: Overprivileged service account

### 4.8 CoreConfig LDAP stanza -- matches TAK Portal reference

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
- **Our addition**: `adminGroup="ROLE_ADMIN"` appended

### 4.9 CoreConfig auth block structure

- **Decision**: The `<auth>` block uses `<ldap .../>` before `<File .../>` (not the other way around)
- **Why**: Matches the known-good CoreConfig from a working deployment. Reversing the order caused issues.
- **Critical attributes on `<auth>`**: `x509groups="true"`, `x509useGroupCache="true"`, `x509useGroupCacheDefaultActive="true"`, `x509checkRevocation="true"` -- without these, TAK clients get disconnected when webadmin logs into 8446

### 4.10 CoreConfig LDAP detection

- **Decision**: Check for substring `adm_ldapservice` in CoreConfig, not `serviceAccountDN="cn=adm_ldapservice"`
- **Why**: The full attribute value is `serviceAccountDN="cn=adm_ldapservice,ou=users,dc=takldap"` -- checking for `serviceAccountDN="cn=adm_ldapservice"` (with closing `"`) never matches because `"` follows `dc=takldap`, not `adm_ldapservice`. This bug caused false negatives.

### 4.11 MediaMTX LDAP overlay (deploy-time patching)

- **Decision**: Keep one branch on the MediaMTX repo (vanilla editor). infra-TAK applies `mediamtx_ldap_overlay.py` at deploy time when Authentik is detected.
- **Why**: Standalone MediaMTX users get the vanilla editor unchanged. infra-TAK users get Authentik header auth + Stream Access page without maintaining a separate LDAP branch.
- **Implementation**: Copy overlay file, inject gated import (`LDAP_ENABLED` env var) before `app.run()`, set env vars in systemd service.
- **Self-healing**: `ensure_overlay.py` runs as `ExecStartPre` in the systemd service. If the upstream editor self-updates and overwrites the overlay injection, this script re-applies it on every service start.

### 4.12 App access policies (automated)

- **Decision**: Auto-create and bind Authentik policies during Authentik deploy
- **Why**: Regular users should only see TAK Portal tile. Admins see everything. MediaMTX visible to vid_* group members.
- **Implementation**: `_ensure_app_access_policies()` creates "Allow authentik Admins" (group membership) and "Allow MediaMTX users" (expression policy checking vid_private OR vid_public OR authentik Admins). Idempotent -- safe to run on every deploy.

### 4.13 Blueprint password management

- **Decision**: The blueprint `authentik_core.user` model does NOT set `password` (the line `password: !Context password` was removed)
- **Why**: With `state: created`, Authentik only applies the user model once. But `state: present` or blueprint reconciliation could overwrite the API-set password with a hashed version of the env var, causing LDAP bind failures. The password is set exclusively via the Authentik API (`/api/v3/core/users/{pk}/set_password/`) after user creation.
- **CRITICAL LESSON**: Never set password in blueprints for service accounts that need to authenticate via LDAP. The password must be set via API to ensure proper hashing.

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
| 17 | **"exceeded stage recursion depth"** | **Blueprint password stage had `configure_flow` pointing to default-password-change; identification stage had embedded `password_stage`** | **Removed both from blueprint. The `configure_flow` redirected on auth failure, creating infinite loop. The embedded `password_stage` created double-password pattern. Fixed in blueprint definition in app.py.** |
| 18 | **Blueprint overwrites API fixes** | **`state: present` in blueprint re-applies stage config on every Authentik restart** | **Must fix the blueprint file itself, not just API. Any API-only fix gets overwritten.** |
| 19 | **Blueprint overwrites service account password** | **`password: !Context password` in user model caused password drift** | **Removed password line from blueprint user model. Password set exclusively via API.** |
| 20 | **"Access denied for user" after flow fix** | **Likely missing flow bindings or stale permission state after extensive API manipulation** | **IN PROGRESS — see Critical section above** |

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

### 6.8 Blueprint debugging methodology
When LDAP breaks: check outpost logs FIRST for the specific error. "exceeded stage recursion depth" = flow stage problem. "Access denied" = permission/authorization problem. "Invalid credentials (49)" = password mismatch. Don't change passwords if the error is about stages.

---

## 7. Known Limitations and Technical Debt

### HIGH

- **LDAP "Insufficient access" on live server** — Active issue, see Section 0
- `search_full_directory` permission throws `ValueError` in Authentik 2025.x blueprints -- workaround is superuser via Admins group
- Single 550KB `app.py` file
- No automated tests
- No CI/CD pipeline

### MEDIUM

- LDAP `bind_mode: cached` and `search_mode: cached` -- cache behavior during outpost recreation poorly understood. Cache masks flow execution bugs until it expires.
- Hardcoded LDAP base DN `DC=takldap` and group prefix `tak_`
- Inline HTML/JS/CSS in Python strings
- systemd service still named `takwerx-console`
- VM needs 8+ cores / 16GB+ RAM for all services (4-core machines get overloaded during cascading restarts)

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
6. **TAK Portal** -- deploy (auto-configures email if relay deployed, TAK_URL with :8443/Marti)
7. **MediaMTX** -- deploy (auto-applies LDAP overlay when Authentik present, self-healing on update)
8. **Node-RED, CloudTAK** -- as needed

---

## 9. Critical Knowledge Transfer Notes

### Hidden Assumptions

- TAK Server is a **systemd service**, NOT Docker. `sudo systemctl restart takserver` after CoreConfig changes.
- LDAP outpost maps host port **389->3389** (not 389->389).
- `authentik_host` in LDAP outpost config = `http://authentik-server-1:9000/` (Docker internal). Embedded outpost = public URL. These are DIFFERENT.
- The LDAP stanza MUST match TAK Portal's reference. Extra attributes cause phantom device profile pushes.
- `adm_ldapservice` user pk is **54** on the current server (was recreated during debugging — original was pk=48).

### Gotchas

- **`ldapsearch` CLI is UNRELIABLE** against Authentik's LDAP outpost. Use Docker logs.
- **Authentik blueprints with `state: present`** re-apply on every restart. API changes get overwritten. FIX THE BLUEPRINT FILE.
- **Browser cache** aggressively caches Authentik login pages. Hard refresh often needed.
- **`flow__pk` API filter on bindings is broken**. Always fetch all and filter client-side.
- **CoreConfig `.pre-ldap.bak`** is only created once. Don't overwrite.
- **Never check for `serviceAccountDN="cn=adm_ldapservice"`** (with closing quote). Check for `adm_ldapservice` substring.
- **CoreConfig auth block element order**: `<ldap .../>` before `<File .../>`.
- **LDAP flow stages MUST NOT have `configure_flow` or `password_stage`** — causes `exceeded stage recursion depth`.
- **LDAP outpost caches flow execution results** — `docker compose up -d --force-recreate ldap` required after flow changes.
- **Password MUST be set via API**, never via blueprint. Use `/api/v3/core/users/{pk}/set_password/`.
- **4-core VMs struggle** under full load. Cascading restarts of Authentik + TAK Server can spike load to 25+ and cause all services to become unresponsive.

### Edge-Case Logic That Must Not Be Removed

- `_ensure_authentik_recovery_flow`: Client-side binding filter (`target == recovery_flow_pk`) is critical
- `_ensure_authentik_ldap_service_account`: `path: 'users'` patch is required
- `generate_caddyfile`: `/login*` route without `forward_auth` is the backdoor
- `generate_caddyfile`: `/watch/*`, `/hls-proxy/*`, `/shared/*`, `/shared-hls/*` bypass `forward_auth` on stream subdomain
- `_coreconfig_has_ldap`: Must check `adm_ldapservice` substring, NOT full attribute
- `_apply_ldap_to_coreconfig`: Uses `str.find()` NOT regex. `<ldap>` before `<File>`.
- `_ensure_authentik_webadmin`: Must run during Connect flow regardless of deploy order
- `_ensure_app_access_policies`: Runs after all apps created in Authentik deploy. Idempotent.
- `ensure_overlay.py`: Self-healing script that re-injects LDAP overlay if upstream editor updates overwrite it. Runs as `ExecStartPre` in systemd service.

### Authentik LDAP Flow Architecture (MUST understand to debug)

```
LDAP Bind Request (port 389)
  → LDAP Outpost Container (authentik-ldap-1)
    → Extracts username from bind DN (cn=USERNAME,ou=users,dc=takldap)
    → Checks session cache (bind_mode: cached)
      → If cached session matches DN+password hash: return success immediately
      → If no cache hit: execute ldap-authentication-flow
        → Stage 1 (order 10): ldap-identification-stage
          - Finds user by username field
          - MUST NOT have password_stage (causes recursion)
        → Stage 2 (order 15): ldap-authentication-password
          - Verifies password against InbuiltBackend
          - MUST NOT have configure_flow (causes recursion)
        → Stage 3 (order 20): ldap-authentication-login
          - Creates session
        → Flow complete: bind succeeds
    → After successful flow: cache the session
    → Return LDAP bind result to client
```

Error decoding:
- `exceeded stage recursion depth` = flow stage misconfiguration (configure_flow, password_stage, MFA)
- `Invalid credentials (49)` = password wrong OR flow failed to execute
- `Insufficient access (50)` / `Access denied for user` = user authenticated but not authorized for LDAP provider
- `authenticated from session` in logs = using cached bind (may mask underlying flow issues)
