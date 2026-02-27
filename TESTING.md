# TAKWERX Console — Testing Guide

> **v0.1.5-alpha** — This guide covers what is functional, what is placeholder, and what testers should focus on for this release.

---

## Test Environment Requirements

- Fresh Ubuntu 22.04 LTS VPS (4+ vCPU, 8GB+ RAM, 50GB+ disk)
- A domain name with a wildcard DNS A record pointing to the VPS (e.g. `*.takwerx.org → 190.x.x.x`)
- TAK Server `.deb` package from [tak.gov](https://tak.gov)
- TAK client (e.g. ATAK on Android, WinTAK, iTAK) for device enrollment testing

---

## Subdomains Created

When you set your FQDN (e.g. `takwerx.org`), the console automatically creates and manages the following subdomains via Caddy:

| Subdomain | Service | Status |
|-----------|---------|--------|
| `console.takwerx.org` | TAKWERX Console management UI | ✅ Active immediately |
| `tak.takwerx.org` | TAK Server WebGUI (8446) | ✅ Active after TAK Server deploy |
| `authentik.takwerx.org` | Authentik admin UI | ✅ Active after Authentik deploy |
| `takportal.takwerx.org` | TAK Portal user management | ✅ Active after TAK Portal deploy |
| `cloudtak.takwerx.org` | CloudTAK | ⚠️ Placeholder — not yet implemented |
| `nodered.takwerx.org` | Node-RED | ⚠️ Placeholder — not yet implemented |

All subdomains get automatic Let's Encrypt certificates via Caddy. A wildcard DNS A record (`*.yourdomain.com`) pointing to your VPS IP is the easiest way to cover all of them at once.

---

## Deployment Flow — What to Test

Work through these in order. Each step depends on the previous.

### 1. Caddy SSL
**Status: ✅ Functional — Start here if using a domain**

- [ ] Enter your domain, click Update & Reload
- [ ] Let's Encrypt certificates issued successfully (green lock in browser)
- [ ] `console.{domain}` loads over HTTPS
- [ ] `tak.{domain}` loads after TAK Server is deployed

> **IP Address Mode** — If you don't have a domain, skip Caddy entirely. The console runs on a self-signed cert at `https://{IP}:5001`. All services are accessible by IP and port. Good for field deployments with no DNS.

---

### 2. TAK Server
**Status: ✅ Functional**

- [ ] Upload `.deb` package via the browser
- [ ] Deploy completes without errors
- [ ] All 6 Java services show green in the Services panel (Messaging, API, Config, Plugin Manager, Retention, PostgreSQL)
- [ ] `tak.{domain}` accessible in browser (use Firefox — Chrome caches redirects aggressively)
- [ ] Start / Stop / Restart controls work
- [ ] Certificate Management page shows all cert files

---

### 3. Authentik
**Status: ✅ Functional (fixed in v0.1.5)**

- [ ] Deploy completes all 12 steps without manual intervention
- [ ] Log shows `✓ Blueprint LDAP outpost found`
- [ ] Log shows `✓ LDAP outpost token injected`
- [ ] Log shows `✓ LDAP container recreated with injected token`
- [ ] LDAP bind test passes (run from VPS):
  ```bash
  LDAP_PW=$(grep AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD ~/authentik/.env | cut -d= -f2)
  ldapsearch -x -H ldap://127.0.0.1:389 \
    -D "cn=adm_ldapservice,ou=users,dc=takldap" \
    -w "$LDAP_PW" -b "dc=takldap" "(cn=webadmin)" 2>&1 | head -5
  ```
  Expected: returns `# LDAPv3` not `Can't contact LDAP server`
- [ ] `tak.{domain}` login with `webadmin` and the password from the deploy log works
- [ ] After login, TAK Server admin UI loads (not WebTAK)
- [ ] Deploy log persists after completion with buttons — no auto-redirect

---

### 4. TAK Portal
**Status: ✅ Functional (fixed in v0.1.5)**

- [ ] Deploy completes all steps including:
  - `✓ Got authorization flow`
  - `✓ Got invalidation flow`
  - `✓ Application 'TAK Portal' created`
  - `✓ TAK Portal added to embedded outpost`
- [ ] 2-minute sync countdown visible in deploy log
- [ ] After completion, clickable link to `takportal.{domain}` appears in log
- [ ] `takportal.{domain}` redirects to Authentik login
- [ ] Login with `webadmin` credentials works
- [ ] TAK Portal dashboard loads after login
- [ ] Self-service access request page at `takportal.{domain}/request-access` is accessible **without** logging in

---

## Feature Status Reference

| Feature | Status | Notes |
|---------|--------|-------|
| TAK Server deploy | ✅ Working | Ubuntu 22.04 |
| Caddy SSL / Let's Encrypt | ✅ Working | FQDN mode |
| IP address mode (no domain) | ✅ Working | Self-signed cert, field use |
| Authentik LDAP auth | ✅ Working | Fixed in v0.1.5 |
| TAK Portal forward auth | ✅ Working | Fixed in v0.1.5 |
| TAK Portal self-service enrollment | 🚧 In Development | `/request-access` page exists, backend WIP |
| TAK client QR enrollment | 🚧 In Development | Via TAK Portal, not yet tested end-to-end |
| CloudTAK | ⚠️ Placeholder | Card visible, deploy not yet implemented |
| MediaMTX video streaming | ⚠️ Placeholder | Card visible, config editor UI exists, deploy not yet implemented |
| Node-RED | ⚠️ Placeholder | Card visible, deploy not yet implemented |
| Guard Dog monitoring | ⚠️ Placeholder | Card visible, alerting not yet implemented |
| Rocky Linux 9 support | 🚧 Planned | Not yet tested |
| ARM64 / Raspberry Pi support | 🚧 Planned | Not yet tested |

---

## Known Issues

- **Chrome caches redirects aggressively** — If `tak.{domain}` redirects to `127.0.0.1:8446`, clear HSTS at `chrome://net-internals/#hsts` or use Firefox
- **TAK Server shows WebTAK at root** — Navigate to `tak.{domain}/index.html` for the admin UI, or wait ~60 seconds for LDAP group sync after a fresh Authentik deploy
- **Authentik first boot is slow** — Bootstrap token can take 3-5 minutes on first deploy. The deploy log shows a countdown — this is normal
- **TAK Portal needs 2 minutes after deploy** — Authentik embedded outpost sync delay. The deploy log counts down automatically

---

## Regression Tests — Run After Any Code Change

- [ ] Caddyfile regenerates correctly after Update & Reload — check `cat /etc/caddy/Caddyfile` for `header_down` lines in the TAK block
- [ ] LDAP bind test passes after fresh Authentik deploy
- [ ] TAK Server 8446 login works after full stack deploy
- [ ] `takportal.{domain}/request-access` is accessible without authentication

---

## Reporting Issues

Include in any bug report:
- Which step failed
- The deploy log output (copy from browser before navigating away)
- Output of `sudo journalctl -u takwerx-console -n 50 --no-pager`
- VPS specs and OS version
