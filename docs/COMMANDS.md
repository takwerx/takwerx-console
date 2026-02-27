# infra-TAK — Copy-paste commands

## Fresh clone on a VPS (dev branch)

```bash
git clone -b dev https://github.com/takwerx/infra-TAK.git
cd infra-TAK
chmod +x start.sh
sudo ./start.sh
```

Then open the URL shown (e.g. `https://<VPS_IP>:5001`) and set your admin password.

---

## TAK Portal enrollment + Authentik (new user password)

When you enroll a user in TAK Portal, they get an email with a link to TAK Portal. In infra-TAK that link goes through **Authentik** first (login/gateway), not straight to a "set password" page. The **standard TAK Portal email template** does not mention this.

**Intended flow:** User clicks the link → lands on Authentik → uses **Forgot password** to set their password (recovery email is sent via your Email Relay / Authentik SMTP) → then can sign in and reach TAK Portal.

**Recommendation:** Edit the **User Created (without Password)** email template in TAK Portal to tell new users to use **Forgot password?** on the login page. A ready-to-paste HTML version is in **`docs/email-template-user-created-without-password.html`**.

---

## Authentik — who sees which applications

**Desired model:**

- **Regular TAK Portal user** (created in TAK Portal, set password via Forgot password): Sees **only TAK Portal** on "My applications".
- **authentik Admins**: See **all** applications (infra-TAK, TAK Portal, MediaMTX, Node-RED).
- **TAK Portal** itself: Once they open TAK Portal, what they see there is controlled by TAK Portal + LDAP (e.g. agency admin vs regular user). Authentik only controls whether the **TAK Portal tile** appears.
- **MediaMTX** tile: Visible to `authentik Admins` + users in `vid_admin`, `vid_private`, or `vid_public` LDAP groups. Once inside, MediaMTX checks LDAP groups for what you get:
  - `vid_admin` → full config editor (like agency admin in TAK Portal)
  - `vid_private` / `vid_public` → active streams page only

**Automated on deploy:** infra-TAK creates two policies during Authentik deploy:

1. **Allow authentik Admins** (group membership) — bound to admin-only apps: infra-TAK, Node-RED, LDAP.
2. **Allow MediaMTX users** (expression) — bound to MediaMTX; allows `authentik Admins` OR `vid_admin` / `vid_private` / `vid_public`.

TAK Portal is left unbound so all authenticated users see it. No manual steps required.

**Manual override (if needed):**

1. **Policies** — Admin → **Policies** → look for `Allow authentik Admins` and `Allow MediaMTX users`.

2. **Admin-only apps** (infra-TAK, Node-RED, LDAP) → bind `Allow authentik Admins`.

3. **MediaMTX** → bind `Allow MediaMTX users` (covers admins + vid groups).

4. **TAK Portal** — should have **no** restrictive bindings.

**Result:**
- Regular TAK Portal users → see only **TAK Portal**.
- Users in `vid_admin` / `vid_private` / `vid_public` → see **TAK Portal** + **MediaMTX**.
- **authentik Admins** → see **all** applications.
- Inside each app, LDAP groups control permissions (agency admin, vid_admin, etc.).

---

## Authentik password recovery — not receiving email

If users click **Forgot username or password**, enter their username, but never get the reset email, work through these checks. (TAK Portal sending email means the relay works; the break is between Authentik and the relay.)

**Quick diagnostic (run on the server)**

```bash
# 1) Authentik has SMTP in .env?
grep AUTHENTIK_EMAIL__ ~/authentik/.env
# Expect: AUTHENTIK_EMAIL__HOST=host.docker.internal, AUTHENTIK_EMAIL__PORT=25, AUTHENTIK_EMAIL__FROM=...

# 2) Containers can reach host? Override must exist.
grep -A2 "server:" ~/authentik/docker-compose.override.yml
# Expect: extra_hosts: and "host.docker.internal:host-gateway"

# 3) From inside the worker, can we reach host:25? (use python if nc not in image)
docker exec authentik-worker-1 python -c "import socket; s=socket.socket(); s.settimeout(5); s.connect(('host.docker.internal', 25)); print('OK'); s.close()"
# Expect: OK. If timeout: Postfix inet_interfaces or firewall. Allow Docker→host port 25 (see below).

# 4) When did Postfix last see mail from Authentik?
sudo grep -i "authentik\|127.0.0.1\|relay" /var/log/mail.log | tail -20

# 5) Authentik worker email errors (container name may be authentik-worker-1)
docker ps --format "{{.Names}}" | grep -i authentik
docker logs authentik-worker-1 --tail 300 2>&1 | grep -i "email\|smtp\|error\|failed"
```

If (1) or (2) is missing, run **Email Relay** → **Configure Authentik to use these settings** and reload the page until the card shows **✓ Authentik SMTP: Configured**. If (3) **times out**, fix in order:

**A) Postfix listening only on localhost**
```bash
sudo postconf -e 'inet_interfaces = all'
sudo systemctl restart postfix
```

**B) Firewall blocking Docker → host port 25.** Authentik containers are usually on 172.18.0.0/16; allow that (or 172.16.0.0/12 to cover all Docker subnets):
```bash
sudo ufw allow from 172.18.0.0/16 to any port 25
# or: sudo ufw allow from 172.16.0.0/12 to any port 25
sudo ufw reload
```

Then retest from container (expect `OK`):
```bash
docker exec authentik-worker-1 python -c "import socket; s=socket.socket(); s.settimeout(5); s.connect(('host.docker.internal', 25)); print('OK'); s.close()"
```

If (4) shows nothing when you trigger a reset, Authentik isn't reaching Postfix. If (5) shows errors, that's the direct cause.

**1. Authentik SMTP configured**

- In the infra-TAK console: **Email Relay** → **Configure Authentik to use these settings** (run this after the relay is deployed so Authentik uses Postfix on the host).
- On the server:
  ```bash
  grep AUTHENTIK_EMAIL__ ~/authentik/.env
  ```
  You should see `AUTHENTIK_EMAIL__HOST=host.docker.internal`, `AUTHENTIK_EMAIL__PORT=25`, and `AUTHENTIK_EMAIL__FROM=...`.

**2. Containers can reach host Postfix**

- Check that the override is present:
  ```bash
  cat ~/authentik/docker-compose.override.yml
  ```
  It should add `extra_hosts: - "host.docker.internal:host-gateway"` for `server` and `worker`. If missing, run **Configure Authentik** again from the Email Relay page, or create the override and run `cd ~/authentik && docker compose up -d --force-recreate`.

**3. Test with a local Authentik user (e.g. superuser)**

- In Authentik Admin: **Directory** → **Users** → open your admin user → ensure **Email** is set.
- Log out, go to the login page, click **Forgot username or password**, enter that user's username.
- If the superuser gets the reset email, SMTP and the recovery flow work; the problem may be specific to users created by TAK Portal (e.g. LDAP user email not set or not visible to Authentik).
- If the superuser also does **not** get the email, the issue is Authentik SMTP or the recovery flow (see below).

**4. Recovery flow and "Forgot" link**

- In Authentik Admin: **Flows & Stages** → **Flows** → open the recovery flow (e.g. **Password Recovery** / `default-password-recovery`). It should have stages: Identification → Recovery Email → prompt (new password) → User Write → User Login.
- **Stages** → **Identification** → open **default-authentication-identification** → **Recovery flow** should be set to that recovery flow (so "Forgot username or password" uses it).

**5. Host Postfix and worker logs**

- On the host, check whether Postfix receives mail from Authentik:
  ```bash
  sudo tail -100 /var/log/mail.log
  ```
- Authentik worker (sends the email):
  ```bash
  docker logs authentik-worker --tail 200 2>&1
  ```
  Look for SMTP or email errors when a user requests a password reset.

**6. Users created by TAK Portal (LDAP)**

- Those users may live in LDAP. Authentik recovery looks up the user and sends to the **email** attribute. If the LDAP user has no email, or it isn't synced into Authentik, no email is sent. In Authentik, open the user (Directory → Users), confirm an email is shown; if not, fix the LDAP attribute or how TAK Portal/Authentik sync it.

---

## Pull newest dev and restart console

```bash
cd ~/infra-TAK && git fetch origin dev && git checkout dev && git pull origin dev && sudo systemctl restart takwerx-console
```

*(If your repo lives elsewhere, use that path instead of `~/infra-TAK`, e.g. `~/tak-infra`.)*

---

## Restart console only

```bash
sudo systemctl restart takwerx-console
```

---

## Remove clone and start over

Stops the console, removes the repo directory (and its `.config`), so you can re-clone from scratch. **Replace `~/infra-TAK` with your actual clone path if different.**

```bash
sudo systemctl stop takwerx-console
sudo systemctl disable takwerx-console
rm -rf ~/infra-TAK
cd ~
```

Then run the **Fresh clone** commands above. (`cd ~` is required — after `rm -rf` you're still "in" the deleted dir and clone will fail until you change to a real directory.) If you used a different path (e.g. `~/tak-infra`), use that in the `rm -rf` line instead.
