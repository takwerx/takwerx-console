# MediaMTX access driven by TAK Portal / LDAP

This doc captures how MediaMTX is used today and the target model: **one place to manage people (TAK Portal)** and have that control MediaMTX access (admin vs viewer, and optionally which streams).

---

## How MediaMTX works today (stream.fqdn)

- **Landing page** at `stream.fqdn` (or `mediamtx_domain`): users see a login.
- **Admin login** -> full web console (config, paths, recordings, etc.).
- **Viewer login** -> only the **Active Streams** tab (watch live streams, no config).

So the same app already has "admin vs viewer" and restricts the UI by role. The goal is to keep that same logic but **drive roles from TAK Portal / LDAP** so you don't manage users in multiple places (MediaMTX, Authentik, etc.).

---

## Goal: TAK Portal drives it all

- **Single place for people**: Add users or approve request-access in **TAK Portal** only.
- **No separate user management** in MediaMTX or in Authentik for "who can use streams."
- **LDAP** (and thus TAK Portal <-> Authentik <-> LDAP) is the source of truth for identity and, by extension, for "who is Stream Admin vs Stream Viewer."

So: "TAK Portal that talks back to the LDAP could control what access MediaMTX has" -- yes. The flow is:

1. You manage users (and optionally roles) in TAK Portal (or via request-access + approval).
2. That flows into Authentik and LDAP (as it already does for TAK Server, etc.).
3. **stream.fqdn** uses that same identity to decide: admin (full console) vs viewer (active streams only), and optionally which streams a viewer can see.

Nobody has to "go to MediaMTX to add users" or "go to Authentik to add them to Stream Viewers" -- TAK Portal drives it.

---

## Do not configure MediaMTX email

**Do not configure the email/SMTP portion of MediaMTX.** You don't need it anymore.

The only use for MediaMTX email was: user enters email to request an account -> admin approves -> SMTP sent them an "you're approved" email. That flow is being replaced by **TAK Portal**:

- **TAK Portal** will offer an **open request-access page** (not behind Authentik) so anyone can reach it and request access.
- When someone requests access, the admin gets a **notification by email** and a **notification in TAK Portal**.
- The admin **approves in TAK Portal**; the user is then in LDAP/Authentik and can log in everywhere -- including **stream.fqdn** (MediaMTX).
- No approval email needs to be sent from MediaMTX; TAK Portal and your Email Relay (e.g. infra-TAK's Email Relay + "Configure Authentik") handle recovery and notifications.

So: **skip MediaMTX email config.** Request access, approval, and notifications live in TAK Portal and Email Relay.

---

## LDAP groups that control what users see at stream.fqdn

**Yes -- a group controls what they see.** Use **LDAP groups** for both "viewer vs admin" and "which streams a viewer can see."

### Keep stream groups out of TAK clients

**TAK Portal only looks at groups with the `tak_` prefix** (e.g. `tak_CA-COR TEST3`, `tak_ROLE_ADMIN`) for TAK Server, missions, and what shows up in TAK clients. If you put stream-visibility groups in that same namespace, they would appear in TAK clients and users could think they're operational/mission groups.

**Use a separate prefix for stream-only groups** so they never show in TAK Portal or TAK clients:

| LDAP group     | Effect at stream.fqdn | Visible in TAK Portal / TAK clients? |
|----------------|----------------------|--------------------------------------|
| **vid_public** | Viewer; which streams = per-path groups in MediaMTX. | **No** -- not `tak_*`, so TAK Portal and TAK clients ignore them. |
| **vid_private**| Same as above; different path->group mapping in MediaMTX. | **No** |
| **vid_admin**  | Full MediaMTX console (admin). | **No** |

So: **`vid_*`** = stream access only. **`tak_*`** = TAK Server / missions / TAK clients. Same LDAP, same users; different prefixes keep the two worlds from overlapping.

When MediaMTX is deployed with Authentik present, infra-TAK automatically creates **vid_public**, **vid_private**, and **vid_admin** in Authentik. Assign users to these via the **Stream Access** page in MediaMTX (see below) or in Authentik; they will not appear as TAK groups in TAK clients.

For **access to all apps** (Node-RED, infratak, MediaMTX, TAK Portal): use an **Authentik superuser** or **authentik Admins**. You can map **vid_admin** in the stream app to "full console" and keep superuser for "can open every app."

### Naming convention: `vid_*` for stream only, `tak_*` for TAK clients

TAK Server and TAK Portal use LDAP groups for **datasync missions** and only consider groups with the **`tak_`** prefix (e.g. `tak_CA-COR TEST3`, `tak_ROLE_ADMIN`). Those are what show up in TAK clients. Stream-visibility groups must **not** use that prefix so they never appear as mission/operational groups in TAK clients.

**Recommendation:** Use **`vid_*`** for stream-only groups (`vid_public`, `vid_private`, `vid_admin`). Then:

- In the **MediaMTX console**, **only show** groups that match **`vid_*`** for the "Visible to groups" toggles and for the Stream Access page. Do not show `tak_*` groups there -- they are for TAK, not for streams.
- In **TAK Portal**, only show **`tak_*`** groups for user/mission assignment. Do not show `vid_*` groups there -- they are for streams only and would confuse users if they appeared in TAK clients.

Same LDAP, same directory; **`vid_*`** = stream access only (MediaMTX), **`tak_*`** = TAK Server / missions / TAK clients (TAK Portal). The prefix keeps the two namespaces separate so stream groups never show in TAK clients.

---

## MediaMTX "Stream Access" page (implemented)

When Authentik is present, infra-TAK applies an **LDAP overlay** (`mediamtx_ldap_overlay.py`) to the vanilla MediaMTX editor at deploy time. This adds:

1. **Authentik header auth** -- Caddy `forward_auth` handles login; the editor reads `X-Authentik-Username` and `X-Authentik-Groups` headers to auto-authenticate. No local login page; `vid_admin` or `authentik Admins` -> admin role (full console), `vid_private`/`vid_public` -> viewer role (Active Streams only).

2. **Stream Access page** (`/stream-access`) -- A standalone user management page for `vid_admin` users. Lists all Authentik users with their `vid_*` group memberships. Click a group badge to toggle the user in/out of that group. Same LDAP, same users as TAK Portal -- you're just assigning existing people to stream groups, not creating users.

3. **Sidebar injection** -- The editor's "Web Users" sidebar item is replaced with "Stream Access" linking to the new page. The standalone login/register/forgot-password routes redirect to `/` (Authentik handles all of that).

**How it works at deploy time:**
- infra-TAK clones the vanilla editor from `takwerx/mediamtx-installer`
- Copies `mediamtx_ldap_overlay.py` alongside it
- Injects an import before `app.run()` gated by `LDAP_ENABLED` env var
- Sets env vars in the systemd service: `LDAP_ENABLED=1`, `AUTHENTIK_API_URL`, `AUTHENTIK_TOKEN`
- Without Authentik, the vanilla editor runs as-is (file-based users, local login)

**With TAK Portal:** Two UIs manage the same people -- TAK Portal for `tak_*` groups (TAK Server, missions), MediaMTX Stream Access for `vid_*` groups (stream access). Same LDAP directory.

**Without TAK Portal:** Stream Access is the only user management UI. Users are in Authentik/LDAP; admins assign stream groups here.

---

## Vanilla vs LDAP-enhanced MediaMTX (single branch, infra-TAK overlay)

**One branch** on the MediaMTX repo (`takwerx/mediamtx-installer`, `main` branch). No LDAP-specific code there; standalone users clone and run as-is.

**infra-TAK applies the overlay at deploy time** when Authentik is detected:
- Clones the vanilla editor
- Copies `mediamtx_ldap_overlay.py` next to it
- Injects a gated import (`LDAP_ENABLED` env var)
- Sets env vars in the systemd service

Without Authentik, the vanilla editor runs unchanged (local login, file-based users, email config). With Authentik, the overlay activates: header auth, Stream Access page, sidebar injection.

| LDAP/Authentik | Source used | Result |
|----------------|-------------|--------|
| Not installed | Vanilla editor from repo | Standard editor, local login, no LDAP features |
| Installed | Vanilla editor + LDAP overlay from infra-TAK | Authentik header auth, Stream Access page, vid_* group management |
| Clone fails | Local file fallback | Whatever is at app dir / config-editor / /opt/takwerx |

---

## Authentik Password Recovery / Reset Portal (TAK-Portal doc)

The [Authentik Password Reset / Recovery Portal](https://github.com/AdventureSeeker423/TAK-Portal/blob/main/docs/authentik-password-portal.md) doc describes a **manual** setup in the Authentik Admin UI: create a Password Policy, Recovery Identification stage, Recovery Email stage, a "Password Recovery" flow, and link that flow to the default authentication flow so users get a "Forgot password?" option and can set their own password via email.

**Current state:** infra-TAK's Authentik deploy now creates the Recovery flow, stages, and bindings automatically via `_configure_authentik_smtp_and_recovery`. The "Forgot username or password" link appears on the Authentik login page when Email Relay is configured.

---

## What streams show up in a viewer's Active Streams (path to LDAP groups)

When a viewer logs in, the **Active Streams** list should only show streams they're allowed to see, and when they hit play, MediaMTX's auth should be **tied to LDAP groups** so it enforces the same thing.

### 1. Mapping: path to which LDAP groups can see it

Define a **mapping** (config or DB): which groups can see which paths, e.g.:

- Path `live/drone1` -> groups: `vid_public`, `vid_private`
- Path `live/drone2` -> `vid_private`
- Path `live/ops/cam1` -> `vid_admin`

You can use path patterns (e.g. `live/alpha/*` -> vid_private) if supported. This mapping defines "what streams show up" for which groups.

### 2. What streams show up in the list (UI)

1. Viewer is logged in (Authentik); app gets identity (`X-Authentik-Username`, `X-Authentik-Groups`) or looks up groups in LDAP.
2. **Backend** calls MediaMTX API (`GET /v3/paths/list` on 9898) for the full path list.
3. Backend **filters** the list: keep only paths where the user's groups intersect the path's allowed groups (from the mapping).
4. Return filtered list to frontend = what the viewer sees in Active Streams.

### 3. Tying MediaMTX auth to LDAP groups (playback)

When the viewer clicks a stream, the browser requests HLS from MediaMTX. MediaMTX must enforce that this user is allowed to read that path.

**Option 1: MediaMTX HTTP auth (recommended)**

- MediaMTX config: `authMethod: http`, `authHTTPAddress: https://your-backend/auth/mediamtx` (exclude `api` so your backend can still call the API).
- On each read request MediaMTX POSTs to your endpoint: `user`, `password` or `token`, `path`, `action` (e.g. `read`).
- Your **auth endpoint**: identify the user (validate token or user/pass via LDAP), get their **LDAP groups**, check the **path -> groups** mapping; return **200** to allow, **401** to deny.

**Option 2: MediaMTX JWT auth**

- After Authentik login your backend builds the list of paths the user may read (from their LDAP groups + mapping), then issues a **JWT** with `mediamtx_permissions: [ { "action": "read", "path": "live/drone1" }, ... ]`.
- MediaMTX: `authMethod: jwt`, your JWKS URL. Viewer page sends `Authorization: Bearer <token>` for HLS. MediaMTX validates the JWT and allows only the paths in the claim.

### Per-path group toggles (future)

In the **admin** side of the MediaMTX console: for each **path** (stream / publisher), show a list of **vid_* groups** with **on/off toggles** (checkboxes). "Who can see this stream?" = which groups are turned on for this path. This is the path-to-group mapping made editable in the UI.

This is a future enhancement to the Stream Access page -- the current implementation handles user-to-group assignment; path-to-group mapping comes next.
