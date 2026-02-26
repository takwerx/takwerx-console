# MediaMTX access driven by TAK Portal / LDAP

This doc captures how MediaMTX is used today and the target model: **one place to manage people (TAK Portal)** and have that control MediaMTX access (admin vs viewer, and optionally which streams).

---

## How MediaMTX works today (stream.fqdn)

- **Landing page** at `stream.fqdn` (or `mediamtx_domain`): users see a login.
- **Admin login** → full web console (config, paths, recordings, etc.).
- **Viewer login** → only the **Active Streams** tab (watch live streams, no config).

So the same app already has “admin vs viewer” and restricts the UI by role. The goal is to keep that same logic but **drive roles from TAK Portal / LDAP** so you don’t manage users in multiple places (MediaMTX, Authentik, etc.).

---

## Goal: TAK Portal drives it all

- **Single place for people**: Add users or approve request-access in **TAK Portal** only.
- **No separate user management** in MediaMTX or in Authentik for “who can use streams.”
- **LDAP** (and thus TAK Portal ↔ Authentik ↔ LDAP) is the source of truth for identity and, by extension, for “who is Stream Admin vs Stream Viewer.”

So: “TAK Portal that talks back to the LDAP could control what access MediaMTX has” — yes. The flow is:

1. You manage users (and optionally roles) in TAK Portal (or via request-access + approval).
2. That flows into Authentik and LDAP (as it already does for TAK Server, etc.).
3. **stream.fqdn** uses that same identity to decide: admin (full console) vs viewer (active streams only), and optionally which streams a viewer can see.

Nobody has to “go to MediaMTX to add users” or “go to Authentik to add them to Stream Viewers” — TAK Portal drives it.

---

## Do not configure MediaMTX email

**Do not configure the email/SMTP portion of MediaMTX.** You don't need it anymore.

The only use for MediaMTX email was: user enters email to request an account → admin approves → SMTP sent them an "you're approved" email. That flow is being replaced by **TAK Portal**:

- **TAK Portal** will offer an **open request-access page** (not behind Authentik) so anyone can reach it and request access.
- When someone requests access, the admin gets a **notification by email** and a **notification in TAK Portal**.
- The admin **approves in TAK Portal**; the user is then in LDAP/Authentik and can log in everywhere — including **stream.fqdn** (MediaMTX).
- No approval email needs to be sent from MediaMTX; TAK Portal and your Email Relay (e.g. infra-TAK's Email Relay + "Configure Authentik") handle recovery and notifications.

So: **skip MediaMTX email config.** Request access, approval, and notifications live in TAK Portal and Email Relay.

---

## LDAP groups that control what users see at stream.fqdn

**Yes — a group controls what they see.** Use **LDAP groups** for both "viewer vs admin" and "which streams a viewer can see."

### Keep stream groups out of TAK / ATAK

**TAK Portal only looks at groups with the `tak_` prefix** (e.g. `tak_CA-COR TEST3`, `tak_ROLE_ADMIN`) for TAK Server, missions, and what shows up in ATAK clients. If you put stream-visibility groups in that same namespace, they would appear in ATAK and users could think they're operational/mission groups.

**Use a separate prefix for stream-only groups** so they never show in TAK Portal or ATAK:

| LDAP group     | Effect at stream.fqdn | Visible in TAK Portal / ATAK? |
|----------------|----------------------|-------------------------------|
| **vid_public** | Viewer; which streams = per-path groups in MediaMTX. | **No** — not `tak_*`, so TAK Portal and ATAK ignore them. |
| **vid_private**| Same as above; different path→group mapping in MediaMTX. | **No** |
| **vid_admin**  | Full MediaMTX console (admin). | **No** |

So: **`vid_*`** = stream access only. **`tak_*`** = TAK Server / missions / ATAK. Same LDAP, same users; different prefixes keep the two worlds from overlapping.

When MediaMTX is deployed with Authentik present, infra-TAK automatically creates **vid_public**, **vid_private**, and **vid_admin** in Authentik. Assign users to these in a **MediaMTX-only user page** (see below) or in Authentik; they will not appear as TAK groups in ATAK.

For **access to all apps** (Node-RED, infratak, MediaMTX, TAK Portal): use an **Authentik superuser** or **authentik Admins**. You can map **vid_admin** in the stream app to "full console" and keep superuser for "can open every app."

### MediaMTX-only user page (recommended)

To avoid confusion and accidental use of stream groups in TAK:

- **TAK Portal** continues to show and assign only **`tak_*`** groups (for TAK Server, missions, ATAK). The "Create New User" / group list in TAK Portal should only list groups with the `tak_` prefix.
- **MediaMTX** should have a **separate "Users" or "Stream access" page** that:
  - Reads **users from LDAP** (same directory as TAK Portal).
  - Lists users and lets you assign **only** the **`vid_public`**, **`vid_private`**, **`vid_admin`** groups for stream access.
  - Does **not** show or touch `tak_*` groups — so stream visibility is managed only here, and ATAK never sees these groups.

Same LDAP, same people; **TAK Portal** = TAK/mission groups (`tak_*`), **MediaMTX** = stream groups (`vid_*`). The MediaMTX user page is the right place to assign who can see which streams without affecting TAK Server or what appears in ATAK clients.

This works whether or not TAK Portal is deployed: **With TAK Portal**, you have two UIs (TAK Portal for `tak_*`, MediaMTX for `vid_*`). **With MediaMTX + Authentik only** (no TAK Server, no TAK Portal), the MediaMTX user page is the only place to manage users and stream access — same `vid_*` groups, same LDAP. You don't depend on what TAK Portal does or doesn't show; stream access is always managed in MediaMTX.

---

## Implementation options

### Option A: stream.fqdn behind Authentik + LDAP groups

- Put **stream.fqdn** behind Caddy + Authentik forward_auth (same pattern as TAK Portal, Node-RED).
- Authentik already authenticates users (and can use LDAP); it sends headers like `X-Authentik-Username`, `X-Authentik-Groups`.
- **MediaMTX web app** (mediamtx_config_editor or a thin wrapper) is updated to:
  - Treat “logged in” when these headers are present (no separate login page, or skip it when behind Authentik).
  - Map **groups** to role: e.g. `Stream Admins` or `authentik Admins` → full console; `Stream Viewers` or default → active streams only.
- So you only need **group membership** in Authentik/LDAP. To have “TAK Portal drive it,” TAK Portal would set that when you assign a role (e.g. “Stream Admin” / “Stream Viewer”) — either by calling Authentik API to put the user in the right group, or by storing the role in TAK Portal and syncing to LDAP (e.g. group membership). One place (TAK Portal) → one directory (LDAP) → one set of groups → stream.fqdn shows admin or viewer UI.

### Option B: stream.fqdn uses TAK Portal API for role

- stream.fqdn still behind Authentik (so same login as TAK Portal).
- After login, the MediaMTX web app gets the username (e.g. from `X-Authentik-Username`), then calls a **TAK Portal API**: “what is this user’s MediaMTX role?” (admin / viewer, and optionally allowed paths).
- TAK Portal stores that role (or maps LDAP groups to it) and returns it. No need to push groups into Authentik for MediaMTX; TAK Portal is the single source of “who has what access” and the stream app just asks.

---

## Summary

| Aspect | Today | Target |
|--------|--------|--------|
| **Where users are managed** | (MediaMTX has its own admin/viewer users) | TAK Portal only; LDAP/Authentik reflect that |
| **stream.fqdn login** | Own landing + admin/viewer | Same UI (admin = full console, viewer = active streams), but role from TAK Portal / LDAP |
| **Managing “who gets in”** | Could be separate in MediaMTX or Authentik | One place: TAK Portal (request-access, add user, assign Stream Admin / Stream Viewer); no need to touch MediaMTX or Authentik for that |

So yes: using TAK Portal (and the LDAP it talks to) to control MediaMTX access is the right model, and it matches “use TAK Portal to drive it all” and “don’t deal with people in different locations.”

---

## What streams show up in a viewer's Active Streams (path to LDAP groups)

When a viewer logs in, the **Active Streams** list should only show streams they're allowed to see, and when they hit play, MediaMTX's auth should be **tied to LDAP groups** so it enforces the same thing.

### 1. Mapping: path to which LDAP groups can see it

Define a **mapping** (config or DB): which groups can see which paths, e.g.:

- Path `live/drone1` -> groups: `Stream Viewers`, `Team Alpha`
- Path `live/drone2` -> `Stream Viewers`, `Team Beta`
- Path `live/ops/cam1` -> `Stream Viewers`, `Stream Admins`

You can use path patterns (e.g. `live/alpha/*` -> `Team Alpha`) if supported. This mapping defines "what streams show up" for which groups.

### 2. What streams show up in the list (UI)

1. Viewer is logged in (Authentik); app gets identity (`X-Authentik-Username`, `X-Authentik-Groups`) or looks up groups in LDAP.
2. **Backend** calls MediaMTX API (`GET /v3/paths/list` on 9898) for the full path list.
3. Backend **filters** the list: keep only paths where the user's groups intersect the path's allowed groups (from the mapping).
4. Return filtered list to frontend = what the viewer sees in Active Streams.

So the path for "what streams show up" is: **path -> allowed LDAP groups** (mapping) + **current user's LDAP groups** -> **intersection** = list to show.

### 3. Tying MediaMTX auth to LDAP groups (playback)

When the viewer clicks a stream, the browser requests HLS from MediaMTX. MediaMTX must enforce that this user is allowed to read that path. MediaMTX doesn't talk to LDAP; you tie its auth to LDAP groups in two ways.

**Option 1: MediaMTX HTTP auth (recommended)**

- MediaMTX config: `authMethod: http`, `authHTTPAddress: https://your-backend/auth/mediamtx` (exclude `api` so your backend can still call the API).
- On each read request MediaMTX POSTs to your endpoint: `user`, `password` or `token`, `path`, `action` (e.g. `read`).
- Your **auth endpoint**: identify the user (validate token or user/pass via LDAP), get their **LDAP groups**, check the **path -> groups** mapping; return **200** to allow, **401** to deny.

So the "auth that comes out of MediaMTX" (the HTTP call to you) is **tied to LDAP groups**: you allow/deny from group membership and the mapping. MediaMTX just trusts your 200 vs 401.

**Option 2: MediaMTX JWT auth**

- After Authentik login your backend builds the list of paths the user may read (from their LDAP groups + mapping), then issues a **JWT** with `mediamtx_permissions: [ { "action": "read", "path": "live/drone1" }, ... ]`.
- MediaMTX: `authMethod: jwt`, your JWKS URL. Viewer page sends `Authorization: Bearer <token>` for HLS. MediaMTX validates the JWT and allows only the paths in the claim.

The JWT is tied to LDAP groups indirectly: the path list in the JWT was derived from the user's LDAP groups and the mapping.

### Can MediaMTX auth be tied to an LDAP group?

**Yes.** MediaMTX doesn't talk to LDAP directly:

- **HTTP auth**: Your endpoint does. You resolve user -> LDAP groups and check path -> allowed groups; MediaMTX trusts your 200/401. So MediaMTX auth is fully tied to LDAP groups.
- **JWT auth**: The JWT is built from the user's LDAP groups and the path mapping, so enforcement is still tied to LDAP groups.

**Path for what streams show up:** Maintain **path -> LDAP groups** mapping; filter the path list by the user's groups for the UI; use HTTP or JWT auth so MediaMTX only allows reads your mapping permits for that user's groups.

---

## Per-path group toggles in the MediaMTX console (who can see this stream)

You want to **go to a stream in the MediaMTX console** (the people who publish / the path) and **choose which groups can see it** — e.g. "Restricted" and "Public". When a mission isn't public, you turn the Public group off for that stream and only Restricted folks see it on the Active Streams page. The console already talks to LDAP so it knows all existing groups.

### What you're asking for

- In the **admin** side of the MediaMTX console: for each **path** (stream / publisher), show a list of **LDAP groups** (Restricted, Public, etc.) with **on/off toggles** (or checkboxes).
- "Who can see this stream?" = which groups are turned on for this path. Turn Public off → only other selected groups (e.g. Restricted) can see it in Active Streams and in playback.
- So the **path -> groups** mapping is **editable in the UI** per path, and the group list comes from LDAP (the console already talks to LDAP).

### Is this a crazy change in the UI?

**No.** It's a contained, clear addition:

1. **Data** — You already have the concept of a mapping: path -> allowed groups. That mapping just becomes **editable** and **stored** (file or DB) by the console backend.
2. **LDAP groups** — The console already talks to LDAP (or Authentik) and can list groups. So you have a list of group names to show (Restricted, Public, Stream Viewers, etc.).
3. **UI** — In the admin console, for each path (or "user" / publisher) you already show:
   - Add a section: **"Visible to groups"** with a checkbox or toggle per LDAP group. For path `live/drone1`: [x] Restricted [x] Public [ ] Team Beta. Uncheck Public → save → only Restricted (and any other checked groups) can see that stream.
   - Optional: a **quick action** like "Restrict to Restricted only" (turns off Public for this path) for when you're about to fly a non-public mission.

So the UI change is: **per-path group selector** (checkboxes or toggles) using the existing LDAP group list. Backend: load/save the path->groups mapping and use it for the Active Streams filter and for MediaMTX HTTP (or JWT) auth. Not a rewrite — an extra panel or modal per path and an API to get/set allowed groups for that path.

### Naming convention: `vid_*` for stream only, `tak_*` for TAK/ATAK

TAK Server and TAK Portal use LDAP groups for **datasync missions** and only consider groups with the **`tak_`** prefix (e.g. `tak_CA-COR TEST3`, `tak_ROLE_ADMIN`). Those are what show up in ATAK clients. Stream-visibility groups must **not** use that prefix so they never appear as mission/operational groups in ATAK.

**Recommendation:** Use **`vid_*`** for stream-only groups (`vid_public`, `vid_private`, `vid_admin`). Then:

- In the **MediaMTX console**, **only show** groups that match **`vid_*`** for the "Visible to groups" toggles and for the MediaMTX user/stream-access page. Do not show `tak_*` groups there — they are for TAK, not for streams.
- In **TAK Portal**, only show **`tak_*`** groups for user/mission assignment. Do not show `vid_*` groups there — they are for streams only and would confuse users if they appeared in ATAK.

Same LDAP, same directory; **`vid_*`** = stream access only (MediaMTX), **`tak_*`** = TAK Server / missions / ATAK (TAK Portal). The prefix keeps the two namespaces separate so stream groups never show in ATAK clients.

---

## Keeping the regular MediaMTX repo + flexible deploy (detect LDAP)

You want to **keep your regular MediaMTX repo** for people who don't use Authentik — no LDAP, no path→group toggles, just the standard web editor. In infra-TAK, when we build the MediaMTX module we should:

1. **Support both** a "regular" editor (from your existing repo) and an "LDAP-enhanced" editor (when Authentik/LDAP is in use).
2. **Be flexible**: **detect** if LDAP/Authentik is installed and choose which variant to pull/deploy.

### How it can work

- **Detection:** During MediaMTX deploy, infra-TAK already has `detect_modules()` and knows if Authentik is installed (`ak_installed`). Use that as "LDAP available" (Authentik implies LDAP outpost). Optionally also check that LDAP is reachable (e.g. port 389) if you want to be stricter.
- **Regular variant (no LDAP):** When Authentik is **not** installed, pull the web editor from your **regular MediaMTX repo** (e.g. `takwerx/mediamtx-installer`, path `config-editor/` or main). Same app as today for standalone deployments — landing, admin/viewer, active streams, no group toggles.
- **LDAP variant:** When Authentik **is** installed, infra-TAK can produce the LDAP-enhanced editor in either of these ways (see "Vanilla vs LDAP-enhanced MediaMTX" below):
  - **Preferred:** Pull the **same branch** (e.g. `main`) and have infra-TAK **apply patches or overlay** at build/deploy time — no second branch to maintain on the MediaMTX repo.
  - **Alternative:** Pull from a **branch** of the same repo (e.g. `ldap` or `infratak`) or a different repo that has the LDAP code built in.
- **Fallback:** If clone/pull fails (no network, repo private, etc.), fall back to **local files** as today (look for `mediamtx_config_editor.py` next to app.py, in `config-editor/`, or in `/opt/takwerx/`). So placing the file manually still works.

### Summary

| LDAP/Authentik | Source used | Result |
|----------------|-------------|--------|
| Not installed | Regular MediaMTX repo (your repo) | Standard editor, no LDAP features |
| Installed     | LDAP-enhanced source (branch or repo) | Editor with path→group toggles, LDAP groups |
| Clone fails   | Local file fallback (current behavior) | Whatever is at app dir / config-editor / /opt/takwerx |

So: **regular repo stays** for non-Authentik users; infra-TAK **detects LDAP** (via Authentik installed) and chooses which variant to pull; fallback to local file keeps existing behavior.

**Configuration (in app.py):** `MEDIAMTX_EDITOR_REPO`, `MEDIAMTX_EDITOR_PATH`, and optionally `MEDIAMTX_EDITOR_LDAP_BRANCH`. If you use the **single-branch + infra-TAK patches** approach, you always pull the same branch and infra-TAK applies the LDAP/User-tab changes from its own repo (no second branch). If you use a separate LDAP branch instead, set `MEDIAMTX_EDITOR_LDAP_BRANCH` (e.g. `infratak`); when Authentik is installed, deploy tries that branch and falls back to default if clone fails. Set `MEDIAMTX_EDITOR_LDAP_BRANCH = None` to always use the default branch (e.g. when using patches/overlay for the LDAP variant).

---

## Authentik Password Recovery / Reset Portal (TAK-Portal doc)

The [Authentik Password Reset / Recovery Portal](https://github.com/AdventureSeeker423/TAK-Portal/blob/main/docs/authentik-password-portal.md) doc describes a **manual** setup in the Authentik Admin UI: create a Password Policy, Recovery Identification stage, Recovery Email stage, a "Password Recovery" flow, and link that flow to the default authentication flow so users get a "Forgot password?" option and can set their own password via email.

**Current state:** The infra-TAK **TAK Portal deploy does not create** this. The Authentik deploy creates the LDAP blueprint (auth flow, password stage, identification, etc.) but does **not** create the Recovery flow, Recovery Identification, or Recovery Email stages, or the binding that adds "Recovery Flow" to the login screen. So after deploy, you get standard login; password recovery is a **manual follow-up** using the TAK-Portal doc (or the [Authentik docs](https://docs.goauthentik.io/) and the linked YouTube video).

**Optional enhancement:** We could add a post-deploy step (or an optional "Enable password recovery" in infra-TAK) that uses the Authentik API to create the Recovery flow and stages and link them, so the password portal is available without manual steps. That would require SMTP to be configured (e.g. Email Relay) so Authentik can send recovery emails.

---

## User-created password and management (both MediaMTX and TAK Portal)

**Requirement:** Users setting their own password and having a clear place to manage people (request access, groups, roles) is **crucial for both** deployments:

- **MediaMTX only** (Authentik + MediaMTX, no TAK Server/TAK Portal): need a User tab in the MediaMTX console so people can request access, set password, and admins can manage groups.
- **TAK Portal deployed**: same need (e.g. via TAK Portal’s request-access + password recovery). MediaMTX can still have a User tab that **references the same people** — see below.

---

## MediaMTX "User management" tab

**Request:** A **User management** tab in the MediaMTX console that talks to **Authentik/LDAP** so you can:

- **MediaMTX-only deploy:** Create groups, let users request to join and set their own password, and use those groups for stream visibility and admin vs viewer — without TAK Portal.
- **TAK Portal also deployed:** The User tab **still exists** in MediaMTX and **references the same people** (same Authentik/LDAP). One directory, one set of users and groups. You can manage in TAK Portal and see the same users/groups in MediaMTX, or offer management in both (both write to Authentik/LDAP). No duplicate user stores.

So the MediaMTX console would have a tab that:

- Lists existing LDAP/Authentik groups (for stream visibility and roles).
- Allows an admin to create new groups (via Authentik API), when that’s the chosen place to manage.
- Offers a "request access" flow: user signs up, sets password, is added to a chosen group (or pending approval). When TAK Portal is present, this can be the same flow (same backend) or a link to TAK Portal; when it’s MediaMTX-only, the flow lives in the MediaMTX UI.

**Implementation direction:** The LDAP-enhanced MediaMTX editor (or a small companion service) calls the **Authentik API** (token or service account) to read/write groups and users. Same API whether TAK Portal is deployed or not — so the same people everywhere. Request-access can use Authentik enrollment/set-password flows or a form that creates the user in Authentik and sends a set-password link.

---

## Vanilla vs LDAP-enhanced MediaMTX (single branch preferred)

**Goal:** Maintain **one branch** for the MediaMTX web editor on GitHub. When infra-TAK pulls and builds it (with Authentik present), **infra-TAK applies the additional changes** needed for LDAP/User tab — so you don't maintain two branches on the MediaMTX repo.

**Preferred: single branch, infra-TAK does the tweaks**

- **MediaMTX repo:** One branch (e.g. `main`) with the vanilla web editor. No LDAP-specific code there; standalone users clone and build as-is.
- **infra-TAK:** When it deploys MediaMTX and Authentik is present, infra-TAK either:
  - **Patches at deploy time** — clones the editor repo, applies patch files (or a small script) that live in the infra-TAK repo, then builds. The LDAP/User-tab diff lives in infra-TAK, not in the MediaMTX repo.
  - **Build-time feature flag** — the editor repo has optional LDAP code behind an env var (e.g. `LDAP_ENABLED`). Default build = vanilla. infra-TAK builds with the flag set; the MediaMTX repo still has only one branch, with the extra code gated by the flag.
  - **Overlay** — infra-TAK serves the vanilla editor plus an overlay (e.g. extra static bundle or a small companion service that adds the User tab). The MediaMTX repo stays vanilla; the "variant" is entirely in infra-TAK (extra routes, proxy, or sidecar).

So: **one branch on the MediaMTX repo**; the "LDAP variant" is produced by infra-TAK when it's told to build with Authentik, not by a second branch you maintain.

**Alternatives (if you later want them):**

- Separate branch in the MediaMTX repo (e.g. `infratak`) with LDAP built in — more to maintain.
- Separate image tag (vanilla vs `:ldap`) from the same single-branch build, by building with/without the flag above.
