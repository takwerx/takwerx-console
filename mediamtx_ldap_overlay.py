"""MediaMTX LDAP Overlay — Authentik-aware auth + Stream Access user management.

Applied by infra-TAK at deploy time when Authentik/LDAP is detected.
Patches the vanilla MediaMTX config editor Flask app to:
  1. Auto-authenticate via Authentik forward_auth headers (no local login page)
  2. Map vid_* LDAP groups to admin/viewer roles
  3. Viewers (vid_public, vid_private): only see Active Streams page at /viewer — same idea as TAK Portal regular user page
  4. Admins (vid_admin, authentik Admins): full config editor + Stream Access at /stream-access
  5. Future: filter streams in /viewer by path-to-group mapping (vid_public vs vid_private determines which streams each user sees)
"""

import os
import json
import urllib.request
import urllib.error
from flask import session, request, redirect, jsonify, Response

AK_URL = os.environ.get('AUTHENTIK_API_URL', 'http://127.0.0.1:9090')
AK_TOKEN = os.environ.get('AUTHENTIK_TOKEN', '')
VID_GROUPS = ('vid_admin', 'vid_private', 'vid_public')
ADMIN_GROUPS = frozenset({'vid_admin', 'authentik Admins'})
VIEWER_GROUPS = frozenset({'vid_private', 'vid_public'})


def _ak_headers():
    return {'Authorization': f'Bearer {AK_TOKEN}', 'Content-Type': 'application/json'}


def _ak_get(path):
    r = urllib.request.Request(f'{AK_URL}/api/v3/{path}', headers=_ak_headers())
    return json.loads(urllib.request.urlopen(r, timeout=15).read().decode())


def _ak_post(path, body=None):
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(f'{AK_URL}/api/v3/{path}', data=data, headers=_ak_headers(), method='POST')
    return json.loads(urllib.request.urlopen(r, timeout=15).read().decode())


def apply_ldap_overlay(app):
    """Patch the Flask app for Authentik/LDAP mode."""

    # Paths a viewer is allowed to access (no full editor)
    VIEWER_ALLOWED = ('/viewer', '/api/viewer/streams')

    @app.before_request
    def _authentik_auto_auth():
        ak_user = request.headers.get('X-Authentik-Username', '')
        ak_groups_raw = request.headers.get('X-Authentik-Groups', '')
        if not ak_user:
            return
        groups = [g.strip() for g in ak_groups_raw.split('|') if g.strip()]
        role = 'admin' if any(g in ADMIN_GROUPS for g in groups) else 'viewer'
        session['username'] = ak_user
        session['logged_in'] = True
        session['role'] = role
        session['ldap_groups'] = groups
        session['ldap_mode'] = True
        # Redirect away from standalone auth pages
        if request.path in ('/login', '/register', '/forgot-password', '/reset-password'):
            return redirect('/')
        # Viewers (vid_public, vid_private) only see Active Streams — redirect to viewer page, block full editor
        if role == 'viewer':
            if request.path not in VIEWER_ALLOWED and not request.path.startswith('/static'):
                return redirect('/viewer')

    # ── Active Streams viewer page (vid_public / vid_private) ────────────

    @app.route('/viewer')
    def viewer_page():
        if session.get('role') != 'viewer':
            return redirect('/')
        return Response(ACTIVE_STREAMS_VIEWER_HTML, content_type='text/html')

    @app.route('/api/viewer/streams')
    def api_viewer_streams():
        if session.get('role') != 'viewer':
            return jsonify({'error': 'Unauthorized'}), 403
        try:
            api_url = os.environ.get('MEDIAMTX_API_URL', 'http://127.0.0.1:9898')
            req = urllib.request.Request(f'{api_url.rstrip("/")}/v3/paths/list', headers={'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            items = data.get('items') or []
            # Only show paths that are ready/available (active). TODO: filter by session['ldap_groups'] and path-to-group mapping so vid_public vs vid_private see different streams.
            streams = []
            for p in items:
                name = p.get('name') or p.get('confName') or ''
                if not name:
                    continue
                ready = p.get('ready', False)
                available = p.get('available', True)
                streams.append({
                    'name': name,
                    'ready': ready,
                    'available': available,
                })
            return jsonify({'streams': streams})
        except Exception as e:
            return jsonify({'error': str(e)[:200], 'streams': []}), 500

    # ── Stream Access page (vid_admin only) ──────────────────────────────

    @app.route('/stream-access')
    def stream_access_page():
        if session.get('role') != 'admin':
            return redirect('/viewer')
        return Response(STREAM_ACCESS_HTML, content_type='text/html')

    # ── Stream Access API ───────────────────────────────────────────────

    @app.route('/api/stream-access/users')
    def api_stream_users():
        if session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        try:
            vid_group_map = {}
            for gname in VID_GROUPS:
                try:
                    result = _ak_get(f'core/groups/?search={urllib.request.quote(gname)}')
                    for g in result.get('results', []):
                        if g['name'] == gname:
                            vid_group_map[gname] = g['pk']
                except Exception:
                    pass

            users = []
            page = 1
            while True:
                result = _ak_get(f'core/users/?page={page}&page_size=100&ordering=username')
                for u in result.get('results', []):
                    user_groups = []
                    for g in (u.get('groups_obj') or []):
                        if g.get('name') in vid_group_map:
                            user_groups.append(g['name'])
                    users.append({
                        'pk': u['pk'],
                        'username': u.get('username', ''),
                        'name': u.get('name', ''),
                        'email': u.get('email', ''),
                        'groups': user_groups,
                        'is_active': u.get('is_active', True),
                    })
                pagination = result.get('pagination', {})
                if not pagination.get('next'):
                    break
                page += 1

            return jsonify({
                'users': users,
                'available_groups': list(VID_GROUPS),
                'group_pks': vid_group_map,
            })
        except Exception as e:
            return jsonify({'error': str(e)[:200]}), 500

    @app.route('/api/stream-access/toggle-group', methods=['POST'])
    def api_toggle_group():
        if session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        try:
            data = request.get_json()
            user_pk = data['user_pk']
            group_pk = data['group_pk']
            action = data['action']
            if action == 'add':
                _ak_post(f'core/groups/{group_pk}/add_user/', {'pk': user_pk})
            elif action == 'remove':
                _ak_post(f'core/groups/{group_pk}/remove_user/', {'pk': user_pk})
            else:
                return jsonify({'error': 'Invalid action'}), 400
            return jsonify({'ok': True})
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode()[:300]
            except Exception:
                pass
            return jsonify({'error': f'Authentik API {e.code}: {body}'}), 502
        except Exception as e:
            return jsonify({'error': str(e)[:200]}), 500

    # ── Sidebar injection ───────────────────────────────────────────────
    # Replace "Web Users" sidebar item with "Stream Access" link and hide
    # standalone auth-related UI elements when in LDAP mode.

    @app.after_request
    def _inject_ldap_sidebar(response):
        if not (response.content_type and 'text/html' in response.content_type):
            return response
        if not session.get('ldap_mode'):
            return response
        if session.get('role') != 'admin':
            return response
        try:
            html = response.get_data(as_text=True)
            if '</body>' not in html:
                return response
            script = (
                '<script>'
                'document.addEventListener("DOMContentLoaded",function(){'
                'document.querySelectorAll(".sidebar-item").forEach(function(b){'
                'var t=b.textContent||"";'
                'if(t.indexOf("Web Users")!==-1){'
                'b.innerHTML=\'<span class="sidebar-label">Stream Access</span>\';'
                'b.onclick=function(e){e.preventDefault();window.location.href="/stream-access"};'
                '}'
                'if(t.indexOf("Account")!==-1){b.style.display="none"}'
                '});'
                '});'
                '</script>'
            )
            idx = html.rfind('</body>')
            if idx == -1:
                return response
            html = html[:idx] + script + html[idx:]
            response.set_data(html)
            response.headers['Content-Length'] = len(response.get_data())
        except Exception:
            pass
        return response

    print("[LDAP Overlay] Authentik/LDAP mode active — auto-auth via headers, Stream Access at /stream-access")


# ════════════════════════════════════════════════════════════════════════
# Active Streams viewer page (vid_public / vid_private — regular users)
# ════════════════════════════════════════════════════════════════════════

ACTIVE_STREAMS_VIEWER_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Active Streams — MediaMTX</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200&display=swap">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#121212;--surface:#1e1e1e;--surface2:#2a2a2a;--border:#333;
  --text:#e0e0e0;--text-dim:#888;--text-faint:#555;
  --accent:#00bcd4;--accent-hover:#00acc1;--success:#22c55e;
}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5}
.header{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 24px}
.header h1{font-size:20px;font-weight:600}
.header .subtitle{color:var(--text-dim);font-size:13px;margin-top:4px}
.container{max-width:800px;margin:0 auto;padding:24px}
.stream-list{display:flex;flex-direction:column;gap:10px}
.stream-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px 18px;display:flex;align-items:center;justify-content:space-between;gap:16px}
.stream-card.live{border-left:4px solid var(--success)}
.stream-name{font-weight:500;font-size:15px;font-family:monospace}
.stream-badge{font-size:11px;color:var(--text-dim);text-transform:uppercase}
.watch-link{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;background:var(--accent);color:#fff;border-radius:6px;text-decoration:none;font-size:13px;font-weight:500;transition:background .15s}
.watch-link:hover{background:var(--accent-hover)}
.loading{text-align:center;padding:48px 20px;color:var(--text-dim)}
.spinner{width:32px;height:32px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 16px}
@keyframes spin{to{transform:rotate(360deg)}}
.empty-state{text-align:center;padding:48px 20px;color:var(--text-dim)}
.empty-state .material-symbols-outlined{font-size:42px;margin-bottom:12px;color:var(--text-faint)}
</style>
</head>
<body>
<div class="header">
  <h1>Active Streams</h1>
  <div class="subtitle">Streams you can watch</div>
</div>
<div class="container">
  <div id="content">
    <div class="loading"><div class="spinner"></div><div>Loading streams...</div></div>
  </div>
</div>
<script>
(async function(){
  const content = document.getElementById('content');
  try {
    const r = await fetch('/api/viewer/streams');
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Failed to load streams');
    const streams = (data.streams || []).filter(s => s.ready || s.available);
    if (streams.length === 0) {
      content.innerHTML = '<div class="empty-state"><span class="material-symbols-outlined">videocam_off</span><p>No active streams right now.</p><p style="margin-top:8px;font-size:13px">When someone publishes a stream, it will appear here.</p></div>';
      return;
    }
    const base = window.location.origin;
    let html = '<div class="stream-list">';
    for (const s of streams) {
      const path = (s.name || '').replace(/^\/+|\/+$/g, '');
      const url = path ? base + '/' + path + '/' : base + '/';
      html += '<div class="stream-card live"><div><div class="stream-name">' + escapeHtml(s.name) + '</div><div class="stream-badge">Live</div></div><a href="' + escapeHtml(url) + '" class="watch-link" target="_blank" rel="noopener"><span class="material-symbols-outlined" style="font-size:18px">play_circle</span>Watch</a></div>';
    }
    html += '</div>';
    content.innerHTML = html;
  } catch (err) {
    content.innerHTML = '<div class="empty-state"><span class="material-symbols-outlined">error</span><p>' + escapeHtml(err.message) + '</p></div>';
  }
})();
function escapeHtml(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}
</script>
</body>
</html>
'''

# ════════════════════════════════════════════════════════════════════════
# Stream Access HTML — standalone page (vid_admin only)
# ════════════════════════════════════════════════════════════════════════

STREAM_ACCESS_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Stream Access — MediaMTX</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200&display=swap">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#121212;--surface:#1e1e1e;--surface2:#2a2a2a;--border:#333;
  --text:#e0e0e0;--text-dim:#888;--text-faint:#555;
  --accent:#00bcd4;--accent-hover:#00acc1;
  --admin:#f59e0b;--private:#3b82f6;--public:#22c55e;
  --danger:#ef4444;--success:#22c55e;
}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5}

/* Header */
.header{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.header-left{display:flex;align-items:center;gap:14px}
.header-left h1{font-size:20px;font-weight:600;letter-spacing:-0.3px}
.header-left .subtitle{color:var(--text-dim);font-size:13px}
.back-link{color:var(--accent);text-decoration:none;font-size:13px;display:flex;align-items:center;gap:4px;padding:6px 12px;border-radius:6px;transition:background .15s}
.back-link:hover{background:rgba(0,188,212,.1)}

/* Container */
.container{max-width:1100px;margin:0 auto;padding:24px}

/* Search */
.search-bar{position:relative;margin-bottom:20px}
.search-bar input{width:100%;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 16px 12px 44px;color:var(--text);font-size:14px;outline:none;transition:border-color .15s}
.search-bar input:focus{border-color:var(--accent)}
.search-bar input::placeholder{color:var(--text-faint)}
.search-bar .search-icon{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--text-faint);font-size:20px}

/* Stats bar */
.stats{display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.stat-chip{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:6px 14px;font-size:12px;color:var(--text-dim);display:flex;align-items:center;gap:6px}
.stat-chip .num{color:var(--text);font-weight:600;font-size:14px}

/* Table */
.user-table{width:100%;border-collapse:separate;border-spacing:0}
.user-table thead th{text-align:left;padding:10px 14px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--text-dim);border-bottom:1px solid var(--border);position:sticky;top:63px;background:var(--bg);z-index:10}
.user-table tbody tr{transition:background .1s}
.user-table tbody tr:hover{background:var(--surface)}
.user-table td{padding:12px 14px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle}
.user-cell{display:flex;align-items:center;gap:10px}
.user-avatar{width:32px;height:32px;border-radius:50%;background:var(--surface2);display:flex;align-items:center;justify-content:center;font-weight:600;font-size:13px;color:var(--accent);text-transform:uppercase;flex-shrink:0}
.user-name{font-weight:500;font-size:14px}
.user-email{color:var(--text-dim);font-size:12px}
.user-inactive{opacity:.45}

/* Group badges */
.groups-cell{display:flex;gap:6px;flex-wrap:wrap}
.group-badge{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;cursor:pointer;transition:all .15s;user-select:none;border:1.5px solid transparent;display:flex;align-items:center;gap:4px}
.group-badge .material-symbols-outlined{font-size:14px}
.group-badge.active.vid_admin{background:rgba(245,158,11,.15);color:var(--admin);border-color:rgba(245,158,11,.35)}
.group-badge.active.vid_private{background:rgba(59,130,246,.15);color:var(--private);border-color:rgba(59,130,246,.35)}
.group-badge.active.vid_public{background:rgba(34,197,94,.15);color:var(--public);border-color:rgba(34,197,94,.35)}
.group-badge.inactive{background:transparent;color:var(--text-faint);border-color:var(--border)}
.group-badge.inactive:hover{border-color:var(--text-dim);color:var(--text-dim)}
.group-badge.active:hover{filter:brightness(1.2)}
.group-badge.loading{opacity:.5;pointer-events:none}
.no-groups{color:var(--text-faint);font-size:12px;font-style:italic}

/* Toast */
.toast{position:fixed;bottom:24px;right:24px;padding:12px 20px;border-radius:8px;font-size:13px;z-index:1000;transform:translateY(100px);opacity:0;transition:all .3s ease}
.toast.show{transform:translateY(0);opacity:1}
.toast.success{background:#16a34a;color:#fff}
.toast.error{background:#dc2626;color:#fff}

/* Loading */
.loading-overlay{display:flex;align-items:center;justify-content:center;min-height:300px;flex-direction:column;gap:12px;color:var(--text-dim)}
.spinner{width:32px;height:32px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* Empty state */
.empty-state{text-align:center;padding:60px 20px;color:var(--text-dim)}
.empty-state .material-symbols-outlined{font-size:48px;margin-bottom:12px;color:var(--text-faint)}
.empty-state p{font-size:14px}

/* Legend */
.legend{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px 20px;margin-bottom:20px;display:flex;gap:24px;flex-wrap:wrap;align-items:center}
.legend-title{font-size:12px;font-weight:600;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px}
.legend-item{display:flex;align-items:center;gap:8px;font-size:13px}
.legend-dot{width:10px;height:10px;border-radius:50%}
.legend-dot.admin{background:var(--admin)}
.legend-dot.private{background:var(--private)}
.legend-dot.public{background:var(--public)}

/* Responsive */
@media(max-width:768px){
  .header{flex-direction:column;gap:10px;align-items:flex-start}
  .container{padding:16px}
  .legend{flex-direction:column;align-items:flex-start;gap:8px}
  .stats{flex-direction:column}
  .user-table thead{display:none}
  .user-table tbody tr{display:block;padding:12px;margin-bottom:8px;background:var(--surface);border-radius:8px;border:1px solid var(--border)}
  .user-table td{display:block;padding:4px 0;border:none}
  .user-table td:first-child{padding-bottom:8px}
  .groups-cell{padding-top:8px}
}
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <div>
      <h1>Stream Access</h1>
      <div class="subtitle">Manage who can access MediaMTX streams</div>
    </div>
  </div>
  <a href="/" class="back-link">
    <span class="material-symbols-outlined" style="font-size:18px">arrow_back</span>
    Back to Editor
  </a>
</div>

<div class="container">
  <div class="legend">
    <span class="legend-title">Groups</span>
    <div class="legend-item"><span class="legend-dot admin"></span> <strong>vid_admin</strong> — Full config editor</div>
    <div class="legend-item"><span class="legend-dot private"></span> <strong>vid_private</strong> — Private streams viewer</div>
    <div class="legend-item"><span class="legend-dot public"></span> <strong>vid_public</strong> — Public streams viewer</div>
  </div>

  <div class="search-bar">
    <span class="material-symbols-outlined search-icon">search</span>
    <input type="text" id="search" placeholder="Search users by name, username, or email..." oninput="filterUsers()">
  </div>

  <div class="stats" id="stats"></div>

  <div id="content">
    <div class="loading-overlay">
      <div class="spinner"></div>
      <div>Loading users from Authentik...</div>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let allUsers = [];
let groupPks = {};
let availableGroups = [];

async function loadUsers() {
  const content = document.getElementById('content');
  try {
    const resp = await fetch('/api/stream-access/users');
    if (!resp.ok) throw new Error('API error ' + resp.status);
    const data = await resp.json();
    if (data.error) throw new Error(data.error);
    allUsers = data.users;
    groupPks = data.group_pks;
    availableGroups = data.available_groups;
    renderStats();
    renderTable();
  } catch (err) {
    content.innerHTML = '<div class="empty-state"><span class="material-symbols-outlined">error</span><p>Failed to load users: ' + escHtml(err.message) + '</p><p style="margin-top:8px;font-size:12px">Check that Authentik is running and the API token is valid.</p></div>';
  }
}

function renderStats() {
  const active = allUsers.filter(u => u.is_active).length;
  const admins = allUsers.filter(u => u.groups.includes('vid_admin')).length;
  const priv = allUsers.filter(u => u.groups.includes('vid_private')).length;
  const pub = allUsers.filter(u => u.groups.includes('vid_public')).length;
  const noAccess = allUsers.filter(u => u.groups.length === 0).length;
  document.getElementById('stats').innerHTML =
    '<div class="stat-chip"><span class="num">' + active + '</span> active users</div>' +
    '<div class="stat-chip"><span class="num" style="color:var(--admin)">' + admins + '</span> admins</div>' +
    '<div class="stat-chip"><span class="num" style="color:var(--private)">' + priv + '</span> private</div>' +
    '<div class="stat-chip"><span class="num" style="color:var(--public)">' + pub + '</span> public</div>' +
    '<div class="stat-chip"><span class="num" style="color:var(--text-faint)">' + noAccess + '</span> no stream access</div>';
}

function renderTable() {
  const q = (document.getElementById('search').value || '').toLowerCase();
  let filtered = allUsers;
  if (q) {
    filtered = allUsers.filter(u =>
      u.username.toLowerCase().includes(q) ||
      (u.name || '').toLowerCase().includes(q) ||
      (u.email || '').toLowerCase().includes(q)
    );
  }
  if (filtered.length === 0) {
    document.getElementById('content').innerHTML = '<div class="empty-state"><span class="material-symbols-outlined">person_off</span><p>' + (q ? 'No users match your search.' : 'No users found in Authentik.') + '</p></div>';
    return;
  }
  let html = '<table class="user-table"><thead><tr><th>User</th><th>Email</th><th>Stream Groups (click to toggle)</th></tr></thead><tbody>';
  for (const u of filtered) {
    const cls = u.is_active ? '' : ' class="user-inactive"';
    const initial = (u.username || '?')[0];
    const displayName = u.name || u.username;
    html += '<tr' + cls + '><td><div class="user-cell"><div class="user-avatar">' + escHtml(initial) + '</div><div><div class="user-name">' + escHtml(displayName) + '</div><div style="color:var(--text-dim);font-size:12px">@' + escHtml(u.username) + '</div></div></div></td>';
    html += '<td><span style="font-size:13px;color:var(--text-dim)">' + escHtml(u.email || '—') + '</span></td>';
    html += '<td><div class="groups-cell">';
    if (availableGroups.length === 0) {
      html += '<span class="no-groups">No vid_* groups created</span>';
    } else {
      for (const g of availableGroups) {
        const active = u.groups.includes(g);
        const cls2 = 'group-badge ' + (active ? 'active' : 'inactive') + ' ' + g;
        const icon = active ? 'check_circle' : 'add_circle_outline';
        html += '<span class="' + cls2 + '" data-user="' + u.pk + '" data-group="' + g + '" onclick="toggleGroup(this,' + u.pk + ',\'' + g + '\',' + active + ')">';
        html += '<span class="material-symbols-outlined">' + icon + '</span>' + g.replace('vid_', '');
        html += '</span>';
      }
    }
    html += '</div></td></tr>';
  }
  html += '</tbody></table>';
  document.getElementById('content').innerHTML = html;
}

function filterUsers() { renderTable(); }

async function toggleGroup(el, userPk, groupName, currentlyActive) {
  const gPk = groupPks[groupName];
  if (!gPk) { showToast('Group not found: ' + groupName, 'error'); return; }
  el.classList.add('loading');
  try {
    const resp = await fetch('/api/stream-access/toggle-group', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({user_pk: userPk, group_pk: gPk, action: currentlyActive ? 'remove' : 'add'})
    });
    const data = await resp.json();
    if (!resp.ok || data.error) throw new Error(data.error || 'API error');
    const user = allUsers.find(u => u.pk === userPk);
    if (user) {
      if (currentlyActive) {
        user.groups = user.groups.filter(g => g !== groupName);
      } else {
        user.groups.push(groupName);
      }
    }
    renderStats();
    renderTable();
    showToast((currentlyActive ? 'Removed from ' : 'Added to ') + groupName, 'success');
  } catch (err) {
    showToast('Failed: ' + err.message, 'error');
    el.classList.remove('loading');
  }
}

function showToast(msg, type) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast ' + type + ' show';
  setTimeout(() => { t.classList.remove('show'); }, 3000);
}

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

loadUsers();
</script>
</body>
</html>
'''
