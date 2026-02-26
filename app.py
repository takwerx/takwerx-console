#!/usr/bin/env python3
"""infra-TAK v0.1.6 - TAK Infrastructure Platform"""

from flask import (Flask, render_template_string, request, jsonify,
    redirect, url_for, session, send_from_directory, make_response)
from werkzeug.security import check_password_hash
from functools import wraps
import os, ssl, json, secrets, subprocess, time, psutil, threading, html
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024
# When using domain (infratak.*) set cookie domain for session; when using IP (backdoor) use no domain so cookie is sent
def _set_session_cookie_domain():
    try:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.config', 'settings.json')
        if os.path.exists(p) and (not app.config.get('SESSION_COOKIE_DOMAIN')):
            _s = json.load(open(p))
            if _s.get('fqdn'):
                app.config['SESSION_COOKIE_DOMAIN'] = '.' + _s['fqdn'].split(':')[0]
    except Exception:
        pass
_set_session_cookie_domain()

@app.context_processor
def inject_cloudtak_icon():
    from flask import request
    from markupsafe import Markup
    d = {'cloudtak_icon': CLOUDTAK_ICON, 'mediamtx_logo_url': MEDIAMTX_LOGO_URL, 'nodered_logo_url': NODERED_LOGO_URL, 'authentik_logo_url': AUTHENTIK_LOGO_URL, 'caddy_logo_url': CADDY_LOGO_URL, 'tak_logo_url': TAK_LOGO_URL}
    if not request.path.startswith('/api') and not request.path.startswith('/cloudtak/page.js'):
        d['sidebar_html'] = Markup(render_sidebar(detect_modules(), request.path.strip('/') or 'console'))
    return d

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Pin config to env so auth works even if service WorkingDirectory and code path ever differ (e.g. after git pull)
CONFIG_DIR = os.environ.get('CONFIG_DIR') or os.path.join(BASE_DIR, '.config')
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')

def _request_host_is_ip():
    """True if the request is to an IP address (backdoor), so we must not set cookie domain."""
    try:
        host = (request.host or '').split(':')[0]
        if not host:
            return True
        parts = host.split('.')
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    except Exception:
        return True

@app.before_request
def ensure_session_cookie_domain():
    """When access is via IP (backdoor), do not set cookie domain so the cookie is sent. Otherwise use FQDN for cross-subdomain."""
    if _request_host_is_ip():
        app.config['SESSION_COOKIE_DOMAIN'] = False
        return
    if app.config.get('SESSION_COOKIE_DOMAIN'):
        return
    try:
        s = load_settings()
        if s.get('fqdn'):
            app.config['SESSION_COOKIE_DOMAIN'] = '.' + s['fqdn'].split(':')[0]
    except Exception:
        pass
VERSION = "0.1.7-alpha"
GITHUB_REPO = "takwerx/infra-TAK"
CADDYFILE_PATH = "/etc/caddy/Caddyfile"
# CloudTAK official icon (SVG data URL)
CLOUDTAK_ICON = "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c3ZnIGlkPSJMYXllcl8xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2aWV3Qm94PSIwIDAgNzQuMyA0Ni42MiI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOnVybCgjbGluZWFyLWdyYWRpZW50LTIpO30uY2xzLTJ7ZmlsbDp1cmwoI2xpbmVhci1ncmFkaWVudCk7fTwvc3R5bGU+PGxpbmVhckdyYWRpZW50IGlkPSJsaW5lYXItZ3JhZGllbnQiIHgxPSIxNC4zOCIgeTE9IjguOTMiIHgyPSI2Ni45MiIgeTI9IjYxLjQ3IiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHN0b3Agb2Zmc2V0PSIwIiBzdG9wLWNvbG9yPSIjZmY5ODIwIi8+PHN0b3Agb2Zmc2V0PSIuNDIiIHN0b3AtY29sb3I9IiNmZmNlMDQiLz48c3RvcCBvZmZzZXQ9Ii40OSIgc3RvcC1jb2xvcj0iZ29sZCIvPjwvbGluZWFyR3JhZGllbnQ+PGxpbmVhckdyYWRpZW50IGlkPSJsaW5lYXItZ3JhZGllbnQtMiIgeDE9IjU5LjI3IiB5MT0iLS4zOCIgeDI9IjcyLjc0IiB5Mj0iMTIuMDgiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj48c3RvcCBvZmZzZXQ9IjAiIHN0b3AtY29sb3I9IiNmZjk4MjAiLz48c3RvcCBvZmZzZXQ9Ii4yOSIgc3RvcC1jb2xvcj0iI2ZmYjYxMCIvPjxzdG9wIG9mZnNldD0iLjU3IiBzdG9wLWNvbG9yPSJnb2xkIi8+PC9saW5lYXJHcmFkaWVudD48L2RlZnM+PHBhdGggY2xhc3M9ImNscy0yIiBkPSJNNzIuMDUsMjMuNTVjLTEuMjYtMS44OC0zLjAxLTMuNDUtNS4yMS00LjY1LTEuODUtMS4wMS0zLjY5LTEuNTktNS4wNi0xLjkxLS40Mi0xLjc0LTEuMjMtNC4yOC0yLjc3LTYuODVDNTYuNDQsNS44OCw1MS4zNy42Nyw0MS43LjA2Yy0uNTktLjA0LTEuMTgtLjA2LTEuNzUtLjA2LTcuODIsMC0xMi4wNCwzLjUyLTE0LjE5LDYuNDctLjkxLDEuMjQtMS41MywyLjQ4LTEuOTUsMy41NS0uODYtLjEzLTEuODYtLjIyLTIuOTMtLjIyLTMuNTYsMC02LjUyLDEuMDgtOC41NCwzLjEzLTEuOTEsMS45Mi0zLjIsNC4yNi0zLjczLDYuNzUtLjA5LjQxLS4xNS44LS4xOSwxLjE2LS45NS40Ny0yLjEyLDEuMTYtMy4yOSwyLjExQzEuNTYsMjUuODMtLjIsMjkuNjcuMDIsMzQuMDZjLjIyLDQuNDEsMi4yNyw3Ljk2LDUuOTQsMTAuMjksMi42LDEuNjUsNS4xLDIuMTksNS4zOCwyLjIzbC4yMi4wM2guMjJzNDguODYsMCw0OC44NiwwaC4xcy4xLDAsLjEsMGMuMzQtLjAyLDMuMzktLjI2LDYuNTQtMi4xMywzLjA0LTEuOCw2LjctNS40NSw2LjkyLTEyLjU2LjEtMy4xOC0uNjYtNS45OS0yLjI0LTguMzZaTTE0LjQzLDE1YzEuNzUtMS43Nyw0LjI0LTIuMjYsNi40NS0yLjI2LDIuNzEsMCw0Ljk5LjczLDQuOTkuNzMsMCwwLDEuMzMtMTAuNTMsMTQuMDctMTAuNTMuNSwwLDEuMDMuMDIsMS41Ny4wNSwxNi4yNCwxLjAzLDE3Ljc0LDE2LjU0LDE3Ljc0LDE2LjU0LDAsMCw0LjY3LjQyLDguMjEsMy4zMS0zLjQ3LDMuMjItNC45NSw1LjE5LTEyLjc3LDUuNzUtOC42NS42MS03LjQ3LDMuOTUtNy40NywzLjk1bC00LjA1LTguOThoNS43OWMuMTQtMi44NS0uODctNS42NS01LjMxLTUuNjVoLTguNDlsLTYuNTYsMTQuNjJzMS45Ni0zLjMxLTYuNjktMy45NWMtNy42OS0uNTUtNy41OC0yLjY5LTEwLjYxLTUuODgtLjA2LS41OC0uMjYtNC4zLDMuMTMtNy43MloiLz48cGF0aCBjbGFzcz0iY2xzLTEiIGQ9Ik02MS43OSwzLjczaDIuNTl2LjY0aC0uOTN2Mi4zOGgtLjc0di0yLjM4aC0uOTN2LS42NFpNNjcuMDUsMy43M2wtLjc3LDIuMDMtLjc3LTIuMDNoLS45M3YzLjAzaC43di0ybC43MywyaC41NGwuNzMtMnYyaC43di0zLjAzaC0uOTNaIi8+PC9zdmc+"
# MediaMTX official logo (external URL to avoid long inline strings)
MEDIAMTX_LOGO_URL = "https://raw.githubusercontent.com/bluenviron/mediamtx/main/logo.png"
# MediaMTX web editor: regular repo (no LDAP); when Authentik/LDAP is installed we use LDAP branch if set
MEDIAMTX_EDITOR_REPO = "https://github.com/takwerx/mediamtx-installer.git"
MEDIAMTX_EDITOR_PATH = "config-editor"  # subdir containing mediamtx_config_editor.py
MEDIAMTX_EDITOR_LDAP_BRANCH = "infratak"  # when LDAP/Authentik installed, try this branch first; None = always use default branch
# Node-RED official icons (https://nodered.org/about/resources/media/)
NODERED_LOGO_URL = "https://nodered.org/about/resources/media/node-red-icon.png"       # icon only (e.g. small nav)
NODERED_LOGO_URL_2 = "https://nodered.org/about/resources/media/node-red-icon-2.png"   # icon + "Node-RED" text (card, sidebar)
# Authentik official brand icon (external URL)
AUTHENTIK_LOGO_URL = "https://raw.githubusercontent.com/goauthentik/authentik/main/web/icons/icon_left_brand.png"
# Caddy official logo for dark backgrounds — white text (Wikimedia Commons)
CADDY_LOGO_URL = "https://upload.wikimedia.org/wikipedia/commons/5/56/Caddyserver_logo_dark.svg"
# TAK (Team Awareness Kit) official brand logo from tak.gov
TAK_LOGO_URL = "https://tak.gov/assets/logos/brand-06b80939.svg"
update_cache = {'latest': None, 'checked': 0, 'notes': ''}
os.makedirs(UPLOAD_DIR, exist_ok=True)

def load_settings():
    p = os.path.join(CONFIG_DIR, 'settings.json')
    return json.load(open(p)) if os.path.exists(p) else {}

def save_settings(s):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    json.dump(s, open(os.path.join(CONFIG_DIR, 'settings.json'), 'w'), indent=2)

def load_auth():
    """Load auth.json from CONFIG_DIR. Never raises — returns {} on missing file or error."""
    try:
        p = os.path.join(CONFIG_DIR, 'auth.json')
        if os.path.exists(p):
            with open(p) as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def _apply_authentik_session():
    """If request has Authentik headers (from Caddy forward_auth), set session so we treat user as logged in."""
    uname = request.headers.get('X-Authentik-Username')
    if uname:
        session['authenticated'] = True
        session['authentik_username'] = uname
        return True
    return False

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if _apply_authentik_session():
            return f(*args, **kwargs)
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def detect_modules():
    modules = {}
    settings = load_settings()
    has_fqdn = bool(settings.get('fqdn', ''))
    # Caddy SSL - First when no FQDN configured
    caddy_installed = subprocess.run(['which', 'caddy'], capture_output=True).returncode == 0
    caddy_running = False
    if caddy_installed:
        r = subprocess.run(['systemctl', 'is-active', 'caddy'], capture_output=True, text=True)
        caddy_running = r.stdout.strip() == 'active'
    modules['caddy'] = {'name': 'Caddy SSL', 'installed': caddy_installed, 'running': caddy_running,
        'description': "Domain setup, Let's Encrypt SSL & reverse proxy" if not has_fqdn else f"SSL & reverse proxy — {settings.get('fqdn', '')}",
        'icon': '🔒', 'icon_url': CADDY_LOGO_URL, 'route': '/caddy', 'priority': 0 if not has_fqdn else 10}
    # TAK Server
    tak_installed = os.path.exists('/opt/tak') and os.path.exists('/opt/tak/CoreConfig.xml')
    tak_running = False
    if tak_installed:
        r = subprocess.run(['systemctl', 'is-active', 'takserver'], capture_output=True, text=True)
        tak_running = r.stdout.strip() == 'active'
    modules['takserver'] = {'name': 'TAK Server', 'installed': tak_installed, 'running': tak_running,
        'description': 'Team Awareness Kit server for situational awareness', 'icon': '🗺️', 'icon_url': TAK_LOGO_URL, 'route': '/takserver', 'priority': 1}
    # Authentik - Identity Provider
    ak_installed = os.path.exists(os.path.expanduser('~/authentik/docker-compose.yml'))
    ak_running = False
    if ak_installed:
        r = subprocess.run('docker ps --filter name=authentik-server --format "{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True)
        ak_running = 'Up' in r.stdout
    modules['authentik'] = {'name': 'Authentik', 'installed': ak_installed, 'running': ak_running,
        'description': 'Identity provider — SSO, LDAP, user management', 'icon': '🔐', 'icon_url': AUTHENTIK_LOGO_URL, 'route': '/authentik', 'priority': 2}
    # TAK Portal - Docker-based user management
    portal_installed = os.path.exists(os.path.expanduser('~/TAK-Portal/docker-compose.yml'))
    portal_running = False
    if portal_installed:
        r = subprocess.run('docker ps --filter name=tak-portal --format "{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True)
        portal_running = 'Up' in r.stdout
    modules['takportal'] = {'name': 'TAK Portal', 'installed': portal_installed, 'running': portal_running,
        'description': 'User & certificate management with Authentik', 'icon': '👥', 'route': '/takportal', 'priority': 3}
    # MediaMTX
    mtx_installed = os.path.exists('/usr/local/bin/mediamtx') and os.path.exists('/usr/local/etc/mediamtx.yml')
    mtx_running = False
    if mtx_installed:
        r = subprocess.run(['systemctl', 'is-active', 'mediamtx'], capture_output=True, text=True)
        mtx_running = r.stdout.strip() == 'active'
    modules['mediamtx'] = {'name': 'MediaMTX', 'installed': mtx_installed, 'running': mtx_running,
        'description': 'Video Streaming Server', 'icon': '📹', 'icon_url': MEDIAMTX_LOGO_URL, 'route': '/mediamtx', 'priority': 4}
    # Guard Dog
    gd_installed = os.path.exists('/opt/tak-guarddog')
    gd_running = False
    if gd_installed:
        r = subprocess.run(['systemctl', 'list-timers', '--no-pager'], capture_output=True, text=True)
        gd_running = 'tak8089guard' in r.stdout
    modules['guarddog'] = {'name': 'Guard Dog', 'installed': gd_installed, 'running': gd_running,
        'description': 'Health monitoring and auto-recovery', 'icon': '🐕', 'route': '/guarddog', 'priority': 5}
    # Node-RED (container name is "nodered" from compose container_name)
    nodered_installed = False
    nodered_running = False
    nr_dir = os.path.expanduser('~/node-red')
    nr_compose = os.path.join(nr_dir, 'docker-compose.yml')
    if os.path.exists(nr_compose):
        nodered_installed = True
        r = subprocess.run(f'docker compose -f "{nr_compose}" ps -q 2>/dev/null', shell=True, capture_output=True, text=True, timeout=5, cwd=nr_dir)
        if r.returncode == 0 and (r.stdout or '').strip():
            r2 = subprocess.run('docker ps --filter name=nodered --format "{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True)
            nodered_running = bool(r2.stdout and 'Up' in r2.stdout)
    if not nodered_installed and (os.path.exists(os.path.expanduser('~/node-red')) or os.path.exists('/opt/nodered')):
        nodered_installed = True
        r = subprocess.run(['systemctl', 'is-active', 'nodered'], capture_output=True, text=True)
        if r.stdout.strip() == 'active':
            nodered_running = True
    modules['nodered'] = {'name': 'Node-RED', 'installed': nodered_installed, 'running': nodered_running,
        'description': 'Flow-based automation & integrations', 'icon': '🔴', 'icon_url': NODERED_LOGO_URL_2, 'route': '/nodered', 'priority': 6}
    # CloudTAK
    cloudtak_dir = os.path.expanduser('~/CloudTAK')
    cloudtak_installed = os.path.exists(cloudtak_dir) and os.path.exists(os.path.join(cloudtak_dir, 'docker-compose.yml'))
    cloudtak_running = False
    r = subprocess.run('docker ps --filter name=cloudtak-api --format "{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True, timeout=5)
    if r.stdout and 'Up' in r.stdout:
        cloudtak_running = True
    if not cloudtak_installed and cloudtak_running:
        cloudtak_installed = True  # container up but dir missing (e.g. different user) — show as installed so card is accurate
    modules['cloudtak'] = {'name': 'CloudTAK', 'installed': cloudtak_installed, 'running': cloudtak_running,
        'description': 'Web-based TAK client — browser access to TAK', 'icon': '☁️', 'icon_data': CLOUDTAK_ICON, 'route': '/cloudtak', 'priority': 7}
    # Email Relay (Postfix)
    email_installed = subprocess.run(['which', 'postfix'], capture_output=True).returncode == 0
    email_running = False
    if email_installed:
        r = subprocess.run(['systemctl', 'is-active', 'postfix'], capture_output=True, text=True)
        email_running = r.stdout.strip() == 'active'
    modules['emailrelay'] = {'name': 'Email Relay', 'installed': email_installed, 'running': email_running,
        'description': 'Postfix relay — notifications for TAK Portal & MediaMTX', 'icon': '📧', 'route': '/emailrelay', 'priority': 8}
    return dict(sorted(modules.items(), key=lambda x: x[1].get('priority', 99)))

def render_sidebar(modules, active_path):
    """Build sidebar nav HTML: Console and Marketplace always; tool links only when installed.
    active_path is the current path (e.g. 'console', 'nodered') for highlighting."""
    active = (active_path or '').strip('/') or 'console'
    def link(href, content, title=None):
        path = href.strip('/')
        cls = 'nav-item active' if path == active else 'nav-item'
        t = f' title="{html.escape(title)}"' if title else ''
        return f'<a href="{href}" class="{cls}"{t}>{content}</a>'
    logo = '<div class="sidebar-logo"><span>infra-TAK</span><small>TAK Infrastructure Platform</small><small style="display:block;margin-top:2px;font-size:9px;color:var(--text-dim);opacity:0.85">built by TAKWERX</small></div>'
    parts = [logo]
    parts.append(link('/console', '<span class="nav-icon material-symbols-outlined">dashboard</span>Console'))
    caddy = modules.get('caddy', {})
    if caddy.get('installed'):
        parts.append(link('/caddy', f'<img src="{html.escape(CADDY_LOGO_URL)}" alt="Caddy SSL" class="nav-icon" style="height:24px;width:auto;max-width:72px;object-fit:contain;display:block">', 'Caddy SSL'))
    tak = modules.get('takserver', {})
    if tak.get('installed'):
        parts.append(link('/takserver', f'<img src="{html.escape(TAK_LOGO_URL)}" alt="TAK Server" class="nav-icon" style="height:24px;width:auto;max-width:48px;object-fit:contain;display:block"><span>TAK Server</span>', 'TAK Server'))
    ak = modules.get('authentik', {})
    if ak.get('installed'):
        parts.append(link('/authentik', f'<img src="{html.escape(AUTHENTIK_LOGO_URL)}" alt="Authentik" class="nav-icon" style="height:48px;width:auto;max-width:100px;object-fit:contain;display:block">', 'Authentik'))
    portal = modules.get('takportal', {})
    if portal.get('installed'):
        parts.append(link('/takportal', '<span class="nav-icon material-symbols-outlined">group</span>TAK Portal'))
    cloudtak = modules.get('cloudtak', {})
    if cloudtak.get('installed'):
        parts.append(link('/cloudtak', f'<img src="{html.escape(CLOUDTAK_ICON)}" alt="" class="nav-icon" style="height:24px;width:auto;max-width:72px;object-fit:contain;display:block"><span>CloudTAK</span>'))
    mtx = modules.get('mediamtx', {})
    if mtx.get('installed'):
        parts.append(link('/mediamtx', f'<img src="{html.escape(MEDIAMTX_LOGO_URL)}" alt="MediaMTX" class="nav-icon" style="height:48px;width:auto;max-width:100px;object-fit:contain;display:block">', 'MediaMTX'))
    nr = modules.get('nodered', {})
    if nr.get('installed'):
        parts.append(link('/nodered', f'<img src="{html.escape(NODERED_LOGO_URL)}" alt="" class="nav-icon" style="height:24px;width:auto;max-width:72px;object-fit:contain;display:block"><span>Node-RED</span>'))
    email = modules.get('emailrelay', {})
    if email.get('installed'):
        parts.append(link('/emailrelay', '<span class="nav-icon material-symbols-outlined">outgoing_mail</span>Email Relay'))
    parts.append(link('/marketplace', '<span class="nav-icon material-symbols-outlined">shopping_cart</span>Marketplace'))
    return '<nav class="sidebar">\n  ' + '\n  '.join(parts) + '\n</nav>'

def get_system_metrics():
    cpu = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    boot = datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.now() - boot
    d, h, m = uptime.days, uptime.seconds // 3600, (uptime.seconds % 3600) // 60
    return {'cpu_percent': cpu, 'ram_percent': round(ram.percent, 1),
        'ram_used_gb': round(ram.used / (1024**3), 1), 'ram_total_gb': round(ram.total / (1024**3), 1),
        'disk_percent': round(disk.percent, 1), 'disk_used_gb': round(disk.used / (1024**3), 1),
        'disk_total_gb': round(disk.total / (1024**3), 1), 'uptime': f"{d}d {h}h {m}m"}

# === Routes ===

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET' and _apply_authentik_session():
        return redirect(url_for('console_page'))
    if request.method == 'POST':
        auth = load_auth()
        if not auth.get('password_hash'):
            return render_template_string(
                LOGIN_TEMPLATE,
                error='Password not set or wrong install path. Use backdoor: https://YOUR_SERVER_IP:5001 and run ./reset-console-password.sh from the install directory.',
                version=VERSION)
        if check_password_hash(auth['password_hash'], request.form.get('password', '')):
            session['authenticated'] = True
            return redirect(url_for('console_page'))
        return render_template_string(LOGIN_TEMPLATE, error='Invalid password', version=VERSION)
    return render_template_string(LOGIN_TEMPLATE, error=None, version=VERSION)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/', methods=['GET', 'POST'])
def index():
    """Landing: login at / (infratak.fqdn); when logged in redirect to console. Authentik headers = auto-login."""
    if request.method == 'GET' and _apply_authentik_session():
        return redirect(url_for('console_page'))
    if request.method == 'POST':
        auth = load_auth()
        if not auth.get('password_hash'):
            return render_template_string(
                LOGIN_TEMPLATE,
                error='Password not set or wrong install path. Use backdoor: https://YOUR_SERVER_IP:5001 and run ./reset-console-password.sh from the install directory.',
                version=VERSION)
        if check_password_hash(auth['password_hash'], request.form.get('password', '')):
            session['authenticated'] = True
            return redirect(url_for('console_page'))
        return render_template_string(LOGIN_TEMPLATE, error='Invalid password', version=VERSION)
    if not session.get('authenticated'):
        return render_template_string(LOGIN_TEMPLATE, error=None, version=VERSION)
    return redirect(url_for('console_page'))

@app.route('/api/forward-auth')
def forward_auth():
    """Caddy forward_auth: return 200 if session is authenticated; else redirect to console login."""
    if session.get('authenticated'):
        return '', 200
    # Redirect to console login so user can log in and retry (Caddy passes this response to the client)
    settings = load_settings()
    fqdn = (settings.get('fqdn') or '').split(':')[0]
    if fqdn:
        login_url = f"https://infratak.{fqdn}/login"
        return redirect(login_url, code=302)
    return '', 401

@app.route('/console')
@login_required
def console_page():
    """Console: only installed/deployed services."""
    settings = load_settings()
    all_modules = detect_modules()
    modules = {k: m for k, m in all_modules.items() if m.get('installed')}
    resp = render_template_string(CONSOLE_TEMPLATE,
        settings=settings, modules=modules, metrics=get_system_metrics(), version=VERSION)
    from flask import make_response
    r = make_response(resp)
    r.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return r

@app.route('/marketplace')
@login_required
def marketplace_page():
    """Marketplace: only services that are not yet installed (deploy from here)."""
    settings = load_settings()
    all_modules = detect_modules()
    modules = {k: m for k, m in all_modules.items() if not m.get('installed')}
    resp = render_template_string(MARKETPLACE_TEMPLATE,
        settings=settings, modules=modules, metrics=get_system_metrics(), version=VERSION)
    from flask import make_response
    r = make_response(resp)
    r.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return r

@app.route('/api/update/check')
@login_required
def update_check():
    import urllib.request
    now = time.time()
    # Cache for 1 hour
    if update_cache['latest'] and (now - update_cache['checked']) < 3600:
        return jsonify({'current': VERSION, 'latest': update_cache['latest'], 'notes': update_cache['notes'],
            'update_available': update_cache['latest'] != VERSION})
    try:
        req = urllib.request.Request(
            f'https://api.github.com/repos/{GITHUB_REPO}/tags',
            headers={'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'infra-TAK'}
        )
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read().decode())
        if not data:
            return jsonify({'current': VERSION, 'latest': None, 'error': 'No tags found', 'update_available': False})
        # Find the latest semver tag (sort by version)
        versions = []
        for tag in data:
            name = tag.get('name', '').lstrip('v').replace('-alpha','').replace('-beta','')
            parts = name.split('.')
            try:
                versions.append((tuple(int(p) for p in parts), tag))
            except (ValueError, IndexError):
                continue
        if not versions:
            return jsonify({'current': VERSION, 'latest': None, 'error': 'No version tags', 'update_available': False})
        versions.sort(key=lambda x: x[0], reverse=True)
        latest_tag = versions[0][1]
        latest = latest_tag.get('name', '').lstrip('v')
        # Strip -alpha/-beta for comparison
        latest_cmp = latest.replace('-alpha','').replace('-beta','')
        current_cmp = VERSION.replace('-alpha','').replace('-beta','')
        notes = f"Version {latest_tag.get('name', '')}"
        update_cache.update({'latest': latest, 'checked': now, 'notes': notes})
        return jsonify({'current': VERSION, 'latest': latest, 'notes': notes, 'body': '',
            'update_available': latest_cmp != current_cmp})
    except Exception as e:
        return jsonify({'current': VERSION, 'latest': None, 'error': str(e), 'update_available': False})

@app.route('/api/update/apply', methods=['POST'])
@login_required
def update_apply():
    console_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        r = subprocess.run(f'cd {console_dir} && git pull --rebase --autostash 2>&1', shell=True, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return jsonify({'success': False, 'error': r.stderr.strip() or r.stdout.strip()})
        update_cache.update({'latest': None, 'checked': 0})
        subprocess.Popen('sleep 2 && systemctl restart takwerx-console', shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return jsonify({'success': True, 'output': r.stdout.strip(), 'restart_required': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/takserver')
@login_required
def takserver_page():
    modules = detect_modules()
    tak = modules.get('takserver', {})
    ak = modules.get('authentik', {})
    # Show "Connect TAK Server to LDAP" when: TAK Server + Authentik installed, CoreConfig exists, LDAP not yet applied
    show_connect_ldap = (
        tak.get('installed') and ak.get('installed') and
        os.path.exists('/opt/tak/CoreConfig.xml') and not _coreconfig_has_ldap()
    )
    # Reset deploy_done once TAK Server is running so the running view shows
    if tak.get('installed') and tak.get('running') and not deploy_status.get('running', False):
        deploy_status.update({'complete': False, 'error': False})
    return render_template_string(TAKSERVER_TEMPLATE,
        settings=load_settings(), modules=modules, tak=tak,
        show_connect_ldap=show_connect_ldap,
        metrics=get_system_metrics(), version=VERSION, deploying=deploy_status.get('running', False),
        deploy_done=deploy_status.get('complete', False), deploy_error=deploy_status.get('error', False))

@app.route('/mediamtx')
@login_required
def mediamtx_page():
    settings = load_settings()
    modules = detect_modules()
    mtx = modules.get('mediamtx', {})
    cloudtak_installed = modules.get('cloudtak', {}).get('installed', False)
    return render_template_string(MEDIAMTX_TEMPLATE,
        settings=settings, mtx=mtx, version=VERSION,
        cloudtak_installed=cloudtak_installed,
        deploying=mediamtx_deploy_status.get('running', False),
        deploy_done=mediamtx_deploy_status.get('complete', False))

@app.route('/guarddog')
@login_required
def guarddog_page():
    return redirect(url_for('marketplace_page'))

@app.route('/nodered')
@login_required
def nodered_page():
    settings = load_settings()
    modules = detect_modules()
    nr = modules.get('nodered', {})
    ak = modules.get('authentik', {})
    resp = make_response(render_template_string(NODERED_TEMPLATE,
        settings=settings, nr=nr, version=VERSION,
        authentik_installed=ak.get('installed'),
        deploying=nodered_deploy_status.get('running', False),
        deploy_done=nodered_deploy_status.get('complete', False),
        caddy_logo_url=CADDY_LOGO_URL, tak_logo_url=TAK_LOGO_URL, authentik_logo_url=AUTHENTIK_LOGO_URL,
        cloudtak_icon=CLOUDTAK_ICON, mediamtx_logo_url=MEDIAMTX_LOGO_URL))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return resp

@app.route('/cloudtak')
@login_required
def cloudtak_page():
    settings = load_settings()
    cloudtak = detect_modules().get('cloudtak', {})
    container_info = {}
    if cloudtak.get('running'):
        r = subprocess.run('docker ps --filter "name=cloudtak" --format "{{.Names}}|||{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True, timeout=5)
        containers = []
        for line in (r.stdout or '').strip().split('\n'):
            if line.strip():
                parts = line.split('|||')
                containers.append({'name': parts[0], 'status': parts[1] if len(parts) > 1 else ''})
        container_info['containers'] = containers
    return render_template_string(CLOUDTAK_TEMPLATE,
        settings=settings, cloudtak=cloudtak,
        version=VERSION,
        cloudtak_icon=CLOUDTAK_ICON,
        container_info=container_info,
        deploying=cloudtak_deploy_status.get('running', False),
        deploy_done=cloudtak_deploy_status.get('complete', False))

@app.route('/cloudtak/page.js')
@login_required
def cloudtak_page_js():
    return app.response_class(CLOUDTAK_PAGE_JS, mimetype='application/javascript')

def _caddy_configured_urls(settings, modules):
    """Build list of configured subdomain → service for the Caddy page. Only when FQDN is set."""
    fqdn = settings.get('fqdn', '').strip()
    if not fqdn:
        return []
    base = f'https://{fqdn}'
    urls = []
    # infra-TAK (single URL: login + console; behind Authentik when installed)
    ak = modules.get('authentik', {})
    infratak_desc = 'Console (Authentik when enabled)' if ak.get('installed') else 'Console (after login)'
    urls.append({'name': 'infra-TAK', 'host': f'infratak.{fqdn}', 'url': f'https://infratak.{fqdn}', 'desc': infratak_desc})
    tak = modules.get('takserver', {})
    if tak.get('installed'):
        urls.append({'name': 'TAK Server', 'host': f'tak.{fqdn}', 'url': f'https://tak.{fqdn}', 'desc': 'WebGUI, Marti API'})
    ak = modules.get('authentik', {})
    if ak.get('installed'):
        urls.append({'name': 'Authentik', 'host': f'authentik.{fqdn}', 'url': f'https://authentik.{fqdn}', 'desc': 'Identity provider'})
    portal = modules.get('takportal', {})
    if portal.get('installed'):
        urls.append({'name': 'TAK Portal', 'host': f'takportal.{fqdn}', 'url': f'https://takportal.{fqdn}', 'desc': 'User & cert management'})
    nodered = modules.get('nodered', {})
    if nodered.get('installed'):
        urls.append({'name': 'Node-RED', 'host': f'nodered.{fqdn}', 'url': f'https://nodered.{fqdn}', 'desc': 'Flow editor (Authentik when enabled)'})
    cloudtak = modules.get('cloudtak', {})
    if cloudtak.get('installed'):
        urls.append({'name': 'CloudTAK (map)', 'host': f'map.{fqdn}', 'url': f'https://map.{fqdn}', 'desc': 'Browser TAK client'})
        urls.append({'name': 'CloudTAK (tiles)', 'host': f'tiles.map.{fqdn}', 'url': f'https://tiles.map.{fqdn}', 'desc': 'Tile server'})
        urls.append({'name': 'CloudTAK (video)', 'host': f'video.{fqdn}', 'url': f'https://video.{fqdn}', 'desc': 'Map video / HLS'})
    mtx = modules.get('mediamtx', {})
    if mtx.get('installed'):
        mtx_host = settings.get('mediamtx_domain', f'stream.{fqdn}')
        if '.' not in mtx_host:
            mtx_host = f'{mtx_host}.{fqdn}'
        urls.append({'name': 'MediaMTX', 'host': mtx_host, 'url': f'https://{mtx_host}', 'desc': 'Stream web console & HLS'})
    return urls

@app.route('/caddy')
@login_required
def caddy_page():
    modules = detect_modules()
    caddy = modules.get('caddy', {})
    settings = load_settings()
    # Reset deploy state if running
    if caddy.get('installed') and caddy.get('running') and not caddy_deploy_status.get('running', False):
        caddy_deploy_status.update({'complete': False, 'error': False})
    # Read current Caddyfile if exists
    caddyfile_content = ''
    if os.path.exists(CADDYFILE_PATH):
        try:
            with open(CADDYFILE_PATH) as f:
                caddyfile_content = f.read()
        except Exception:
            pass
    configured_urls = _caddy_configured_urls(settings, modules)
    return render_template_string(CADDY_TEMPLATE,
        settings=settings, caddy=caddy, caddyfile=caddyfile_content,
        configured_urls=configured_urls,
        version=VERSION, deploying=caddy_deploy_status.get('running', False),
        deploy_done=caddy_deploy_status.get('complete', False))

# Caddy deploy state
caddy_deploy_status = {'running': False, 'complete': False, 'error': False}
caddy_deploy_log = []

@app.route('/api/caddy/deploy', methods=['POST'])
@login_required
def caddy_deploy():
    if caddy_deploy_status['running']:
        return jsonify({'success': False, 'error': 'Deployment already in progress'})
    data = request.get_json()
    domain = data.get('domain', '').strip().lower()
    if not domain:
        return jsonify({'success': False, 'error': 'Domain is required'})
    # Save domain to settings
    settings = load_settings()
    settings['fqdn'] = domain
    save_settings(settings)
    caddy_deploy_log.clear()
    caddy_deploy_status.update({'running': True, 'complete': False, 'error': False})
    threading.Thread(target=run_caddy_deploy, args=(domain,), daemon=True).start()
    return jsonify({'success': True})

@app.route('/api/caddy/log')
@login_required
def caddy_log():
    return jsonify({
        'running': caddy_deploy_status['running'], 'complete': caddy_deploy_status['complete'],
        'error': caddy_deploy_status['error'], 'entries': list(caddy_deploy_log)})

@app.route('/api/caddy/domain', methods=['POST'])
@login_required
def caddy_update_domain():
    """Update domain and regenerate Caddyfile"""
    data = request.get_json()
    domain = data.get('domain', '').strip().lower()
    if not domain:
        return jsonify({'success': False, 'error': 'Domain is required'})
    settings = load_settings()
    settings['fqdn'] = domain
    save_settings(settings)
    generate_caddyfile(settings)
    # If Authentik is installed, ensure infra-TAK Console provider exists (so infratak/console are behind Authentik)
    ak_installed = os.path.exists(os.path.expanduser('~/authentik/docker-compose.yml'))
    if ak_installed:
        def _ensure_console_app():
            time.sleep(1)
            try:
                env_path = os.path.expanduser('~/authentik/.env')
                ak_token = ''
                if os.path.exists(env_path):
                    with open(env_path) as f:
                        for line in f:
                            if line.strip().startswith('AUTHENTIK_TOKEN='):
                                ak_token = line.strip().split('=', 1)[1].strip()
                                break
                if ak_token:
                    _ensure_authentik_console_app(domain, ak_token)
            except Exception:
                pass
        threading.Thread(target=_ensure_console_app, daemon=True).start()
    # Restart in background so response reaches client before Caddy restarts (console is behind Caddy)
    def _restart():
        time.sleep(2)
        try:
            subprocess.run('systemctl restart caddy 2>&1', shell=True, capture_output=True, text=True, timeout=30)
        except Exception:
            pass
    threading.Thread(target=_restart, daemon=True).start()
    return jsonify({'success': True, 'domain': domain, 'output': 'Caddy restart scheduled.'})

@app.route('/api/caddy/caddyfile')
@login_required
def caddy_get_caddyfile():
    if os.path.exists(CADDYFILE_PATH):
        with open(CADDYFILE_PATH) as f:
            return jsonify({'success': True, 'content': f.read()})
    return jsonify({'success': False, 'content': ''})

def _caddy_restart_after_response():
    """Run in background: write Caddyfile and restart Caddy after a short delay so the HTTP response can be sent first (console is often behind Caddy)."""
    time.sleep(2)
    try:
        generate_caddyfile(load_settings())
        subprocess.run('systemctl restart caddy 2>&1', shell=True, capture_output=True, text=True, timeout=30)
    except Exception:
        pass

@app.route('/api/caddy/control', methods=['POST'])
@login_required
def caddy_control():
    data = request.get_json()
    action = data.get('action', '')
    if action == 'restart':
        generate_caddyfile(load_settings())
        threading.Thread(target=_caddy_restart_after_response, daemon=True).start()
        return jsonify({'success': True, 'output': 'Caddy restart scheduled; connection may drop briefly.'})
    elif action == 'stop':
        r = subprocess.run('systemctl stop caddy 2>&1', shell=True, capture_output=True, text=True, timeout=30)
        return jsonify({'success': r.returncode == 0, 'output': (r.stdout or r.stderr or '').strip()})
    elif action == 'start':
        generate_caddyfile(load_settings())
        threading.Thread(target=_caddy_restart_after_response, daemon=True).start()
        return jsonify({'success': True, 'output': 'Caddy start scheduled; connection may drop briefly.'})
    elif action == 'reload':
        generate_caddyfile(load_settings())
        threading.Thread(target=_caddy_restart_after_response, daemon=True).start()
        return jsonify({'success': True, 'output': 'Caddy restart scheduled; connection may drop briefly.'})
    else:
        return jsonify({'success': False, 'error': 'Unknown action'})

@app.route('/api/caddy/uninstall', methods=['POST'])
@login_required
def caddy_uninstall():
    steps = []
    subprocess.run('systemctl stop caddy 2>/dev/null; true', shell=True, capture_output=True, timeout=30)
    subprocess.run('systemctl disable caddy 2>/dev/null; true', shell=True, capture_output=True, timeout=30)
    steps.append('Stopped and disabled Caddy')
    settings = load_settings()
    pkg_mgr = settings.get('pkg_mgr', 'apt')
    if pkg_mgr == 'apt':
        subprocess.run('apt-get remove -y caddy 2>/dev/null; true', shell=True, capture_output=True, timeout=120)
    else:
        subprocess.run('dnf remove -y caddy 2>/dev/null; true', shell=True, capture_output=True, timeout=120)
    steps.append('Removed Caddy package')
    settings['fqdn'] = ''
    save_settings(settings)
    steps.append('Cleared domain from settings')
    caddy_deploy_log.clear()
    caddy_deploy_status.update({'running': False, 'complete': False, 'error': False})
    return jsonify({'success': True, 'steps': steps})

def generate_caddyfile(settings=None):
    """Generate Caddyfile based on current settings and deployed services.
    Each service gets its own subdomain: infratak.domain, tak.domain, etc. (console removed — use infratak)."""
    if settings is None:
        settings = load_settings()
    domain = settings.get('fqdn', '')
    if not domain:
        return
    modules = detect_modules()

    lines = [f"# infra-TAK - Auto-generated Caddyfile", f"# Base Domain: {domain}", ""]

    ak = modules.get('authentik', {})
    nodered = modules.get('nodered', {})
    # infra-TAK (login & platform) — infratak.domain (behind Authentik when Authentik is installed)
    # /login and / go to app without forward_auth so console password works after pull/restart
    lines.append(f"infratak.{domain} {{")
    if ak.get('installed'):
        lines.append(f"    route /login* {{")
        lines.append(f"        reverse_proxy 127.0.0.1:5001 {{")
        lines.append(f"            transport http {{")
        lines.append(f"                tls")
        lines.append(f"                tls_insecure_skip_verify")
        lines.append(f"            }}")
        lines.append(f"        }}")
        lines.append(f"    }}")
        lines.append(f"    route / {{")
        lines.append(f"        reverse_proxy 127.0.0.1:5001 {{")
        lines.append(f"            transport http {{")
        lines.append(f"                tls")
        lines.append(f"                tls_insecure_skip_verify")
        lines.append(f"            }}")
        lines.append(f"        }}")
        lines.append(f"    }}")
        lines.append(f"    route {{")
        lines.append(f"        reverse_proxy /outpost.goauthentik.io/* 127.0.0.1:9090")
        lines.append(f"        forward_auth 127.0.0.1:9090 {{")
        lines.append(f"            uri /outpost.goauthentik.io/auth/caddy")
        lines.append(f"            copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid")
        lines.append(f"            trusted_proxies private_ranges")
        lines.append(f"        }}")
        lines.append(f"        reverse_proxy 127.0.0.1:5001 {{")
        lines.append(f"            transport http {{")
        lines.append(f"                tls")
        lines.append(f"                tls_insecure_skip_verify")
        lines.append(f"            }}")
        lines.append(f"        }}")
        lines.append(f"    }}")
    else:
        lines.append(f"    reverse_proxy 127.0.0.1:5001 {{")
        lines.append(f"        transport http {{")
        lines.append(f"            tls")
        lines.append(f"            tls_insecure_skip_verify")
        lines.append(f"        }}")
        lines.append(f"    }}")
    lines.append(f"}}")
    lines.append("")

    # Node-RED — nodered.domain (behind Authentik when Authentik is installed)
    if nodered.get('installed'):
        lines.append(f"# Node-RED flow editor")
        lines.append(f"nodered.{domain} {{")
        if ak.get('installed'):
            lines.append(f"    route {{")
            lines.append(f"        reverse_proxy /outpost.goauthentik.io/* 127.0.0.1:9090")
            lines.append(f"        forward_auth 127.0.0.1:9090 {{")
            lines.append(f"            uri /outpost.goauthentik.io/auth/caddy")
            lines.append(f"            trusted_proxies private_ranges")
            lines.append(f"        }}")
            lines.append(f"        reverse_proxy 127.0.0.1:1880")
            lines.append(f"    }}")
        else:
            lines.append(f"    reverse_proxy 127.0.0.1:1880")
        lines.append(f"}}")
        lines.append("")

    # TAK Server — tak.domain
    tak = modules.get('takserver', {})
    if tak.get('installed'):
        lines.append(f"# TAK Server")
        lines.append(f"tak.{domain} {{")
        lines.append(f"    reverse_proxy 127.0.0.1:8446 {{")
        lines.append(f"        transport http {{")
        lines.append(f"            tls")
        lines.append(f"            tls_insecure_skip_verify")
        lines.append(f"        }}")
        lines.append(f"        header_down Location 127.0.0.1:8446 tak.{domain}")
        lines.append(f"        header_down Location http:// https://")
        lines.append(f"    }}")
        lines.append(f"}}")
        lines.append("")

    # Authentik — authentik.domain
    ak = modules.get('authentik', {})
    if ak.get('installed'):
        lines.append(f"# Authentik")
        lines.append(f"authentik.{domain} {{")
        lines.append(f"    reverse_proxy 127.0.0.1:9090")
        lines.append(f"}}")
        lines.append("")

    # TAK Portal — portal.domain (with forward_auth if Authentik is deployed)
    portal = modules.get('takportal', {})
    if portal.get('installed'):
        lines.append(f"# TAK Portal")
        lines.append(f"takportal.{domain} {{")
        if ak.get('installed'):
            lines.append(f"    route {{")
            lines.append(f"        reverse_proxy /outpost.goauthentik.io/* 127.0.0.1:9090")
            lines.append(f"")
            lines.append(f"        @public {{")
            lines.append(f"            path /request-access* /styles.css /favicon.ico /branding/* /public/*")
            lines.append(f"        }}")
            lines.append(f"")
            lines.append(f"        handle @public {{")
            lines.append(f"            reverse_proxy 127.0.0.1:3000")
            lines.append(f"        }}")
            lines.append(f"")
            lines.append(f"        forward_auth 127.0.0.1:9090 {{")
            lines.append(f"            uri /outpost.goauthentik.io/auth/caddy")
            lines.append(f"            copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Entitlements X-Authentik-Email X-Authentik-Name X-Authentik-Uid X-Authentik-Jwt X-Authentik-Meta-Jwks X-Authentik-Meta-Outpost X-Authentik-Meta-Provider X-Authentik-Meta-App X-Authentik-Meta-Version")
            lines.append(f"            trusted_proxies private_ranges")
            lines.append(f"        }}")
            lines.append(f"")
            lines.append(f"        reverse_proxy 127.0.0.1:3000")
            lines.append(f"    }}")
        else:
            lines.append(f"    reverse_proxy 127.0.0.1:3000")
        lines.append(f"}}")
        lines.append("")

    # CloudTAK — map.domain, tiles.map.domain, video.domain
    cloudtak = modules.get('cloudtak', {})
    if cloudtak.get('installed'):
        lines.append(f"# CloudTAK Web UI")
        lines.append(f"map.{domain} {{")
        lines.append(f"    reverse_proxy 127.0.0.1:5000")
        lines.append(f"}}")
        lines.append("")
        lines.append(f"# CloudTAK Tile Server (CORS for map origin)")
        lines.append(f"tiles.map.{domain} {{")
        lines.append(f"    header Access-Control-Allow-Origin *")
        lines.append(f"    reverse_proxy 127.0.0.1:5002")
        lines.append(f"}}")
        lines.append("")
        # CloudTAK Media: one host on 443. /stream/* → HLS (18888), rest → MediaMTX API (9997).
        # CORS inside handle blocks so HLS manifest/segments from map.domain get Allow-Origin (avoids status 0).
        lines.append(f"# CloudTAK Media (video) — /stream/* → HLS, rest → MediaMTX API")
        lines.append(f"video.{domain} {{")
        lines.append(f"    handle /stream/* {{")
        lines.append(f"        header Access-Control-Allow-Origin *")
        lines.append(f"        reverse_proxy 127.0.0.1:18888")
        lines.append(f"    }}")
        lines.append(f"    handle {{")
        lines.append(f"        header Access-Control-Allow-Origin *")
        lines.append(f"        reverse_proxy 127.0.0.1:9997")
        lines.append(f"    }}")
        lines.append(f"}}")
        lines.append("")

    # MediaMTX — stream.domain (behind Authentik when installed). Web editor only; drone/controller/ATAK push to 8554/8890.
    mtx = modules.get('mediamtx', {})
    if mtx.get('installed'):
        mtx_domain = settings.get('mediamtx_domain', f'stream.{domain}')
        lines.append(f"# MediaMTX Web Console")
        lines.append(f"{mtx_domain} {{")
        if ak.get('installed'):
            lines.append(f"    route {{")
            lines.append(f"        reverse_proxy /outpost.goauthentik.io/* 127.0.0.1:9090")
            lines.append(f"        forward_auth 127.0.0.1:9090 {{")
            lines.append(f"            uri /outpost.goauthentik.io/auth/caddy")
            lines.append(f"            copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid")
            lines.append(f"            trusted_proxies private_ranges")
            lines.append(f"        }}")
            lines.append(f"        reverse_proxy 127.0.0.1:5080")
            lines.append(f"    }}")
        else:
            lines.append(f"    reverse_proxy 127.0.0.1:5080")
        lines.append(f"}}")
        lines.append("")

    caddyfile = '\n'.join(lines)
    os.makedirs(os.path.dirname(CADDYFILE_PATH), exist_ok=True)
    with open(CADDYFILE_PATH, 'w') as f:
        f.write(caddyfile)
    return caddyfile

def wait_for_apt_lock(log_fn, log_list):
    """
    Wait for unattended-upgrades / apt locks to release before installing packages.
    Called at the start of every deploy that uses apt/dpkg.
    Waits indefinitely — no timeout. Checks both process and dpkg lock file.
    Appends a ⏳ ticker line every 10s — the frontend JS overwrites it in place.
    """
    def is_locked():
        # Check dpkg lock file
        lock = subprocess.run('lsof /var/lib/dpkg/lock-frontend 2>/dev/null',
            shell=True, capture_output=True, text=True)
        if lock.stdout.strip():
            return True
        # Check for active upgrade process (exclude the shutdown watcher)
        proc = subprocess.run('ps aux | grep "/usr/bin/unattended-upgrade" | grep -v shutdown | grep -v grep',
            shell=True, capture_output=True, text=True)
        return bool(proc.stdout.strip())

    if not is_locked():
        return True
    log_fn("⏳ Unattended-upgrades is running — waiting for it to finish...")
    log_fn("  This can take 20-45 minutes on a fresh VPS. Do not cancel.")
    waited = 0
    while True:
        time.sleep(10)
        waited += 10
        if not is_locked():
            m, s = divmod(waited, 60)
            log_fn(f"✓ System upgrades complete (waited {m}m {s}s)")
            time.sleep(5)
            return True
        m, s = divmod(waited, 60)
        log_list.append(f"  ⏳ {m:02d}:{s:02d}")


def install_le_cert_on_8446(domain, log_fn, wait_for_cert=True):
    """
    Install the Caddy-managed Let's Encrypt cert on TAK Server's port 8446
    so ATAK trusts the enrollment endpoint without a data package.

    Called from:
      - run_caddy_deploy  (Step 5/5) — wait_for_cert=True  (Caddy just started, cert may need a moment)
      - run_takserver_deploy (end)   — wait_for_cert=False (Caddy already running, cert should exist)

    Args:
        domain:        Base FQDN, e.g. "taktical.net"
        log_fn:        Logging function (plog or log_step)
        wait_for_cert: If True, poll up to 60s for cert files before giving up
    """
    import re, shutil

    tak_domain = f"tak.{domain}"
    cert_dir = (f"/var/lib/caddy/.local/share/caddy/certificates/"
                f"acme-v02.api.letsencrypt.org-directory/{tak_domain}")
    cert_crt = f"{cert_dir}/{tak_domain}.crt"
    cert_key = f"{cert_dir}/{tak_domain}.key"
    core_config = "/opt/tak/CoreConfig.xml"

    # Optionally wait for Caddy to finish obtaining the cert
    if wait_for_cert:
        waited = 0
        while not (os.path.exists(cert_crt) and os.path.exists(cert_key)) and waited < 120:
            log_fn(f"  Waiting for LE cert files... ({waited}s)")
            time.sleep(10)
            waited += 10

    if not (os.path.exists(cert_crt) and os.path.exists(cert_key)):
        log_fn(f"  ⚠ LE cert not found at {cert_dir}")
        log_fn("  Skipping 8446 cert install — DNS may not be propagated yet")
        log_fn("  Re-run Caddy deploy once the cert is available")
        return False

    log_fn(f"  ✓ LE cert files found for {tak_domain}")

    # Step A: LE cert → PKCS12
    r = subprocess.run(
        f'openssl pkcs12 -export -in "{cert_crt}" -inkey "{cert_key}" '
        f'-out /tmp/takserver-le.p12 -name "{tak_domain}" -password pass:atakatak 2>&1',
        shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        log_fn(f"  ⚠ PKCS12 conversion failed: {r.stderr.strip()[:200]}")
        return False
    log_fn("  ✓ PKCS12 created")

    # Step B: PKCS12 → JKS
    r = subprocess.run(
        'keytool -importkeystore -srcstorepass atakatak -deststorepass atakatak '
        '-destkeystore /tmp/takserver-le.jks -srckeystore /tmp/takserver-le.p12 '
        '-srcstoretype pkcs12 2>&1',
        shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        log_fn(f"  ⚠ JKS conversion failed: {r.stderr.strip()[:200]}")
        return False

    subprocess.run(
        'mv /tmp/takserver-le.jks /opt/tak/certs/files/ && '
        'chown tak:tak /opt/tak/certs/files/takserver-le.jks',
        shell=True)
    log_fn("  ✓ JKS installed to /opt/tak/certs/files/takserver-le.jks")

    # Step C: Patch CoreConfig.xml 8446 connector
    try:
        with open(core_config, 'r') as f:
            content = f.read()
        shutil.copy(core_config, core_config + '.bak-le')
        new_connector = (
            '<connector port="8446" clientAuth="false" _name="LetsEncrypt" '
            'keystore="JKS" keystoreFile="certs/files/takserver-le.jks" '
            'keystorePass="atakatak" enableAdminUI="true" enableWebtak="true" '
            'enableNonAdminUI="false"/>'
        )
        patched = re.sub(r'<connector port="8446"[^/]*/>', new_connector, content)
        if patched != content:
            with open(core_config, 'w') as f:
                f.write(patched)
            log_fn("  ✓ CoreConfig.xml 8446 connector patched to use LE cert")
        else:
            log_fn("  ⚠ 8446 connector pattern not matched in CoreConfig.xml — check manually")
    except Exception as ce:
        log_fn(f"  ⚠ CoreConfig patch error: {ce}")

    # Step D: Write renewal script
    renewal_script = f'''#!/bin/bash
# TAK Server Let's Encrypt Certificate Renewal
# Triggered monthly by systemd timer. Rebuilds TAK JKS from Caddy cert when
# within 40 days of expiry, then restarts TAK Server.
set -euo pipefail

TAK_DOMAIN="{tak_domain}"
CERT_DIR="{cert_dir}"
CERT_CRT="$CERT_DIR/$TAK_DOMAIN.crt"
CERT_KEY="$CERT_DIR/$TAK_DOMAIN.key"
RENEW_WINDOW_DAYS=40
LOG_FILE="/var/log/takserver-cert-renewal.log"

log() {{ echo "[$(date -Is)] $*" | tee -a "$LOG_FILE"; }}

if [ ! -f "$CERT_CRT" ] || [ ! -f "$CERT_KEY" ]; then
  log "ERROR: Caddy cert files not found for $TAK_DOMAIN"
  exit 1
fi

END_DATE_RAW=$(openssl x509 -enddate -noout -in "$CERT_CRT" | cut -d= -f2)
END_EPOCH=$(date -d "$END_DATE_RAW" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (END_EPOCH - NOW_EPOCH) / 86400 ))
log "Certificate days remaining for $TAK_DOMAIN: ${{DAYS_LEFT}} day(s)"

if [ "$DAYS_LEFT" -gt "$RENEW_WINDOW_DAYS" ]; then
  log "Outside renewal window (${{RENEW_WINDOW_DAYS}}d). No action taken."
  exit 0
fi

log "Within renewal window. Triggering Caddy reload and refreshing TAK keystore..."
if ! systemctl reload caddy; then
  log "Caddy reload failed; restarting..."
  systemctl restart caddy
fi
sleep 15

openssl pkcs12 -export -in "$CERT_CRT" -inkey "$CERT_KEY" \\
  -out /tmp/takserver-le.p12 -name "$TAK_DOMAIN" -password pass:atakatak

keytool -importkeystore -srcstorepass atakatak -deststorepass atakatak \\
  -destkeystore /tmp/takserver-le.jks -srckeystore /tmp/takserver-le.p12 \\
  -srcstoretype pkcs12

rm -f /opt/tak/certs/files/takserver-le.jks
mv /tmp/takserver-le.jks /opt/tak/certs/files/
chown tak:tak /opt/tak/certs/files/takserver-le.jks

systemctl restart takserver
log "TAK keystore refreshed and TAK Server restarted."
'''
    with open('/opt/tak/renew-letsencrypt.sh', 'w') as f:
        f.write(renewal_script)
    subprocess.run('chmod +x /opt/tak/renew-letsencrypt.sh', shell=True)
    log_fn("  ✓ Renewal script created at /opt/tak/renew-letsencrypt.sh")

    # Step E: Create systemd service + timer
    svc = '''[Unit]
Description=TAK Server Let's Encrypt Certificate Renewal
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/tak/renew-letsencrypt.sh
'''
    timer = '''[Unit]
Description=TAK Server Certificate Renewal Timer
Requires=takserver-cert-renewal.service

[Timer]
OnCalendar=monthly
Persistent=true

[Install]
WantedBy=timers.target
'''
    with open('/etc/systemd/system/takserver-cert-renewal.service', 'w') as f:
        f.write(svc)
    with open('/etc/systemd/system/takserver-cert-renewal.timer', 'w') as f:
        f.write(timer)
    subprocess.run(
        'systemctl daemon-reload && systemctl enable --now takserver-cert-renewal.timer 2>/dev/null; true',
        shell=True, capture_output=True)
    log_fn("  ✓ Auto-renewal timer enabled (monthly)")

    # Step F: Restart TAK Server to load new cert
    log_fn("  Restarting TAK Server to load LE cert on port 8446...")
    subprocess.run('systemctl restart takserver 2>/dev/null; true', shell=True, capture_output=True)
    log_fn("  ✓ TAK Server restarted")
    log_fn("✓ Port 8446 now serving Let's Encrypt cert — ATAK enrollment ready")
    return True


def run_caddy_deploy(domain):
    def plog(msg):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        caddy_deploy_log.append(entry)
        print(entry, flush=True)
    try:
        settings = load_settings()
        pkg_mgr = settings.get('pkg_mgr', 'apt')

        if pkg_mgr == 'apt':
            wait_for_apt_lock(plog, caddy_deploy_log)

        plog("━━━ Step 1/4: Installing Caddy ━━━")
        if pkg_mgr == 'apt':
            plog("  Adding Caddy repository...")
            cmds = [
                'apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl 2>&1',
                'curl -1sLf "https://dl.cloudsmith.io/public/caddy/stable/gpg.key" | gpg --batch --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>&1',
                'curl -1sLf "https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt" | tee /etc/apt/sources.list.d/caddy-stable.list 2>&1',
                'apt-get update -qq 2>&1',
                'apt-get install -y caddy 2>&1'
            ]
            for cmd in cmds:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120,
                    env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'a'})
                if r.returncode != 0:
                    err = (r.stderr.strip() or r.stdout.strip())[:300]
                    plog(f"✗ Caddy install failed at: {cmd[:60]}")
                    plog(f"  Error: {err}")
                    caddy_deploy_status.update({'running': False, 'error': True})
                    return
        else:
            plog("  Installing Caddy via dnf...")
            subprocess.run('dnf install -y "dnf-command(copr)" 2>&1', shell=True, capture_output=True, text=True, timeout=60)
            subprocess.run('dnf copr enable -y @caddy/caddy 2>&1', shell=True, capture_output=True, text=True, timeout=60)
            r = subprocess.run('dnf install -y caddy 2>&1', shell=True, capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                plog(f"✗ Caddy install failed")
                caddy_deploy_status.update({'running': False, 'error': True})
                return

        # Verify install
        r = subprocess.run('which caddy', shell=True, capture_output=True, text=True)
        if r.returncode != 0:
            plog("✗ Caddy binary not found after install")
            caddy_deploy_status.update({'running': False, 'error': True})
            return
        plog("✓ Caddy installed")

        plog("")
        plog("━━━ Step 2/4: Generating Caddyfile ━━━")
        plog(f"  Domain: {domain}")
        caddyfile = generate_caddyfile(settings)
        plog(f"  Generated Caddyfile ({len(caddyfile)} bytes)")
        plog("✓ Caddyfile written to /etc/caddy/Caddyfile")

        plog("")
        plog("━━━ Step 3/4: Configuring Firewall ━━━")
        # Open ports 80 and 443
        r = subprocess.run('which ufw', shell=True, capture_output=True)
        if r.returncode == 0:
            subprocess.run('ufw allow 80/tcp 2>/dev/null; true', shell=True, capture_output=True)
            subprocess.run('ufw allow 443/tcp 2>/dev/null; true', shell=True, capture_output=True)
            plog("  ✓ UFW: ports 80 and 443 opened")
        r = subprocess.run('which firewall-cmd', shell=True, capture_output=True)
        if r.returncode == 0:
            subprocess.run('firewall-cmd --permanent --add-service=http 2>/dev/null; true', shell=True, capture_output=True)
            subprocess.run('firewall-cmd --permanent --add-service=https 2>/dev/null; true', shell=True, capture_output=True)
            subprocess.run('firewall-cmd --reload 2>/dev/null; true', shell=True, capture_output=True)
            plog("  ✓ firewalld: ports 80 and 443 opened")
        plog("✓ Firewall configured")

        plog("")
        plog("━━━ Step 4/4: Starting Caddy ━━━")
        subprocess.run('systemctl enable caddy 2>/dev/null; true', shell=True, capture_output=True)
        r = subprocess.run('systemctl restart caddy 2>&1', shell=True, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            plog(f"⚠ Caddy start issue: {r.stderr.strip()[:200]}")
        time.sleep(3)
        r = subprocess.run('systemctl is-active caddy', shell=True, capture_output=True, text=True)
        if r.stdout.strip() == 'active':
            plog("✓ Caddy is running")
        else:
            plog("⚠ Caddy may not be fully started — check with: systemctl status caddy")

        # Update settings
        settings['ssl_mode'] = 'fqdn'
        save_settings(settings)

        plog("")
        plog("=" * 50)
        plog(f"✓ Caddy deployed successfully!")
        plog(f"  Domain: https://{domain}")
        plog(f"  SSL: Let's Encrypt (automatic)")
        plog("  Note: DNS must point to this server's IP for SSL to activate")
        plog("=" * 50)
        caddy_deploy_status.update({'running': False, 'complete': True})

    except Exception as e:
        plog(f"✗ Error: {str(e)}")
        caddy_deploy_status.update({'running': False, 'error': True})

@app.route('/takportal')
@login_required
def takportal_page():
    modules = detect_modules()
    portal = modules.get('takportal', {})
    settings = load_settings()
    # Reset deploy_done once TAK Portal is running so the running view shows
    if portal.get('installed') and portal.get('running') and not takportal_deploy_status.get('running', False):
        takportal_deploy_status.update({'complete': False, 'error': False})
    # Get container info if running
    container_info = {}
    if portal.get('running'):
        r = subprocess.run('docker ps --filter name=tak-portal --format "{{.Names}}|||{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True)
        if r.stdout.strip():
            containers = []
            for line in r.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.strip().split('|||')
                    containers.append({'name': parts[0] if len(parts) > 0 else 'tak-portal', 'status': parts[1] if len(parts) > 1 else ''})
            container_info['containers'] = containers
            container_info['status'] = containers[0]['status'] if containers else ''
    # Get portal port from .env if exists
    portal_port = '3000'
    env_path = os.path.expanduser('~/TAK-Portal/.env')
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                if line.strip().startswith('WEB_UI_PORT='):
                    portal_port = line.strip().split('=', 1)[1].strip() or '3000'
    return render_template_string(TAKPORTAL_TEMPLATE,
        settings=settings, portal=portal, container_info=container_info,
        portal_port=portal_port, version=VERSION,
        deploying=takportal_deploy_status.get('running', False),
        deploy_done=takportal_deploy_status.get('complete', False))

# TAK Portal deploy state
takportal_deploy_log = []
takportal_deploy_status = {'running': False, 'complete': False, 'error': False}

@app.route('/api/takportal/control', methods=['POST'])
@login_required
def takportal_control():
    action = request.json.get('action')
    portal_dir = os.path.expanduser('~/TAK-Portal')
    if action == 'start':
        subprocess.run(f'cd {portal_dir} && docker compose up -d --build', shell=True, capture_output=True, text=True, timeout=120)
    elif action == 'stop':
        subprocess.run(f'cd {portal_dir} && docker compose down', shell=True, capture_output=True, text=True, timeout=60)
    elif action == 'restart':
        subprocess.run(f'cd {portal_dir} && docker compose down && docker compose up -d', shell=True, capture_output=True, text=True, timeout=120)
    elif action == 'update':
        subprocess.run(f'cd {portal_dir} && git pull --rebase --autostash && docker compose up -d --build && docker image prune -f', shell=True, capture_output=True, text=True, timeout=180)
    else:
        return jsonify({'error': 'Invalid action'}), 400
    time.sleep(3)
    r = subprocess.run('docker ps --filter name=tak-portal --format "{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True)
    running = 'Up' in r.stdout
    return jsonify({'success': True, 'running': running, 'action': action})

@app.route('/api/takportal/deploy', methods=['POST'])
@login_required
def takportal_deploy():
    if takportal_deploy_status.get('running'):
        return jsonify({'error': 'Deployment already in progress'}), 409
    takportal_deploy_log.clear()
    takportal_deploy_status.update({'running': True, 'complete': False, 'error': False})
    threading.Thread(target=run_takportal_deploy, daemon=True).start()
    return jsonify({'success': True})

@app.route('/api/takportal/deploy/log')
@login_required
def takportal_deploy_log_api():
    idx = request.args.get('index', 0, type=int)
    return jsonify({'entries': takportal_deploy_log[idx:], 'total': len(takportal_deploy_log),
        'running': takportal_deploy_status['running'], 'complete': takportal_deploy_status['complete'],
        'error': takportal_deploy_status['error']})

@app.route('/api/takportal/logs')
@login_required
def takportal_container_logs():
    """Get recent container logs"""
    lines = request.args.get('lines', 50, type=int)
    r = subprocess.run(f'docker logs tak-portal --tail {lines} 2>&1', shell=True, capture_output=True, text=True, timeout=10)
    entries = []
    skip_lines = {'npm error', 'npm ERR', 'signal SIGTERM', 'command failed', 'A complete log of this run'}
    for line in (r.stdout.strip().split('\n') if r.stdout.strip() else []):
        if not any(s in line for s in skip_lines):
            entries.append(line)
    return jsonify({'entries': entries})

@app.route('/api/takportal/uninstall', methods=['POST'])
@login_required
def takportal_uninstall():
    data = request.json or {}
    password = data.get('password', '')
    auth = load_auth()
    if not auth.get('password_hash') or not check_password_hash(auth['password_hash'], password):
        return jsonify({'error': 'Invalid admin password'}), 403
    portal_dir = os.path.expanduser('~/TAK-Portal')
    steps = []
    subprocess.run(f'cd {portal_dir} && docker compose down -v --rmi local 2>/dev/null; true', shell=True, capture_output=True, timeout=120)
    steps.append('Stopped and removed Docker containers/volumes')
    if os.path.exists(portal_dir):
        subprocess.run(f'rm -rf {portal_dir}', shell=True, capture_output=True)
        steps.append('Removed ~/TAK-Portal')
    takportal_deploy_log.clear()
    takportal_deploy_status.update({'running': False, 'complete': False, 'error': False})
    return jsonify({'success': True, 'steps': steps})

def run_takportal_deploy():
    def plog(msg):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        takportal_deploy_log.append(entry)
        print(entry, flush=True)
    try:
        portal_dir = os.path.expanduser('~/TAK-Portal')
        settings = load_settings()
        if settings.get('pkg_mgr', 'apt') == 'apt':
            wait_for_apt_lock(plog, takportal_deploy_log)
        # Step 1: Check Docker
        plog("\u2501\u2501\u2501 Step 1/6: Checking Docker \u2501\u2501\u2501")
        r = subprocess.run('docker --version', shell=True, capture_output=True, text=True)
        if r.returncode != 0:
            plog("Docker not found. Installing...")
            subprocess.run('curl -fsSL https://get.docker.com | sh', shell=True, capture_output=True, text=True, timeout=300)
            r2 = subprocess.run('docker --version', shell=True, capture_output=True, text=True)
            if r2.returncode != 0:
                plog("\u2717 Failed to install Docker")
                takportal_deploy_status.update({'running': False, 'error': True})
                return
            plog(f"  {r2.stdout.strip()}")
            plog("\u2713 Docker installed")
        else:
            plog(f"  {r.stdout.strip()}")
            plog("\u2713 Docker available")

        # Step 2: Clone repo
        plog("")
        plog("\u2501\u2501\u2501 Step 2/6: Cloning TAK Portal \u2501\u2501\u2501")
        if os.path.exists(portal_dir):
            plog("  TAK-Portal directory already exists, pulling latest...")
            subprocess.run(f'cd {portal_dir} && git pull --rebase --autostash', shell=True, capture_output=True, text=True, timeout=60)
        else:
            plog("  Cloning from GitHub...")
            r = subprocess.run(f'git clone https://github.com/AdventureSeeker423/TAK-Portal.git {portal_dir}', shell=True, capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                plog(f"\u2717 Clone failed: {r.stderr.strip()}")
                takportal_deploy_status.update({'running': False, 'error': True})
                return
        plog("\u2713 Repository ready")

        # Step 3: Create .env if missing
        plog("")
        plog("\u2501\u2501\u2501 Step 3/6: Configuring \u2501\u2501\u2501")
        env_path = os.path.join(portal_dir, '.env')
        if not os.path.exists(env_path):
            plog("  Creating default .env...")
            with open(env_path, 'w') as f:
                f.write("WEB_UI_PORT=3000\n")
            plog("\u2713 Default .env created (port 3000)")
        else:
            plog("\u2713 .env already exists")

        # Step 4: Build and start
        plog("")
        plog("\u2501\u2501\u2501 Step 4/6: Building & Starting Docker Container \u2501\u2501\u2501")
        # Patch docker-compose.yml with healthcheck if not already present
        compose_path = os.path.join(portal_dir, 'docker-compose.yml')
        if os.path.exists(compose_path):
            with open(compose_path, 'r') as f:
                compose_content = f.read()
            if 'healthcheck' not in compose_content:
                # Insert healthcheck after 'restart: unless-stopped' inside the service block
                healthcheck = (
                    "    healthcheck:\n"
                    "      test: [\"CMD-SHELL\", \"wget -qO- http://localhost:3000 2>&1 | grep -q setup-my-device && exit 0 || exit 1\"]\n"
                    "      interval: 30s\n"
                    "      timeout: 10s\n"
                    "      retries: 3\n"
                    "      start_period: 15s\n"
                )
                compose_content = compose_content.replace(
                    'restart: unless-stopped',
                    'restart: unless-stopped\n' + healthcheck.rstrip('\n')
                )
                with open(compose_path, 'w') as f:
                    f.write(compose_content)
                plog("  ✓ Healthcheck added to docker-compose.yml")

        plog("  Building image (this may take a minute)...")
        r = subprocess.run(f'cd {portal_dir} && docker compose up -d --build 2>&1', shell=True, capture_output=True, text=True, timeout=900)
        for line in r.stdout.strip().split('\n'):
            if line.strip() and 'NEEDRESTART' not in line:
                takportal_deploy_log.append(f"  {line.strip()}")
        if r.returncode != 0:
            plog(f"\u2717 Docker build failed")
            for line in r.stderr.strip().split('\n'):
                if line.strip():
                    takportal_deploy_log.append(f"  \u2717 {line.strip()}")
            takportal_deploy_status.update({'running': False, 'error': True})
            return

        # Wait for container to be healthy
        plog("  Waiting for container...")
        time.sleep(5)
        r = subprocess.run('docker ps --filter name=tak-portal --format "{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True)
        if 'Up' in r.stdout:
            plog("\u2713 TAK Portal is running")
        else:
            plog("\u26a0 Container may not be fully started yet")

        # Step 5: Copy TAK Server certs into container
        plog("")
        plog("\u2501\u2501\u2501 Step 5/6: Copying TAK Server Certificates \u2501\u2501\u2501")
        cert_dir = '/opt/tak/certs/files'
        webadmin_p12 = os.path.join(cert_dir, 'admin.p12')
        tak_ca = os.path.join(cert_dir, 'truststore-root.p12')
        # Find the actual cert files
        if not os.path.exists(webadmin_p12):
            # Try alternate names
            for name in ['webadmin.p12', 'admin.p12']:
                p = os.path.join(cert_dir, name)
                if os.path.exists(p):
                    webadmin_p12 = p
                    break
        if not os.path.exists(tak_ca):
            for name in ['truststore-root.p12', 'tak-ca.pem', 'ca.pem']:
                p = os.path.join(cert_dir, name)
                if os.path.exists(p):
                    tak_ca = p
                    break
        # Create certs dir in container and copy
        subprocess.run('docker exec tak-portal mkdir -p /usr/src/app/certs', shell=True, capture_output=True, text=True)
        certs_copied = True
        if os.path.exists(webadmin_p12):
            r = subprocess.run(f'docker cp {webadmin_p12} tak-portal:/usr/src/app/certs/admin.p12', shell=True, capture_output=True, text=True)
            plog(f"  Copied {os.path.basename(webadmin_p12)} -> admin.p12")
        else:
            plog("\u26a0 admin.p12 not found in /opt/tak/certs/files/")
            certs_copied = False
        # Export tak-ca.pem from truststore or copy directly
        tak_ca_pem = os.path.join(cert_dir, 'tak-ca.pem')
        if not os.path.exists(tak_ca_pem):
            # Try to find any .pem CA file
            for name in ['ca.pem', 'root-ca.pem', 'truststore-root.pem']:
                p = os.path.join(cert_dir, name)
                if os.path.exists(p):
                    tak_ca_pem = p
                    break
        if os.path.exists(tak_ca_pem):
            r = subprocess.run(f'docker cp {tak_ca_pem} tak-portal:/usr/src/app/certs/tak-ca.pem', shell=True, capture_output=True, text=True)
            plog(f"  Copied {os.path.basename(tak_ca_pem)} -> tak-ca.pem")
        else:
            plog("\u26a0 tak-ca.pem not found, trying to extract from truststore")
            # Extract from Java truststore
            ts = os.path.join(cert_dir, 'truststore-root.p12')
            if os.path.exists(ts):
                r = subprocess.run(f'openssl pkcs12 -in {ts} -clcerts -nokeys -passin pass:atakatak 2>/dev/null | openssl x509 > /tmp/tak-ca.pem', shell=True, capture_output=True, text=True)
                if os.path.exists('/tmp/tak-ca.pem') and os.path.getsize('/tmp/tak-ca.pem') > 0:
                    subprocess.run('docker cp /tmp/tak-ca.pem tak-portal:/usr/src/app/certs/tak-ca.pem', shell=True, capture_output=True, text=True)
                    plog("  Extracted and copied tak-ca.pem from truststore")
                else:
                    plog("\u26a0 Could not extract CA cert")
                    certs_copied = False
            else:
                plog("\u26a0 No CA cert found")
                certs_copied = False
        if certs_copied:
            plog("\u2713 Certificates copied to container")

        # Step 6: Auto-configure settings.json
        plog("")
        plog("\u2501\u2501\u2501 Step 6/6: Auto-configuring TAK Portal Settings \u2501\u2501\u2501")
        settings = load_settings()
        server_ip = settings.get('server_ip', 'localhost')
        # Read Authentik bootstrap token
        ak_env_path = os.path.expanduser('~/authentik/.env')
        ak_token = ''
        if os.path.exists(ak_env_path):
            with open(ak_env_path) as f:
                for line in f:
                    if line.strip().startswith('AUTHENTIK_BOOTSTRAP_TOKEN='):
                        ak_token = line.strip().split('=', 1)[1].strip()
        import json as json_mod
        portal_settings = {
            "AUTHENTIK_URL": f"http://{server_ip}:9090",
            "AUTHENTIK_TOKEN": ak_token,
            "USERS_HIDDEN_PREFIXES": "ak-,adm_,nodered-,ma-",
            "GROUPS_HIDDEN_PREFIXES": "authentik, MA -",
            "USERS_ACTIONS_HIDDEN_PREFIXES": "",
            "GROUPS_ACTIONS_HIDDEN_PREFIXES": "",
            "DASHBOARD_AUTHENTIK_STATS_REFRESH_SECONDS": "300",
            "PORTAL_AUTH_ENABLED": "true" if settings.get('fqdn') else "false",
            "PORTAL_AUTH_REQUIRED_GROUP": "authentik Admins" if settings.get('fqdn') else "",
            "AUTHENTIK_PUBLIC_URL": f"https://authentik.{settings['fqdn']}" if settings.get('fqdn') else f"http://{server_ip}:9090",
            "TAK_PORTAL_PUBLIC_URL": f"https://takportal.{settings['fqdn']}" if settings.get('fqdn') else f"http://{server_ip}:3000",
            "TAK_URL": f"https://tak.{settings['fqdn']}" if settings.get('fqdn') else f"https://{server_ip}:8443/Marti",
            "TAK_API_P12_PATH": "./certs/admin.p12",
            "TAK_API_P12_PASSPHRASE": "atakatak",
            "TAK_CA_PATH": "./certs/tak-ca.pem",
            "TAK_REVOKE_ON_DISABLE": "true",
            "TAK_DEBUG": "false",
            "TAK_BYPASS_ENABLED": "false",
            "CLOUDTAK_URL": f"https://cloudtak.{settings['fqdn']}" if settings.get('fqdn') else "",
            "EMAIL_ENABLED": "false",
            "EMAIL_PROVIDER": "smtp",
            "SMTP_HOST": "",
            "SMTP_PORT": "587",
            "SMTP_SECURE": "false",
            "SMTP_USER": "",
            "SMTP_PASS": "",
            "SMTP_FROM": "",
            "EMAIL_ALWAYS_CC": "",
            "EMAIL_SEND_COPY_TO": "",
            "EMAIL_FAIL_HARD": "false",
            "BRAND_THEME": "dark",
            "BRAND_LOGO_URL": ""
        }
        # Write settings.json into the container data volume
        settings_json = json_mod.dumps(portal_settings, indent=2)
        # Write to temp file then docker cp
        with open('/tmp/tak-portal-settings.json', 'w') as f:
            f.write(settings_json)
        subprocess.run('docker cp /tmp/tak-portal-settings.json tak-portal:/usr/src/app/data/settings.json', shell=True, capture_output=True, text=True)
        os.remove('/tmp/tak-portal-settings.json')
        plog(f"  Authentik URL: {portal_settings['AUTHENTIK_PUBLIC_URL']}")
        plog(f"  TAK Server URL: {portal_settings['TAK_URL']}")
        plog(f"  Portal Auth: {portal_settings['PORTAL_AUTH_ENABLED']}")
        if ak_token:
            plog("  Authentik API token: configured")
        else:
            plog("\u26a0 Authentik not deployed yet - configure token in Server Settings")
        plog("\u2713 Settings auto-configured")

        # Restart container to pick up settings
        subprocess.run('docker restart tak-portal', shell=True, capture_output=True, text=True, timeout=30)
        time.sleep(3)
        plog("\u2713 TAK Portal restarted with new settings")

        # Get port
        port = '3000'
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if line.strip().startswith('WEB_UI_PORT='):
                        port = line.strip().split('=', 1)[1].strip() or '3000'

        # Configure Authentik forward auth for TAK Portal
        fqdn = settings.get('fqdn', '')
        if fqdn and ak_token:
            plog("")
            plog("\u2501\u2501\u2501 Configuring Authentik Forward Auth \u2501\u2501\u2501")
            try:
                import urllib.request as _urlreq
                _ak_headers = {'Authorization': f'Bearer {ak_token}', 'Content-Type': 'application/json'}
                _ak_url = 'http://127.0.0.1:9090'

                # Update brand domain
                try:
                    req = _urlreq.Request(f'{_ak_url}/api/v3/core/brands/', headers=_ak_headers)
                    resp = _urlreq.urlopen(req, timeout=10)
                    brands = json_mod.loads(resp.read().decode())['results']
                    if brands:
                        brand_id = brands[0]['brand_uuid']
                        req = _urlreq.Request(f'{_ak_url}/api/v3/core/brands/{brand_id}/',
                            data=json_mod.dumps({'domain': f'authentik.{fqdn}'}).encode(),
                            headers=_ak_headers, method='PATCH')
                        _urlreq.urlopen(req, timeout=10)
                        plog(f"  \u2713 Brand domain set to authentik.{fqdn}")
                except Exception as e:
                    plog(f"  \u26a0 Brand update: {str(e)[:80]}")

                # Wait forever for authorization flow
                flow_pk = None
                attempt = 0
                while True:
                    try:
                        req = _urlreq.Request(f'{_ak_url}/api/v3/flows/instances/?designation=authorization&ordering=slug', headers=_ak_headers)
                        resp = _urlreq.urlopen(req, timeout=10)
                        flows = json_mod.loads(resp.read().decode())['results']
                        for fl in flows:
                            if 'implicit' in fl.get('slug', ''):
                                flow_pk = fl['pk']
                                break
                        if not flow_pk and flows:
                            flow_pk = flows[0]['pk']
                        if flow_pk:
                            break
                    except Exception:
                        pass
                    if attempt % 6 == 0:
                        plog(f"  ⏳ Waiting for authorization flow... ({attempt * 5}s)")
                    else:
                        authentik_deploy_log.append(f"  ⏳ {attempt * 5 // 60:02d}:{attempt * 5 % 60:02d}")
                    time.sleep(5)
                    attempt += 1
                plog(f"  ✓ Got authorization flow")

                # Wait forever for invalidation flow
                inv_flow_pk = None
                attempt = 0
                while True:
                    try:
                        req = _urlreq.Request(f'{_ak_url}/api/v3/flows/instances/?designation=invalidation', headers=_ak_headers)
                        resp = _urlreq.urlopen(req, timeout=10)
                        inv_flows = json_mod.loads(resp.read().decode())['results']
                        inv_flow_pk = next((f['pk'] for f in inv_flows if 'provider' not in f['slug']), inv_flows[0]['pk'] if inv_flows else None)
                        if inv_flow_pk:
                            break
                    except Exception:
                        pass
                    if attempt % 6 == 0:
                        plog(f"  ⏳ Waiting for invalidation flow... ({attempt * 5}s)")
                    else:
                        authentik_deploy_log.append(f"  ⏳ {attempt * 5 // 60:02d}:{attempt * 5 % 60:02d}")
                    time.sleep(5)
                    attempt += 1
                plog(f"  ✓ Got invalidation flow")

                # Create proxy provider
                provider_pk = None
                if flow_pk and inv_flow_pk:
                    try:
                        req = _urlreq.Request(f'{_ak_url}/api/v3/providers/proxy/',
                            data=json_mod.dumps({'name': 'TAK Portal Proxy', 'authorization_flow': flow_pk,
                                'invalidation_flow': inv_flow_pk,
                                'external_host': f'https://takportal.{fqdn}', 'mode': 'forward_single',
                                'token_validity': 'hours=24'}).encode(),
                            headers=_ak_headers, method='POST')
                        resp = _urlreq.urlopen(req, timeout=10)
                        provider_pk = json_mod.loads(resp.read().decode())['pk']
                        plog(f"  \u2713 Proxy provider created")
                    except Exception as e:
                        if hasattr(e, 'code') and e.code == 400:
                            req = _urlreq.Request(f'{_ak_url}/api/v3/providers/proxy/?search=TAK+Portal', headers=_ak_headers)
                            resp = _urlreq.urlopen(req, timeout=10)
                            results = json_mod.loads(resp.read().decode())['results']
                            if results:
                                provider_pk = results[0]['pk']
                            plog(f"  \u2713 Proxy provider already exists")
                        else:
                            plog(f"  \u26a0 Proxy provider error: {str(e)[:100]}")

                # Create application
                if provider_pk:
                    try:
                        req = _urlreq.Request(f'{_ak_url}/api/v3/core/applications/',
                            data=json_mod.dumps({'name': 'TAK Portal', 'slug': 'tak-portal',
                                'provider': provider_pk}).encode(),
                            headers=_ak_headers, method='POST')
                        _urlreq.urlopen(req, timeout=10)
                        plog(f"  \u2713 Application 'TAK Portal' created")
                    except Exception as e:
                        if hasattr(e, 'code') and e.code == 400:
                            plog(f"  \u2713 Application 'TAK Portal' already exists")
                        else:
                            plog(f"  \u26a0 Application error: {str(e)[:80]}")

                    # Add to embedded outpost
                    try:
                        req = _urlreq.Request(f'{_ak_url}/api/v3/outposts/instances/?search=embedded', headers=_ak_headers)
                        resp = _urlreq.urlopen(req, timeout=10)
                        outposts = json_mod.loads(resp.read().decode())['results']
                        embedded = next((o for o in outposts if 'embed' in o.get('name','').lower() or o.get('type') == 'proxy'), None)
                        if embedded:
                            current_providers = embedded.get('providers', [])
                            if provider_pk not in current_providers:
                                current_providers.append(provider_pk)
                            req = _urlreq.Request(f'{_ak_url}/api/v3/outposts/instances/{embedded["pk"]}/',
                                data=json_mod.dumps({'providers': current_providers}).encode(),
                                headers=_ak_headers, method='PATCH')
                            _urlreq.urlopen(req, timeout=10)
                            plog(f"  \u2713 TAK Portal added to embedded outpost")
                        else:
                            plog(f"  \u26a0 No embedded outpost found")
                    except Exception as e:
                        plog(f"  \u26a0 Outpost error: {str(e)[:80]}")
            except Exception as e:
                plog(f"  \u26a0 Forward auth setup error: {str(e)[:100]}")

        plog("")
        plog("=" * 50)
        plog(f"\u2713 TAK Portal deployed successfully!")
        plog(f"  Access: http://{server_ip}:{port}")
        # Regenerate Caddyfile if Caddy is configured
        if settings.get('fqdn'):
            generate_caddyfile(settings)
            subprocess.run('systemctl reload caddy 2>/dev/null; true', shell=True, capture_output=True)
            plog(f"  \u2713 Caddy config updated for TAK Portal")
            plog(f"  Open: https://takportal.{settings.get('fqdn')}")
        plog("=" * 50)
        plog("")
        plog("  Waiting 2 minutes for Authentik to fully sync...")
        for i in range(24):
            time.sleep(5)
            remaining = 120 - (i + 1) * 5
            if remaining % 30 == 0:
                plog(f"  ⏳ {remaining} seconds remaining...")
        plog("  ✓ Sync complete — TAK Portal is ready")
        takportal_deploy_status.update({'running': False, 'complete': True})
    except Exception as e:
        plog(f"\u2717 FATAL ERROR: {str(e)}")
        takportal_deploy_status.update({'running': False, 'error': True})

@app.route('/certs')
@login_required
def certs_page():
    settings = load_settings()
    cert_dir = '/opt/tak/certs/files'
    files = []
    if os.path.isdir(cert_dir):
        for fn in sorted(os.listdir(cert_dir)):
            fp = os.path.join(cert_dir, fn)
            if os.path.isfile(fp):
                sz = os.path.getsize(fp)
                if sz < 1024: sz_d = f"{sz} B"
                elif sz < 1048576: sz_d = f"{round(sz/1024,1)} KB"
                else: sz_d = f"{round(sz/1048576,1)} MB"
                ext = fn.split('.')[-1].lower() if '.' in fn else ''
                icon = {'p12':'🔑','pem':'📄','jks':'☕','crt':'📜','key':'🔐','crl':'📋','csr':'📝'}.get(ext, '📁')
                files.append({'name': fn, 'size': sz_d, 'icon': icon, 'ext': ext})
    return render_template_string(CERTS_TEMPLATE, settings=settings, files=files, version=VERSION)

# === Email Relay (Postfix) ===

# ── MediaMTX ──────────────────────────────────────────────────────────────────
mediamtx_deploy_log = []
mediamtx_deploy_status = {'running': False, 'complete': False, 'error': False}

@app.route('/api/mediamtx/deploy', methods=['POST'])
@login_required
def mediamtx_deploy_api():
    if mediamtx_deploy_status.get('running'):
        return jsonify({'error': 'Deployment already in progress'}), 409
    mediamtx_deploy_log.clear()
    mediamtx_deploy_status.update({'running': True, 'complete': False, 'error': False})
    threading.Thread(target=run_mediamtx_deploy, daemon=True).start()
    return jsonify({'success': True})

@app.route('/api/mediamtx/deploy/log')
@login_required
def mediamtx_deploy_log_api():
    idx = request.args.get('index', 0, type=int)
    return jsonify({'entries': mediamtx_deploy_log[idx:], 'total': len(mediamtx_deploy_log),
        'running': mediamtx_deploy_status['running'], 'complete': mediamtx_deploy_status['complete'],
        'error': mediamtx_deploy_status['error']})

@app.route('/api/mediamtx/control', methods=['POST'])
@login_required
def mediamtx_control():
    action = (request.json or {}).get('action', '')
    if action == 'start':
        subprocess.run('systemctl start mediamtx mediamtx-webeditor 2>&1', shell=True, capture_output=True)
    elif action == 'stop':
        subprocess.run('systemctl stop mediamtx mediamtx-webeditor 2>&1', shell=True, capture_output=True)
    elif action == 'restart':
        subprocess.run('systemctl restart mediamtx mediamtx-webeditor 2>&1', shell=True, capture_output=True)
    else:
        return jsonify({'error': 'Invalid action'}), 400
    time.sleep(2)
    r = subprocess.run(['systemctl', 'is-active', 'mediamtx'], capture_output=True, text=True)
    running = r.stdout.strip() == 'active'
    return jsonify({'success': True, 'running': running})

@app.route('/api/mediamtx/logs')
@login_required
def mediamtx_logs():
    lines = request.args.get('lines', 60, type=int)
    r = subprocess.run(f'journalctl -u mediamtx --no-pager -n {lines} 2>&1', shell=True, capture_output=True, text=True, timeout=10)
    entries = [l for l in (r.stdout.strip().split('\n') if r.stdout.strip() else []) if l.strip()]
    return jsonify({'entries': entries})

@app.route('/api/mediamtx/uninstall', methods=['POST'])
@login_required
def mediamtx_uninstall():
    data = request.json or {}
    password = data.get('password', '')
    auth = load_auth()
    if not auth.get('password_hash') or not check_password_hash(auth['password_hash'], password):
        return jsonify({'error': 'Invalid admin password'}), 403
    steps = []
    subprocess.run('systemctl stop mediamtx mediamtx-webeditor 2>/dev/null; true', shell=True, capture_output=True)
    subprocess.run('systemctl disable mediamtx mediamtx-webeditor 2>/dev/null; true', shell=True, capture_output=True)
    for f in ['/etc/systemd/system/mediamtx.service', '/etc/systemd/system/mediamtx-webeditor.service',
              '/usr/local/bin/mediamtx', '/usr/local/etc/mediamtx.yml']:
        if os.path.exists(f):
            os.remove(f)
    if os.path.exists('/opt/mediamtx-webeditor'):
        subprocess.run('rm -rf /opt/mediamtx-webeditor', shell=True, capture_output=True)
    subprocess.run('systemctl daemon-reload 2>/dev/null; true', shell=True, capture_output=True)
    steps.append('Stopped and disabled mediamtx and mediamtx-webeditor services')
    steps.append('Removed binary, config, and web editor files')
    mediamtx_deploy_log.clear()
    mediamtx_deploy_status.update({'running': False, 'complete': False, 'error': False})
    generate_caddyfile()
    subprocess.run('systemctl reload caddy 2>/dev/null; true', shell=True, capture_output=True)
    steps.append('Updated Caddyfile')
    return jsonify({'success': True, 'steps': steps})

def run_mediamtx_deploy():
    def plog(msg):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        mediamtx_deploy_log.append(entry)
        print(entry, flush=True)
    try:
        settings = load_settings()
        domain = settings.get('fqdn', '')

        # Step 1: Wait for apt lock / install deps
        plog("━━━ Step 1/7: Installing Dependencies ━━━")
        wait_for_apt_lock(plog, mediamtx_deploy_log)
        r = subprocess.run('apt-get update -qq && apt-get install -y wget tar curl ffmpeg openssl python3 python3-pip 2>&1',
            shell=True, capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            plog(f"✗ apt install failed: {r.stdout[-200:]}")
            mediamtx_deploy_status.update({'running': False, 'error': True})
            return
        plog("✓ Dependencies installed (wget, ffmpeg, python3)")

        # Install Python packages
        plog("  Installing Python packages...")
        subprocess.run('pip3 install Flask ruamel.yaml requests psutil --break-system-packages 2>&1',
            shell=True, capture_output=True, text=True, timeout=120)
        plog("✓ Python packages installed")

        # Step 2: Detect architecture and latest version
        plog("")
        plog("━━━ Step 2/7: Detecting MediaMTX Version ━━━")
        arch_map = {'x86_64': 'amd64', 'aarch64': 'arm64v8', 'armv7l': 'armv7'}
        arch_raw = subprocess.run('uname -m', shell=True, capture_output=True, text=True).stdout.strip()
        mtx_arch = arch_map.get(arch_raw, 'amd64')
        plog(f"  Architecture: {arch_raw} → {mtx_arch}")

        r = subprocess.run('curl -s https://api.github.com/repos/bluenviron/mediamtx/releases/latest',
            shell=True, capture_output=True, text=True, timeout=30)
        import re as _re
        m = _re.search(r'"tag_name":\s*"v([^"]+)"', r.stdout)
        if not m:
            plog("✗ Could not detect latest MediaMTX version")
            mediamtx_deploy_status.update({'running': False, 'error': True})
            return
        version = m.group(1)
        plog(f"✓ Latest version: {version}")

        # Step 3: Download and install binary
        plog("")
        plog("━━━ Step 3/7: Downloading & Installing MediaMTX ━━━")
        url = f"https://github.com/bluenviron/mediamtx/releases/download/v{version}/mediamtx_v{version}_linux_{mtx_arch}.tar.gz"
        tmp = '/tmp/mediamtx_install'
        os.makedirs(tmp, exist_ok=True)
        r = subprocess.run(f'wget -q -O {tmp}/mediamtx.tar.gz "{url}"', shell=True, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            plog(f"✗ Download failed")
            mediamtx_deploy_status.update({'running': False, 'error': True})
            return
        subprocess.run(f'tar -xzf {tmp}/mediamtx.tar.gz -C {tmp}', shell=True, capture_output=True)
        subprocess.run(f'mv -f {tmp}/mediamtx /usr/local/bin/mediamtx && chmod +x /usr/local/bin/mediamtx', shell=True, capture_output=True)
        subprocess.run(f'rm -rf {tmp}', shell=True, capture_output=True)
        plog(f"✓ MediaMTX v{version} installed to /usr/local/bin/mediamtx")

        # Step 4: Write config
        plog("")
        plog("━━━ Step 4/7: Writing Configuration ━━━")
        os.makedirs('/usr/local/etc', exist_ok=True)
        import secrets as _sec
        hls_pass = _sec.token_hex(8)

        mediamtx_yml = f"""# MediaMTX Configuration - Generated by TAKWERX Console
logLevel: info
logDestinations: [stdout]
logStructured: no
logFile: mediamtx.log
readTimeout: 10s
writeTimeout: 10s
writeQueueSize: 512
udpMaxPayloadSize: 1472

authMethod: internal
authInternalUsers:
- user: any
  ips: ['127.0.0.1', '::1']
  permissions:
  - action: read
  - action: publish
  - action: api
- user: hlsviewer
  pass: {hls_pass}
  ips: []
  permissions:
  - action: read
- user: any
  pass: ''
  ips: []
  permissions:
  - action: read
    path: teststream
authHTTPAddress:
authHTTPExclude:
- action: api
- action: metrics
- action: pprof

api: yes
apiAddress: :9898  # moved from 9997 — CloudTAK media container owns port 9997 (hardcoded in video-service.ts)
apiEncryption: no
apiAllowOrigins: ['*']
apiTrustedProxies: []

metrics: no
metricsAddress: :9998
pprof: no
pprofAddress: :9999
playback: no
playbackAddress: :9996

rtsp: yes
rtspTransports: [tcp]
rtspEncryption: "no"
rtspAddress: :8554
rtspsAddress: :8322
rtpAddress: :8000
rtcpAddress: :8001
rtspServerKey:
rtspServerCert:
rtspAuthMethods: [basic]

rtmp: no
rtmpAddress: :1935
rtmpEncryption: "no"
rtmpsAddress: :1936
rtmpServerKey:
rtmpServerCert:

hls: yes
hlsAddress: :8888
hlsEncryption: no
hlsServerKey:
hlsServerCert:
hlsAllowOrigins: ['*']
hlsTrustedProxies: ['127.0.0.1']
hlsAlwaysRemux: no
hlsVariant: mpegts
hlsSegmentCount: 3
hlsSegmentDuration: 500ms
hlsPartDuration: 200ms
hlsSegmentMaxSize: 50M
hlsDirectory: ''
hlsMuxerCloseAfter: 60s

webrtc: no
webrtcAddress: :8889
webrtcEncryption: no
webrtcAllowOrigins: ['*']

srt: yes
srtAddress: :8890

paths:
  teststream:
    record: no
  all_others:
  ~^live/(.+)$:
    runOnReady: ffmpeg -i rtsp://localhost:8554/live/$G1 -c copy -f rtsp rtsp://localhost:8554/$G1
    runOnReadyRestart: true
"""
        with open('/usr/local/etc/mediamtx.yml', 'w') as f:
            f.write(mediamtx_yml)
        plog("✓ Configuration written to /usr/local/etc/mediamtx.yml")
        plog(f"  HLS viewer password: {hls_pass}")

        # Step 5: Create mediamtx systemd service
        plog("")
        plog("━━━ Step 5/7: Creating systemd Services ━━━")
        mediamtx_svc = """[Unit]
Description=MediaMTX RTSP/HLS/SRT Streaming Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mediamtx /usr/local/etc/mediamtx.yml
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
        with open('/etc/systemd/system/mediamtx.service', 'w') as f:
            f.write(mediamtx_svc)
        plog("✓ mediamtx.service created")

        # Write web editor Python app — flexible: detect LDAP/Authentik and choose regular vs LDAP-enhanced source
        webeditor_dir = '/opt/mediamtx-webeditor'
        os.makedirs(webeditor_dir, exist_ok=True)
        os.makedirs(f'{webeditor_dir}/backups', exist_ok=True)
        os.makedirs(f'{webeditor_dir}/recordings', exist_ok=True)

        modules = detect_modules()
        ak = modules.get('authentik', {})
        ldap_available = bool(ak.get('installed'))
        if ldap_available:
            plog("  LDAP/Authentik detected — using editor source for LDAP-aware console")
        else:
            plog("  No LDAP — using regular MediaMTX editor from repo")

        webeditor_src = None
        clone_dir = '/tmp/mediamtx_editor_clone'
        try:
            subprocess.run(f'rm -rf {clone_dir}', shell=True, capture_output=True)
            os.makedirs(clone_dir, exist_ok=True)
            branch = MEDIAMTX_EDITOR_LDAP_BRANCH if (ldap_available and MEDIAMTX_EDITOR_LDAP_BRANCH) else None
            if branch:
                r = subprocess.run(f'git clone --depth 1 -b "{branch}" "{MEDIAMTX_EDITOR_REPO}" {clone_dir}',
                    shell=True, capture_output=True, text=True, timeout=60)
                if r.returncode != 0:
                    plog(f"  LDAP branch \"{branch}\" not found or clone failed, trying default branch")
                    subprocess.run(f'rm -rf {clone_dir}', shell=True, capture_output=True)
                    r = subprocess.run(f'git clone --depth 1 "{MEDIAMTX_EDITOR_REPO}" {clone_dir}',
                        shell=True, capture_output=True, text=True, timeout=60)
            else:
                r = subprocess.run(f'git clone --depth 1 "{MEDIAMTX_EDITOR_REPO}" {clone_dir}',
                    shell=True, capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                candidate = os.path.join(clone_dir, MEDIAMTX_EDITOR_PATH, 'mediamtx_config_editor.py')
                if os.path.exists(candidate):
                    webeditor_src = candidate
                    plog(f"  Cloned editor from {MEDIAMTX_EDITOR_REPO}" + (f" (branch {branch})" if branch else ""))
        except Exception as e:
            plog(f"  Clone failed: {e}")
        if not webeditor_src:
            app_dir = os.path.dirname(os.path.abspath(__file__))
            for p in [os.path.join(app_dir, 'mediamtx_config_editor.py'),
                      os.path.join(app_dir, 'config-editor', 'mediamtx_config_editor.py'),
                      '/opt/takwerx/mediamtx_config_editor.py']:
                if os.path.exists(p):
                    webeditor_src = p
                    plog("  Using local web editor (clone skipped or failed)")
                    break
        try:
            subprocess.run(f'rm -rf {clone_dir}', shell=True, capture_output=True)
        except Exception:
            pass

        if webeditor_src:
            subprocess.run(f'cp "{webeditor_src}" {webeditor_dir}/mediamtx_config_editor.py', shell=True)
            # Patch port to read from PORT env var instead of hardcoded 5000
            subprocess.run(
                f"sed -i 's/app.run(host=.0.0.0.0., port=5000/app.run(host=\"0.0.0.0\", port=int(os.environ.get(\"PORT\", 5080))/' {webeditor_dir}/mediamtx_config_editor.py",
                shell=True)
            # Console-deployed MediaMTX uses API port 9898 (CloudTAK uses 9997). Patch editor so "active streams" works.
            subprocess.run(f"sed -i 's/9997/9898/g' {webeditor_dir}/mediamtx_config_editor.py", shell=True)
            # When CloudTAK is installed, MediaMTX is at stream.* so "Stream URLs" in the editor should show stream. not video.
            if domain:
                subprocess.run(f"sed -i 's/video\\./stream./g' {webeditor_dir}/mediamtx_config_editor.py", shell=True)
                plog("  Stream URL host set to stream.*")
            plog("✓ Web editor installed (port 5080, API 9898)")
        else:
            plog("⚠ mediamtx_config_editor.py not found (clone failed and no local file)")
            plog("  Place it next to app.py or in config-editor/, or fix repo access, then redeploy")
            plog("  MediaMTX streaming will work — web editor unavailable until then")

        # Download test video
        test_video_dir = f'{webeditor_dir}/test_videos'
        os.makedirs(test_video_dir, exist_ok=True)
        test_video_url = 'https://raw.githubusercontent.com/takwerx/mediamtx-installer/main/config-editor/truck_60.ts'
        plog("  Downloading test video (truck_60.ts)...")
        r = subprocess.run(f'wget -q -O {test_video_dir}/truck_60.ts "{test_video_url}"',
            shell=True, capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            plog("✓ Test video installed")
        else:
            plog("⚠ Test video download failed — you can upload it manually via the web console")

        # Web editor systemd service
        webeditor_svc = """[Unit]
Description=MediaMTX Web Configuration Editor
After=network.target mediamtx.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/mediamtx-webeditor/mediamtx_config_editor.py
WorkingDirectory=/opt/mediamtx-webeditor
Environment=PORT=5080
Environment=MEDIAMTX_API_URL=http://127.0.0.1:9898
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
        with open('/etc/systemd/system/mediamtx-webeditor.service', 'w') as f:
            f.write(webeditor_svc)
        plog("✓ mediamtx-webeditor.service created")

        subprocess.run('systemctl daemon-reload', shell=True, capture_output=True)
        subprocess.run('systemctl enable mediamtx mediamtx-webeditor', shell=True, capture_output=True)
        subprocess.run('systemctl start mediamtx', shell=True, capture_output=True)
        if os.path.exists(f'{webeditor_dir}/mediamtx_config_editor.py'):
            subprocess.run('systemctl start mediamtx-webeditor', shell=True, capture_output=True)
        plog("✓ Services enabled and started")

        # Step 6: Firewall
        plog("")
        plog("━━━ Step 6/7: Configuring Firewall ━━━")
        for port_proto in ['8554/tcp', '8322/tcp', '8888/tcp', '8890/udp', '8000/udp', '8001/udp', '5080/tcp', '9898/tcp']:
            subprocess.run(f'ufw allow {port_proto} 2>/dev/null; true', shell=True, capture_output=True)
        plog("✓ Ports opened: 8554 (RTSP), 8322 (RTSPS), 8888 (HLS), 8890 (SRT), 5080 (Web Editor), 9898 (API)")

        # Step 7: Caddy integration
        plog("")
        plog("━━━ Step 7/7: Caddy Integration ━━━")
        caddy_running = subprocess.run(['systemctl', 'is-active', 'caddy'], capture_output=True, text=True).stdout.strip() == 'active'
        if caddy_running and domain:
            # Update Caddyfile first so Caddy issues the cert
            generate_caddyfile(settings)
            subprocess.run('systemctl reload caddy 2>/dev/null; true', shell=True, capture_output=True)
            mtx_domain = settings.get('mediamtx_domain', f'stream.{domain}')
            plog(f"✓ Caddyfile updated — {mtx_domain}")

            # Wait up to 60s for cert
            cert_base = '/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory'
            cert_file = f'{cert_base}/{mtx_domain}/{mtx_domain}.crt'
            key_file  = f'{cert_base}/{mtx_domain}/{mtx_domain}.key'
            plog(f"  Waiting for Caddy to issue cert for {mtx_domain}...")
            for i in range(30):
                if os.path.exists(cert_file) and os.path.exists(key_file):
                    break
                if i % 5 == 0:
                    plog(f"  ⏳ {i * 2}s...")
                time.sleep(2)

            if os.path.exists(cert_file):
                yml = '/usr/local/etc/mediamtx.yml'
                # Wire cert paths — strip continuation lines first then replace
                for key in ['rtspServerKey', 'rtspServerCert', 'hlsServerKey', 'hlsServerCert', 'rtmpServerKey', 'rtmpServerCert']:
                    subprocess.run(f"sed -i '/^{key}:/{{ n; /^  /d }}' {yml}", shell=True)
                subprocess.run(f"sed -i 's|^rtspServerKey:.*|rtspServerKey: {key_file}|' {yml}", shell=True)
                subprocess.run(f"sed -i 's|^rtspServerCert:.*|rtspServerCert: {cert_file}|' {yml}", shell=True)
                subprocess.run(f"sed -i 's|^hlsServerKey:.*|hlsServerKey: {key_file}|' {yml}", shell=True)
                subprocess.run(f"sed -i 's|^hlsServerCert:.*|hlsServerCert: {cert_file}|' {yml}", shell=True)
                subprocess.run(f"sed -i 's|^rtmpServerKey:.*|rtmpServerKey: {key_file}|' {yml}", shell=True)
                subprocess.run(f"sed -i 's|^rtmpServerCert:.*|rtmpServerCert: {cert_file}|' {yml}", shell=True)
                # Enable encryption
                subprocess.run(f"sed -i 's|^rtspEncryption:.*|rtspEncryption: \"optional\"|' {yml}", shell=True)
                subprocess.run(f"sed -i 's|^hlsEncryption:.*|hlsEncryption: yes|' {yml}", shell=True)
                plog(f"✓ SSL certificates wired — RTSPS and HTTPS HLS enabled")
                plog(f"  Cert: {cert_file}")
                subprocess.run('systemctl restart mediamtx', shell=True, capture_output=True)
                time.sleep(2)
            else:
                plog(f"  ⚠ Cert not found after 60s — SSL not wired")
                plog(f"  Go to Caddy page, reload, then restart MediaMTX to retry")
        elif not domain:
            plog("  No domain configured — skipping Caddy (access via port 5080 directly)")
        else:
            plog("  Caddy not running — skipping SSL integration")

        # Verify MediaMTX is up
        time.sleep(3)
        r = subprocess.run(['systemctl', 'is-active', 'mediamtx'], capture_output=True, text=True)
        if r.stdout.strip() == 'active':
            # If Authentik is running, ensure stream visibility groups exist (video-public, video-private, video-admin)
            ak_dir = os.path.expanduser('~/authentik')
            env_path = os.path.join(ak_dir, '.env')
            if os.path.exists(os.path.join(ak_dir, 'docker-compose.yml')) and os.path.exists(env_path):
                ak_token = ''
                with open(env_path) as f:
                    for line in f:
                        if line.strip().startswith('AUTHENTIK_BOOTSTRAP_TOKEN='):
                            ak_token = line.strip().split('=', 1)[1].strip()
                            break
                if ak_token:
                    import urllib.request
                    import urllib.error
                    plog("")
                    plog("━━━ Creating Authentik groups for stream access ━━━")
                    ak_url = 'http://127.0.0.1:9090'
                    ak_headers = {'Authorization': f'Bearer {ak_token}', 'Content-Type': 'application/json'}
                    for group_name in ('vid_public', 'vid_private', 'vid_admin'):
                        try:
                            req = urllib.request.Request(f'{ak_url}/api/v3/core/groups/',
                                data=json.dumps({'name': group_name, 'is_superuser': False}).encode(),
                                headers=ak_headers, method='POST')
                            urllib.request.urlopen(req, timeout=10)
                            plog(f"  ✓ Created group: {group_name}")
                        except urllib.error.HTTPError as e:
                            if e.code == 400:
                                plog(f"  ✓ Group already exists: {group_name}")
                            else:
                                plog(f"  ⚠ Could not create {group_name}: {e.code}")
                        except Exception as ex:
                            plog(f"  ⚠ Could not create {group_name}: {str(ex)[:60]}")
                    plog("  Assign users to vid_* groups in MediaMTX stream-access page or Authentik (they do not show in TAK/ATAK).")

            plog("")
            plog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            plog(f"🎉 MediaMTX v{version} deployed successfully!")
            if domain:
                mtx_display_domain = f"stream.{domain}"
                plog(f"   Web Console: https://{mtx_display_domain}")
                plog(f"   HLS streams: https://{mtx_display_domain}/[stream]/index.m3u8")
            else:
                plog(f"   Web Editor: http://{settings.get('server_ip','server')}:5080")
            plog(f"   RTSP: rtsp://[server]:8554/[stream]")
            plog(f"   SRT:  srt://[server]:8890?streamid=[stream]")
            plog(f"   HLS viewer password: {hls_pass}")
            plog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            mediamtx_deploy_status.update({'running': False, 'complete': True, 'error': False})
        else:
            plog("✗ MediaMTX service not active after deploy — check logs")
            mediamtx_deploy_status.update({'running': False, 'error': True})

    except Exception as e:
        plog(f"✗ Unexpected error: {str(e)}")
        mediamtx_deploy_status.update({'running': False, 'error': True})

# ── CloudTAK ──────────────────────────────────────────────────────────────────
cloudtak_deploy_log = []
cloudtak_deploy_status = {'running': False, 'complete': False, 'error': False}
cloudtak_uninstall_status = {'running': False, 'done': False, 'error': None}

@app.route('/api/cloudtak/deploy', methods=['POST'])
@login_required
def cloudtak_deploy_api():
    if cloudtak_deploy_status.get('running'):
        return jsonify({'error': 'Deployment already in progress'}), 409
    cloudtak_deploy_log.clear()
    cloudtak_deploy_status.update({'running': True, 'complete': False, 'error': False})
    threading.Thread(target=run_cloudtak_deploy, daemon=True).start()
    return jsonify({'success': True})

@app.route('/api/cloudtak/deploy/log')
@login_required
def cloudtak_deploy_log_api():
    idx = request.args.get('index', 0, type=int)
    return jsonify({'entries': cloudtak_deploy_log[idx:], 'total': len(cloudtak_deploy_log),
        'running': cloudtak_deploy_status['running'], 'complete': cloudtak_deploy_status['complete'],
        'error': cloudtak_deploy_status['error']})

@app.route('/api/cloudtak/redeploy', methods=['POST'])
@login_required
def cloudtak_redeploy_api():
    """Update .env and override, restart containers, re-apply nginx patch. Use when CloudTAK is already installed."""
    if cloudtak_deploy_status.get('running'):
        return jsonify({'error': 'Another operation is in progress'}), 409
    cloudtak_deploy_log.clear()
    cloudtak_deploy_status.update({'running': True, 'complete': False, 'error': False})
    # First line so pollers see activity immediately
    cloudtak_deploy_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Update config & restart started")
    threading.Thread(target=run_cloudtak_redeploy, daemon=True).start()
    return jsonify({'success': True, 'message': 'Update config & restart started'})

@app.route('/api/cloudtak/control', methods=['POST'])
@login_required
def cloudtak_control():
    action = (request.json or {}).get('action', '')
    cloudtak_dir = os.path.expanduser('~/CloudTAK')
    if action == 'start':
        subprocess.run(f'cd {cloudtak_dir} && docker compose up -d 2>&1', shell=True, capture_output=True, timeout=60)
    elif action == 'stop':
        subprocess.run(f'cd {cloudtak_dir} && docker compose stop 2>&1', shell=True, capture_output=True, timeout=60)
    elif action == 'restart':
        subprocess.run(f'cd {cloudtak_dir} && docker compose restart 2>&1', shell=True, capture_output=True, timeout=60)
    elif action == 'update':
        subprocess.run(f'cd {cloudtak_dir} && ./cloudtak.sh update 2>&1', shell=True, capture_output=True, timeout=600)
    else:
        return jsonify({'error': 'Invalid action'}), 400
    time.sleep(3)
    r = subprocess.run('docker ps --filter name=cloudtak-api --format "{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True)
    running = 'Up' in r.stdout
    return jsonify({'success': True, 'running': running})

@app.route('/api/cloudtak/logs')
@login_required
def cloudtak_container_logs():
    lines = request.args.get('lines', 80, type=int)
    container = request.args.get('container', '').strip()
    cloudtak_dir = os.path.expanduser('~/CloudTAK')
    compose_yml = os.path.join(cloudtak_dir, 'docker-compose.yml')
    if not os.path.exists(compose_yml):
        compose_yml = os.path.join(cloudtak_dir, 'compose.yaml')
    if container:
        r = subprocess.run(f'docker logs {container} --tail {lines} 2>&1', shell=True, capture_output=True, text=True, timeout=15)
    else:
        if os.path.exists(compose_yml):
            r = subprocess.run(f'docker compose -f "{compose_yml}" logs --tail {lines} 2>&1', shell=True, capture_output=True, text=True, timeout=15, cwd=cloudtak_dir)
        else:
            r = subprocess.run(f'docker logs cloudtak-api-1 --tail {lines} 2>&1', shell=True, capture_output=True, text=True, timeout=15)
    entries = [l for l in (r.stdout.strip().split('\n') if r.stdout.strip() else []) if l.strip()]
    return jsonify({'entries': entries})

@app.route('/api/cloudtak/uninstall', methods=['POST'])
@login_required
def cloudtak_uninstall():
    data = request.json or {}
    password = data.get('password', '')
    auth = load_auth()
    if not auth.get('password_hash') or not check_password_hash(auth['password_hash'], password):
        return jsonify({'error': 'Invalid admin password'}), 403
    if cloudtak_uninstall_status.get('running'):
        return jsonify({'error': 'Uninstall already in progress'}), 409
    cloudtak_uninstall_status.update({'running': True, 'done': False, 'error': None})
    def do_uninstall():
        try:
            cloudtak_dir = os.path.expanduser('~/CloudTAK')
            compose_yml = os.path.join(cloudtak_dir, 'docker-compose.yml')
            compose_yaml = os.path.join(cloudtak_dir, 'compose.yaml')
            if os.path.exists(cloudtak_dir):
                yml = compose_yml if os.path.exists(compose_yml) else (compose_yaml if os.path.exists(compose_yaml) else None)
                if yml:
                    subprocess.run(
                        f'docker compose -f "{yml}" down -v --rmi local',
                        shell=True, capture_output=True, timeout=180, cwd=cloudtak_dir
                    )
                subprocess.run(f'rm -rf "{cloudtak_dir}"', shell=True, capture_output=True, timeout=60)
            cloudtak_deploy_log.clear()
            cloudtak_deploy_status.update({'running': False, 'complete': False, 'error': False})
            generate_caddyfile()
            subprocess.run('systemctl reload caddy 2>/dev/null; true', shell=True, capture_output=True, timeout=15)
            cloudtak_uninstall_status.update({'running': False, 'done': True, 'error': None})
        except subprocess.TimeoutExpired:
            cloudtak_uninstall_status.update({'running': False, 'done': True, 'error': 'Uninstall timed out'})
        except Exception as e:
            cloudtak_uninstall_status.update({'running': False, 'done': True, 'error': str(e)})
    threading.Thread(target=do_uninstall, daemon=True).start()
    return jsonify({'success': True, 'message': 'Uninstall started'})

@app.route('/api/cloudtak/uninstall/status')
@login_required
def cloudtak_uninstall_status_api():
    return jsonify({
        'running': cloudtak_uninstall_status.get('running', False),
        'done': cloudtak_uninstall_status.get('done', False),
        'error': cloudtak_uninstall_status.get('error')
    })

def run_cloudtak_deploy():
    def plog(msg):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        cloudtak_deploy_log.append(entry)
        print(entry, flush=True)
    try:
        cloudtak_dir = os.path.expanduser('~/CloudTAK')
        settings = load_settings()
        domain = settings.get('fqdn', '')

        # Step 1: Check Docker
        plog("━━━ Step 1/7: Checking Docker ━━━")
        r = subprocess.run('docker --version', shell=True, capture_output=True, text=True)
        if r.returncode != 0:
            plog("  Docker not found — installing...")
            subprocess.run('curl -fsSL https://get.docker.com | sh', shell=True, capture_output=True, text=True, timeout=300)
            r2 = subprocess.run('docker --version', shell=True, capture_output=True, text=True)
            if r2.returncode != 0:
                plog("✗ Failed to install Docker")
                cloudtak_deploy_status.update({'running': False, 'error': True})
                return
            plog(f"  {r2.stdout.strip()}")
        else:
            plog(f"  {r.stdout.strip()}")
        plog("✓ Docker available")

        # Step 2: Clone or update repo
        plog("")
        plog("━━━ Step 2/7: Cloning CloudTAK ━━━")
        if os.path.exists(cloudtak_dir):
            plog("  ~/CloudTAK exists — pulling latest...")
            r = subprocess.run(f'cd {cloudtak_dir} && git pull --rebase --autostash', shell=True, capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                plog(f"  ⚠ git pull warning: {r.stderr.strip()[:100]}")
        else:
            plog("  Cloning from GitHub...")
            r = subprocess.run(f'git clone https://github.com/dfpc-coe/CloudTAK.git {cloudtak_dir}', shell=True, capture_output=True, text=True, timeout=600)
            if r.returncode != 0:
                plog(f"✗ Clone failed: {r.stderr.strip()[:200]}")
                cloudtak_deploy_status.update({'running': False, 'error': True})
                return
        plog("✓ Repository ready")

        # Ensure compose file exists (fix partial/bad clone)
        compose_yml = os.path.join(cloudtak_dir, 'docker-compose.yml')
        compose_yaml = os.path.join(cloudtak_dir, 'compose.yaml')
        if not os.path.exists(compose_yml) and not os.path.exists(compose_yaml):
            plog("  docker-compose.yml missing — re-cloning...")
            subprocess.run(f'rm -rf {cloudtak_dir}', shell=True, capture_output=True, timeout=30)
            r = subprocess.run(f'git clone https://github.com/dfpc-coe/CloudTAK.git {cloudtak_dir}', shell=True, capture_output=True, text=True, timeout=600)
            if r.returncode != 0:
                plog(f"✗ Re-clone failed: {r.stderr.strip()[:200]}")
                cloudtak_deploy_status.update({'running': False, 'error': True})
                return
            compose_yml = os.path.join(cloudtak_dir, 'docker-compose.yml')
            compose_yaml = os.path.join(cloudtak_dir, 'compose.yaml')
        if not os.path.exists(compose_yml):
            compose_yml = compose_yaml if os.path.exists(compose_yaml) else os.path.join(cloudtak_dir, 'docker-compose.yml')
        if not os.path.exists(compose_yml):
            plog(f"✗ No compose file found in {cloudtak_dir}")
            cloudtak_deploy_status.update({'running': False, 'error': True})
            return

        # Step 3: Generate .env and docker-compose.override.yml
        plog("")
        plog("━━━ Step 3/7: Configuring .env ━━━")
        env_path = os.path.join(cloudtak_dir, '.env')
        import secrets as _secrets
        signing_secret = _secrets.token_hex(32)
        minio_pass = _secrets.token_hex(16)

        # Build URLs
        # API_URL is used in two places: (1) TileJSON/tile URLs sent to the browser — must be
        # reachable by the user's browser (public URL). (2) Media container callback to the API.
        # We use the public URL when domain is set so the map and basemaps render. The media
        # container then calls the same URL; on same-host deployments this usually works.
        # If domain is not set, use Docker gateway so containers can reach the API.
        if domain:
            api_url = f"https://map.{domain}"
            pmtiles_url = f"https://tiles.map.{domain}"
        else:
            api_url = f"http://172.20.0.1:5000"
            pmtiles_url = f"http://{settings.get('server_ip', '127.0.0.1')}:5002"

        if domain:
            media_url = f"https://video.{domain}"
        else:
            media_url = "http://media:9997"

        env_content = f"""CLOUDTAK_Mode=docker-compose
CLOUDTAK_Config_media_url={media_url}

SigningSecret={signing_secret}

ASSET_BUCKET=cloudtak
AWS_S3_Endpoint=http://store:9000
AWS_S3_AccessKeyId=cloudtakminioadmin
AWS_S3_SecretAccessKey={minio_pass}
MINIO_ROOT_USER=cloudtakminioadmin
MINIO_ROOT_PASSWORD={minio_pass}

POSTGRES=postgres://docker:docker@postgis:5432/gis

# API_URL must be reachable by the browser (for tile URLs in TileJSON). We set it to the public
# map URL when domain is set so the map and basemaps render.
API_URL={api_url}
PMTILES_URL={pmtiles_url}

# Port remapping — avoids conflicts with standalone MediaMTX which owns the original ports.
# CloudTAK's docker-compose.yml supports these env vars natively (no override file needed).
# MEDIA_PORT_API=9997 because video-service.ts hardcodes port 9997 for all MediaMTX API calls.
# Standalone MediaMTX API moved to 9898 to free up 9997 for CloudTAK media container.
MEDIA_PORT_API=9997
MEDIA_PORT_RTSP=18554
MEDIA_PORT_RTMP=11935
MEDIA_PORT_HLS=18888
MEDIA_PORT_SRT=18890
"""
        with open(env_path, 'w') as f:
            f.write(env_content)

        # So the API container can reach the host (e.g. TAKWERX Console / Marti at :5001)
        override_path = os.path.join(cloudtak_dir, 'docker-compose.override.yml')
        override_yml = """# TAKWERX: API container must reach host (e.g. :5001 for Marti/TAK Server proxy)
services:
  api:
    extra_hosts:
      - "host.docker.internal:host-gateway"
"""
        with open(override_path, 'w') as f:
            f.write(override_yml)
        plog("  docker-compose.override.yml written (api → host.docker.internal for :5001)")

        plog(f"✓ .env written")
        plog(f"  API URL: {api_url}")
        plog(f"  Media URL: {media_url} (CloudTAK media container — port 9997 hardcoded in source)")

        # Step 4: Build Docker images (use -f so compose file is found regardless of cwd)
        plog("")
        plog("━━━ Step 4/7: Building Docker Images ━━━")
        plog("  This may take 5-10 minutes on first run...")
        r = subprocess.run(f'docker compose -f {compose_yml} build 2>&1', shell=True, capture_output=True, text=True, timeout=1800, cwd=cloudtak_dir)
        if r.returncode != 0:
            plog(f"✗ Docker build failed")
            for line in r.stdout.strip().split('\n')[-20:]:
                if line.strip():
                    plog(f"  {line}")
            cloudtak_deploy_status.update({'running': False, 'error': True})
            return
        plog("✓ Images built")

        # Step 5: Start containers including media on remapped ports
        plog("")
        plog("━━━ Step 5/7: Starting Containers ━━━")
        plog("  Starting all containers including media (remapped ports)...")
        plog("  Standalone MediaMTX stays on original ports — no conflict")
        r = subprocess.run(
            f'docker compose -f {compose_yml} up -d 2>&1',
            shell=True, capture_output=True, text=True, timeout=120, cwd=cloudtak_dir
        )
        if r.returncode != 0:
            plog(f"✗ docker compose up failed")
            for line in r.stdout.strip().split('\n')[-10:]:
                if line.strip():
                    plog(f"  {line}")
            cloudtak_deploy_status.update({'running': False, 'error': True})
            return
        plog("✓ Containers started")

        # CloudTAK nginx proxies /api to 127.0.0.1:5001 (Node app in same container). Do NOT
        # replace that with host:5001 or /api would hit TAKWERX Console and the app would stay on "Loading CloudTAK".

        # Step 6: Wait for API to be ready
        plog("")
        plog("━━━ Step 6/7: Waiting for CloudTAK API ━━━")
        import urllib.request as _urlreq
        for attempt in range(30):
            try:
                _urlreq.urlopen('http://localhost:5000/', timeout=3)
                plog("✓ CloudTAK API is responding")
                break
            except Exception:
                if attempt % 5 == 0:
                    plog(f"  ⏳ Waiting... ({attempt * 2}s)")
                time.sleep(2)
        else:
            plog("⚠ CloudTAK API did not respond in time — check container logs")

        # Step 7: Update Caddyfile
        plog("")
        plog("━━━ Step 7/7: Updating Caddy ━━━")
        if domain:
            generate_caddyfile(settings)
            r = subprocess.run('systemctl reload caddy 2>&1', shell=True, capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                plog(f"✓ Caddy updated — map.{domain} and tiles.map.{domain} live")
            else:
                plog(f"⚠ Caddy reload: {r.stdout.strip()[:100]}")
        else:
            plog("  No domain configured — skipping Caddy (access via port 5000)")

        plog("")
        plog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        if domain:
            plog(f"🎉 CloudTAK deployed! Open https://map.{domain} in your browser")
            plog(f"   Tiles: https://tiles.map.{domain}")
            plog(f"   Video: https://video.{domain} (via standalone MediaMTX)")
        else:
            server_ip = settings.get('server_ip', 'your-server-ip')
            plog(f"🎉 CloudTAK deployed! Open http://{server_ip}:5000 in your browser")
        plog(f"   Log in and go to Admin → Connections to configure your TAK Server")
        plog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        cloudtak_deploy_status.update({'running': False, 'complete': True, 'error': False})

    except Exception as e:
        plog(f"✗ Unexpected error: {str(e)}")
        cloudtak_deploy_status.update({'running': False, 'error': True})

def run_cloudtak_redeploy():
    """Rewrite .env and override, restart stack, re-apply nginx patch. Reuses deploy log/status."""
    def plog(msg):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        cloudtak_deploy_log.append(entry)
        print(entry, flush=True)
    try:
        cloudtak_dir = os.path.expanduser('~/CloudTAK')
        compose_yml = os.path.join(cloudtak_dir, 'docker-compose.yml')
        if not os.path.exists(compose_yml):
            compose_yml = os.path.join(cloudtak_dir, 'compose.yaml')
        if not os.path.exists(compose_yml):
            plog("✗ CloudTAK not found (no compose file)")
            cloudtak_deploy_status.update({'running': False, 'error': True})
            return
        settings = load_settings()
        domain = (settings.get('fqdn') or '').strip() or None
        if domain:
            api_url = f"https://map.{domain}"
            pmtiles_url = f"https://tiles.map.{domain}"
            media_url = f"https://video.{domain}"
        else:
            api_url = f"http://172.20.0.1:5000"
            pmtiles_url = f"http://{settings.get('server_ip', '127.0.0.1')}:5002"
            media_url = "http://media:9997"
        env_path = os.path.join(cloudtak_dir, '.env')
        signing_secret = None
        minio_pass = None
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('SigningSecret='):
                        signing_secret = line.split('=', 1)[1].strip()
                    elif line.startswith('MINIO_ROOT_PASSWORD='):
                        minio_pass = line.split('=', 1)[1].strip()
        import secrets as _secrets
        if not signing_secret:
            signing_secret = _secrets.token_hex(32)
        if not minio_pass:
            minio_pass = _secrets.token_hex(16)
        env_content = f"""CLOUDTAK_Mode=docker-compose
CLOUDTAK_Config_media_url={media_url}

SigningSecret={signing_secret}

ASSET_BUCKET=cloudtak
AWS_S3_Endpoint=http://store:9000
AWS_S3_AccessKeyId=cloudtakminioadmin
AWS_S3_SecretAccessKey={minio_pass}
MINIO_ROOT_USER=cloudtakminioadmin
MINIO_ROOT_PASSWORD={minio_pass}

POSTGRES=postgres://docker:docker@postgis:5432/gis

API_URL={api_url}
PMTILES_URL={pmtiles_url}

MEDIA_PORT_API=9997
MEDIA_PORT_RTSP=18554
MEDIA_PORT_RTMP=11935
MEDIA_PORT_HLS=18888
MEDIA_PORT_SRT=18890
"""
        with open(env_path, 'w') as f:
            f.write(env_content)
        override_path = os.path.join(cloudtak_dir, 'docker-compose.override.yml')
        with open(override_path, 'w') as f:
            f.write("""# TAKWERX: API container must reach host (e.g. :5001 for Marti/TAK Server proxy)
services:
  api:
    extra_hosts:
      - "host.docker.internal:host-gateway"
""")
        plog("✓ .env and override written")
        plog("  Restarting containers...")
        r = subprocess.run(f'docker compose -f "{compose_yml}" restart 2>&1', shell=True, capture_output=True, text=True, timeout=120, cwd=cloudtak_dir)
        if r.returncode != 0:
            # Fallback for systems with docker-compose (hyphen) instead of docker compose
            r = subprocess.run(f'docker-compose -f "{compose_yml}" restart 2>&1', shell=True, capture_output=True, text=True, timeout=120, cwd=cloudtak_dir)
        if r.returncode != 0:
            plog(f"✗ Restart failed: {r.stderr or r.stdout or 'unknown'}")
            cloudtak_deploy_status.update({'running': False, 'error': True})
            return
        plog("✓ Containers restarted")
        time.sleep(3)
        # Restore /api proxy to 127.0.0.1:5001 (Node in container) if a previous patch sent it to the host
        api_container = None
        for _ in range(15):
            r = subprocess.run(f'docker compose -f "{compose_yml}" ps -q api 2>/dev/null', shell=True, capture_output=True, text=True, timeout=5, cwd=cloudtak_dir)
            cid = (r.stdout or '').strip()
            if cid and len(cid) >= 8:
                api_container = cid
                break
            time.sleep(1)
        if api_container:
            for nf in ['/etc/nginx/nginx.conf', '/etc/nginx/conf.d/default.conf']:
                subprocess.run(f'docker exec {api_container} sed -i "s|proxy_pass http://[^;]*:5001|proxy_pass http://127.0.0.1:5001|g" {nf} 2>/dev/null', shell=True, capture_output=True, timeout=5)
            subprocess.run(f'docker exec {api_container} nginx -s reload 2>/dev/null', shell=True, capture_output=True, timeout=5)
            plog("  Nginx /api proxy pointed at CloudTAK API (127.0.0.1:5001)")
        plog("  Waiting for CloudTAK API to respond...")
        import urllib.request as _urlreq
        for attempt in range(45):
            try:
                _urlreq.urlopen('http://localhost:5000/', timeout=3)
                plog("✓ CloudTAK API is responding")
                break
            except Exception:
                if attempt % 5 == 0 and attempt > 0:
                    plog(f"  Still waiting... ({attempt * 2}s)")
                time.sleep(2)
        else:
            plog("⚠ API did not respond in time — if map.<domain> stays on 'Loading CloudTAK', check Container Logs and ensure the api container is running")
        if domain:
            generate_caddyfile(settings)
            try:
                subprocess.run('systemctl reload caddy 2>/dev/null', shell=True, capture_output=True, timeout=45)
                plog("✓ Caddy reloaded")
            except subprocess.TimeoutExpired:
                plog("⚠ Caddy reload timed out — reload it from the Caddy page if needed")
        plog("✓ Update config & restart done")
        cloudtak_deploy_status.update({'running': False, 'complete': True, 'error': False})
    except Exception as e:
        plog(f"✗ Error: {str(e)}")
        cloudtak_deploy_status.update({'running': False, 'error': True})
    finally:
        cloudtak_deploy_status['running'] = False

# ── Email Relay ────────────────────────────────────────────────────────────────
email_deploy_log = []
email_deploy_status = {'running': False, 'complete': False, 'error': False}

PROVIDERS = {
    'brevo':   {'name': 'Brevo',   'host': 'smtp-relay.brevo.com', 'port': '587', 'url': 'https://app.brevo.com/settings/keys/smtp'},
    'smtp2go': {'name': 'SMTP2GO', 'host': 'mail.smtp2go.com',     'port': '587', 'url': 'https://app.smtp2go.com/settings/users/smtp'},
    'mailgun': {'name': 'Mailgun', 'host': 'smtp.mailgun.org',      'port': '587', 'url': 'https://app.mailgun.com/mg/sending/domains'},
    'custom':  {'name': 'Custom',  'host': '',                      'port': '587', 'url': ''},
}

def run_email_deploy(provider_key, smtp_user, smtp_pass, from_addr, from_name):
    log = email_deploy_log
    status = email_deploy_status

    def plog(msg):
        log.append(msg)

    try:
        settings = load_settings()
        pkg_mgr = settings.get('pkg_mgr', 'apt')
        provider = PROVIDERS.get(provider_key, PROVIDERS['brevo'])

        plog(f"📧 Step 1/5 — Installing Postfix...")
        if pkg_mgr == 'apt':
            wait_for_apt_lock(plog, log)
            r = subprocess.run(
                'DEBIAN_FRONTEND=noninteractive apt-get install -y postfix libsasl2-modules 2>&1',
                shell=True, capture_output=True, text=True, timeout=300)
        else:
            r = subprocess.run('dnf install -y postfix cyrus-sasl-plain 2>&1',
                shell=True, capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            plog(f"✗ Postfix install failed: {r.stdout[-500:]}")
            status.update({'running': False, 'error': True})
            return
        plog("✓ Postfix installed")

        plog(f"📧 Step 2/5 — Configuring main.cf...")
        relay_host = provider['host']
        relay_port = provider['port']
        main_cf_additions = f"""
# TAKWERX Email Relay — managed by TAK-infra
relayhost = [{relay_host}]:{relay_port}
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = may
smtp_use_tls = yes
header_size_limit = 4096000
smtp_generic_maps = hash:/etc/postfix/generic
"""
        # Read existing main.cf and strip any previous TAKWERX block
        main_cf_path = '/etc/postfix/main.cf'
        if os.path.exists(main_cf_path):
            with open(main_cf_path) as f:
                existing = f.read()
            # Remove previous TAKWERX block if present
            import re
            existing = re.sub(r'\n# TAKWERX Email Relay.*', '', existing, flags=re.DOTALL)
            # Remove any existing relayhost line (Ubuntu default has a blank one)
            existing = re.sub(r'^\s*relayhost\s*=.*$', '', existing, flags=re.MULTILINE)
            existing = existing.rstrip()
        else:
            existing = ''
        with open(main_cf_path, 'w') as f:
            f.write(existing + '\n' + main_cf_additions)
        plog("✓ main.cf configured")

        plog(f"📧 Step 3/5 — Writing credentials...")
        sasl_line = f"[{relay_host}]:{relay_port}    {smtp_user}:{smtp_pass}"
        with open('/etc/postfix/sasl_passwd', 'w') as f:
            f.write(sasl_line + '\n')
        subprocess.run('postmap /etc/postfix/sasl_passwd', shell=True, capture_output=True)
        subprocess.run('chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db', shell=True, capture_output=True)

        # Generic map for from address rewriting
        hostname = subprocess.run('hostname -f', shell=True, capture_output=True, text=True).stdout.strip()
        generic_line = f"root@{hostname}    {from_addr}"
        with open('/etc/postfix/generic', 'w') as f:
            f.write(generic_line + '\n')
        subprocess.run('postmap /etc/postfix/generic', shell=True, capture_output=True)
        plog("✓ Credentials written and hashed")

        plog(f"📧 Step 4/5 — Enabling and starting Postfix...")
        subprocess.run('systemctl enable postfix 2>&1', shell=True, capture_output=True, text=True)
        r = subprocess.run('systemctl restart postfix 2>&1', shell=True, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            plog(f"✗ Postfix restart failed: {r.stdout}")
            status.update({'running': False, 'error': True})
            return
        plog("✓ Postfix running")

        plog(f"📧 Step 5/5 — Saving configuration...")
        settings['email_relay'] = {
            'provider': provider_key,
            'relay_host': relay_host,
            'relay_port': relay_port,
            'smtp_user': smtp_user,
            'from_addr': from_addr,
            'from_name': from_name,
        }
        # Store password separately (still in settings.json, local only)
        settings['email_relay']['smtp_pass'] = smtp_pass
        save_settings(settings)
        plog("✓ Configuration saved")
        plog("")
        plog("✅ Email Relay deployed successfully!")
        plog(f"   Provider: {provider['name']}")
        plog(f"   Relay:    {relay_host}:{relay_port}")
        plog(f"   From:     {from_name} <{from_addr}>")
        plog("")
        plog("📋 Configure apps to use SMTP:")
        plog("   Host: localhost   Port: 25   No auth required")
        status.update({'running': False, 'complete': True, 'error': False})

    except Exception as e:
        plog(f"✗ Deploy failed: {str(e)}")
        status.update({'running': False, 'error': True})


@app.route('/emailrelay')
@login_required
def emailrelay_page():
    modules = detect_modules()
    email = modules.get('emailrelay', {})
    settings = load_settings()
    relay_config = settings.get('email_relay', {})
    return render_template_string(EMAIL_RELAY_TEMPLATE,
        settings=settings, modules=modules, email=email,
        relay_config=relay_config, providers=PROVIDERS,
        metrics=get_system_metrics(), version=VERSION,
        deploying=email_deploy_status.get('running', False),
        deploy_done=email_deploy_status.get('complete', False),
        deploy_error=email_deploy_status.get('error', False))

@app.route('/api/emailrelay/deploy', methods=['POST'])
@login_required
def emailrelay_deploy():
    if email_deploy_status['running']:
        return jsonify({'success': False, 'error': 'Deployment already in progress'})
    data = request.get_json()
    provider = data.get('provider', 'brevo')
    smtp_user = data.get('smtp_user', '').strip()
    smtp_pass = data.get('smtp_pass', '').strip()
    from_addr = data.get('from_addr', '').strip()
    from_name = data.get('from_name', '').strip()
    if not smtp_user or not smtp_pass or not from_addr:
        return jsonify({'success': False, 'error': 'SMTP username, password, and from address are required'})
    if provider == 'custom':
        custom_host = data.get('custom_host', '').strip()
        custom_port = data.get('custom_port', '587').strip()
        if not custom_host:
            return jsonify({'success': False, 'error': 'Custom host is required'})
        PROVIDERS['custom']['host'] = custom_host
        PROVIDERS['custom']['port'] = custom_port
    email_deploy_log.clear()
    email_deploy_status.update({'running': True, 'complete': False, 'error': False})
    threading.Thread(target=run_email_deploy,
        args=(provider, smtp_user, smtp_pass, from_addr, from_name), daemon=True).start()
    return jsonify({'success': True})

@app.route('/api/emailrelay/log')
@login_required
def emailrelay_log():
    return jsonify({
        'running': email_deploy_status['running'],
        'complete': email_deploy_status['complete'],
        'error': email_deploy_status['error'],
        'entries': list(email_deploy_log)})

@app.route('/api/emailrelay/test', methods=['POST'])
@login_required
def emailrelay_test():
    data = request.get_json()
    to_addr = data.get('to', '').strip()
    if not to_addr:
        return jsonify({'success': False, 'error': 'Recipient address required'})
    settings = load_settings()
    relay_config = settings.get('email_relay', {})
    from_addr = relay_config.get('from_addr', 'noreply@localhost')
    from_name = relay_config.get('from_name', 'TAK-infra')
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        msg = MIMEMultipart()
        msg['From'] = f'{from_name} <{from_addr}>'
        msg['To'] = to_addr
        msg['Subject'] = 'TAK-infra Test Email'
        msg.attach(MIMEText('Test email from TAK-infra Email Relay.\n\nIf you received this, your email relay is working correctly.', 'plain'))
        with smtplib.SMTP('localhost', 25, timeout=15) as s:
            s.sendmail(from_addr, [to_addr], msg.as_string())
        return jsonify({'success': True, 'output': f'Test email sent to {to_addr}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/emailrelay/swap', methods=['POST'])
@login_required
def emailrelay_swap():
    """Swap provider — reconfigure Postfix with new credentials"""
    if email_deploy_status['running']:
        return jsonify({'success': False, 'error': 'Deployment already in progress'})
    data = request.get_json()
    provider = data.get('provider', 'brevo')
    smtp_user = data.get('smtp_user', '').strip()
    smtp_pass = data.get('smtp_pass', '').strip()
    from_addr = data.get('from_addr', '').strip()
    from_name = data.get('from_name', '').strip()
    if not smtp_user or not smtp_pass or not from_addr:
        return jsonify({'success': False, 'error': 'All fields required'})
    if provider == 'custom':
        custom_host = data.get('custom_host', '').strip()
        custom_port = data.get('custom_port', '587').strip()
        if not custom_host:
            return jsonify({'success': False, 'error': 'Custom host is required'})
        PROVIDERS['custom']['host'] = custom_host
        PROVIDERS['custom']['port'] = custom_port
    email_deploy_log.clear()
    email_deploy_status.update({'running': True, 'complete': False, 'error': False})
    threading.Thread(target=run_email_deploy,
        args=(provider, smtp_user, smtp_pass, from_addr, from_name), daemon=True).start()
    return jsonify({'success': True})

@app.route('/api/emailrelay/control', methods=['POST'])
@login_required
def emailrelay_control():
    data = request.get_json()
    action = data.get('action', '')
    if action == 'restart':
        r = subprocess.run('systemctl restart postfix 2>&1', shell=True, capture_output=True, text=True, timeout=30)
    elif action == 'stop':
        r = subprocess.run('systemctl stop postfix 2>&1', shell=True, capture_output=True, text=True, timeout=30)
    elif action == 'start':
        r = subprocess.run('systemctl start postfix 2>&1', shell=True, capture_output=True, text=True, timeout=30)
    else:
        return jsonify({'success': False, 'error': 'Unknown action'})
    return jsonify({'success': r.returncode == 0, 'output': r.stdout.strip()})

@app.route('/api/emailrelay/uninstall', methods=['POST'])
@login_required
def emailrelay_uninstall():
    subprocess.run('systemctl stop postfix 2>/dev/null; true', shell=True, capture_output=True, timeout=30)
    subprocess.run('systemctl disable postfix 2>/dev/null; true', shell=True, capture_output=True, timeout=30)
    settings = load_settings()
    pkg_mgr = settings.get('pkg_mgr', 'apt')
    if pkg_mgr == 'apt':
        subprocess.run('apt-get remove -y postfix 2>/dev/null; true', shell=True, capture_output=True, timeout=120)
    else:
        subprocess.run('dnf remove -y postfix 2>/dev/null; true', shell=True, capture_output=True, timeout=120)
    settings.pop('email_relay', None)
    save_settings(settings)
    email_deploy_log.clear()
    email_deploy_status.update({'running': False, 'complete': False, 'error': False})
    return jsonify({'success': True, 'steps': ['Postfix stopped and removed', 'Configuration cleared']})


def _ensure_authentik_recovery_flow(ak_url, ak_headers):
    """Create recovery flow + stages + bindings and link to default authentication flow.
    Returns (success: bool, message: str)."""
    import urllib.request as _req
    import urllib.error
    try:
        # 1) Get or create recovery flow
        req = _req.Request(f'{ak_url}/api/v3/flows/instances/?designation=recovery', headers=ak_headers)
        resp = _req.urlopen(req, timeout=15)
        recovery_flows = json.loads(resp.read().decode()).get('results', [])
        recovery_flow_pk = next((f['pk'] for f in recovery_flows if f.get('slug') == 'default-password-recovery'), None)
        if not recovery_flow_pk and recovery_flows:
            recovery_flow_pk = recovery_flows[0]['pk']
        if not recovery_flow_pk:
            req = _req.Request(f'{ak_url}/api/v3/flows/instances/',
                data=json.dumps({'name': 'Password Recovery', 'slug': 'default-password-recovery',
                    'designation': 'recovery', 'title': 'Recover password'}).encode(),
                headers=ak_headers, method='POST')
            resp = _req.urlopen(req, timeout=15)
            recovery_flow_pk = json.loads(resp.read().decode())['pk']

        # 2) Get existing bindings for recovery flow
        req = _req.Request(f'{ak_url}/api/v3/flows/bindings/?flow__pk={recovery_flow_pk}', headers=ak_headers)
        resp = _req.urlopen(req, timeout=15)
        bindings = json.loads(resp.read().decode()).get('results', [])
        existing_stage_pks = set()
        for b in bindings:
            s = b.get('stage')
            if isinstance(s, (int, str)):
                existing_stage_pks.add(s)
            elif isinstance(s, dict) and 'pk' in s:
                existing_stage_pks.add(s['pk'])

        # 3) Create stages if not already bound
        def create_stage(path, body):
            r = _req.Request(f'{ak_url}/api/v3/{path}', data=json.dumps(body).encode(), headers=ak_headers, method='POST')
            resp = _req.urlopen(r, timeout=15)
            return json.loads(resp.read().decode())['pk']

        stage_pks_to_bind = []
        # Identification (recovery: identify by email)
        req = _req.Request(f'{ak_url}/api/v3/stages/identification/?search=Recovery+Identification', headers=ak_headers)
        try:
            resp = _req.urlopen(req, timeout=15)
            results = json.loads(resp.read().decode()).get('results', [])
            id_stage_pk = results[0]['pk'] if results else None
        except Exception:
            id_stage_pk = None
        if not id_stage_pk:
            try:
                id_stage_pk = create_stage('stages/identification/', {'name': 'Recovery Identification', 'user_fields': ['email']})
            except urllib.error.HTTPError as e:
                if e.code == 400:
                    req = _req.Request(f'{ak_url}/api/v3/stages/identification/', headers=ak_headers)
                    resp = _req.urlopen(req, timeout=15)
                    results = json.loads(resp.read().decode()).get('results', [])
                    id_stage_pk = results[0]['pk'] if results else None
                else:
                    raise
        if id_stage_pk and id_stage_pk not in existing_stage_pks:
            stage_pks_to_bind.append((10, id_stage_pk))

        # Email stage (sends recovery link)
        req = _req.Request(f'{ak_url}/api/v3/stages/email/?search=Recovery+Email', headers=ak_headers)
        try:
            resp = _req.urlopen(req, timeout=15)
            results = json.loads(resp.read().decode()).get('results', [])
            email_stage_pk = results[0]['pk'] if results else None
        except Exception:
            email_stage_pk = None
        if not email_stage_pk:
            try:
                email_stage_pk = create_stage('stages/email/', {'name': 'Recovery Email'})
            except urllib.error.HTTPError as e:
                if e.code == 400:
                    req = _req.Request(f'{ak_url}/api/v3/stages/email/', headers=ak_headers)
                    resp = _req.urlopen(req, timeout=15)
                    results = json.loads(resp.read().decode()).get('results', [])
                    email_stage_pk = results[0]['pk'] if results else None
                else:
                    raise
        if email_stage_pk and email_stage_pk not in existing_stage_pks:
            stage_pks_to_bind.append((20, email_stage_pk))

        # Password stage (set new password)
        req = _req.Request(f'{ak_url}/api/v3/stages/password/?search=Recovery+Password', headers=ak_headers)
        try:
            resp = _req.urlopen(req, timeout=15)
            results = json.loads(resp.read().decode()).get('results', [])
            pw_stage_pk = results[0]['pk'] if results else None
        except Exception:
            pw_stage_pk = None
        if not pw_stage_pk:
            try:
                pw_stage_pk = create_stage('stages/password/', {'name': 'Recovery Password'})
            except urllib.error.HTTPError as e:
                if e.code == 400:
                    req = _req.Request(f'{ak_url}/api/v3/stages/password/', headers=ak_headers)
                    resp = _req.urlopen(req, timeout=15)
                    results = json.loads(resp.read().decode()).get('results', [])
                    pw_stage_pk = results[0]['pk'] if results else None
                else:
                    raise
        if pw_stage_pk and pw_stage_pk not in existing_stage_pks:
            stage_pks_to_bind.append((30, pw_stage_pk))

        # 4) Bind stages to recovery flow
        for order, stage_pk in stage_pks_to_bind:
            _req.urlopen(_req.Request(f'{ak_url}/api/v3/flows/bindings/',
                data=json.dumps({'flow': recovery_flow_pk, 'stage': stage_pk, 'order': order}).encode(),
                headers=ak_headers, method='POST'), timeout=15)

        # 5) Get default authentication flow and its identification stage, set recovery_flow
        req = _req.Request(f'{ak_url}/api/v3/flows/instances/?designation=authentication', headers=ak_headers)
        resp = _req.urlopen(req, timeout=15)
        auth_flows = json.loads(resp.read().decode()).get('results', [])
        auth_flow_pk = next((f['pk'] for f in auth_flows if f.get('slug') == 'default-authentication-flow'),
            auth_flows[0]['pk'] if auth_flows else None)
        if not auth_flow_pk:
            return True, 'Recovery flow created; link to login skipped (no default authentication flow).'
        req = _req.Request(f'{ak_url}/api/v3/flows/bindings/?flow__pk={auth_flow_pk}', headers=ak_headers)
        resp = _req.urlopen(req, timeout=15)
        auth_bindings = json.loads(resp.read().decode()).get('results', [])
        for b in auth_bindings:
            stage = b.get('stage')
            stage_pk = stage if isinstance(stage, (int, str)) else (stage.get('pk') if isinstance(stage, dict) else None)
            if not stage_pk:
                continue
            req = _req.Request(f'{ak_url}/api/v3/stages/identification/{stage_pk}/', headers=ak_headers)
            try:
                resp = _req.urlopen(req, timeout=15)
                stage_data = json.loads(resp.read().decode())
                if stage_data.get('recovery_flow') != recovery_flow_pk:
                    _req.urlopen(_req.Request(f'{ak_url}/api/v3/stages/identification/{stage_pk}/',
                        data=json.dumps({**stage_data, 'recovery_flow': recovery_flow_pk}).encode(),
                        headers=ak_headers, method='PUT'), timeout=15)
                break
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    continue
                raise
        return True, 'Recovery flow created and linked; "Forgot password?" is on the login page.'
    except Exception as e:
        return False, str(e)


@app.route('/api/emailrelay/configure-authentik', methods=['POST'])
@login_required
def emailrelay_configure_authentik():
    """Push Email Relay settings into Authentik and set up recovery flow (SMTP + Forgot password?)."""
    settings = load_settings()
    relay = settings.get('email_relay') or {}
    if not relay.get('from_addr'):
        return jsonify({'success': False, 'error': 'Email Relay not configured. Deploy the relay first.'}), 400
    ak_dir = os.path.expanduser('~/authentik')
    env_path = os.path.join(ak_dir, '.env')
    if not os.path.exists(os.path.join(ak_dir, 'docker-compose.yml')):
        return jsonify({'success': False, 'error': 'Authentik is not installed.'}), 400
    from_addr = (relay.get('from_addr') or '').strip() or 'authentik@localhost'
    # Authentik email env vars (docs: https://docs.goauthentik.io/install-config/email/)
    email_block = [
        '',
        '# Email — use local relay (Postfix)',
        'AUTHENTIK_EMAIL__HOST=localhost',
        'AUTHENTIK_EMAIL__PORT=25',
        'AUTHENTIK_EMAIL__USERNAME=',
        'AUTHENTIK_EMAIL__PASSWORD=',
        'AUTHENTIK_EMAIL__USE_TLS=false',
        'AUTHENTIK_EMAIL__USE_SSL=false',
        'AUTHENTIK_EMAIL__TIMEOUT=10',
        f'AUTHENTIK_EMAIL__FROM={from_addr}',
    ]
    try:
        lines = []
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if line.strip().startswith('AUTHENTIK_EMAIL__'):
                        continue
                    lines.append(line.rstrip('\n'))
        if lines and lines[-1].strip() != '':
            lines.append('')
        lines.extend(email_block)
        with open(env_path, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        r = subprocess.run(
            f'cd {ak_dir} && docker compose up -d --force-recreate',
            shell=True, capture_output=True, text=True, timeout=120
        )
        if r.returncode != 0:
            return jsonify({'success': False, 'error': f'Authentik restart failed: {r.stderr or r.stdout}'}), 500

        # Wait for API then set up recovery flow
        ak_token = ''
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if line.strip().startswith('AUTHENTIK_BOOTSTRAP_TOKEN='):
                        ak_token = line.strip().split('=', 1)[1].strip()
                        break
        message = 'Authentik is now configured to use the local Email Relay (localhost:25). Restart complete.'
        if ak_token:
            import urllib.error as _urllib_err
            ak_url = 'http://127.0.0.1:9090'
            ak_headers = {'Authorization': f'Bearer {ak_token}', 'Content-Type': 'application/json'}
            api_ready = False
            max_wait = 600  # 10 min cap
            waited = 0
            while waited < max_wait:
                try:
                    req = urllib.request.Request(f'{ak_url}/api/v3/core/users/', headers=ak_headers)
                    urllib.request.urlopen(req, timeout=5)
                    api_ready = True
                    break
                except _urllib_err.HTTPError as e:
                    if e.code in (401, 403):
                        api_ready = True
                        break
                    time.sleep(3)
                    waited += 3
                except Exception:
                    time.sleep(3)
                    waited += 3
            if api_ready:
                ok, recovery_msg = _ensure_authentik_recovery_flow(ak_url, ak_headers)
                if ok:
                    message = 'Authentik is configured to use the local Email Relay. ' + recovery_msg
                else:
                    message += f' Recovery flow could not be created: {recovery_msg}. You can set it up manually in Authentik.'
            else:
                message += ' Recovery flow was not set up (API not ready in time). You can run "Configure Authentik" again or set up recovery manually in Authentik.'

        return jsonify({'success': True, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── Node-RED ──────────────────────────────────────────────────────────────────
nodered_deploy_log = []
nodered_deploy_status = {'running': False, 'complete': False, 'error': False, 'cancelled': False}

@app.route('/api/nodered/deploy', methods=['POST'])
@login_required
def nodered_deploy_api():
    if nodered_deploy_status.get('running'):
        return jsonify({'error': 'Deployment already in progress'}), 409
    nodered_deploy_log.clear()
    nodered_deploy_status.update({'running': True, 'complete': False, 'error': False, 'cancelled': False})
    threading.Thread(target=run_nodered_deploy, daemon=True).start()
    return jsonify({'success': True})

@app.route('/api/nodered/deploy/cancel', methods=['POST'])
@login_required
def nodered_deploy_cancel():
    nodered_deploy_status['cancelled'] = True
    return jsonify({'success': True})

@app.route('/api/nodered/deploy/log')
@login_required
def nodered_deploy_log_api():
    idx = request.args.get('index', 0, type=int)
    return jsonify({'entries': nodered_deploy_log[idx:], 'total': len(nodered_deploy_log),
        'running': nodered_deploy_status['running'], 'complete': nodered_deploy_status['complete'],
        'error': nodered_deploy_status['error'], 'cancelled': nodered_deploy_status.get('cancelled', False)})

@app.route('/api/nodered/control', methods=['POST'])
@login_required
def nodered_control():
    action = (request.json or {}).get('action', '')
    nr_dir = os.path.expanduser('~/node-red')
    compose = os.path.join(nr_dir, 'docker-compose.yml')
    if not os.path.exists(compose):
        return jsonify({'error': 'Node-RED not deployed here'}), 400
    if action == 'start':
        subprocess.run(f'docker compose -f "{compose}" up -d 2>&1', shell=True, capture_output=True, timeout=60, cwd=nr_dir)
    elif action == 'stop':
        subprocess.run(f'docker compose -f "{compose}" stop 2>&1', shell=True, capture_output=True, timeout=60, cwd=nr_dir)
    elif action == 'restart':
        subprocess.run(f'docker compose -f "{compose}" restart 2>&1', shell=True, capture_output=True, timeout=60, cwd=nr_dir)
    else:
        return jsonify({'error': 'Invalid action'}), 400
    time.sleep(2)
    r = subprocess.run('docker ps --filter name=nodered --format "{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True)
    running = r.stdout and 'Up' in r.stdout
    return jsonify({'success': True, 'running': running})

@app.route('/api/nodered/logs')
@login_required
def nodered_logs():
    lines = request.args.get('lines', 80, type=int)
    nr_dir = os.path.expanduser('~/node-red')
    compose = os.path.join(nr_dir, 'docker-compose.yml')
    if not os.path.exists(compose):
        return jsonify({'entries': []})
    r = subprocess.run(f'docker compose -f "{compose}" logs --tail={lines} 2>&1', shell=True, capture_output=True, text=True, timeout=15, cwd=nr_dir)
    entries = [l for l in (r.stdout.strip().split('\n') if r.stdout else []) if l.strip()]
    return jsonify({'entries': entries})

@app.route('/api/nodered/uninstall', methods=['POST'])
@login_required
def nodered_uninstall():
    try:
        data = request.get_json(silent=True) or {}
        password = data.get('password', '')
        auth = load_auth()
        if not auth.get('password_hash') or not check_password_hash(auth['password_hash'], password):
            return jsonify({'error': 'Invalid admin password'}), 403
        nr_dir = os.path.expanduser('~/node-red')
        compose = os.path.join(nr_dir, 'docker-compose.yml')
        if os.path.exists(compose):
            subprocess.run(f'docker compose -f "{compose}" down -v 2>&1', shell=True, capture_output=True, timeout=60, cwd=nr_dir)
        if os.path.exists(nr_dir):
            subprocess.run(f'rm -rf "{nr_dir}"', shell=True, capture_output=True, timeout=10)
        nodered_deploy_log.clear()
        nodered_deploy_status.update({'running': False, 'complete': False, 'error': False})
        settings = load_settings()
        if settings.get('fqdn'):
            generate_caddyfile(settings)
            subprocess.run('systemctl reload caddy 2>/dev/null; true', shell=True, capture_output=True, timeout=15)
        return jsonify({'success': True, 'steps': ['Node-RED container and data removed', 'Caddyfile updated']})
    except Exception as e:
        return jsonify({'error': f'Uninstall failed: {str(e)}'}), 500

def _ensure_authentik_nodered_app(fqdn, ak_token, plog=None, flow_pk=None, inv_flow_pk=None):
    """Create Node-RED proxy provider + application in Authentik, add to embedded outpost.
    When flow_pk/inv_flow_pk are provided (e.g. from Step 12), use them. Otherwise wait for flows."""
    if not fqdn or not ak_token:
        return False
    def log(msg):
        if plog:
            plog(msg)
    import urllib.request as _urlreq
    import urllib.error
    _ak_headers = {'Authorization': f'Bearer {ak_token}', 'Content-Type': 'application/json'}
    _ak_url = 'http://127.0.0.1:9090'

    try:
        if not flow_pk or not inv_flow_pk:
            for attempt in range(36):
                try:
                    req = _urlreq.Request(f'{_ak_url}/api/v3/flows/instances/?designation=authorization&ordering=slug', headers=_ak_headers)
                    resp = _urlreq.urlopen(req, timeout=10)
                    flows = json.loads(resp.read().decode())['results']
                    flow_pk = next((f['pk'] for f in flows if 'implicit' in f.get('slug', '')), flows[0]['pk'] if flows else None)
                    if flow_pk:
                        req = _urlreq.Request(f'{_ak_url}/api/v3/flows/instances/?designation=invalidation', headers=_ak_headers)
                        resp = _urlreq.urlopen(req, timeout=10)
                        inv_flows = json.loads(resp.read().decode())['results']
                        inv_flow_pk = next((f['pk'] for f in inv_flows if 'provider' not in f.get('slug', '')), inv_flows[0]['pk'] if inv_flows else None)
                        if inv_flow_pk:
                            break
                except Exception:
                    pass
                if attempt % 6 == 0:
                    log(f"  ⏳ Waiting for authorization flow... ({attempt * 5}s)")
                time.sleep(5)
            if not flow_pk or not inv_flow_pk:
                log("  ⚠ No authorization/invalidation flow — skipping Node-RED proxy provider")
                return False
            log("  ✓ Got authorization and invalidation flows")

        # Create proxy provider (same payload structure as TAK Portal)
        provider_pk = None
        try:
            req = _urlreq.Request(f'{_ak_url}/api/v3/providers/proxy/',
                data=json.dumps({'name': 'Node-RED Proxy', 'authorization_flow': flow_pk,
                    'invalidation_flow': inv_flow_pk,
                    'external_host': f'https://nodered.{fqdn}', 'mode': 'forward_single',
                    'token_validity': 'hours=24'}).encode(),
                headers=_ak_headers, method='POST')
            resp = _urlreq.urlopen(req, timeout=10)
            provider_pk = json.loads(resp.read().decode())['pk']
            log("  ✓ Proxy provider created")
        except Exception as e:
            if hasattr(e, 'code') and e.code == 400:
                req = _urlreq.Request(f'{_ak_url}/api/v3/providers/proxy/?search=Node-RED', headers=_ak_headers)
                resp = _urlreq.urlopen(req, timeout=10)
                results = json.loads(resp.read().decode())['results']
                if results:
                    provider_pk = results[0]['pk']
                    try:
                        req = _urlreq.Request(f'{_ak_url}/api/v3/providers/proxy/{provider_pk}/',
                            data=json.dumps({'external_host': f'https://nodered.{fqdn}'}).encode(),
                            headers=_ak_headers, method='PATCH')
                        _urlreq.urlopen(req, timeout=10)
                    except Exception:
                        pass
                log("  ✓ Proxy provider already exists (external_host updated to nodered subdomain)")
            else:
                log(f"  ⚠ Proxy provider error: {str(e)[:100]}")

        # Create application
        if provider_pk:
            try:
                req = _urlreq.Request(f'{_ak_url}/api/v3/core/applications/',
                    data=json.dumps({'name': 'Node-RED', 'slug': 'node-red',
                        'provider': provider_pk}).encode(),
                    headers=_ak_headers, method='POST')
                _urlreq.urlopen(req, timeout=10)
                log("  ✓ Application 'Node-RED' created")
            except Exception as e:
                if hasattr(e, 'code') and e.code == 400:
                    try:
                        req = _urlreq.Request(f'{_ak_url}/api/v3/core/applications/node-red/',
                            data=json.dumps({'provider': provider_pk}).encode(),
                            headers=_ak_headers, method='PATCH')
                        _urlreq.urlopen(req, timeout=10)
                    except Exception:
                        pass
                    log("  ✓ Application 'Node-RED' updated")
                else:
                    log(f"  ⚠ Application error: {str(e)[:80]}")

            # 5) Add to embedded outpost
            try:
                req = _urlreq.Request(f'{_ak_url}/api/v3/outposts/instances/?search=embedded', headers=_ak_headers)
                resp = _urlreq.urlopen(req, timeout=10)
                outposts = json.loads(resp.read().decode())['results']
                embedded = next((o for o in outposts if 'embed' in o.get('name','').lower() or o.get('type') == 'proxy'), None)
                if embedded:
                    current_providers = embedded.get('providers', [])
                    if provider_pk not in current_providers:
                        current_providers.append(provider_pk)
                    req = _urlreq.Request(f'{_ak_url}/api/v3/outposts/instances/{embedded["pk"]}/',
                        data=json.dumps({'providers': current_providers}).encode(),
                        headers=_ak_headers, method='PATCH')
                    _urlreq.urlopen(req, timeout=10)
                    log("  ✓ Node-RED added to embedded outpost")
                else:
                    log("  ⚠ No embedded outpost found")
            except Exception as e:
                log(f"  ⚠ Outpost error: {str(e)[:80]}")
        else:
            log("  ⚠ Could not create or find Node-RED proxy provider")
    except Exception as e:
        log(f"  ⚠ Forward auth setup error: {str(e)[:100]}")
    return True

def _ensure_authentik_console_app(fqdn, ak_token, plog=None, flow_pk=None, inv_flow_pk=None):
    """Create infra-TAK Console proxy providers (infratak + console) and applications in Authentik, add to embedded outpost.
    When flow_pk/inv_flow_pk are provided (e.g. from Step 12), use them. Otherwise wait for flows (e.g. when called from Caddy save)."""
    if not fqdn or not ak_token:
        return False
    def log(msg):
        if plog:
            plog(msg)
    import urllib.request as _urlreq
    _ak_headers = {'Authorization': f'Bearer {ak_token}', 'Content-Type': 'application/json'}
    _ak_url = 'http://127.0.0.1:9090'

    try:
        if not flow_pk or not inv_flow_pk:
            for attempt in range(36):
                try:
                    req = _urlreq.Request(f'{_ak_url}/api/v3/flows/instances/?designation=authorization&ordering=slug', headers=_ak_headers)
                    resp = _urlreq.urlopen(req, timeout=10)
                    flows = json.loads(resp.read().decode())['results']
                    flow_pk = next((f['pk'] for f in flows if 'implicit' in f.get('slug', '')), flows[0]['pk'] if flows else None)
                    if flow_pk:
                        req = _urlreq.Request(f'{_ak_url}/api/v3/flows/instances/?designation=invalidation', headers=_ak_headers)
                        resp = _urlreq.urlopen(req, timeout=10)
                        inv_flows = json.loads(resp.read().decode())['results']
                        inv_flow_pk = next((f['pk'] for f in inv_flows if 'provider' not in f.get('slug', '')), inv_flows[0]['pk'] if inv_flows else None)
                        if inv_flow_pk:
                            break
                except Exception:
                    pass
                if attempt % 6 == 0 and plog:
                    plog(f"  ⏳ Waiting for authorization flow... ({attempt * 5}s)")
                time.sleep(5)
        if not flow_pk or not inv_flow_pk:
            log("  ⚠ No authorization/invalidation flow — skipping infra-TAK Console proxy providers")
            return False

        entries = [('infra-TAK', 'infratak', f'https://infratak.{fqdn}')]
        try:
            s = load_settings()
            mtx_domain = s.get('mediamtx_domain', f'stream.{fqdn}')
            if '.' not in mtx_domain:
                mtx_domain = f'{mtx_domain}.{fqdn}'
            mtx_installed = (os.path.exists(os.path.expanduser('~/mediamtx-webeditor/mediamtx_config_editor.py')) or
                detect_modules().get('mediamtx', {}).get('installed'))
            if mtx_installed:
                entries.append(('MediaMTX', 'stream', f'https://{mtx_domain}'))
        except Exception:
            pass
        provider_pks = []
        for name, slug, host in entries:
            pk = None
            try:
                req = _urlreq.Request(f'{_ak_url}/api/v3/providers/proxy/',
                    data=json.dumps({'name': name, 'authorization_flow': flow_pk,
                        'invalidation_flow': inv_flow_pk,
                        'external_host': host, 'mode': 'forward_single',
                        'token_validity': 'hours=24'}).encode(),
                    headers=_ak_headers, method='POST')
                resp = _urlreq.urlopen(req, timeout=10)
                pk = json.loads(resp.read().decode())['pk']
                provider_pks.append(pk)
                log(f"  ✓ Proxy provider created: {name}")
            except Exception as e:
                if hasattr(e, 'code') and e.code == 400:
                    req = _urlreq.Request(f'{_ak_url}/api/v3/providers/proxy/?search={slug}', headers=_ak_headers)
                    resp = _urlreq.urlopen(req, timeout=10)
                    results = json.loads(resp.read().decode())['results']
                    if results:
                        pk = results[0]['pk']
                        provider_pks.append(pk)
                    log(f"  ✓ Proxy provider already exists: {name}")
                else:
                    log(f"  ⚠ Provider error {name}: {str(e)[:80]}")
            if pk:
                try:
                    req = _urlreq.Request(f'{_ak_url}/api/v3/core/applications/',
                        data=json.dumps({'name': name, 'slug': slug, 'provider': pk}).encode(),
                        headers=_ak_headers, method='POST')
                    _urlreq.urlopen(req, timeout=10)
                    log(f"  ✓ Application created: {name}")
                except Exception as e:
                    if hasattr(e, 'code') and e.code == 400:
                        log(f"  ✓ Application already exists: {name}")
                    else:
                        log(f"  ⚠ Application error: {str(e)[:80]}")

        if provider_pks:
            try:
                req = _urlreq.Request(f'{_ak_url}/api/v3/outposts/instances/?search=embedded', headers=_ak_headers)
                resp = _urlreq.urlopen(req, timeout=10)
                outposts = json.loads(resp.read().decode())['results']
                embedded = next((o for o in outposts if 'embed' in o.get('name', '').lower() or o.get('type') == 'proxy'), None)
                if embedded:
                    current = list(embedded.get('providers', []))
                    for pk in provider_pks:
                        if pk not in current:
                            current.append(pk)
                    req = _urlreq.Request(f'{_ak_url}/api/v3/outposts/instances/{embedded["pk"]}/',
                        data=json.dumps({'providers': current}).encode(),
                        headers=_ak_headers, method='PATCH')
                    _urlreq.urlopen(req, timeout=10)
                    log("  ✓ infra-TAK Console added to embedded outpost")
            except Exception as e:
                log(f"  ⚠ Outpost error: {str(e)[:80]}")
        return True
    except Exception as e:
        log(f"  ⚠ Console forward auth setup: {str(e)[:100]}")
        return False

def run_nodered_deploy():
    def plog(msg):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        nodered_deploy_log.append(entry)
        print(entry, flush=True)
    try:
        if nodered_deploy_status.get('cancelled'):
            nodered_deploy_status.update({'running': False, 'complete': False, 'cancelled': True})
            return
        settings = load_settings()
        domain = (settings.get('fqdn') or '').strip()
        nr_dir = os.path.expanduser('~/node-red')
        os.makedirs(nr_dir, exist_ok=True)
        plog("━━━ Step 1/3: Creating Docker Compose ━━━")
        compose_yml = os.path.join(nr_dir, 'docker-compose.yml')
        settings_js = os.path.join(nr_dir, 'settings.js')
        # Node-RED at root (/) so Caddy can proxy nodered.domain to 1880
        with open(settings_js, 'w') as f:
            f.write("""module.exports = {
  flowFile: 'flows.json',
  flowFilePretty: true,
  userDir: '/data',
  httpAdminRoot: '/',
  httpNodeRoot: '/'
};
""")
        with open(compose_yml, 'w') as f:
            f.write("""services:
  node-red:
    image: nodered/node-red:latest
    container_name: nodered
    ports:
      - "1880:1880"
    volumes:
      - node_red_data:/data
      - ./settings.js:/data/settings.js
volumes:
  node_red_data:
""")
        plog("✓ docker-compose.yml written")
        plog("")
        plog("━━━ Step 2/3: Starting Node-RED ━━━")
        r = subprocess.run(f'docker compose -f "{compose_yml}" up -d 2>&1', shell=True, capture_output=True, text=True, timeout=120, cwd=nr_dir)
        if r.returncode != 0:
            plog(f"✗ docker compose up failed: {r.stderr or r.stdout or 'unknown'}")
            nodered_deploy_status.update({'running': False, 'error': True})
            return
        plog("✓ Node-RED container started")
        plog("")
        plog("━━━ Step 3/3: Updating Caddy ━━━")
        if domain:
            generate_caddyfile(settings)
            subprocess.run('systemctl reload caddy 2>/dev/null', shell=True, capture_output=True, timeout=15)
            plog(f"✓ Caddy updated — open via https://nodered.{domain}")
        else:
            plog("  No domain configured — access via http://<server>:1880")
        if not nodered_deploy_status.get('cancelled') and domain and os.path.exists(os.path.expanduser('~/authentik/.env')):
            plog("")
            plog("━━━ Configuring Authentik for Node-RED ━━━")
            ak_token = ''
            with open(os.path.expanduser('~/authentik/.env')) as f:
                for line in f:
                    if line.strip().startswith('AUTHENTIK_BOOTSTRAP_TOKEN='):
                        ak_token = line.strip().split('=', 1)[1].strip()
                        break
            _ensure_authentik_nodered_app(domain, ak_token, plog)
            plog("")
            plog("  Waiting 2 minutes for Authentik outpost to sync...")
            for i in range(24):
                if nodered_deploy_status.get('cancelled'):
                    plog("  ⚠ Cancelled by user")
                    break
                time.sleep(5)
                remaining = 120 - (i + 1) * 5
                if remaining > 0 and remaining % 30 == 0:
                    plog(f"  ⏳ {remaining} seconds remaining...")
            if not nodered_deploy_status.get('cancelled'):
                plog("  ✓ Sync complete — Node-RED is ready behind Authentik")
        plog("")
        if nodered_deploy_status.get('cancelled'):
            plog("Deployment cancelled.")
        else:
            plog("✅ Node-RED deployed. Open the flow editor and build your flows.")
        nodered_deploy_status.update({'running': False, 'complete': not nodered_deploy_status.get('cancelled', False), 'error': False})
    except Exception as e:
        plog(f"✗ Error: {str(e)}")
        nodered_deploy_status.update({'running': False, 'error': True})


NODERED_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Node-RED — infra-TAK</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0" rel="stylesheet">
<style>
:root{--bg-deep:#080b14;--bg-surface:#0f1219;--bg-card:#161b26;--border:#1e2736;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-dim:#94a3b8;--accent:#3b82f6;--cyan:#06b6d4;--green:#10b981;--red:#ef4444;--yellow:#eab308}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg-deep);color:var(--text-primary);font-family:'DM Sans',sans-serif;min-height:100vh;display:flex;flex-direction:row}
.sidebar{width:220px;min-width:220px;background:var(--bg-surface);border-right:1px solid var(--border);padding:24px 0;flex-shrink:0}
.material-symbols-outlined{font-family:'Material Symbols Outlined';font-weight:400;font-style:normal;font-size:20px;line-height:1;letter-spacing:normal;white-space:nowrap;direction:ltr;-webkit-font-smoothing:antialiased}
.nav-icon.material-symbols-outlined{font-size:22px;width:22px;text-align:center}
.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}
.sidebar-logo span{font-size:15px;font-weight:700}.sidebar-logo small{display:block;font-size:10px;color:var(--text-dim);font-family:'JetBrains Mono',monospace;margin-top:2px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 20px;color:var(--text-secondary);text-decoration:none;font-size:13px;font-weight:500;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{color:var(--text-primary);background:rgba(255,255,255,.03)}.nav-item.active{color:var(--cyan);background:rgba(6,182,212,.06);border-left-color:var(--cyan)}
.nav-icon{font-size:15px;width:18px;text-align:center}
.main{flex:1;min-width:0;overflow-y:auto;padding:32px}
.page-header{margin-bottom:28px}.page-header h1{font-size:22px;font-weight:700}.page-header p{color:var(--text-secondary);font-size:13px;margin-top:4px}
.card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:20px}
.card-title{font-size:13px;font-weight:600;color:var(--text-dim);text-transform:uppercase;letter-spacing:.08em;margin-bottom:16px}
.status-banner{display:flex;align-items:center;gap:12px;padding:14px 18px;border-radius:10px;margin-bottom:20px;font-size:13px}
.status-banner.running{background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.2);color:var(--green)}
.status-banner.stopped{background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.2);color:var(--yellow)}
.status-banner.not-installed{background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.2);color:var(--accent)}
.dot{width:8px;height:8px;border-radius:50%;background:currentColor}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.info-item{background:#0a0e1a;border-radius:8px;padding:12px 14px}
.info-label{font-size:11px;color:var(--text-dim);margin-bottom:3px;text-transform:uppercase}
.info-value{font-size:13px;font-family:'JetBrains Mono',monospace;word-break:break-all}
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;border:none}
.btn-primary{background:var(--accent);color:#fff}.btn-success{background:var(--green);color:#fff}.btn-ghost{background:rgba(255,255,255,.05);color:var(--text-secondary);border:1px solid var(--border)}
.btn-danger{background:var(--red);color:#fff}
.controls{display:flex;gap:10px;flex-wrap:wrap}
.log-box{background:#070a12;border:1px solid var(--border);border-radius:8px;padding:16px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);max-height:340px;overflow-y:auto;white-space:pre-wrap}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;display:none;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg-card);border:1px solid var(--border);border-radius:14px;padding:28px;width:400px;max-width:90vw}
.modal h3{font-size:16px;margin-bottom:8px;color:var(--red)}
.modal p{font-size:13px;color:var(--text-secondary);margin-bottom:20px}
.modal-actions{display:flex;gap:10px;justify-content:flex-end}
.form-label{display:block;font-size:12px;font-weight:600;color:var(--text-secondary);margin-bottom:6px}
.form-input{width:100%;background:#0a0e1a;border:1px solid var(--border);border-radius:8px;padding:10px 14px;color:var(--text-primary);font-size:13px}
</style></head>
<body>
{{ sidebar_html }}
<div class="main">
  <div class="page-header"><h1 style="display:flex;flex-direction:column;align-items:flex-start;gap:6px"><img src="{{ nodered_logo_url }}" alt="" style="height:32px;width:auto;object-fit:contain"><span>Node-RED</span></h1><p>Flow-based automation and integrations</p></div>
  {% if nr.running %}<div class="status-banner running"><div class="dot"></div>Node-RED is running</div>
  {% elif nr.installed %}<div class="status-banner stopped"><div class="dot"></div>Node-RED is installed but stopped</div>
  {% else %}<div class="status-banner not-installed"><div class="dot"></div>Node-RED is not installed</div>{% endif %}
  {% if nr.installed %}
  {% if authentik_installed and settings.fqdn %}<div class="card" style="border-color:rgba(59,130,246,.3);background:rgba(59,130,246,.05)"><div class="card-title">&#128274; Protected by Authentik</div><p style="font-size:13px;color:var(--text-secondary);line-height:1.5">Node-RED is behind Authentik. The application and proxy provider are created automatically when you deploy Authentik or Node-RED.</p></div>{% endif %}
  <div class="card"><div class="card-title">Access</div><div class="info-grid">
    {% if settings.fqdn %}<div class="info-item"><div class="info-label">Flow editor</div><div class="info-value"><a href="https://nodered.{{ settings.fqdn }}" target="_blank" rel="noopener noreferrer" style="color:var(--cyan);text-decoration:none">https://nodered.{{ settings.fqdn }}</a> &#8599;</div></div>
    {% else %}<div class="info-item"><div class="info-label">Flow editor</div><div class="info-value"><a href="http://{{ settings.server_ip }}:1880" target="_blank" rel="noopener noreferrer" style="color:var(--cyan);text-decoration:none">http://{{ settings.server_ip }}:1880</a> &#8599;</div></div>{% endif %}
    <div class="info-item"><div class="info-label">Install dir</div><div class="info-value">~/node-red</div></div>
  </div></div>
  <div class="card"><div class="card-title">Controls</div><div class="controls">
    <button class="btn {% if nr.running %}btn-ghost{% else %}btn-success{% endif %}" onclick="control('start')">&#x25b6; Start</button>
    <button class="btn {% if nr.running %}btn-danger{% else %}btn-ghost{% endif %}" onclick="control('stop')">&#x23f9; Stop</button>
    <button class="btn btn-ghost" onclick="control('restart')">&#x27fa; Restart</button>
    <button class="btn btn-ghost" onclick="loadLogs()">&#x1f4cb; Logs</button>
    <button class="btn btn-danger" onclick="document.getElementById('uninstall-modal').classList.add('open')">&#x1f5d1; Uninstall</button>
  </div><div id="control-status" style="margin-top:12px;font-size:12px;color:var(--text-dim)"></div></div>
  <div class="card" id="logs-card" style="display:none"><div class="card-title">Container logs</div><div class="log-box" id="container-logs">Loading...</div></div>
  {% else %}
  <div class="card"><div class="card-title">Deploy Node-RED</div>
  <p style="font-size:13px;color:var(--text-secondary);margin-bottom:20px">Runs Node-RED in Docker with a persistent volume. With a domain set, the flow editor is at <code style="color:var(--cyan)">https://nodered.{{ settings.fqdn if settings.fqdn else '&lt;your-domain&gt;' }}</code> (behind Authentik when enabled).</p>
  {% if settings.fqdn %}<p style="font-size:12px;color:var(--text-dim);margin-bottom:16px">Open <a href="https://nodered.{{ settings.fqdn }}" target="_blank" rel="noopener noreferrer" style="color:var(--cyan)">nodered.{{ settings.fqdn }}</a> to use the flow editor. If you upgraded from console.*/nodered/ and the link does not load, redeploy Node-RED once from this page.</p>{% endif %}
  <button class="btn btn-primary" id="deploy-btn" onclick="startDeploy()">&#x1f680; Deploy Node-RED</button></div>
  {% endif %}
  {% if deploying %}<div class="card" id="deploy-log-card"><div class="card-title" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">Deploy log<button class="btn btn-ghost" id="nodered-cancel-btn-static" onclick="cancelNoderedDeploy()" style="display:none">&#x2717; Cancel</button></div><div class="log-box" id="deploy-log">Initializing...</div></div>{% endif %}
  <div class="card" id="log-card" style="display:none"><div class="card-title" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">Deploy log<button class="btn btn-ghost" id="nodered-cancel-btn-dyn" onclick="cancelNoderedDeploy()" style="display:none">&#x2717; Cancel</button></div><div class="log-box" id="deploy-log-dyn">Waiting...</div></div>
</div>
<div class="modal-overlay" id="uninstall-modal"><div class="modal">
  <h3>&#x26a0; Uninstall Node-RED?</h3><p>This will stop and remove the container and data volume. Flows will be deleted.</p>
  <div style="margin-bottom:16px"><label class="form-label">Admin password</label><input class="form-input" id="uninstall-password" type="password" placeholder="Confirm password"></div>
  <div class="modal-actions"><button class="btn btn-ghost" onclick="document.getElementById('uninstall-modal').classList.remove('open')">Cancel</button><button class="btn btn-danger" onclick="doUninstall()">Uninstall</button></div>
  <div id="uninstall-msg" style="margin-top:10px;font-size:12px;color:var(--red)"></div>
</div></div>
<script>
var logIndex=0,logInterval=null;
function startDeploy(){var btn=document.getElementById('deploy-btn');btn.disabled=true;document.getElementById('log-card').style.display='block';document.getElementById('deploy-log-dyn').textContent='Starting...';logIndex=0;
fetch('/api/nodered/deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({}),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){
if(d.error){document.getElementById('deploy-log-dyn').textContent='Error: '+d.error;btn.disabled=false;return;}pollLog();});}
function pollLog(){function pickLogEl(){var lc=document.getElementById('log-card');return (lc&&lc.style.display!=='none'?document.getElementById('deploy-log-dyn'):null)||document.getElementById('deploy-log')||document.getElementById('deploy-log-dyn');}
var logEl=pickLogEl();function showCancel(show){var s=document.getElementById('nodered-cancel-btn-static'),d=document.getElementById('nodered-cancel-btn-dyn');if(s)s.style.display=show?'inline-block':'none';if(d)d.style.display=show?'inline-block':'none';}
function doPoll(){logEl=pickLogEl();fetch('/api/nodered/deploy/log?index='+logIndex,{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){
if(d.entries&&d.entries.length){if(logIndex===0&&logEl)logEl.textContent='';if(logEl){logEl.textContent+=d.entries.join(String.fromCharCode(10))+String.fromCharCode(10);logEl.scrollTop=logEl.scrollHeight;}logIndex+=d.entries.length;}
showCancel(d.running);
if(!d.running){clearInterval(logInterval);var btn=document.getElementById('deploy-btn');if(btn)btn.disabled=false;
if(d.cancelled){if(logEl)logEl.textContent+=String.fromCharCode(10,10)+'Cancelled.';}
else if(d.complete){if(logEl)logEl.textContent+=String.fromCharCode(10,10)+'Deploy complete - page will reload in 15s (or refresh now).';setTimeout(function(){location.reload();},15000);}}});}doPoll();logInterval=setInterval(doPoll,800);}
function cancelNoderedDeploy(){if(!confirm('Cancel the deployment? You can deploy again after.'))return;fetch('/api/nodered/deploy/cancel',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin'}).then(function(){/* next poll will show cancelled */});}
if(document.getElementById('deploy-log-card')){logIndex=0;pollLog();}
function control(action){document.getElementById('control-status').textContent=action+'...';
fetch('/api/nodered/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:action}),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){document.getElementById('control-status').textContent=d.running?'Running':'Stopped';setTimeout(function(){window.location.href=window.location.pathname+'?t='+Date.now();},1500);});}
function loadLogs(){document.getElementById('logs-card').style.display='block';fetch('/api/nodered/logs?lines=80').then(function(r){return r.json();}).then(function(d){document.getElementById('container-logs').textContent=(d.entries||[]).join(String.fromCharCode(10))||'(no output)';});}
function doUninstall(){var pw=document.getElementById('uninstall-password').value,msg=document.getElementById('uninstall-msg');msg.textContent='';fetch('/api/nodered/uninstall',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw}),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){if(d.error){msg.textContent=d.error;return;}msg.textContent='Done. Reloading...';setTimeout(function(){location.reload();},800);}).catch(function(e){msg.textContent=e.message||'Request failed';});}
</script>
</body></html>
'''


MEDIAMTX_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MediaMTX — infra-TAK</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0" rel="stylesheet">
<style>
:root{--bg-deep:#080b14;--bg-surface:#0f1219;--bg-card:#161b26;--border:#1e2736;--border-hover:#2a3548;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-dim:#94a3b8;--accent:#3b82f6;--cyan:#06b6d4;--green:#10b981;--red:#ef4444;--yellow:#eab308}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg-deep);color:var(--text-primary);font-family:'DM Sans',sans-serif;min-height:100vh;display:flex;flex-direction:row}
.sidebar{width:220px;min-width:220px;background:var(--bg-surface);border-right:1px solid var(--border);padding:24px 0;display:flex;flex-direction:column;flex-shrink:0}
.material-symbols-outlined{font-family:'Material Symbols Outlined';font-weight:400;font-style:normal;font-size:20px;line-height:1;letter-spacing:normal;white-space:nowrap;direction:ltr;-webkit-font-smoothing:antialiased}
.nav-icon.material-symbols-outlined{font-size:22px;width:22px;text-align:center}
.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}
.sidebar-logo span{font-size:15px;font-weight:700;letter-spacing:.05em;color:var(--text-primary)}
.sidebar-logo small{display:block;font-size:10px;color:var(--text-dim);font-family:'JetBrains Mono',monospace;margin-top:2px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 20px;color:var(--text-secondary);text-decoration:none;font-size:13px;font-weight:500;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{color:var(--text-primary);background:rgba(255,255,255,.03);border-left-color:var(--border-hover)}
.nav-item.active{color:var(--cyan);background:rgba(6,182,212,.06);border-left-color:var(--cyan)}
.nav-icon{font-size:15px;width:18px;text-align:center}
.main{flex:1;min-width:0;overflow-y:auto;padding:32px}
.page-header{margin-bottom:28px}
.page-header h1{font-size:22px;font-weight:700}
.page-header p{color:var(--text-secondary);font-size:13px;margin-top:4px}
.card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:20px}
.card-title{font-size:13px;font-weight:600;color:var(--text-dim);text-transform:uppercase;letter-spacing:.08em;margin-bottom:16px}
.status-banner{display:flex;align-items:center;gap:12px;padding:14px 18px;border-radius:10px;margin-bottom:20px;font-size:13px;font-weight:500}
.status-banner.running{background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.2);color:var(--green)}
.status-banner.stopped{background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.2);color:var(--yellow)}
.status-banner.not-installed{background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.2);color:var(--accent)}
.dot{width:8px;height:8px;border-radius:50%;background:currentColor;flex-shrink:0}
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;border:none;transition:all .15s}
.btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:#2563eb}
.btn-ghost{background:rgba(255,255,255,.05);color:var(--text-secondary);border:1px solid var(--border)}.btn-ghost:hover{color:var(--text-primary);border-color:var(--border-hover)}
.btn-danger{background:var(--red);color:#fff}.btn-danger:hover{background:#dc2626}
.btn:disabled{opacity:.5;cursor:not-allowed}
.controls{display:flex;gap:10px;flex-wrap:wrap}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.info-item{background:#0a0e1a;border-radius:8px;padding:12px 14px}
.info-label{font-size:11px;color:var(--text-dim);margin-bottom:3px;text-transform:uppercase;letter-spacing:.05em}
.info-value{font-size:13px;color:var(--text-primary);font-family:'JetBrains Mono',monospace;word-break:break-all}
.log-box{background:#070a12;border:1px solid var(--border);border-radius:8px;padding:16px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);max-height:360px;overflow-y:auto;line-height:1.7;white-space:pre-wrap}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;display:none;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg-card);border:1px solid var(--border);border-radius:14px;padding:28px;width:400px;max-width:90vw}
.modal h3{font-size:16px;font-weight:700;margin-bottom:8px;color:var(--red)}
.modal p{font-size:13px;color:var(--text-secondary);margin-bottom:20px}
.modal-actions{display:flex;gap:10px;justify-content:flex-end}
.form-group{margin-bottom:0}
.form-label{display:block;font-size:12px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em}
.form-input{width:100%;background:#0a0e1a;border:1px solid var(--border);border-radius:8px;padding:10px 14px;color:var(--text-primary);font-size:13px;font-family:'DM Sans',sans-serif;outline:none;transition:border-color .15s}
.form-input:focus{border-color:var(--accent)}
.proto-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:4px}
.proto-item{background:#0a0e1a;border-radius:8px;padding:10px 12px;text-align:center}
.proto-name{font-size:11px;font-weight:700;color:var(--cyan);margin-bottom:2px}
.proto-port{font-size:11px;color:var(--text-dim);font-family:'JetBrains Mono',monospace}
.uninstall-spinner{display:inline-block;width:18px;height:18px;border:2px solid var(--border);border-top-color:var(--cyan);border-radius:50%;animation:uninstall-spin .7s linear infinite;vertical-align:middle;margin-right:8px}
@keyframes uninstall-spin{to{transform:rotate(360deg)}}
.uninstall-progress-row{display:flex;align-items:center;gap:8px;margin-top:10px;font-size:13px;color:var(--text-secondary)}
</style></head>
<body>
{{ sidebar_html }}
<div class="main">
  <div class="page-header">
    <h1><img src="{{ mediamtx_logo_url }}" alt="MediaMTX" style="height:28px;vertical-align:middle"></h1>
    <p>Video Streaming Server</p>
  </div>

  {% if mtx.running %}
  <div class="status-banner running"><div class="dot"></div>MediaMTX is running</div>
  {% elif mtx.installed %}
  <div class="status-banner stopped"><div class="dot"></div>MediaMTX is installed but stopped</div>
  {% else %}
  <div class="status-banner not-installed"><div class="dot"></div>MediaMTX is not installed</div>
  {% endif %}

  {% if mtx.installed %}

  <!-- Access info -->
  <div class="card">
    <div class="card-title">Access</div>
    <div class="info-grid">
      {% if settings.fqdn %}
      <div class="info-item"><div class="info-label">Web Console</div><div class="info-value"><a href="https://stream.{{ settings.fqdn }}" target="_blank" rel="noopener noreferrer" style="color:var(--cyan);text-decoration:none">https://stream.{{ settings.fqdn }}</a> <span style="color:var(--text-dim);font-size:11px">↗</span></div></div>
      {% else %}
      <div class="info-item"><div class="info-label">Web Console</div><div class="info-value"><a href="http://{{ settings.server_ip }}:5080" target="_blank" rel="noopener noreferrer" style="color:var(--cyan);text-decoration:none">http://{{ settings.server_ip }}:5080</a> <span style="color:var(--text-dim);font-size:11px">↗</span></div></div>
      {% endif %}
    </div>
  </div>

  <!-- Controls -->
  <div class="card">
    <div class="card-title">Controls</div>
    <div class="controls">
      <button class="btn btn-ghost" onclick="control('start')">▶ Start</button>
      <button class="btn btn-ghost" onclick="control('stop')">⏹ Stop</button>
      <button class="btn btn-ghost" onclick="control('restart')">↺ Restart</button>
      <button class="btn btn-ghost" onclick="loadLogs()">📋 Logs</button>
      <button class="btn btn-danger" onclick="document.getElementById('uninstall-modal').classList.add('open')">🗑 Uninstall</button>
    </div>
    <div id="control-status" style="margin-top:12px;font-size:12px;color:var(--text-dim)"></div>
  </div>

  <!-- Container logs -->
  <div class="card" id="logs-card" style="display:none">
    <div class="card-title">Service Logs</div>
    <div class="log-box" id="service-logs">Loading...</div>
  </div>

  {% else %}
  <!-- Deploy -->
  <div class="card">
    <div class="card-title">Deploy MediaMTX</div>
    <p style="font-size:13px;color:var(--text-secondary);margin-bottom:20px">
      Installs MediaMTX streaming server with FFmpeg for drone video (MPEG-TS to RTSP to HLS),
      the web configuration editor, and wires SSL certificates from Caddy automatically.
    </p>
    {% if settings.fqdn %}
    <div style="background:rgba(16,185,129,.06);border:1px solid rgba(16,185,129,.15);border-radius:8px;padding:12px 16px;margin-bottom:20px;font-size:12px;color:var(--text-secondary)">
      Caddy domain detected — <span style="color:var(--green)">SSL will be configured automatically</span><br>
      Web editor will be available at <span style="font-family:'JetBrains Mono',monospace;color:var(--cyan)">https://stream.{{ settings.fqdn }}</span>
    </div>
    {% endif %}
    <button class="btn btn-primary" id="deploy-btn" onclick="startDeploy()">🚀 Deploy MediaMTX</button>
  </div>
  {% endif %}

  <!-- Deploy log -->
  <div class="card" id="log-card" style="display:{% if deploying or deploy_done %}block{% else %}none{% endif %}">
    <div class="card-title">Deploy Log</div>
    <div class="log-box" id="deploy-log">{% if deploying %}Starting...{% elif deploy_done %}Deploy complete.{% endif %}</div>
  </div>
</div>

<!-- Uninstall modal -->
<div class="modal-overlay" id="uninstall-modal">
  <div class="modal">
    <h3>⚠ Uninstall MediaMTX?</h3>
    <p>This will stop and remove MediaMTX, the web editor, all systemd services, and the binary. Config and recordings will be removed.</p>
    <div class="form-group" style="margin-bottom:16px">
      <label class="form-label">Admin Password</label>
      <input class="form-input" id="uninstall-password" type="password" placeholder="Confirm your password">
    </div>
    <div class="modal-actions">
      <button class="btn btn-ghost" id="uninstall-cancel-btn" onclick="document.getElementById('uninstall-modal').classList.remove('open')">Cancel</button>
      <button class="btn btn-danger" id="uninstall-confirm-btn" onclick="doUninstall()">Uninstall</button>
    </div>
    <div id="uninstall-msg" style="margin-top:10px;font-size:12px;color:var(--red)"></div>
    <div id="uninstall-progress" class="uninstall-progress-row" style="display:none" aria-live="polite"></div>
  </div>
</div>

<script>
let logIndex = 0;
let logInterval = null;

function startDeploy() {
  document.getElementById('deploy-btn').disabled = true;
  document.getElementById('log-card').style.display = 'block';
  document.getElementById('deploy-log').textContent = 'Starting deployment...';
  logIndex = 0;
  fetch('/api/mediamtx/deploy', {method:'POST', headers:{'Content-Type':'application/json'}})
    .then(r => r.json()).then(d => {
      if (d.error) {
        document.getElementById('deploy-log').textContent = 'Error: ' + d.error;
        document.getElementById('deploy-btn').disabled = false;
      } else {
        pollLog();
      }
    });
}

function pollLog() {
  logInterval = setInterval(() => {
    fetch('/api/mediamtx/deploy/log?index=' + logIndex)
      .then(r => r.json()).then(d => {
        if (d.entries && d.entries.length) {
          const box = document.getElementById('deploy-log');
          if (logIndex === 0) box.textContent = '';
          box.textContent += d.entries.join(String.fromCharCode(10)) + String.fromCharCode(10);
          box.scrollTop = box.scrollHeight;
          logIndex += d.entries.length;
        }
        if (!d.running) {
          clearInterval(logInterval);
          if (d.complete) setTimeout(() => location.reload(), 1500);
        }
      });
  }, 800);
}

function control(action) {
  document.getElementById('control-status').textContent = action + '...';
  fetch('/api/mediamtx/control', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action})
  }).then(r => r.json()).then(d => {
    document.getElementById('control-status').textContent = d.running ? '✓ Running' : '○ Stopped';
    setTimeout(() => document.getElementById('control-status').textContent = '', 3000);
  });
}

function loadLogs() {
  const card = document.getElementById('logs-card');
  card.style.display = 'block';
  fetch('/api/mediamtx/logs?lines=80').then(r => r.json()).then(d => {
    document.getElementById('service-logs').textContent = d.entries.join(String.fromCharCode(10)) || '(no output)';
  });
}

function doUninstall() {
  const password = document.getElementById('uninstall-password').value;
  const msgEl = document.getElementById('uninstall-msg');
  const progressEl = document.getElementById('uninstall-progress');
  const cancelBtn = document.getElementById('uninstall-cancel-btn');
  const confirmBtn = document.getElementById('uninstall-confirm-btn');
  msgEl.textContent = '';
  progressEl.style.display = 'flex';
  progressEl.innerHTML = '<span class="uninstall-spinner"></span><span>Uninstalling…</span>';
  confirmBtn.disabled = true;
  cancelBtn.disabled = true;
  fetch('/api/mediamtx/uninstall', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({password})
  }).then(r => r.json()).then(d => {
    if (d.error) {
      msgEl.textContent = d.error;
      progressEl.style.display = 'none';
      progressEl.innerHTML = '';
      confirmBtn.disabled = false;
      cancelBtn.disabled = false;
      return;
    }
    progressEl.innerHTML = '<span class="uninstall-spinner"></span><span>Done. Reloading…</span>';
    setTimeout(() => location.reload(), 800);
  }).catch(err => {
    msgEl.textContent = 'Request failed: ' + (err.message || 'network error');
    progressEl.style.display = 'none';
    progressEl.innerHTML = '';
    confirmBtn.disabled = false;
    cancelBtn.disabled = false;
  });
}

{% if deploying %}
document.addEventListener('DOMContentLoaded', () => { logIndex = 0; pollLog(); });
{% endif %}
</script>
</body></html>'''

CLOUDTAK_PAGE_JS = r'''window.logIndex = 0;
window.logInterval = null;

window.startRedeploy = function() {
  var btn = document.getElementById("redeploy-btn");
  var logCard = document.getElementById("log-card");
  var dyn = document.getElementById("deploy-log-dyn");
  var stat = document.getElementById("deploy-log");
  function showErr(s) {
    if (dyn) dyn.textContent = s;
    if (stat) stat.textContent = s;
    if (btn) btn.disabled = false;
    alert(s);
  }
  if (btn) btn.disabled = true;
  if (logCard) { logCard.style.display = "block"; logCard.scrollIntoView({ behavior: "smooth", block: "nearest" }); }
  var initMsg = "Updating config and restarting...";
  if (dyn) dyn.textContent = initMsg;
  if (stat) stat.textContent = initMsg;
  var condLog = document.getElementById("deploy-log");
  if (condLog && condLog.closest(".card")) condLog.closest(".card").style.display = "none";
  window.logIndex = 0;
  fetch("/api/cloudtak/redeploy", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({}),
    credentials: "same-origin"
  }).then(function(r) {
    if (!r.ok) {
      return r.text().then(function(t) { throw new Error(r.status + ": " + (t || r.statusText).slice(0, 200)); });
    }
    return r.json();
  }).then(function(d) {
    if (d && d.error) {
      showErr("Error: " + d.error);
    } else {
      window.pollLog(btn);
    }
  }).catch(function(e) {
    showErr("Failed: " + (e && e.message ? e.message : String(e)));
  });
};

window.startDeploy = function() {
  document.getElementById("deploy-btn").disabled = true;
  document.getElementById("log-card").style.display = "block";
  document.getElementById("deploy-log-dyn").textContent = "Starting deployment...";
  window.logIndex = 0;
  fetch("/api/cloudtak/deploy", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({})
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.error) {
      document.getElementById("deploy-log-dyn").textContent = "Error: " + d.error;
      document.getElementById("deploy-btn").disabled = false;
    } else {
      window.pollLog(null);
    }
  });
};

window.pollLog = function(redeployBtn) {
  if (window.logInterval) clearInterval(window.logInterval);
  function doPoll() {
    fetch("/api/cloudtak/deploy/log?index=" + window.logIndex, { credentials: "same-origin" })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (!d) return;
        if (d.entries && d.entries.length) {
          var text = d.entries.join("\n") + "\n";
          var dyn = document.getElementById("deploy-log-dyn");
          var stat = document.getElementById("deploy-log");
          if (window.logIndex === 0) {
            if (dyn) dyn.textContent = text;
            if (stat) stat.textContent = text;
          } else {
            if (dyn) dyn.textContent += text;
            if (stat) stat.textContent += text;
          }
          if (dyn) dyn.scrollTop = dyn.scrollHeight;
          if (stat) stat.scrollTop = stat.scrollHeight;
          window.logIndex += d.entries.length;
        }
        if (!d.running) {
          clearInterval(window.logInterval);
          window.logInterval = null;
          if (redeployBtn) redeployBtn.disabled = false;
          if (d.error && dyn) dyn.textContent = (dyn.textContent || "") + "\nError (see log above)";
          if (d.complete) setTimeout(function() { location.reload(); }, 1500);
        }
      })
      .catch(function(err) {
        clearInterval(window.logInterval);
        window.logInterval = null;
        if (redeployBtn) redeployBtn.disabled = false;
        var dyn = document.getElementById("deploy-log-dyn");
        if (dyn) dyn.textContent = (dyn.textContent || "") + "\nRequest failed: " + (err && err.message ? err.message : String(err));
      });
  }
  doPoll();
  window.logInterval = setInterval(doPoll, 800);
};

window.control = function(action) {
  document.getElementById("control-status").textContent = action + "...";
  fetch("/api/cloudtak/control", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({action: action})
  }).then(function(r) { return r.json(); }).then(function(d) {
    document.getElementById("control-status").textContent = d.running ? "Running" : "Stopped";
    setTimeout(function() { document.getElementById("control-status").textContent = ""; }, 3000);
  });
};

var activeContainer = "";
function filterLogs(containerName) {
  activeContainer = containerName || "";
  document.querySelectorAll(".svc-card").forEach(function(c) { c.style.borderColor = ""; c.style.boxShadow = ""; });
  var id = containerName ? "svc-" + containerName : "svc-all";
  var card = document.getElementById(id);
  if (card) { card.style.borderColor = "var(--cyan)"; card.style.boxShadow = "0 0 0 1px var(--cyan)"; }
  var label = document.getElementById("log-filter-label");
  if (label) label.textContent = containerName ? "\u2014 " + containerName : "";
  loadContainerLogs();
}
function loadContainerLogs() {
  var el = document.getElementById("container-logs");
  if (!el) return;
  var url = activeContainer ? "/api/cloudtak/logs?lines=80&container=" + encodeURIComponent(activeContainer) : "/api/cloudtak/logs?lines=80";
  fetch(url).then(function(r) { return r.json(); }).then(function(d) {
    el.textContent = (d.entries && d.entries.length) ? d.entries.join("\\n") : "(no log output)";
    el.scrollTop = el.scrollHeight;
  }).catch(function() { if (el) el.textContent = "Failed to load logs"; });
}
if (document.getElementById("container-logs")) { filterLogs(""); setInterval(loadContainerLogs, 8000); }

window.doUninstall = function() {
  var password = document.getElementById("uninstall-password").value;
  var msgEl = document.getElementById("uninstall-msg");
  var progressEl = document.getElementById("uninstall-progress");
  var cancelBtn = document.getElementById("uninstall-cancel-btn");
  var confirmBtn = document.getElementById("uninstall-confirm-btn");
  msgEl.textContent = "";
  progressEl.innerHTML = "<span class=\"uninstall-spinner\"></span><span>Uninstalling...</span>";
  confirmBtn.disabled = true;
  cancelBtn.disabled = true;
  fetch("/api/cloudtak/uninstall", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({password: password})
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.error) {
      msgEl.textContent = d.error;
      progressEl.innerHTML = "";
      confirmBtn.disabled = false;
      cancelBtn.disabled = false;
      return;
    }
    progressEl.innerHTML = "<span class=\"uninstall-spinner\"></span><span>Stopping containers and removing data...</span>";
    var poll = setInterval(function() {
      fetch("/api/cloudtak/uninstall/status").then(function(r) { return r.json(); }).then(function(s) {
        if (!s.running) {
          clearInterval(poll);
          if (s.error) {
            msgEl.textContent = s.error;
            progressEl.innerHTML = "";
            confirmBtn.disabled = false;
            cancelBtn.disabled = false;
          } else {
            progressEl.innerHTML = "<span class=\"uninstall-spinner\"></span><span>Done. Reloading...</span>";
            setTimeout(function() { location.reload(); }, 800);
          }
        } else {
          progressEl.innerHTML = "<span class=\"uninstall-spinner\"></span><span>Uninstalling... (this may take 1-2 minutes)</span>";
        }
      }).catch(function() { clearInterval(poll); progressEl.innerHTML = ""; confirmBtn.disabled = false; cancelBtn.disabled = false; });
    }, 1000);
  }).catch(function(err) {
    msgEl.textContent = "Request failed: " + (err.message || "network error");
    progressEl.innerHTML = "";
    confirmBtn.disabled = false;
    cancelBtn.disabled = false;
  });
};
'''

CLOUDTAK_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CloudTAK — infra-TAK</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0" rel="stylesheet">
<style>
:root{--bg-deep:#080b14;--bg-surface:#0f1219;--bg-card:#161b26;--border:#1e2736;--border-hover:#2a3548;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-dim:#94a3b8;--accent:#3b82f6;--cyan:#06b6d4;--green:#10b981;--red:#ef4444;--yellow:#eab308}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg-deep);color:var(--text-primary);font-family:'DM Sans',sans-serif;min-height:100vh;display:flex;flex-direction:row}
.sidebar{width:220px;min-width:220px;background:var(--bg-surface);border-right:1px solid var(--border);padding:24px 0;display:flex;flex-direction:column;flex-shrink:0}
.material-symbols-outlined{font-family:'Material Symbols Outlined';font-weight:400;font-style:normal;font-size:20px;line-height:1;letter-spacing:normal;white-space:nowrap;direction:ltr;-webkit-font-smoothing:antialiased}
.nav-icon.material-symbols-outlined{font-size:22px;width:22px;text-align:center}
.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}
.sidebar-logo span{font-size:15px;font-weight:700;letter-spacing:.05em;color:var(--text-primary)}
.sidebar-logo small{display:block;font-size:10px;color:var(--text-dim);font-family:'JetBrains Mono',monospace;margin-top:2px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 20px;color:var(--text-secondary);text-decoration:none;font-size:13px;font-weight:500;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{color:var(--text-primary);background:rgba(255,255,255,.03);border-left-color:var(--border-hover)}
.nav-item.active{color:var(--cyan);background:rgba(6,182,212,.06);border-left-color:var(--cyan)}
.nav-icon{font-size:15px;width:18px;text-align:center}
.main{flex:1;min-width:0;overflow-y:auto;padding:32px}
.page-header{margin-bottom:28px}
.page-header h1{font-size:22px;font-weight:700;color:var(--text-primary)}
.page-header p{color:var(--text-secondary);font-size:13px;margin-top:4px}
.card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:20px}
.card-title{font-size:13px;font-weight:600;color:var(--text-dim);text-transform:uppercase;letter-spacing:.08em;margin-bottom:16px}
.status-banner{display:flex;align-items:center;gap:12px;padding:14px 18px;border-radius:10px;margin-bottom:20px;font-size:13px;font-weight:500}
.status-banner.running{background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.2);color:var(--green)}
.status-banner.stopped{background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.2);color:var(--yellow)}
.status-banner.not-installed{background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.2);color:var(--accent)}
.dot{width:8px;height:8px;border-radius:50%;background:currentColor;flex-shrink:0}
.form-group{margin-bottom:16px}
.form-label{display:block;font-size:12px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em}
.form-input{width:100%;background:#0a0e1a;border:1px solid var(--border);border-radius:8px;padding:10px 14px;color:var(--text-primary);font-size:13px;font-family:'DM Sans',sans-serif;transition:border-color .15s;outline:none}
.form-input:focus{border-color:var(--accent)}
.form-hint{font-size:11px;color:var(--text-dim);margin-top:4px}
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;border:none;transition:all .15s}
.btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:#2563eb}
.btn-success{background:var(--green);color:#fff}.btn-success:hover{background:#059669}
.btn-danger{background:var(--red);color:#fff}.btn-danger:hover{background:#dc2626}
.btn-ghost{background:rgba(255,255,255,.05);color:var(--text-secondary);border:1px solid var(--border)}.btn-ghost:hover{color:var(--text-primary);border-color:var(--border-hover)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.info-item{background:#0a0e1a;border-radius:8px;padding:12px 14px}
.info-label{font-size:11px;color:var(--text-dim);margin-bottom:3px;text-transform:uppercase;letter-spacing:.05em}
.info-value{font-size:13px;color:var(--text-primary);font-family:'JetBrains Mono',monospace;word-break:break-all}
.log-box{background:#070a12;border:1px solid var(--border);border-radius:8px;padding:16px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);max-height:340px;overflow-y:auto;line-height:1.7;white-space:pre-wrap}
.controls{display:flex;gap:10px;flex-wrap:wrap}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;display:none;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg-card);border:1px solid var(--border);border-radius:14px;padding:28px;width:400px;max-width:90vw}
.modal h3{font-size:16px;font-weight:700;margin-bottom:8px;color:var(--red)}
.modal p{font-size:13px;color:var(--text-secondary);margin-bottom:20px}
.modal-actions{display:flex;gap:10px;justify-content:flex-end}
.tab-bar{display:flex;gap:4px;margin-bottom:20px;background:var(--bg-surface);padding:4px;border-radius:10px;width:fit-content}
.tab{padding:7px 16px;border-radius:7px;font-size:12px;font-weight:600;cursor:pointer;color:var(--text-dim);transition:all .15s}
.tab.active{background:var(--bg-card);color:var(--text-primary)}
.tab-panel{display:none}.tab-panel.active{display:block}
.uninstall-spinner{display:inline-block;width:18px;height:18px;border:2px solid var(--border);border-top-color:var(--cyan);border-radius:50%;animation:uninstall-spin .7s linear infinite;vertical-align:middle;margin-right:8px}
@keyframes uninstall-spin{to{transform:rotate(360deg)}}
.uninstall-progress-row{display:flex;align-items:center;gap:8px;margin-top:10px;font-size:13px;color:var(--text-secondary)}
.svc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-top:8px}
.svc-card{background:var(--bg-surface);border:1px solid var(--border);border-radius:8px;padding:12px;font-family:'JetBrains Mono',monospace;font-size:12px}
.svc-name{color:var(--text-secondary);font-weight:600;margin-bottom:4px}
.svc-status{font-size:11px}
</style></head>
<body data-deploying="{{ 'true' if deploying else 'false' }}">
{{ sidebar_html }}
<div class="main">
  <div class="page-header">
    <h1><img src="{{ cloudtak_icon }}" alt="" style="height:28px;vertical-align:middle;margin-right:8px">CloudTAK</h1>
    <p>Browser-based TAK client — in-browser map and situational awareness via TAK Server</p>
  </div>

  {% if cloudtak.running %}
  <div class="status-banner running"><div class="dot"></div>CloudTAK is running</div>
  {% elif cloudtak.installed %}
  <div class="status-banner stopped"><div class="dot"></div>CloudTAK is installed but stopped</div>
  {% else %}
  <div class="status-banner not-installed"><div class="dot"></div>CloudTAK is not installed</div>
  {% endif %}

  {% if cloudtak.installed %}
  <!-- Controls at top -->
  <div class="card">
    <div class="card-title">Controls</div>
    <div class="controls">
      <button class="btn {% if cloudtak.running %}btn-ghost{% else %}btn-success{% endif %}" onclick="control('start')">▶ Start</button>
      <button class="btn {% if cloudtak.running %}btn-danger{% else %}btn-ghost{% endif %}" onclick="control('stop')">⏹ Stop</button>
      <button class="btn btn-ghost" onclick="control('restart')">↺ Restart</button>
      <button type="button" class="btn btn-primary" onclick="startRedeploy()" id="redeploy-btn">🔄 Update config & restart</button>
      <button class="btn btn-danger" onclick="document.getElementById('uninstall-modal').classList.add('open')">🗑 Uninstall</button>
    </div>
    <div id="control-status" style="margin-top:12px;font-size:12px;color:var(--text-dim)"></div>
  </div>

  <!-- Access -->
  <div class="card">
    <div class="card-title">Access</div>
    <div class="info-grid">
      {% if settings.fqdn %}
      <div class="info-item"><div class="info-label">Web UI</div><div class="info-value"><a href="https://map.{{ settings.fqdn }}" target="_blank" rel="noopener noreferrer" style="color:var(--cyan);text-decoration:none">https://map.{{ settings.fqdn }}</a> <span style="color:var(--text-dim);font-size:11px">↗</span></div></div>
      <div class="info-item"><div class="info-label">Tile Server</div><div class="info-value">https://tiles.map.{{ settings.fqdn }}</div></div>
      <div class="info-item"><div class="info-label">Video (MediaMTX)</div><div class="info-value"><a href="https://video.{{ settings.fqdn }}" target="_blank" rel="noopener noreferrer" style="color:var(--cyan);text-decoration:none">https://video.{{ settings.fqdn }}</a></div></div>
      {% else %}
      <div class="info-item"><div class="info-label">Web UI</div><div class="info-value"><a href="http://{{ settings.server_ip }}:5000" target="_blank" rel="noopener noreferrer" style="color:var(--cyan);text-decoration:none">http://{{ settings.server_ip }}:5000</a> <span style="color:var(--text-dim);font-size:11px">↗</span></div></div>
      <div class="info-item"><div class="info-label">Tile Server</div><div class="info-value">http://{{ settings.server_ip }}:5002</div></div>
      {% endif %}
      <div class="info-item"><div class="info-label">Install Dir</div><div class="info-value">~/CloudTAK</div></div>
    </div>
  </div>

  {% if container_info.get('containers') %}
  <div class="card">
    <div class="card-title">Services</div>
    <div class="svc-grid">
      {% for c in container_info.containers %}
      <div class="svc-card" onclick="filterLogs('{{ c.name }}')" style="cursor:pointer;border-color:{{ 'var(--red)' if 'unhealthy' in c.status else 'var(--green)' if 'Up' in c.status else 'var(--border)' }}" id="svc-{{ c.name }}"><div class="svc-name">{{ c.name }}</div><div class="svc-status" style="color:{{ 'var(--red)' if 'unhealthy' in c.status else 'var(--green)' }}">● {{ c.status }}</div></div>
      {% endfor %}
      <div class="svc-card" onclick="filterLogs('')" style="cursor:pointer" id="svc-all"><div class="svc-name">all containers</div><div class="svc-status" style="color:var(--text-dim)">● combined</div></div>
    </div>
  </div>
  <div class="card">
    <div class="card-title">Container Logs <span id="log-filter-label" style="font-size:11px;color:var(--cyan);margin-left:8px"></span></div>
    <div class="log-box" id="container-logs">Loading...</div>
  </div>
  {% endif %}

  {% else %}
  <!-- Deploy form -->
  <div class="card">
    <div class="card-title">Deploy CloudTAK</div>
    <p style="font-size:13px;color:var(--text-secondary);margin-bottom:20px">
      CloudTAK is a browser-based TAK client built by the Colorado DFPC Center of Excellence.
      It connects to your TAK Server and provides a full map interface in any web browser.
      Video streams from your standalone MediaMTX install will be used automatically.
    </p>

    {% if not settings.fqdn %}
    <div style="background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.2);border-radius:8px;padding:12px 16px;margin-bottom:20px;font-size:12px;color:var(--yellow)">
      ⚠ No domain configured. Deploy Caddy SSL first for HTTPS access.
    </div>
    {% endif %}

    <button class="btn btn-primary" id="deploy-btn" onclick="startDeploy()">🚀 Deploy CloudTAK</button>
    {% if not settings.fqdn %}
    <div style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:8px;padding:12px 16px;margin-top:16px;font-size:12px;color:#f87171">
      🔒 <strong>SSL Required</strong> — CloudTAK requires a domain with SSL configured.<br>
      <span style="color:var(--text-dim)">Go to <a href="/caddy" style="color:var(--cyan)">Caddy SSL</a> and configure your domain first.</span>
    </div>
    {% endif %}
  </div>
  {% endif %}

  <!-- Deploy log -->
  {% if deploying %}
  <div class="card" id="deploy-log-card">
    <div class="card-title">Deploy Log</div>
    <div class="log-box" id="deploy-log">Initializing...</div>
  </div>
  {% endif %}

  <div id="log-card" class="card" style="display:none">
    <div class="card-title">Deploy Log</div>
    <div class="log-box" id="deploy-log-dyn">Waiting...</div>
  </div>
</div>

<!-- Uninstall modal -->
<div class="modal-overlay" id="uninstall-modal">
  <div class="modal">
    <h3>&#x26a0; Uninstall CloudTAK?</h3>
    <p>This will stop and remove all CloudTAK Docker containers, volumes, and the ~/CloudTAK directory. This cannot be undone.</p>
    <div class="form-group">
      <label class="form-label">Admin Password</label>
      <input class="form-input" id="uninstall-password" type="password" placeholder="Confirm your password">
    </div>
    <div class="modal-actions">
      <button class="btn btn-ghost" id="uninstall-cancel-btn" onclick="document.getElementById('uninstall-modal').classList.remove('open')">Cancel</button>
      <button class="btn btn-danger" id="uninstall-confirm-btn" onclick="doUninstall()">Uninstall</button>
    </div>
    <div id="uninstall-msg" style="margin-top:10px;font-size:12px;color:var(--red)"></div>
    <div id="uninstall-progress" class="uninstall-progress-row" style="margin-top:8px;font-size:13px;color:var(--text-secondary);min-height:24px" aria-live="polite"></div>
  </div>
</div>

<script src="/cloudtak/page.js"></script>
<script>
(function(){
  var deploying = document.body.getAttribute('data-deploying') === 'true';
  if (deploying) { document.addEventListener('DOMContentLoaded', function() { window.logIndex = 0; if (window.pollLog) window.pollLog(null); }); }
})();
</script>
</body></html>'''

EMAIL_RELAY_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Email Relay</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0" rel="stylesheet">
<style>
:root{--bg-deep:#080b14;--bg-surface:#0f1219;--bg-card:#161b26;--border:#1e2736;--border-hover:#2a3548;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-dim:#94a3b8;--accent:#3b82f6;--cyan:#06b6d4;--green:#10b981;--red:#ef4444;--yellow:#eab308}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'DM Sans',sans-serif;background:var(--bg-deep);color:var(--text-primary);min-height:100vh}
.top-bar{height:3px;background:linear-gradient(90deg,var(--accent),var(--cyan),var(--green))}
.header{padding:20px 40px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);background:var(--bg-surface)}
.header-left{display:flex;align-items:center;gap:16px}.header-icon{font-size:28px}.header-title{font-family:'JetBrains Mono',monospace;font-size:20px;font-weight:700;letter-spacing:-0.5px}.header-subtitle{font-size:13px;color:var(--text-dim)}
.header-right{display:flex;align-items:center;gap:12px}
.btn-back{color:var(--text-dim);text-decoration:none;font-size:13px;padding:6px 14px;border:1px solid var(--border);border-radius:6px;transition:all 0.2s}.btn-back:hover{color:var(--text-secondary);border-color:var(--border-hover)}
.btn-logout{color:var(--text-dim);text-decoration:none;font-size:13px;padding:6px 14px;border:1px solid var(--border);border-radius:6px;transition:all 0.2s}.btn-logout:hover{color:var(--red);border-color:rgba(239,68,68,0.3)}
.os-badge{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);padding:4px 10px;background:var(--bg-card);border:1px solid var(--border);border-radius:4px}
.section-title{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:2px;text-transform:uppercase;margin-bottom:16px;margin-top:24px}
.status-banner{background:var(--bg-card);border:1px solid var(--border);border-top:none;border-radius:12px;padding:24px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between}
.status-info{display:flex;align-items:center;gap:16px}
.status-icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px}
.status-icon.running{background:rgba(16,185,129,0.1)}.status-icon.stopped{background:rgba(239,68,68,0.1)}.status-icon.not-installed{background:rgba(71,85,105,0.2)}
.status-text{font-family:'JetBrains Mono',monospace;font-size:18px;font-weight:600}
.status-detail{font-size:13px;color:var(--text-dim);margin-top:4px}
.controls{display:flex;gap:10px}
.control-btn{padding:8px 16px;border:1px solid var(--border);border-radius:8px;background:transparent;color:var(--text-secondary);font-family:'JetBrains Mono',monospace;font-size:12px;cursor:pointer;transition:all 0.2s}
.control-btn:hover{border-color:var(--border-hover);background:var(--bg-surface)}
.control-btn.btn-stop{color:var(--red)}.control-btn.btn-stop:hover{border-color:rgba(239,68,68,0.3);background:rgba(239,68,68,0.05)}
.control-btn.btn-start{color:var(--green)}.control-btn.btn-start:hover{border-color:rgba(16,185,129,0.3);background:rgba(16,185,129,0.05)}
.deploy-log{background:#0c0f1a;border:1px solid var(--border);border-radius:12px;padding:20px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);max-height:400px;overflow-y:auto;line-height:1.6;white-space:pre-wrap;margin-top:16px}
.input-field{width:100%;padding:12px 16px;background:var(--bg-surface);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-family:'JetBrains Mono',monospace;font-size:14px;outline:none;transition:border-color 0.2s}
.input-field:focus{border-color:var(--accent)}
select.input-field{cursor:pointer}
.input-label{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-dim);margin-bottom:8px;display:block}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.form-group{display:flex;flex-direction:column}
.form-group.full{grid-column:1/-1}
.provider-link{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--accent);margin-top:8px;display:block}
.info-box{background:rgba(59,130,246,0.07);border:1px solid rgba(59,130,246,0.2);border-radius:10px;padding:16px;font-size:13px;color:var(--text-secondary);line-height:1.6;margin-bottom:16px}
.info-box code{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--cyan);background:rgba(6,182,212,0.1);padding:2px 6px;border-radius:4px}
.config-table{width:100%;border-collapse:collapse;font-family:'JetBrains Mono',monospace;font-size:12px}
.config-table td{padding:10px 14px;border-bottom:1px solid var(--border)}
.config-table td:first-child{color:var(--text-dim);width:140px}
.config-table td:last-child{color:var(--cyan)}
.footer{text-align:center;padding:24px;font-size:12px;color:var(--text-dim);margin-top:40px}
.status-logo-wrap{display:flex;align-items:center;gap:10px}
.status-logo{height:36px;width:auto;max-width:100px;object-fit:contain}
.status-name{font-family:'JetBrains Mono',monospace;font-weight:600;font-size:18px;color:var(--text-primary)}
.tag{display:inline-block;padding:3px 8px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600}
.tag-green{background:rgba(16,185,129,0.1);color:var(--green);border:1px solid rgba(16,185,129,0.2)}
.tag-blue{background:rgba(59,130,246,0.1);color:var(--accent);border:1px solid rgba(59,130,246,0.2)}
body{display:flex;flex-direction:row;min-height:100vh}
.sidebar{width:220px;min-width:220px;background:var(--bg-surface);border-right:1px solid var(--border);padding:24px 0;flex-shrink:0}
.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}
.sidebar-logo span{font-size:15px;font-weight:700}.sidebar-logo small{display:block;font-size:10px;color:var(--text-dim);font-family:'JetBrains Mono',monospace;margin-top:2px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 20px;color:var(--text-secondary);text-decoration:none;font-size:13px;font-weight:500;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{color:var(--text-primary);background:rgba(255,255,255,.03)}
.nav-item.active{color:var(--cyan);background:rgba(6,182,212,.06);border-left-color:var(--cyan)}
.nav-icon{font-size:15px;width:18px;text-align:center}
.material-symbols-outlined{font-family:'Material Symbols Outlined';font-weight:400;font-style:normal;font-size:20px;line-height:1;letter-spacing:normal;white-space:nowrap;direction:ltr;-webkit-font-smoothing:antialiased}
.nav-icon.material-symbols-outlined{font-size:22px;width:22px;text-align:center}
.main{flex:1;min-width:0;overflow-y:auto;padding:32px;max-width:1000px;margin-left:0;margin-right:auto}
</style></head><body>
{{ sidebar_html }}
<div class="main">

<!-- Status Banner -->
<div class="status-banner">
{% if email.installed and email.running %}
<div class="status-info"><div class="status-logo-wrap"><span class="material-symbols-outlined" style="font-size:36px">outgoing_mail</span><span class="status-name">Email Relay</span></div><div>
<div class="status-text" style="color:var(--green)">Running</div>
<div class="status-detail">Postfix relay active{% if relay_config.get('provider') %} · {{ providers.get(relay_config.provider,{}).get('name', relay_config.provider) }}{% endif %}{% if relay_config.get('from_addr') %} · {{ relay_config.from_addr }}{% endif %}</div>
</div></div>
<div class="controls">
<button class="control-btn" onclick="emailControl('restart')">↻ Restart</button>
<button class="control-btn btn-stop" onclick="emailControl('stop')">■ Stop</button>
<button class="control-btn btn-stop" onclick="emailUninstall()" style="margin-left:8px">🗑 Remove</button>
</div>
{% elif email.installed %}
<div class="status-info"><div class="status-logo-wrap"><span class="material-symbols-outlined" style="font-size:36px">outgoing_mail</span><span class="status-name">Email Relay</span></div><div>
<div class="status-text" style="color:var(--red)">Stopped</div>
<div class="status-detail">Postfix is installed but not running</div>
</div></div>
<div class="controls"><button class="control-btn btn-start" onclick="emailControl('start')">▶ Start</button></div>
{% else %}
<div class="status-info"><div class="status-logo-wrap"><span class="material-symbols-outlined" style="font-size:36px">outgoing_mail</span><span class="status-name">Email Relay</span></div><div>
<div class="status-text" style="color:var(--text-dim)">Not Installed</div>
<div class="status-detail">Postfix email relay — apps use localhost, provider handles delivery</div>
</div></div>
{% endif %}
</div>

{% if deploying %}
<!-- Deploy Log -->
<div class="section-title">Deployment Log</div>
<div class="deploy-log" id="deploy-log">Starting deployment...</div>
<script>
(function pollLog(){
    var el=document.getElementById('deploy-log');
    var last=0;
    var iv=setInterval(async()=>{
        var r=await fetch('/api/emailrelay/log');var d=await r.json();
        if(d.entries&&d.entries.length>last){el.textContent=d.entries.join('\\n');el.scrollTop=el.scrollHeight;last=d.entries.length}
        if(!d.running){clearInterval(iv);setTimeout(()=>location.reload(),1500)}
    },1500);
})();
</script>

{% elif email.installed and email.running %}
<!-- Running State -->
<div class="section-title">Current Configuration</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<table class="config-table">
<tr><td>Provider</td><td>{{ providers.get(relay_config.get('provider',''),{}).get('name', relay_config.get('provider','—')) }}</td></tr>
<tr><td>Relay Host</td><td>{{ relay_config.get('relay_host','—') }}:{{ relay_config.get('relay_port','587') }}</td></tr>
<tr><td>SMTP Login</td><td>{{ relay_config.get('smtp_user','—') }}</td></tr>
<tr><td>From Address</td><td>{{ relay_config.get('from_addr','—') }}</td></tr>
<tr><td>From Name</td><td>{{ relay_config.get('from_name','—') }}</td></tr>
</table>
</div>

<div class="section-title">App SMTP Settings</div>
<div class="info-box">
Configure TAK Portal and MediaMTX to use the local relay:<br><br>
<strong>SMTP Host:</strong> <code>localhost</code> &nbsp;&nbsp;
<strong>Port:</strong> <code>25</code> &nbsp;&nbsp;
<strong>Username:</strong> <code>blank</code> &nbsp;&nbsp;
<strong>Password:</strong> <code>blank</code> &nbsp;&nbsp;
<strong>TLS:</strong> <code>off</code>
</div>

{% if modules.get('authentik', {}).get('installed') %}
<div class="section-title">Configure Authentik</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<p style="margin:0 0 16px 0;color:var(--text-muted)">Push this relay (localhost:25) and your From address into Authentik so recovery emails and other Authentik mail use the same relay.</p>
<button onclick="configureAuthentik()" id="cfg-ak-btn" style="padding:12px 24px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;cursor:pointer">Configure Authentik to use these settings</button>
<div id="cfg-ak-result" style="margin-top:12px;font-family:'JetBrains Mono',monospace;font-size:12px;display:none"></div>
</div>
{% endif %}

<div class="section-title">Send Test Email</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="display:flex;gap:12px;align-items:end">
<div style="flex:1"><label class="input-label">Send test to</label>
<input type="email" id="test-addr" class="input-field" placeholder="you@example.com"></div>
<button onclick="sendTest()" style="padding:12px 24px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap">Send Test</button>
</div>
<div id="test-result" style="margin-top:12px;font-family:'JetBrains Mono',monospace;font-size:12px;display:none"></div>
</div>

<div class="section-title">Switch Provider</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div id="swap-form">
<div class="form-grid">
<div class="form-group full">
<label class="input-label">Email Provider</label>
<select class="input-field" id="swap-provider" onchange="updateProviderUI('swap-')">
{% for key, p in providers.items() %}<option value="{{ key }}"{% if relay_config.get("provider")==key %} selected{% endif %}>{{ p.name }}</option>{% endfor %}
</select>
<a id="swap-provider-link" href="#" target="_blank" class="provider-link" style="display:none">→ Get credentials from provider ↗</a>
</div>
<div class="form-group"><label class="input-label">SMTP Username / Login</label>
<input type="text" id="swap-smtp_user" class="input-field" placeholder="user@smtp-brevo.com" value="{{ relay_config.get('smtp_user','') }}"></div>
<div class="form-group"><label class="input-label">SMTP Password / API Key</label>
<input type="password" id="swap-smtp_pass" class="input-field" placeholder="••••••••••••"></div>
<div class="form-group"><label class="input-label">From Address</label>
<input type="email" id="swap-from_addr" class="input-field" placeholder="noreply@yourdomain.com" value="{{ relay_config.get('from_addr','') }}"></div>
<div class="form-group"><label class="input-label">From Name</label>
<input type="text" id="swap-from_name" class="input-field" placeholder="TAK Operations" value="{{ relay_config.get('from_name','') }}"></div>
<div class="form-group full" id="swap-custom-fields" style="display:none;grid-template-columns:1fr 120px;gap:12px">
<div><label class="input-label">Custom SMTP Host</label><input type="text" id="swap-custom_host" class="input-field" placeholder="smtp.yourdomain.com"></div>
<div><label class="input-label">Port</label><input type="text" id="swap-custom_port" class="input-field" placeholder="587" value="587"></div>
</div></div>
<div style="margin-top:20px;text-align:center">
<button onclick="swapProvider()" style="padding:12px 32px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;cursor:pointer">↔ Switch Provider</button>
</div>
</div>
</div>

{% elif not email.installed %}
<!-- Not Installed -->
<div class="section-title">How It Works</div>
<div class="info-box">
The Email Relay installs <strong>Postfix</strong> as a local mail relay on this server. Your apps (TAK Portal, MediaMTX) send to <code>localhost:25</code> with no credentials — Postfix handles authentication and delivery through your chosen provider.<br><br>
Switching providers later requires only updating Postfix credentials — no changes to your apps.
</div>

<div class="section-title">Deploy Email Relay</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div class="form-grid">
<div class="form-group full">
<label class="input-label">Email Provider</label>
<select class="input-field" id="deploy-provider" onchange="updateProviderUI('deploy-')">
{% for key, p in providers.items() %}<option value="{{ key }}">{{ p.name }}</option>{% endfor %}
</select>
<a id="deploy-provider-link" href="#" target="_blank" class="provider-link" style="display:none">→ Get credentials from provider ↗</a>
</div>
<div class="form-group"><label class="input-label">SMTP Username / Login</label>
<input type="text" id="deploy-smtp_user" class="input-field" placeholder="user@smtp-brevo.com"></div>
<div class="form-group"><label class="input-label">SMTP Password / API Key</label>
<input type="password" id="deploy-smtp_pass" class="input-field" placeholder="••••••••••••"></div>
<div class="form-group"><label class="input-label">From Address</label>
<input type="email" id="deploy-from_addr" class="input-field" placeholder="noreply@yourdomain.com"></div>
<div class="form-group"><label class="input-label">From Name</label>
<input type="text" id="deploy-from_name" class="input-field" placeholder="TAK Operations"></div>
<div class="form-group full" id="deploy-custom-fields" style="display:none;grid-template-columns:1fr 120px;gap:12px">
<div><label class="input-label">Custom SMTP Host</label><input type="text" id="deploy-custom_host" class="input-field" placeholder="smtp.yourdomain.com"></div>
<div><label class="input-label">Port</label><input type="text" id="deploy-custom_port" class="input-field" placeholder="587" value="587"></div>
</div></div>
<div style="margin-top:20px;text-align:center">
<button onclick="deployRelay()" id="deploy-btn" style="padding:14px 40px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:10px;font-family:'DM Sans',sans-serif;font-size:16px;font-weight:600;cursor:pointer">📧 Deploy Email Relay</button>
</div>
</div>
{% endif %}

</div>
<footer class="footer"></footer>

<script>
var PROVIDERS = {{ providers | tojson }};

function updateProviderUI(prefix){
    var sel = document.getElementById(prefix+'provider');
    if(!sel) return;
    var key = sel.value;
    var p = PROVIDERS[key] || {};
    var linkEl = document.getElementById(prefix+'provider-link');
    if(linkEl){
        if(p.url){ linkEl.href=p.url; linkEl.style.display='inline'; }
        else { linkEl.style.display='none'; }
    }
    var customFields = document.getElementById(prefix+'custom-fields');
    if(customFields) customFields.style.display = (key==='custom') ? 'grid' : 'none';
}

async function deployRelay(){
    var btn=document.getElementById('deploy-btn');
    var provider=document.getElementById('deploy-provider').value;
    var user=document.getElementById('deploy-smtp_user').value.trim();
    var pass=document.getElementById('deploy-smtp_pass').value.trim();
    var from=document.getElementById('deploy-from_addr').value.trim();
    var name=document.getElementById('deploy-from_name').value.trim();
    if(!user||!pass||!from){alert('SMTP username, password, and From address are required');return}
    var body={provider,smtp_user:user,smtp_pass:pass,from_addr:from,from_name:name};
    if(provider==='custom'){
        body.custom_host=document.getElementById('deploy-custom_host').value.trim();
        body.custom_port=document.getElementById('deploy-custom_port').value.trim();
    }
    btn.disabled=true;btn.textContent='Deploying...';btn.style.opacity='0.7';
    var r=await fetch('/api/emailrelay/deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    var d=await r.json();
    if(d.success){location.reload()}
    else{alert('Error: '+d.error);btn.disabled=false;btn.textContent='📧 Deploy Email Relay';btn.style.opacity='1'}
}

async function swapProvider(){
    var provider=document.getElementById('swap-provider').value;
    var user=document.getElementById('swap-smtp_user').value.trim();
    var pass=document.getElementById('swap-smtp_pass').value.trim();
    var from=document.getElementById('swap-from_addr').value.trim();
    var name=document.getElementById('swap-from_name').value.trim();
    if(!user||!pass||!from){alert('All fields required');return}
    var body={provider,smtp_user:user,smtp_pass:pass,from_addr:from,from_name:name};
    if(provider==='custom'){
        body.custom_host=document.getElementById('swap-custom_host').value.trim();
        body.custom_port=document.getElementById('swap-custom_port').value.trim();
    }
    if(!confirm('Switch to '+PROVIDERS[provider].name+'? Postfix will restart.')){return}
    var r=await fetch('/api/emailrelay/swap',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    var d=await r.json();
    if(d.success){location.reload()}
    else{alert('Error: '+d.error)}
}

async function sendTest(){
    var to=document.getElementById('test-addr').value.trim();
    if(!to){alert('Enter a recipient address');return}
    var res=document.getElementById('test-result');
    res.style.display='block';res.style.color='var(--text-dim)';res.textContent='Sending...';
    var r=await fetch('/api/emailrelay/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to})});
    var d=await r.json();
    if(d.success){res.style.color='var(--green)';res.textContent='✓ '+d.output}
    else{res.style.color='var(--red)';res.textContent='✗ '+d.error}
}

async function configureAuthentik(){
    var btn=document.getElementById('cfg-ak-btn');
    var res=document.getElementById('cfg-ak-result');
    if(!btn||!res) return;
    btn.disabled=true;res.style.display='block';res.style.color='var(--text-dim)';res.textContent='Configuring...';
    var r=await fetch('/api/emailrelay/configure-authentik',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
    var d=await r.json();
    if(d.success){res.style.color='var(--green)';res.textContent='✓ '+d.message}
    else{res.style.color='var(--red)';res.textContent='✗ '+(d.error||'Failed')}
    btn.disabled=false;
}

async function emailControl(action){
    var r=await fetch('/api/emailrelay/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})});
    var d=await r.json();
    if(d.success){location.reload()}else{alert('Error: '+(d.error||d.output))}
}

async function emailUninstall(){
    if(!confirm('Remove Postfix email relay? Apps will need to be reconfigured.')){return}
    var r=await fetch('/api/emailrelay/uninstall',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
    var d=await r.json();
    if(d.success){location.reload()}else{alert('Error removing Postfix')}
}
</script>
</body></html>'''




CADDY_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Caddy SSL</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0" rel="stylesheet">
<style>
:root{--bg-deep:#080b14;--bg-surface:#0f1219;--bg-card:#161b26;--border:#1e2736;--border-hover:#2a3548;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-dim:#94a3b8;--accent:#3b82f6;--cyan:#06b6d4;--green:#10b981;--red:#ef4444;--yellow:#eab308}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'DM Sans',sans-serif;background:var(--bg-deep);color:var(--text-primary);min-height:100vh}
.top-bar{height:3px;background:linear-gradient(90deg,var(--accent),var(--cyan),var(--green))}
.header{padding:20px 40px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);background:var(--bg-surface)}
.header-left{display:flex;align-items:center;gap:16px}.header-icon{font-size:28px}.header-title{font-family:'JetBrains Mono',monospace;font-size:20px;font-weight:700;letter-spacing:-0.5px}.header-subtitle{font-size:13px;color:var(--text-dim)}
.header-right{display:flex;align-items:center;gap:12px}
.btn-back{color:var(--text-dim);text-decoration:none;font-size:13px;padding:6px 14px;border:1px solid var(--border);border-radius:6px;transition:all 0.2s}.btn-back:hover{color:var(--text-secondary);border-color:var(--border-hover)}
.btn-logout{color:var(--text-dim);text-decoration:none;font-size:13px;padding:6px 14px;border:1px solid var(--border);border-radius:6px;transition:all 0.2s}.btn-logout:hover{color:var(--red);border-color:rgba(239,68,68,0.3)}
.os-badge{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);padding:4px 10px;background:var(--bg-card);border:1px solid var(--border);border-radius:4px}
.main{max-width:1000px;margin:0 auto;padding:32px 40px}
.section-title{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:2px;text-transform:uppercase;margin-bottom:16px;margin-top:24px}
.status-banner{background:var(--bg-card);border:1px solid var(--border);border-top:none;border-radius:12px;padding:24px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between}
.status-info{display:flex;align-items:center;gap:16px}
.status-icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px}
.status-icon.running{background:rgba(16,185,129,0.1)}.status-icon.stopped{background:rgba(239,68,68,0.1)}.status-icon.not-installed{background:rgba(71,85,105,0.2)}
.status-text{font-family:'JetBrains Mono',monospace;font-size:18px;font-weight:600}
.status-detail{font-size:13px;color:var(--text-dim);margin-top:4px}
.controls{display:flex;gap:10px}
.control-btn{padding:8px 16px;border:1px solid var(--border);border-radius:8px;background:transparent;color:var(--text-secondary);font-family:'JetBrains Mono',monospace;font-size:12px;cursor:pointer;transition:all 0.2s}
.control-btn:hover{border-color:var(--border-hover);background:var(--bg-surface)}
.control-btn.btn-stop{color:var(--red)}.control-btn.btn-stop:hover{border-color:rgba(239,68,68,0.3);background:rgba(239,68,68,0.05)}
.control-btn.btn-start{color:var(--green)}.control-btn.btn-start:hover{border-color:rgba(16,185,129,0.3);background:rgba(16,185,129,0.05)}
.deploy-log{background:#0c0f1a;border:1px solid var(--border);border-radius:12px;padding:20px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);max-height:400px;overflow-y:auto;line-height:1.6;white-space:pre-wrap;margin-top:16px}
.input-field{width:100%;padding:12px 16px;background:var(--bg-surface);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-family:'JetBrains Mono',monospace;font-size:14px;outline:none;transition:border-color 0.2s}
.input-field:focus{border-color:var(--accent)}
.input-label{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-dim);margin-bottom:8px;display:block}
.footer{text-align:center;padding:24px;font-size:12px;color:var(--text-dim);margin-top:40px}
.status-logo-wrap{display:flex;align-items:center;gap:10px}
.status-logo{height:36px;width:auto;max-width:100px;object-fit:contain}
.status-name{font-family:'JetBrains Mono',monospace;font-weight:600;font-size:18px;color:var(--text-primary)}
.benefit-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-top:16px}
.benefit-item{background:var(--bg-surface);border:1px solid var(--border);border-radius:8px;padding:14px;font-size:12px}
.benefit-item .icon{font-size:18px;margin-bottom:6px}
.benefit-item .title{font-family:'JetBrains Mono',monospace;font-weight:600;color:var(--text-secondary);margin-bottom:4px}
.benefit-item .desc{color:var(--text-dim);line-height:1.4}
body{display:flex;flex-direction:row;min-height:100vh}
.sidebar{width:220px;min-width:220px;background:var(--bg-surface);border-right:1px solid var(--border);padding:24px 0;flex-shrink:0}
.material-symbols-outlined{font-family:'Material Symbols Outlined';font-weight:400;font-style:normal;font-size:20px;line-height:1;letter-spacing:normal;white-space:nowrap;direction:ltr;-webkit-font-smoothing:antialiased}
.nav-icon.material-symbols-outlined{font-size:22px;width:22px;text-align:center}
.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}
.sidebar-logo span{font-size:15px;font-weight:700}.sidebar-logo small{display:block;font-size:10px;color:var(--text-dim);font-family:'JetBrains Mono',monospace;margin-top:2px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 20px;color:var(--text-secondary);text-decoration:none;font-size:13px;font-weight:500;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{color:var(--text-primary);background:rgba(255,255,255,.03)}
.nav-item.active{color:var(--cyan);background:rgba(6,182,212,.06);border-left-color:var(--cyan)}
.nav-icon{font-size:15px;width:18px;text-align:center}
.main{flex:1;min-width:0;overflow-y:auto;padding:32px;max-width:1000px;margin:0 auto}
</style></head><body>
{{ sidebar_html }}
<div class="main">
<div class="status-banner">
{% if caddy.installed and caddy.running %}
<div class="status-info"><div class="status-logo-wrap"><img src="{{ caddy_logo_url }}" alt="" class="status-logo"></div><div><div class="status-text" style="color:var(--green)">Running</div><div class="status-detail">Caddy is active{% if settings.get('fqdn') %} · {{ settings.get('fqdn') }}{% endif %}</div></div></div>
<div class="controls"><button class="control-btn" onclick="caddyControl('reload')">↻ Reload</button><button class="control-btn" onclick="caddyControl('restart')">↻ Restart</button><button class="control-btn btn-stop" onclick="caddyControl('stop')">■ Stop</button><button class="control-btn btn-stop" onclick="caddyUninstall()" style="margin-left:8px">🗑 Remove</button></div>
{% elif caddy.installed %}
<div class="status-info"><div class="status-logo-wrap"><img src="{{ caddy_logo_url }}" alt="" class="status-logo"></div><div><div class="status-text" style="color:var(--red)">Stopped</div><div class="status-detail">Caddy is installed but not running</div></div></div>
<div class="controls"><button class="control-btn btn-start" onclick="caddyControl('start')">▶ Start</button><button class="control-btn btn-stop" onclick="caddyUninstall()" style="margin-left:8px">🗑 Remove</button></div>
{% else %}
<div class="status-info"><div class="status-logo-wrap"><img src="{{ caddy_logo_url }}" alt="" class="status-logo"></div><div><div class="status-text" style="color:var(--text-dim)">Not Installed</div><div class="status-detail">Set up a domain for full functionality</div></div></div>
{% endif %}
</div>

{% if deploying %}
<div class="section-title">Deployment Log</div>
<div class="deploy-log" id="deploy-log">Waiting for deployment to start...</div>
{% elif caddy.installed and caddy.running %}
<div class="section-title">Domain Configuration</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="display:flex;gap:12px;align-items:end">
<div style="flex:1"><label class="input-label">Base Domain (subdomains auto-configured)</label>
<input type="text" id="domain-input" class="input-field" value="{{ settings.get('fqdn', '') }}" placeholder="yourdomain.com"></div>
<button onclick="updateDomain()" style="padding:12px 24px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap">Update & Reload</button>
</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);margin-top:12px">Create DNS A records for *.{{ settings.get('fqdn', '') }} or individual subdomains pointing to <span style="color:var(--cyan)">{{ settings.get('server_ip', '') }}</span></div>
</div>
{% if configured_urls %}
<div class="section-title">Configured URLs</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="display:grid;grid-template-columns:minmax(140px,1fr) minmax(180px,1.4fr) 1fr;gap:12px 24px;align-items:center;font-size:13px;border-bottom:1px solid var(--border);padding-bottom:12px;margin-bottom:12px">
<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.08em">Service</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.08em">URL</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.08em">Where it goes</div>
</div>
{% for u in configured_urls %}
<div style="display:grid;grid-template-columns:minmax(140px,1fr) minmax(180px,1.4fr) 1fr;gap:12px 24px;align-items:center;font-size:13px;padding:10px 0;border-bottom:1px solid var(--border)">
<div style="font-weight:600;color:var(--text-primary)">{{ u.name }}</div>
<div><a href="{{ u.url }}" target="_blank" rel="noopener noreferrer" style="color:var(--cyan);text-decoration:none;font-family:'JetBrains Mono',monospace;font-size:12px;word-break:break-all">{{ u.host }}</a> <span style="color:var(--text-dim);font-size:11px">↗</span></div>
<div style="color:var(--text-dim);font-size:12px">{{ u.desc }}</div>
</div>
{% endfor %}
</div>
{% endif %}
<div class="section-title">Caddyfile</div>
<div style="background:#0c0f1a;border:1px solid var(--border);border-radius:12px;padding:20px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);max-height:400px;overflow-y:auto;line-height:1.6;white-space:pre-wrap">{{ caddyfile }}</div>
{% elif not caddy.installed %}
<div class="section-title">Set Up Your Domain</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:32px;margin-bottom:24px">
<div style="text-align:center;margin-bottom:24px">
<div style="font-size:36px;margin-bottom:12px">🌐</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:16px;font-weight:600;color:var(--text-secondary)">Configure a Domain Name</div>
<div style="font-size:13px;color:var(--text-dim);margin-top:8px;max-width:500px;margin-left:auto;margin-right:auto;line-height:1.5">Caddy provides automatic HTTPS with Let's Encrypt certificates. Enter your domain name and point its DNS to this server's IP address.</div>
</div>
<div style="max-width:500px;margin:0 auto">
<label class="input-label">Base Domain</label>
<input type="text" id="domain-input" class="input-field" placeholder="yourdomain.com" style="margin-bottom:8px">
<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);margin-bottom:20px">Subdomains auto-configured: infratak · console · tak · authentik · portal · nodered · map · tiles.map · video<br>Point a wildcard DNS (*.yourdomain.com) or individual A records to <span style="color:var(--cyan)">{{ settings.get('server_ip', '') }}</span></div>
<div style="text-align:center">
<button onclick="deployCaddy()" id="deploy-btn" style="padding:14px 40px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:10px;font-family:'DM Sans',sans-serif;font-size:16px;font-weight:600;cursor:pointer">🚀 Deploy Caddy</button>
</div>
</div>
</div>
<div class="section-title">What You Get With a Domain</div>
<div class="benefit-grid">
<div class="benefit-item"><div class="icon">📱</div><div class="title">ATAK QR Enrollment</div><div class="desc">Android devices can enroll via QR code with trusted SSL certificates</div></div>
<div class="benefit-item"><div class="icon">🔐</div><div class="title">TAK Portal Auth</div><div class="desc">Secure TAK Portal with Authentik SSO — no more anonymous access</div></div>
<div class="benefit-item"><div class="icon">🔒</div><div class="title">Trusted SSL</div><div class="desc">Let's Encrypt certificates — no more browser warnings</div></div>
<div class="benefit-item"><div class="icon"><img src="{{ mediamtx_logo_url }}" alt="" style="width:28px;height:28px;object-fit:contain"></div><div class="title">Secure Streaming</div><div class="desc">MediaMTX streams over HTTPS with its own subdomain</div></div>
</div>
{% endif %}
</div>
<footer class="footer"></footer>
<script>
async function deployCaddy(){
    var domain=document.getElementById('domain-input').value.trim();
    if(!domain){alert('Please enter a domain name');return}
    if(!confirm('Deploy Caddy with domain: '+domain+'?\\n\\nMake sure DNS is pointing to this server.')){return}
    var btn=document.getElementById('deploy-btn');
    btn.disabled=true;btn.textContent='Deploying...';btn.style.opacity='0.7';
    try{
        var r=await fetch('/api/caddy/deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:domain})});
        var d=await r.json();
        if(d.success){pollCaddyLog()}
        else{alert('Error: '+d.error);btn.disabled=false;btn.textContent='🚀 Deploy Caddy';btn.style.opacity='1'}
    }catch(e){alert('Error: '+e.message);btn.disabled=false;btn.textContent='🚀 Deploy Caddy';btn.style.opacity='1'}
}
function pollCaddyLog(){
    var el=document.getElementById('deploy-log');
    if(!el){location.reload();return}
    var lastCount=0;
    var iv=setInterval(async()=>{
        try{
            var r=await fetch('/api/caddy/log');var d=await r.json();
            if(d.entries&&d.entries.length>lastCount){
                var newEntries=d.entries.slice(lastCount);
                newEntries.forEach(function(e){
                    var isTimer=e.trim().charAt(0)==='\u23f3'&&e.indexOf(':')>0;
                    if(isTimer){var prev=el.querySelector('[data-timer]');if(prev){prev.textContent=e;return}}
                    if(!isTimer){var old=el.querySelector('[data-timer]');if(old)old.removeAttribute('data-timer')}
                    var l=document.createElement('div');
                    if(isTimer)l.setAttribute('data-timer','1');
                    if(e.indexOf('\u2713')>=0)l.style.color='var(--green)';
                    else if(e.indexOf('\u2717')>=0||e.indexOf('FATAL')>=0)l.style.color='var(--red)';
                    else if(e.indexOf('\u2501\u2501\u2501')>=0)l.style.color='var(--cyan)';
                    else if(e.indexOf('\u26a0')>=0)l.style.color='var(--yellow)';
                    else if(e.indexOf('===')>=0)l.style.color='var(--green)';
                    l.textContent=e;el.appendChild(l);
                });
                lastCount=d.entries.length;el.scrollTop=el.scrollHeight;
            }
            if(!d.running){clearInterval(iv);if(d.complete||d.error){setTimeout(()=>location.reload(),3000)}}
        }catch(e){}
    },1000);
}
async function caddyControl(action){
    try{var r=await fetch('/api/caddy/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:action})});
    var d=await r.json();
    if(d.success){setTimeout(()=>location.reload(),1500)}
    else{alert('Caddy '+action+' failed: '+(d.output||d.error||'unknown'))}
    }catch(e){alert('Error: '+e.message)}
}
async function updateDomain(){
    var domain=document.getElementById('domain-input').value.trim();
    if(!domain){alert('Please enter a domain name');return}
    try{var r=await fetch('/api/caddy/domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:domain})});
    var d=await r.json();if(d.success){alert('Domain updated and Caddy reloaded');location.reload()}else{alert('Error: '+d.error)}}catch(e){alert('Error: '+e.message)}
}
async function caddyUninstall(){
    if(!confirm('Remove Caddy and clear domain configuration?'))return;
    try{var r=await fetch('/api/caddy/uninstall',{method:'POST'});var d=await r.json();if(d.success)location.reload()}catch(e){alert('Error: '+e.message)}
}
{% if deploying %}pollCaddyLog();{% endif %}
</script>
</body></html>'''

CERTS_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Certificates · infra-TAK</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg-deep:#080b14;--bg-surface:#0f1219;--bg-card:#161b26;--border:#1e2736;--border-hover:#2a3548;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-dim:#94a3b8;--accent:#3b82f6;--cyan:#06b6d4;--green:#10b981;--red:#ef4444;--yellow:#eab308}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'DM Sans',sans-serif;background:var(--bg-deep);color:var(--text-primary);min-height:100vh}
.top-bar{height:3px;background:linear-gradient(90deg,var(--accent),var(--cyan),var(--green))}
.header{padding:20px 40px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);background:var(--bg-surface)}
.header-left{display:flex;align-items:center;gap:16px}.header-icon{font-size:28px}.header-title{font-family:'JetBrains Mono',monospace;font-size:20px;font-weight:700;letter-spacing:-0.5px}.header-subtitle{font-size:13px;color:var(--text-dim)}
.header-right{display:flex;align-items:center;gap:12px}
.btn-back{color:var(--text-dim);text-decoration:none;font-size:13px;padding:6px 14px;border:1px solid var(--border);border-radius:6px;transition:all 0.2s}.btn-back:hover{color:var(--text-secondary);border-color:var(--border-hover)}
.main{max-width:1000px;margin:0 auto;padding:32px 40px}
.section-title{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:2px;text-transform:uppercase;margin-bottom:16px}
.cert-table{width:100%;border-collapse:collapse}
.cert-table tr{border-bottom:1px solid var(--border);transition:background 0.15s}
.cert-table tr:hover{background:rgba(59,130,246,0.05)}
.cert-table td{padding:12px 8px;font-family:'JetBrains Mono',monospace;font-size:13px}
.cert-icon{width:30px;text-align:center}
.cert-name{color:var(--text-secondary)}
.cert-size{color:var(--text-dim);text-align:right;width:80px}
.cert-dl{text-align:right;width:40px}
.cert-dl a{color:var(--accent);text-decoration:none;font-size:14px;padding:4px 8px;border-radius:4px;transition:background 0.15s}
.cert-dl a:hover{background:rgba(59,130,246,0.1)}
.info-bar{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-dim);margin-bottom:20px}
.info-bar span{color:var(--cyan)}
.filter-btns{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
.filter-btn{padding:6px 14px;border:1px solid var(--border);border-radius:6px;background:transparent;color:var(--text-dim);font-family:'JetBrains Mono',monospace;font-size:11px;cursor:pointer;transition:all 0.2s}
.filter-btn:hover,.filter-btn.active{border-color:var(--accent);color:var(--accent);background:rgba(59,130,246,0.05)}
.footer{text-align:center;padding:24px;font-size:12px;color:var(--text-dim);margin-top:40px}
</style></head><body>
<div class="top-bar"></div>
<header class="header"><div class="header-left"><div class="header-icon">⚡</div><div><div class="header-title">infra-TAK</div><div class="header-subtitle">Certificates</div></div></div><div class="header-right"><a href="/takserver" class="btn-back">← TAK Server</a></div></header>
<main class="main">
<div class="section-title">Certificate Files</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px">
<div class="info-bar">Password: <span>atakatak</span> &nbsp;&middot;&nbsp; {{ files|length }} files in /opt/tak/certs/files/</div>
<div class="filter-btns">
<button class="filter-btn active" onclick="filterCerts('all')">All</button>
<button class="filter-btn" onclick="filterCerts('p12')">🔑 .p12</button>
<button class="filter-btn" onclick="filterCerts('pem')">📄 .pem</button>
<button class="filter-btn" onclick="filterCerts('jks')">☕ .jks</button>
<button class="filter-btn" onclick="filterCerts('key')">🔐 .key</button>
<button class="filter-btn" onclick="filterCerts('other')">Other</button>
</div>
<table class="cert-table">
{% for f in files %}
<tr data-ext="{{ f.ext }}"><td class="cert-icon">{{ f.icon }}</td><td class="cert-name">{{ f.name }}</td><td class="cert-size">{{ f.size }}</td><td class="cert-dl"><a href="/api/certs/download/{{ f.name }}" title="Download">⬇</a></td></tr>
{% endfor %}
</table>
</div>
</main>
<footer class="footer">infra-TAK</footer>
<script>
function filterCerts(ext){
    document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
    event.target.classList.add('active');
    document.querySelectorAll('.cert-table tr').forEach(r=>{
        if(ext==='all')r.style.display='';
        else if(ext==='other')r.style.display=['p12','pem','jks','key'].includes(r.dataset.ext)?'none':'';
        else r.style.display=r.dataset.ext===ext?'':'none';
    });
}
</script>
</body></html>'''

TAKPORTAL_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>TAK Portal</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0" rel="stylesheet">
<style>
:root{--bg-deep:#080b14;--bg-surface:#0f1219;--bg-card:#161b26;--border:#1e2736;--border-hover:#2a3548;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-dim:#94a3b8;--accent:#3b82f6;--cyan:#06b6d4;--green:#10b981;--red:#ef4444;--yellow:#eab308}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'DM Sans',sans-serif;background:var(--bg-deep);color:var(--text-primary);min-height:100vh}
.material-symbols-outlined{font-family:'Material Symbols Outlined';font-weight:400;font-style:normal;font-size:20px;line-height:1;letter-spacing:normal;white-space:nowrap;direction:ltr;-webkit-font-smoothing:antialiased}
.nav-icon.material-symbols-outlined{font-size:22px;width:22px;text-align:center}
.top-bar{height:3px;background:linear-gradient(90deg,var(--accent),var(--cyan),var(--green))}
.header{padding:20px 40px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);background:var(--bg-surface)}
.header-left{display:flex;align-items:center;gap:16px}.header-icon{font-size:28px}.header-title{font-family:'JetBrains Mono',monospace;font-size:20px;font-weight:700;letter-spacing:-0.5px}.header-subtitle{font-size:13px;color:var(--text-dim)}
.header-right{display:flex;align-items:center;gap:12px}
.btn-back{color:var(--text-dim);text-decoration:none;font-size:13px;padding:6px 14px;border:1px solid var(--border);border-radius:6px;transition:all 0.2s}.btn-back:hover{color:var(--text-secondary);border-color:var(--border-hover)}
.btn-logout{color:var(--text-dim);text-decoration:none;font-size:13px;padding:6px 14px;border:1px solid var(--border);border-radius:6px;transition:all 0.2s}.btn-logout:hover{color:var(--red);border-color:rgba(239,68,68,0.3)}
.os-badge{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);padding:4px 10px;background:var(--bg-card);border:1px solid var(--border);border-radius:4px}
.main{max-width:1000px;margin:0 auto;padding:32px 40px}
.section-title{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:2px;text-transform:uppercase;margin-bottom:16px;margin-top:24px}
.status-banner{background:var(--bg-card);border:1px solid var(--border);border-top:none;border-radius:12px;padding:24px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between}
.status-info{display:flex;align-items:center;gap:16px}
.status-icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px}
.status-icon.running{background:rgba(16,185,129,0.1)}.status-icon.stopped{background:rgba(239,68,68,0.1)}.status-icon.not-installed{background:rgba(71,85,105,0.2)}
.status-text{font-family:'JetBrains Mono',monospace;font-size:18px;font-weight:600}
.status-detail{font-size:13px;color:var(--text-dim);margin-top:4px}
.status-logo-wrap{display:flex;align-items:center;gap:10px}
.status-logo{height:36px;width:auto;max-width:100px;object-fit:contain}
.status-name{font-family:'JetBrains Mono',monospace;font-weight:600;font-size:18px;color:var(--text-primary)}
.controls{display:flex;gap:10px}
.control-btn{padding:10px 20px;border:1px solid var(--border);border-radius:8px;background:var(--bg-card);color:var(--text-secondary);font-family:'JetBrains Mono',monospace;font-size:13px;cursor:pointer;transition:all 0.2s}
.control-btn:hover{border-color:var(--border-hover);color:var(--text-primary)}
.control-btn.btn-stop{border-color:rgba(239,68,68,0.3)}.control-btn.btn-stop:hover{background:rgba(239,68,68,0.1);color:var(--red)}
.control-btn.btn-start{border-color:rgba(16,185,129,0.3)}.control-btn.btn-start:hover{background:rgba(16,185,129,0.1);color:var(--green)}
.control-btn.btn-update{border-color:rgba(59,130,246,0.3)}.control-btn.btn-update:hover{background:rgba(59,130,246,0.1);color:var(--accent)}
.control-btn.btn-remove{border-color:rgba(239,68,68,0.2)}.control-btn.btn-remove:hover{background:rgba(239,68,68,0.1);color:var(--red)}
.cert-btn{padding:10px 20px;border-radius:8px;text-decoration:none;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;transition:all 0.2s}
.cert-btn-primary{background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff}
.cert-btn-secondary{background:rgba(59,130,246,0.1);color:var(--accent);border:1px solid var(--border)}
.deploy-btn{padding:14px 32px;border:none;border-radius:10px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:700;cursor:pointer;transition:all 0.2s;display:block;margin:24px auto}
.deploy-btn:hover{transform:translateY(-1px);box-shadow:0 4px 24px rgba(59,130,246,0.25)}
.deploy-log{background:#0c0f1a;border:1px solid var(--border);border-radius:12px;padding:20px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);max-height:400px;overflow-y:auto;line-height:1.6;white-space:pre-wrap;margin-top:16px}
.footer{text-align:center;padding:24px;font-size:12px;color:var(--text-dim);margin-top:40px}
.svc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-top:8px}
.svc-card{background:var(--bg-surface);border:1px solid var(--border);border-radius:8px;padding:12px;font-family:'JetBrains Mono',monospace;font-size:12px}
.svc-name{color:var(--text-secondary);font-weight:600;margin-bottom:4px}
.svc-status{font-size:11px}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;display:none;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg-card);border:1px solid var(--border);border-radius:14px;padding:28px;width:400px;max-width:90vw}
.modal h3{font-size:16px;font-weight:700;margin-bottom:8px;color:var(--red)}
.modal p{font-size:13px;color:var(--text-secondary);margin-bottom:20px}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}
.form-label{display:block;font-size:12px;font-weight:600;color:var(--text-secondary);margin-bottom:6px}
.form-input{width:100%;padding:10px 14px;background:#0a0e1a;border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-size:13px}
.uninstall-spinner{display:inline-block;width:18px;height:18px;border:2px solid var(--border);border-top-color:var(--cyan);border-radius:50%;animation:uninstall-spin .7s linear infinite;vertical-align:middle;margin-right:8px}
@keyframes uninstall-spin{to{transform:rotate(360deg)}}
.uninstall-progress-row{display:flex;align-items:center;gap:8px;margin-top:10px;font-size:13px;color:var(--text-secondary)}
body{display:flex;flex-direction:row;min-height:100vh}
.sidebar{width:220px;min-width:220px;background:var(--bg-surface);border-right:1px solid var(--border);padding:24px 0;flex-shrink:0}
.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}
.sidebar-logo span{font-size:15px;font-weight:700}.sidebar-logo small{display:block;font-size:10px;color:var(--text-dim);font-family:'JetBrains Mono',monospace;margin-top:2px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 20px;color:var(--text-secondary);text-decoration:none;font-size:13px;font-weight:500;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{color:var(--text-primary);background:rgba(255,255,255,.03)}
.nav-item.active{color:var(--cyan);background:rgba(6,182,212,.06);border-left-color:var(--cyan)}
.nav-icon{font-size:15px;width:18px;text-align:center}
.main{flex:1;min-width:0;overflow-y:auto;padding:32px;max-width:1000px;margin:0 auto}
</style></head><body>
{{ sidebar_html }}
<div class="main">
<div class="status-banner">
{% if deploying %}
<div class="status-info"><div class="status-icon running" style="background:rgba(59,130,246,0.1)">🔄</div><div><div class="status-text" style="color:var(--accent)">Deploying...</div><div class="status-detail">TAK Portal installation in progress</div></div></div>
{% elif portal.installed and portal.running %}
<div class="status-info"><div class="status-logo-wrap"><span class="material-symbols-outlined" style="font-size:36px">group</span><span class="status-name">TAK Portal</span></div><div><div class="status-text" style="color:var(--green)">Running</div><div class="status-detail">{{ container_info.get('status', 'Docker container active') }}</div></div></div>
<div class="controls">
<button class="control-btn btn-stop" onclick="portalControl('stop')">⏹ Stop</button>
<button class="control-btn" onclick="portalControl('restart')">🔄 Restart</button>
<button class="control-btn btn-update" onclick="portalControl('update')">⬆ Update</button>
</div>
<div style="margin-top:8px;font-size:11px;color:var(--text-dim)">If TAK Portal's in-app "Update Now" fails (e.g. git not found), use ⬆ Update above — it runs on the host and pulls + rebuilds.</div>
{% elif portal.installed %}
<div class="status-info"><div class="status-logo-wrap"><span class="material-symbols-outlined" style="font-size:36px">group</span><span class="status-name">TAK Portal</span></div><div><div class="status-text" style="color:var(--red)">Stopped</div><div class="status-detail">Docker container not running</div></div></div>
<div class="controls">
<button class="control-btn btn-start" onclick="portalControl('start')">▶ Start</button>
<button class="control-btn btn-update" onclick="portalControl('update')">⬆ Update</button>
</div>
<div style="margin-top:8px;font-size:11px;color:var(--text-dim)">If TAK Portal's in-app "Update Now" fails (e.g. git not found), use ⬆ Update above — it runs on the host and pulls + rebuilds.</div>
{% else %}
<div class="status-info"><div class="status-logo-wrap"><span class="material-symbols-outlined" style="font-size:36px">group</span><span class="status-name">TAK Portal</span></div><div><div class="status-text" style="color:var(--text-dim)">Not Installed</div><div class="status-detail">Deploy TAK Portal for user & certificate management</div></div></div>
{% endif %}
</div>

{% if deploying %}
<div class="section-title">Deployment Log</div>
<div class="deploy-log" id="deploy-log">Waiting for deployment to start...</div>
{% elif portal.installed and portal.running %}
<div class="section-title">Access</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="display:flex;gap:10px;flex-wrap:nowrap;align-items:center">
<a href="{{ 'https://takportal.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':' + str(portal_port) }}" target="_blank" class="cert-btn cert-btn-primary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">👥 TAK Portal{% if not settings.get('fqdn') %} :{{ portal_port }}{% endif %}</a>
<a href="{{ 'https://authentik.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':9090' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔐 Authentik{% if not settings.get('fqdn') %} :9090{% endif %}</a>
<a href="{{ 'https://tak.' + settings.get('fqdn') if settings.get('fqdn') else 'https://' + settings.get('server_ip', '') + ':8443' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔐 WebGUI :8443 (cert)</a>
<a href="{{ 'https://tak.' + settings.get('fqdn') if settings.get('fqdn') else 'https://' + settings.get('server_ip', '') + ':8446' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔑 WebGUI :8446 (password)</a>
</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);margin-top:12px">Admin user: <span style="color:var(--cyan)">akadmin</span> · <button type="button" onclick="showAkPassword()" id="ak-pw-btn" style="background:none;border:1px solid var(--border);color:var(--cyan);padding:2px 10px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:11px;cursor:pointer">🔑 Show Password</button> <span id="ak-pw-display" style="color:var(--green);user-select:all;display:none"></span></div>
</div>
<div class="section-title">Configuration</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="font-family:'JetBrains Mono',monospace;font-size:12px;line-height:2">
<div><span style="color:var(--text-dim)">TAK Server:</span> <span style="color:var(--cyan)">{{ 'https://tak.' + settings.get('fqdn') if settings.get('fqdn') else 'https://' + settings.get('server_ip','') + ':8443' }}</span></div>
<div><span style="color:var(--text-dim)">Authentik URL:</span> <span style="color:var(--cyan)">{{ 'https://authentik.' + settings.get('fqdn') if settings.get('fqdn') else 'http://' + settings.get('server_ip','') + ':9090' }}</span></div>
<div><span style="color:var(--text-dim)">Forward Auth:</span> <span style="color:var(--green)">{{ 'Enabled via Caddy' if settings.get('fqdn') else 'Disabled (no FQDN)' }}</span></div>
<div><span style="color:var(--text-dim)">Self-Service Enrollment:</span> <span style="color:var(--cyan)">{{ 'https://takportal.' + settings.get('fqdn') + '/request-access' if settings.get('fqdn') else 'http://' + settings.get('server_ip','') + ':3000/request-access' }}</span></div>
<div style="margin-top:8px;font-size:11px;color:var(--text-dim)">Users created in TAK Portal flow through Authentik → LDAP → TAK Server automatically</div>
</div>
</div>
{% if container_info.get('containers') %}
<div class="section-title">Services</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div class="svc-grid">
{% for c in container_info.containers %}
<div class="svc-card" onclick="filterLogs('{{ c.name }}')" style="cursor:pointer;border-color:{{ 'var(--red)' if 'unhealthy' in c.status else 'var(--green)' if 'Up' in c.status else 'var(--border)' }}" id="svc-{{ c.name }}"><div class="svc-name">{{ c.name }}</div><div class="svc-status" style="color:{{ 'var(--red)' if 'unhealthy' in c.status else 'var(--green)' }}">● {{ c.status }}</div></div>
{% endfor %}
<div class="svc-card" onclick="filterLogs('')" style="cursor:pointer" id="svc-all"><div class="svc-name">all containers</div><div class="svc-status" style="color:var(--text-dim)">● combined</div></div>
</div>
</div>
{% endif %}
<div class="section-title">Container Logs <span id="log-filter-label" style="font-size:11px;color:var(--cyan);margin-left:8px"></span></div>
<div class="deploy-log" id="container-log">Loading logs...</div>
<div style="margin-top:24px;text-align:center">
<button class="control-btn btn-remove" onclick="document.getElementById('portal-uninstall-modal').classList.add('open')">🗑 Remove TAK Portal</button>
</div>
{% elif portal.installed %}
<div style="margin-top:24px;text-align:center">
<button class="control-btn btn-remove" onclick="document.getElementById('portal-uninstall-modal').classList.add('open')">🗑 Remove TAK Portal</button>
</div>
{% else %}
<div class="section-title">About TAK Portal</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--text-secondary);line-height:1.8">
TAK Portal is a lightweight user-management portal that integrates with <span style="color:var(--cyan)">Authentik</span> and <span style="color:var(--cyan)">TAK Server</span> for streamlined certificate and account control.<br><br>
Features: User creation with auto-cert generation, group management, mutual aid coordination, QR code device setup, agency-level access control, email notifications.<br><br>
<span style="color:var(--text-dim)">Requires: Docker · Authentik instance · TAK Server (optional but recommended)</span>
</div>
</div>
<button class="deploy-btn" id="deploy-btn" onclick="deployPortal()">🚀 Deploy TAK Portal</button>
{% if not settings.fqdn %}
<div style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:10px;padding:16px 20px;margin-top:16px;font-size:13px;color:#f87171">
  🔒 <strong>SSL Required</strong> — TAK Portal requires a domain with SSL configured.<br>
  <span style="color:var(--text-dim)">Go to <a href="/caddy" style="color:var(--cyan)">Caddy SSL</a> and configure your domain first.</span>
</div>
{% endif %}
<div class="deploy-log" id="deploy-log" style="display:none">Waiting for deployment to start...</div>
{% endif %}

{% if deploy_done %}
<div style="background:rgba(16,185,129,0.1);border:1px solid var(--border);border-radius:10px;padding:20px;margin-top:20px;text-align:center">
<div style="font-family:'JetBrains Mono',monospace;font-size:14px;color:var(--green);margin-bottom:12px">✓ TAK Portal deployed! Open Server Settings to configure Authentik & TAK Server.</div>
<button onclick="window.location.href='/takportal'" style="padding:10px 24px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer">Refresh Page</button>
</div>
{% endif %}
</div>
<div class="modal-overlay" id="portal-uninstall-modal">
<div class="modal">
<h3>⚠ Uninstall TAK Portal?</h3>
<p>This will remove TAK Portal, its Docker containers, volumes, and data. This cannot be undone.</p>
<label class="form-label">Admin Password</label>
<input class="form-input" id="portal-uninstall-password" type="password" placeholder="Confirm your password">
<div class="modal-actions">
<button type="button" class="control-btn" id="portal-uninstall-cancel" onclick="document.getElementById('portal-uninstall-modal').classList.remove('open')">Cancel</button>
<button type="button" class="control-btn btn-remove" id="portal-uninstall-confirm" onclick="doUninstallPortal()">Uninstall</button>
</div>
<div id="portal-uninstall-msg" style="margin-top:10px;font-size:12px;color:var(--red)"></div>
<div id="portal-uninstall-progress" class="uninstall-progress-row" style="display:none;margin-top:10px" aria-live="polite"></div>
</div>
</div>
<footer class="footer"></footer>
<script>
    var btn=document.getElementById('ak-pw-btn');
    var display=document.getElementById('ak-pw-display');
    if(display.style.display==='inline'){display.style.display='none';btn.textContent='🔑 Show Password';return}
    try{
        var r=await fetch('/api/authentik/password');
        var d=await r.json();
        if(d.password){display.textContent=d.password;display.style.display='inline';btn.textContent='🔑 Hide'}
        else{display.textContent='Not found';display.style.display='inline'}
    }catch(e){display.textContent='Error';display.style.display='inline'}
}
async function portalControl(action){
    var btns=document.querySelectorAll('.control-btn');
    btns.forEach(function(b){b.disabled=true;b.style.opacity='0.5'});
    try{
        var r=await fetch('/api/takportal/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:action})});
        var d=await r.json();
        if(d.success)window.location.href='/takportal';
        else alert('Error: '+(d.error||'Unknown'));
    }catch(e){alert('Error: '+e.message)}
    btns.forEach(function(b){b.disabled=false;b.style.opacity='1'});
}

async function deployPortal(){
    var btn=document.getElementById('deploy-btn');
    btn.disabled=true;btn.textContent='Deploying...';btn.style.opacity='0.7';btn.style.cursor='wait';
    document.getElementById('deploy-log').style.display='block';
    try{
        var r=await fetch('/api/takportal/deploy',{method:'POST',headers:{'Content-Type':'application/json'}});
        var d=await r.json();
        if(d.success)pollDeployLog();
        else{document.getElementById('deploy-log').textContent='\\u2717 '+d.error;btn.disabled=false;btn.textContent='\\ud83d\\ude80 Deploy TAK Portal';btn.style.opacity='1';btn.style.cursor='pointer'}
    }catch(e){document.getElementById('deploy-log').textContent='Error: '+e.message}
}

var logIndex=0;
function pollDeployLog(){
    fetch('/api/takportal/deploy/log?index='+logIndex).then(function(r){return r.json()}).then(function(d){
        var el=document.getElementById('deploy-log');
        if(d.entries.length>0){
            d.entries.forEach(function(e){
                var isTimer=e.trim().charAt(0)==='\u23f3'&&e.indexOf(':')>0;
                if(isTimer){var prev=el.querySelector('[data-timer]');if(prev){prev.textContent=e;logIndex=d.total;return}}
                if(!isTimer){var old=el.querySelector('[data-timer]');if(old)old.removeAttribute('data-timer')}
                var l=document.createElement('div');
                if(isTimer)l.setAttribute('data-timer','1');
                if(e.indexOf('\u2713')>=0)l.style.color='var(--green)';
                else if(e.indexOf('\u2717')>=0||e.indexOf('FATAL')>=0)l.style.color='var(--red)';
                else if(e.indexOf('\u2501\u2501\u2501')>=0)l.style.color='var(--cyan)';
                else if(e.indexOf('===')>=0)l.style.color='var(--green)';
                l.textContent=e;el.appendChild(l);
            });
            logIndex=d.total;el.scrollTop=el.scrollHeight;
        }
        if(d.running)setTimeout(pollDeployLog,1000);
        else if(d.complete){
            var btn=document.getElementById('deploy-btn');
            if(btn){btn.textContent='\u2713 Deployment Complete';btn.style.background='var(--green)';btn.style.opacity='1';btn.style.cursor='default';}
            var el=document.getElementById('deploy-log');
            var fqdn=window.location.hostname.replace(/^[^.]+\./,'');
            var portalUrl='https://takportal.'+fqdn;
            var refreshBtn=document.createElement('button');
            refreshBtn.textContent='\u21bb Refresh Page';
            refreshBtn.style.cssText='display:block;width:100%;padding:12px;margin-top:16px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;';
            refreshBtn.onclick=function(){window.location.href='/takportal';};
            el.appendChild(refreshBtn);
            el.scrollTop=el.scrollHeight;
        }
    });
}

async function loadContainerLogs(){
    var el=document.getElementById('container-log');
    if(!el)return;
    try{
        var r=await fetch('/api/takportal/logs?lines=80');
        var d=await r.json();
        el.textContent='';
        if(d.entries&&d.entries.length>0){
            d.entries.forEach(function(e){
                var l=document.createElement('div');
                if(e.indexOf('error')>=0||e.indexOf('Error')>=0)l.style.color='var(--red)';
                else if(e.indexOf('warn')>=0||e.indexOf('Warn')>=0)l.style.color='var(--yellow)';
                l.textContent=e;el.appendChild(l);
            });
            el.scrollTop=el.scrollHeight;
        }else{el.textContent='No logs available yet.';}
    }catch(e){el.textContent='Failed to load logs';}
}
if(document.getElementById('container-log')){loadContainerLogs();setInterval(loadContainerLogs,10000)}

function uninstallPortal(){
    document.getElementById('portal-uninstall-modal').classList.add('open');
}
async function doUninstallPortal(){
    var pw=document.getElementById('portal-uninstall-password').value;
    if(!pw){document.getElementById('portal-uninstall-msg').textContent='Please enter your password';return;}
    var msgEl=document.getElementById('portal-uninstall-msg');
    var progressEl=document.getElementById('portal-uninstall-progress');
    var cancelBtn=document.getElementById('portal-uninstall-cancel');
    var confirmBtn=document.getElementById('portal-uninstall-confirm');
    msgEl.textContent='';
    progressEl.style.display='flex';
    progressEl.innerHTML='<span class="uninstall-spinner"></span><span>Uninstalling…</span>';
    confirmBtn.disabled=true;
    cancelBtn.disabled=true;
    try{
        var r=await fetch('/api/takportal/uninstall',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
        var d=await r.json();
        if(d.success){
            progressEl.innerHTML='<span class="uninstall-spinner"></span><span>Done. Reloading…</span>';
            setTimeout(function(){window.location.href='/takportal';},800);
        }else{
            msgEl.textContent=d.error||'Uninstall failed';
            progressEl.style.display='none';
            progressEl.innerHTML='';
            confirmBtn.disabled=false;
            cancelBtn.disabled=false;
        }
    }catch(e){
        msgEl.textContent='Request failed: '+e.message;
        progressEl.style.display='none';
        progressEl.innerHTML='';
        confirmBtn.disabled=false;
        cancelBtn.disabled=false;
    }
}

{% if deploying %}pollDeployLog();{% endif %}
</script>
</body></html>'''

# Authentik module
authentik_deploy_log = []
authentik_deploy_status = {'running': False, 'complete': False, 'error': False}

@app.route('/authentik')
@login_required
def authentik_page():
    modules = detect_modules()
    ak = modules.get('authentik', {})
    settings = load_settings()
    # Reset deploy_done once Authentik is running so the running view shows
    if ak.get('installed') and ak.get('running') and not authentik_deploy_status.get('running', False):
        authentik_deploy_status.update({'complete': False, 'error': False})
    container_info = {}
    ak_port = '9090'
    if ak.get('installed'):
        env_path = os.path.expanduser('~/authentik/.env')
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if line.strip().startswith('COMPOSE_PORT_HTTP='):
                        val = line.strip().split('=', 1)[1].strip()
                        if ':' in val: ak_port = val.split(':')[-1]
                        else: ak_port = val or '9090'
    if ak.get('running'):
        r = subprocess.run('docker ps --filter "name=authentik" --format "{{.Names}}|||{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True)
        containers = []
        for line in r.stdout.strip().split('\n'):
            if line.strip():
                parts = line.split('|||')
                containers.append({'name': parts[0], 'status': parts[1] if len(parts) > 1 else ''})
        container_info['containers'] = containers
    modules = detect_modules()
    portal_installed = modules.get('takportal', {}).get('installed', False)
    portal_running = modules.get('takportal', {}).get('running', False)
    all_healthy = ak.get('installed') and ak.get('running') and all(
        'unhealthy' not in c.get('status', '') for c in container_info.get('containers', [])
    ) and len(container_info.get('containers', [])) > 0
    return render_template_string(AUTHENTIK_TEMPLATE,
        settings=settings, ak=ak, container_info=container_info,
        ak_port=ak_port, version=VERSION,
        deploying=authentik_deploy_status.get('running', False),
        deploy_done=authentik_deploy_status.get('complete', False),
        deploy_error=authentik_deploy_status.get('error', False),
        error_log_exists=os.path.exists(os.path.join(CONFIG_DIR, 'authentik_error.log')),
        all_healthy=all_healthy,
        portal_installed=portal_installed,
        portal_running=portal_running)

@app.route('/api/authentik/control', methods=['POST'])
@login_required
def authentik_control():
    action = request.json.get('action')
    ak_dir = os.path.expanduser('~/authentik')
    if action == 'start':
        subprocess.run(f'cd {ak_dir} && docker compose up -d', shell=True, capture_output=True, text=True, timeout=120)
    elif action == 'stop':
        subprocess.run(f'cd {ak_dir} && docker compose down', shell=True, capture_output=True, text=True, timeout=60)
    elif action == 'restart':
        subprocess.run(f'cd {ak_dir} && docker compose down && docker compose up -d', shell=True, capture_output=True, text=True, timeout=120)
    elif action == 'update':
        subprocess.run(f'cd {ak_dir} && docker compose pull && docker compose up -d && docker image prune -f', shell=True, capture_output=True, text=True, timeout=300)
    else:
        return jsonify({'error': 'Invalid action'}), 400
    time.sleep(5)
    r = subprocess.run('docker ps --filter name=authentik-server --format "{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True)
    running = 'Up' in r.stdout
    return jsonify({'success': True, 'running': running, 'action': action})

@app.route('/api/authentik/deploy', methods=['POST'])
@login_required
def authentik_deploy():
    if authentik_deploy_status.get('running'):
        return jsonify({'error': 'Deployment already in progress'}), 409
    authentik_deploy_log.clear()
    authentik_deploy_status.update({'running': True, 'complete': False, 'error': False})
    threading.Thread(target=run_authentik_deploy, args=(False,), daemon=True).start()
    return jsonify({'success': True})

@app.route('/api/authentik/reconfigure', methods=['POST'])
@login_required
def authentik_reconfigure():
    """Re-run LDAP/CoreConfig/forward-auth setup without removing anything. Use when TAK Server was deployed after Authentik."""
    if authentik_deploy_status.get('running'):
        return jsonify({'error': 'Deployment already in progress'}), 409
    if not os.path.exists(os.path.expanduser('~/authentik/docker-compose.yml')):
        return jsonify({'error': 'Authentik not installed. Deploy Authentik first.'}), 400
    authentik_deploy_log.clear()
    authentik_deploy_status.update({'running': True, 'complete': False, 'error': False})
    threading.Thread(target=run_authentik_deploy, args=(True,), daemon=True).start()
    return jsonify({'success': True})

@app.route('/api/authentik/deploy/log')
@login_required
def authentik_deploy_log_api():
    idx = request.args.get('index', 0, type=int)
    return jsonify({'entries': authentik_deploy_log[idx:], 'total': len(authentik_deploy_log),
        'running': authentik_deploy_status['running'], 'complete': authentik_deploy_status['complete'],
        'error': authentik_deploy_status['error']})

@app.route('/api/authentik/logs')
@login_required
def authentik_container_logs():
    lines = request.args.get('lines', 50, type=int)
    container = request.args.get('container', '').strip()
    if container:
        r = subprocess.run(f'docker logs {container} --tail {lines} 2>&1', shell=True, capture_output=True, text=True, timeout=10)
    else:
        r = subprocess.run(f'cd ~/authentik && docker compose logs --tail {lines} 2>&1', shell=True, capture_output=True, text=True, timeout=10)
    entries = r.stdout.strip().split('\n') if r.stdout.strip() else []
    return jsonify({'entries': entries})

@app.route('/api/authentik/password')
@login_required
def authentik_password():
    env_path = os.path.expanduser('~/authentik/.env')
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                if line.strip().startswith('AUTHENTIK_BOOTSTRAP_PASSWORD='):
                    return jsonify({'password': line.strip().split('=', 1)[1].strip()})
    return jsonify({'error': 'Password not found'}), 404

@app.route('/api/authentik/error-log')
@login_required
def authentik_error_log():
    from flask import send_file
    error_log_path = os.path.join(CONFIG_DIR, 'authentik_error.log')
    if os.path.exists(error_log_path):
        return send_file(error_log_path, as_attachment=True, download_name='authentik_error.log', mimetype='text/plain')
    return jsonify({'error': 'No error log found'}), 404

@app.route('/api/authentik/uninstall', methods=['POST'])
@login_required
def authentik_uninstall():
    data = request.json or {}
    password = data.get('password', '')
    auth = load_auth()
    if not auth.get('password_hash') or not check_password_hash(auth['password_hash'], password):
        return jsonify({'error': 'Invalid admin password'}), 403
    ak_dir = os.path.expanduser('~/authentik')
    steps = []
    if os.path.exists(ak_dir):
        r = subprocess.run(f'cd {ak_dir} && docker compose down -v --rmi all --remove-orphans 2>&1', shell=True, capture_output=True, text=True, timeout=180)
        steps.append('Stopped and removed Docker containers/volumes/images')
        if r.returncode != 0:
            steps.append(f'(compose reported: {(r.stderr or r.stdout or "").strip()[:200]})')
        subprocess.run(f'rm -rf {ak_dir}', shell=True, capture_output=True)
        steps.append('Removed ~/authentik')
    else:
        steps.append('~/authentik not found (already removed)')
    authentik_deploy_log.clear()
    authentik_deploy_status.update({'running': False, 'complete': False, 'error': False})
    return jsonify({'success': True, 'steps': steps})


def run_authentik_deploy(reconfigure=False):
    def plog(msg):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        authentik_deploy_log.append(entry)
        print(entry, flush=True)
    try:
        ak_dir = os.path.expanduser('~/authentik')
        settings = load_settings()
        server_ip = settings.get('server_ip', 'localhost')
        env_path = os.path.join(ak_dir, '.env')
        compose_path = os.path.join(ak_dir, 'docker-compose.yml')
        ldap_svc_pass = None

        if reconfigure:
            if not os.path.exists(ak_dir) or not os.path.exists(env_path) or not os.path.exists(compose_path):
                plog("\u2717 Authentik not fully installed. Run a full Deploy first.")
                authentik_deploy_status.update({'running': False, 'error': True})
                return
            with open(env_path) as f:
                for line in f:
                    if line.strip().startswith('AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD='):
                        ldap_svc_pass = line.strip().split('=', 1)[1].strip()
                        break
            plog("\u2501\u2501\u2501 Reconfigure: Updating LDAP, CoreConfig, Forward Auth (no removal) \u2501\u2501\u2501")
            subprocess.run(f'cd {ak_dir} && docker compose up -d 2>&1', shell=True, capture_output=True, text=True, timeout=120)
            plog("  Ensured containers are up")
        else:
            if settings.get('pkg_mgr', 'apt') == 'apt':
                wait_for_apt_lock(plog, authentik_deploy_log)

            # Step 1: Check Docker
            plog("\u2501\u2501\u2501 Step 1/10: Checking Docker \u2501\u2501\u2501")
            r = subprocess.run('docker --version', shell=True, capture_output=True, text=True)
            if r.returncode != 0:
                plog("Docker not found. Installing...")
                subprocess.run('curl -fsSL https://get.docker.com | sh', shell=True, capture_output=True, text=True, timeout=300)
                r2 = subprocess.run('docker --version', shell=True, capture_output=True, text=True)
                if r2.returncode != 0:
                    plog("\u2717 Failed to install Docker")
                    authentik_deploy_status.update({'running': False, 'error': True})
                    return
                plog(f"  {r2.stdout.strip()}")
            else:
                plog(f"  {r.stdout.strip()}")
            plog("\u2713 Docker available")

            # Step 2: Create directory
            plog("")
            plog("\u2501\u2501\u2501 Step 2/10: Setting Up Directory \u2501\u2501\u2501")
            os.makedirs(ak_dir, exist_ok=True)
            plog(f"  Directory: {ak_dir}")
            plog("\u2713 Directory ready")

            # Step 3: Generate secrets and .env
            plog("")
            plog("\u2501\u2501\u2501 Step 3/10: Generating Configuration \u2501\u2501\u2501")
            ldap_svc_pass = None
            if not os.path.exists(env_path):
                pg_pass = subprocess.run('openssl rand -base64 36 | tr -d "\\n"', shell=True, capture_output=True, text=True).stdout.strip()[:90]
                secret_key = subprocess.run('openssl rand -hex 32', shell=True, capture_output=True, text=True).stdout.strip()
                ldap_svc_pass = subprocess.run('openssl rand -base64 24 | tr -d "\\n"', shell=True, capture_output=True, text=True).stdout.strip()
                bootstrap_pass = subprocess.run('openssl rand -base64 18 | tr -d "\\n"', shell=True, capture_output=True, text=True).stdout.strip()
                bootstrap_token = subprocess.run('openssl rand -hex 32', shell=True, capture_output=True, text=True).stdout.strip()
                env_content = f"""PG_DB=authentik
PG_USER=authentik
PG_PASS={pg_pass}
AUTHENTIK_SECRET_KEY={secret_key}
COMPOSE_PORT_HTTP=9090
COMPOSE_PORT_HTTPS=9443
AUTHENTIK_ERROR_REPORTING__ENABLED=false
# Bootstrap (first run only - sets akadmin password and API token)
AUTHENTIK_BOOTSTRAP_PASSWORD={bootstrap_pass}
AUTHENTIK_BOOTSTRAP_TOKEN={bootstrap_token}
AUTHENTIK_BOOTSTRAP_EMAIL=admin@takwerx.local
# LDAP Blueprint Configuration
AUTHENTIK_BOOTSTRAP_LDAPSERVICE_USERNAME=adm_ldapservice
AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD={ldap_svc_pass}
AUTHENTIK_BOOTSTRAP_LDAP_BASEDN=DC=takldap
AUTHENTIK_BOOTSTRAP_LDAP_AUTHENTIK_HOST=http://authentik-server-1:9000/
# Embedded outpost host — prevents 0.0.0.0:9000 redirect issue
AUTHENTIK_HOST=https://authentik.{settings.get("fqdn") or server_ip}
# Email Configuration (uncomment and configure)
# AUTHENTIK_EMAIL__HOST=smtp.example.com
# AUTHENTIK_EMAIL__PORT=587
# AUTHENTIK_EMAIL__USERNAME=
# AUTHENTIK_EMAIL__PASSWORD=
# AUTHENTIK_EMAIL__USE_TLS=true
# AUTHENTIK_EMAIL__FROM=authentik@example.com
"""
                with open(env_path, 'w') as f:
                    f.write(env_content)
                plog("  Generated PostgreSQL password")
                plog("  Generated secret key")
                plog(f"  Generated LDAP service account password")
                plog("\u2713 .env created")
            else:
                plog("\u2713 .env already exists")
                # Read existing ldap password
                with open(env_path) as f:
                    for line in f:
                        if line.strip().startswith('AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD='):
                            ldap_svc_pass = line.strip().split('=', 1)[1].strip()

            # Step 4: Create LDAP blueprint
            plog("")
            plog("\u2501\u2501\u2501 Step 4/10: Installing LDAP Blueprint \u2501\u2501\u2501")
            bp_dir = os.path.join(ak_dir, 'blueprints')
            os.makedirs(bp_dir, exist_ok=True)
            bp_path = os.path.join(bp_dir, 'tak-ldap-setup.yaml')
            bp_content = """version: 1
metadata:
  name: LDAP Setup for TAK
  labels:
    blueprints.goauthentik.io/description: |
      Configures LDAP service account, provider, and outpost for TAK Server.
    blueprints.goauthentik.io/depends-on: "default-flows,default-stages"
context:
  username: !Env [AUTHENTIK_BOOTSTRAP_LDAPSERVICE_USERNAME, 'adm_ldapservice']
  password: !Env [AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD, null]
  basedn: !Env [AUTHENTIK_BOOTSTRAP_LDAP_BASEDN, 'DC=takldap']
  authentik_host: !Env [AUTHENTIK_BOOTSTRAP_LDAP_AUTHENTIK_HOST, 'http://localhost:9000/']
entries:
  - model: authentik_blueprints.metaapplyblueprint
    attrs:
      identifiers:
        name: Default - Invalidation flow
      required: true
  - model: authentik_blueprints.metaapplyblueprint
    attrs:
      identifiers:
        name: Default - Password change flow
      required: true
  - model: authentik_blueprints.metaapplyblueprint
    attrs:
      identifiers:
        name: Default - Authentication flow
      required: true
  - model: authentik_core.user
    state: created
    id: ldap-service-account
    identifiers:
      username: !Context username
    attrs:
      name: LDAP Service account
      type: service_account
      password: !Context password
  - attrs:
      authentication: require_outpost
      denied_action: message_continue
      designation: authentication
      layout: stacked
      name: ldap-authentication-flow
      policy_engine_mode: any
      title: ldap-authentication-flow
    identifiers:
      slug: ldap-authentication-flow
    model: authentik_flows.flow
    state: present
    id: ldap-authentication-flow
  - attrs:
      backends:
      - authentik.core.auth.InbuiltBackend
      - authentik.core.auth.TokenBackend
      - authentik.sources.ldap.auth.LDAPBackend
      configure_flow: !Find [authentik_flows.flow, [slug, default-password-change]]
      failed_attempts_before_cancel: 5
    identifiers:
      name: ldap-authentication-password
    model: authentik_stages_password.passwordstage
    state: present
    id: ldap-authentication-password
  - attrs:
      case_insensitive_matching: true
      password_stage: !KeyOf ldap-authentication-password
      pretend_user_exists: true
      show_matched_user: true
      user_fields:
      - username
      - email
    identifiers:
      name: ldap-identification-stage
    model: authentik_stages_identification.identificationstage
    state: present
    id: ldap-identification-stage
  - attrs:
      geoip_binding: bind_continent
      network_binding: bind_asn
      remember_me_offset: seconds=0
      session_duration: seconds=0
    identifiers:
      name: ldap-authentication-login
    model: authentik_stages_user_login.userloginstage
    state: present
    id: ldap-authentication-login
  - attrs:
      evaluate_on_plan: true
      invalid_response_action: retry
      policy_engine_mode: any
      re_evaluate_policies: true
    identifiers:
      order: 10
      stage: !KeyOf ldap-identification-stage
      target: !KeyOf ldap-authentication-flow
    model: authentik_flows.flowstagebinding
    state: present
    id: ldap-identification-stage-flow-binding
  - attrs:
      evaluate_on_plan: true
      invalid_response_action: retry
      policy_engine_mode: any
      re_evaluate_policies: true
    identifiers:
      order: 15
      stage: !KeyOf ldap-authentication-password
      target: !KeyOf ldap-authentication-flow
    model: authentik_flows.flowstagebinding
    state: present
    id: ldap-authentication-password-binding
  - attrs:
      evaluate_on_plan: true
      invalid_response_action: retry
      policy_engine_mode: any
      re_evaluate_policies: true
    identifiers:
      order: 20
      stage: !KeyOf ldap-authentication-login
      target: !KeyOf ldap-authentication-flow
    model: authentik_flows.flowstagebinding
    state: present
    id: ldap-authentication-login-binding
  - model: authentik_providers_ldap.ldapprovider
    id: provider
    state: present
    identifiers:
      name: LDAP
    attrs:
      authorization_flow: !KeyOf ldap-authentication-flow
      base_dn: !Context basedn
      bind_mode: cached
      gid_start_number: 4000
      invalidation_flow: !Find [authentik_flows.flow, [slug, default-invalidation-flow]]
      mfa_support: false
      name: Provider for LDAP
      search_mode: cached
      uid_start_number: 2000
    permissions:
      - permission: search_full_directory
        user: !KeyOf ldap-service-account
  - model: authentik_core.application
    id: app
    state: present
    identifiers:
      slug: ldap
    attrs:
      name: LDAP
      policy_engine_mode: any
      provider: !KeyOf provider
  - model: authentik_outposts.outpost
    id: outpost
    state: present
    identifiers:
      name: LDAP
    attrs:
      config:
        authentik_host: !Context authentik_host
      providers:
      - !KeyOf provider
      type: ldap
"""
            with open(bp_path, 'w') as f:
                f.write(bp_content)
            plog("  Created tak-ldap-setup.yaml blueprint")
            plog("  LDAP service account: adm_ldapservice")
            plog("  LDAP Base DN: DC=takldap")

            # Create embedded outpost blueprint to permanently set authentik_host
            bp_embedded_path = os.path.join(bp_dir, 'tak-embedded-outpost.yaml')
            bp_embedded_content = f"""version: 1
metadata:
  name: TAK Embedded Outpost Config
  labels:
    blueprints.goauthentik.io/description: Sets authentik_host for embedded outpost
entries:
  - model: authentik_outposts.outpost
    state: present
    identifiers:
      managed: goauthentik.io/outposts/embedded
    attrs:
      config:
        authentik_host: https://authentik.{settings.get('fqdn') or server_ip}
        authentik_host_insecure: false
"""
            with open(bp_embedded_path, 'w') as f:
                f.write(bp_embedded_content)
            plog("  Created tak-embedded-outpost.yaml blueprint")
            plog("\u2713 Blueprint ready")

            # Step 5: Download docker-compose.yml and patch for blueprints
            plog("")
            plog("\u2501\u2501\u2501 Step 5/10: Downloading Docker Compose File \u2501\u2501\u2501")
            if not os.path.exists(compose_path):
                r = subprocess.run(f'wget -q -O {compose_path} https://goauthentik.io/docker-compose.yml 2>&1', shell=True, capture_output=True, text=True, timeout=30)
                if r.returncode != 0 or not os.path.exists(compose_path):
                    plog("\u2717 Failed to download docker-compose.yml")
                    authentik_deploy_status.update({'running': False, 'error': True})
                    return
                plog("\u2713 docker-compose.yml downloaded")
            else:
                plog("\u2713 docker-compose.yml already exists")

            # Step 6: Patch docker-compose for blueprints + LDAP container
            plog("")
            plog("\u2501\u2501\u2501 Step 6/10: Patching Docker Compose \u2501\u2501\u2501")
            with open(compose_path, 'r') as f:
                lines = f.readlines()
            needs_write = False
            # Add blueprint volume mounts
            if not any('blueprints/custom' in l for l in lines):
                patched = []
                for line in lines:
                    patched.append(line)
                    if './custom-templates:/templates' in line:
                        indent = line[:len(line) - len(line.lstrip())]
                        patched.append(f'{indent}- ./blueprints:/blueprints/custom\n')
                lines = patched
                needs_write = True
                plog("  Added blueprint mount to server & worker")
            # Add POSTGRES_MAX_CONNECTIONS
            if not any('POSTGRES_MAX_CONNECTIONS' in l for l in lines):
                patched = []
                for line in lines:
                    patched.append(line)
                    if 'POSTGRES_USER:' in line:
                        indent = line[:len(line) - len(line.lstrip())]
                        patched.append(f'{indent}POSTGRES_MAX_CONNECTIONS: "200"\n')
                lines = patched
                needs_write = True
                plog("  Added POSTGRES_MAX_CONNECTIONS to postgresql")

            # Add LDAP outpost container
            if not any('ghcr.io/goauthentik/ldap' in l for l in lines):
                ldap_svc = "  ldap:\n    image: ghcr.io/goauthentik/ldap:2025.12.4\n    ports:\n    - 389:3389\n    - 636:6636\n    environment:\n      AUTHENTIK_HOST: http://authentik-server-1:9000\n      AUTHENTIK_INSECURE: \"true\"\n      AUTHENTIK_TOKEN: placeholder\n    restart: unless-stopped\n"
                new_lines = []
                for line in lines:
                    if line.startswith('volumes:'):
                        new_lines.append(ldap_svc)
                    new_lines.append(line)
                lines = new_lines
                needs_write = True
                plog("  Added LDAP outpost container")
            if needs_write:
                with open(compose_path, 'w') as f:
                    f.writelines(lines)
                plog("\u2713 Docker Compose patched")
            else:
                plog("\u2713 Docker Compose already patched")

            # Step 7: Pull and start core services (no verbose docker output in log)
            plog("")
            plog("\u2501\u2501\u2501 Step 7/10: Pulling Images & Starting Containers \u2501\u2501\u2501")
            plog("  Pulling images (this may take a few minutes)...")
            r = subprocess.run(f'cd {ak_dir} && docker compose pull 2>&1', shell=True, capture_output=True, text=True, timeout=600)
            if r.returncode != 0:
                plog(f"  \u26a0 Pull had issues: {r.stderr.strip()[:200] if r.stderr else r.stdout.strip()[:200]}")
            else:
                plog("  \u2713 Images pulled")
            plog("  Starting core services...")
            r = subprocess.run(f'cd {ak_dir} && docker compose up -d postgresql server worker 2>&1', shell=True, capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                plog(f"  \u26a0 Start had issues: {r.stderr.strip()[:200] if r.stderr else r.stdout.strip()[:200]}")
            else:
                plog("  \u2713 Core services started")

        # Step 8: Wait for Authentik API to be ready
        plog("")
        plog("\u2501\u2501\u2501 Step 8/12: Waiting for Authentik API \u2501\u2501\u2501")
        bootstrap_token = None
        with open(env_path) as f:
            for line in f:
                if line.strip().startswith('AUTHENTIK_BOOTSTRAP_TOKEN='):
                    bootstrap_token = line.strip().split('=', 1)[1].strip()
        if not bootstrap_token:
            plog("\u26a0 No bootstrap token found in .env")
        else:
            import urllib.request
            import urllib.error
            import json as json_mod
            api_ready = False
            for attempt in range(90):
                try:
                    req = urllib.request.Request(
                        'http://127.0.0.1:9090/api/v3/core/users/',
                        headers={'Authorization': f'Bearer {bootstrap_token}'}
                    )
                    resp = urllib.request.urlopen(req, timeout=5)
                    json_mod.loads(resp.read().decode())
                    api_ready = True
                    plog("✓ Authentik API is ready")
                    break
                except urllib.error.HTTPError as http_err:
                    # Any HTTP response (401, 403) means API is up and responding
                    if http_err.code in (401, 403):
                        plog(f"✓ Authentik API is ready (HTTP {http_err.code})")
                        api_ready = True
                        break
                    elif http_err.code == 503:
                        if attempt % 12 == 0:
                            em, es = divmod(attempt * 5, 60)
                            plog(f"  Server starting up (503)... ({em}m {es}s elapsed)")
                    else:
                        if attempt % 12 == 0:
                            em, es = divmod(attempt * 5, 60)
                            plog(f"  HTTP {http_err.code}... ({em}m {es}s elapsed)")
                except Exception as poll_err:
                    err_str = str(poll_err)
                    if attempt == 0:
                        plog("  Waiting for Authentik (first boot takes 5-7 minutes)...")
                    elif attempt % 12 == 0:
                        em, es = divmod(attempt * 5, 60)
                        plog(f"  Still waiting... {em}m {es}s elapsed ({err_str[:60]})")
                time.sleep(5)
            if not api_ready:
                plog("⚠ API timeout - check Authentik logs")

        # Step 9: Start LDAP outpost (placeholder token — Step 11 will inject real token and recreate)
        plog("")
        plog("\u2501\u2501\u2501 Step 9/12: Starting LDAP Outpost \u2501\u2501\u2501")
        r = subprocess.run(f'cd {ak_dir} && docker compose up -d ldap 2>&1', shell=True, capture_output=True, text=True, timeout=120)
        for line in (r.stdout or '').strip().split('\n'):
            if line.strip() and 'NEEDRESTART' not in line:
                authentik_deploy_log.append(f"  {line.strip()}")
        plog("  Waiting for LDAP to start...")
        time.sleep(15)
        r2 = subprocess.run('docker logs authentik-ldap-1 2>&1 | tail -3', shell=True, capture_output=True, text=True)
        if r2.stdout and ('Starting LDAP server' in r2.stdout or 'Starting authentik outpost' in r2.stdout):
            plog("\u2713 LDAP outpost is running on port 389")
        else:
            plog("\u26a0 LDAP will be recreated with real token in Step 11")

        # Step 10: Patch CoreConfig.xml for LDAP
        plog("")
        plog("\u2501\u2501\u2501 Step 10/12: Connecting TAK Server to LDAP \u2501\u2501\u2501")
        coreconfig_path = '/opt/tak/CoreConfig.xml'
        if os.path.exists(coreconfig_path):
            # Read LDAP service password
            ldap_pass = ldap_svc_pass or ''
            if not ldap_pass:
                with open(env_path) as f:
                    for line in f:
                        if line.strip().startswith('AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD='):
                            ldap_pass = line.strip().split('=', 1)[1].strip()

            if ldap_pass:
                # Backup
                backup_path = coreconfig_path + '.pre-ldap.bak'
                if not os.path.exists(backup_path):
                    import shutil
                    shutil.copy2(coreconfig_path, backup_path)
                    plog(f"  Backed up CoreConfig.xml")

                # Read current config
                with open(coreconfig_path, 'r') as f:
                    config_content = f.read()

                # Build the new auth block
                auth_block = (
                    '    <auth default="ldap" x509groups="true" x509addAnonymous="false"'
                    ' x509useGroupCache="true" x509useGroupCacheDefaultActive="true"'
                    ' x509checkRevocation="true">\n'
                    '        <File location="UserAuthenticationFile.xml"/>\n'
                    '        <ldap url="ldap://127.0.0.1:389"'
                    ' userstring="cn={username},ou=users,dc=takldap"'
                    ' updateinterval="60"'
                    ' groupprefix="cn=tak_"'
                    ' groupNameExtractorRegex="cn=tak_(.*?)(?:,|$)"'
                    ' matchGroupInChain="true"'
                    f' serviceAccountDN="cn=adm_ldapservice,ou=users,dc=takldap"'
                    f' serviceAccountCredential="{ldap_pass}"'
                    ' groupBaseRDN="ou=groups,dc=takldap"'
                    ' userBaseRDN="ou=users,dc=takldap"'
                    ' groupObjectClass="group" userObjectClass="user"'
                    ' style="DS" ldapSecurityType="simple"'
                    ' dnAttributeName="DN"'
                    ' nameAttr="CN" roleAttribute="memberOf" adminGroup="ROLE_ADMIN"/>\n'
                    '    </auth>'
                )

                # Replace auth block using regex
                import re
                new_content = re.sub(
                    r'    <auth[^>]*>.*?</auth>',
                    auth_block,
                    config_content,
                    flags=re.DOTALL
                )

                if new_content != config_content:
                    with open(coreconfig_path, 'w') as f:
                        f.write(new_content)
                    plog("\u2713 CoreConfig.xml updated with LDAP auth")
                    plog("  - Nested groups enabled (matchGroupInChain)")
                    plog("  - Group cache enabled (x509useGroupCacheDefaultActive)")
                    plog("  - Group prefix: tak_")

                    # Restart TAK Server
                    plog("  Restarting TAK Server...")
                    r = subprocess.run('systemctl restart takserver 2>&1', shell=True, capture_output=True, text=True, timeout=60)
                    if r.returncode == 0:
                        plog("\u2713 TAK Server restarted")
                    else:
                        plog(f"\u26a0 TAK Server restart issue: {r.stderr.strip()[:100]}")
                else:
                    plog("\u2713 CoreConfig.xml already has LDAP auth configured")
            else:
                plog("\u26a0 LDAP service password not found, skipping CoreConfig patch")
        else:
            plog("  ℹ TAK Server not installed — skipping CoreConfig (OK for MediaMTX-only or standalone Authentik)")
            plog("  Deploy TAK Server later, then use Update config & reconnect to add LDAP")

        # Step 11/12: Create admin group and webadmin user in Authentik
        plog("")
        plog("\u2501\u2501\u2501 Step 11/12: Creating Admin Group & WebAdmin User \u2501\u2501\u2501")
        try:
            # Read bootstrap token
            ak_token = ''
            with open(env_path) as f:
                for line in f:
                    if line.strip().startswith('AUTHENTIK_BOOTSTRAP_TOKEN='):
                        ak_token = line.strip().split('=', 1)[1].strip()
            if ak_token:
                ak_headers = {'Authorization': f'Bearer {ak_token}', 'Content-Type': 'application/json'}
                ak_url = f'http://127.0.0.1:9090'
                import urllib.request

                # Verify bootstrap token actually works before proceeding
                # The worker runs apply_blueprint system/bootstrap.yaml before starting
                # which creates the token — this can take 1-3 minutes on first start
                plog("  Waiting for worker to apply bootstrap blueprint...")
                token_ok = False
                attempt = 0
                while True:
                    try:
                        req = urllib.request.Request(f'{ak_url}/api/v3/core/users/',
                            headers=ak_headers)
                        resp = urllib.request.urlopen(req, timeout=10)
                        json.loads(resp.read().decode())
                        token_ok = True
                        m, s = divmod(attempt * 5, 60)
                        plog(f"  ✓ Bootstrap token active (waited {m}m {s}s)")
                        break
                    except urllib.error.HTTPError as e:
                        if e.code == 403:
                            if attempt % 6 == 0:
                                m, s = divmod(attempt * 5, 60)
                                plog(f"  ⏳ Worker still applying bootstrap... ({m}m {s}s)")
                            else:
                                authentik_deploy_log.append(f"  ⏳ {attempt * 5 // 60:02d}:{attempt * 5 % 60:02d}")
                            time.sleep(5)
                            attempt += 1
                        else:
                            plog(f"  ⚠ Token check unexpected error: {e.code} — giving up")
                            break
                    except Exception as e:
                        plog(f"  ⚠ Token check error: {str(e)[:80]} — giving up")
                        break

                # Create tak_ROLE_ADMIN group
                try:
                    req = urllib.request.Request(f'{ak_url}/api/v3/core/groups/',
                        data=json.dumps({'name': 'tak_ROLE_ADMIN', 'is_superuser': False}).encode(),
                        headers=ak_headers, method='POST')
                    resp = urllib.request.urlopen(req, timeout=10)
                    group_data = json.loads(resp.read().decode())
                    group_pk = group_data['pk']
                    plog("  ✓ Created tak_ROLE_ADMIN group")
                except urllib.error.HTTPError as e:
                    if e.code == 400:
                        plog("  ✓ tak_ROLE_ADMIN group already exists")
                        # Get existing group PK
                        req = urllib.request.Request(f'{ak_url}/api/v3/core/groups/?search=tak_ROLE_ADMIN',
                            headers=ak_headers)
                        resp = urllib.request.urlopen(req, timeout=10)
                        results = json.loads(resp.read().decode())['results']
                        group_pk = results[0]['pk'] if results else None
                    elif e.code == 403:
                        plog(f"  ⚠ 403 on group creation — bootstrap token may lack permissions, continuing anyway")
                        group_pk = None
                    else:
                        plog(f"  ⚠ Group creation error: {e.code} — continuing")
                        group_pk = None

                # Create webadmin user in Authentik (only when TAK Server is deployed — used for TAK Server admin)
                webadmin_pass = ''
                if os.path.exists('/opt/tak'):
                    # Read password from TAK Server settings or use default
                    tak_settings_path = os.path.join(CONFIG_DIR, 'settings.json')
                    if os.path.exists(tak_settings_path):
                        with open(tak_settings_path) as f:
                            tak_s = json.load(f)
                            webadmin_pass = tak_s.get('webadmin_password', '')
                    if not webadmin_pass:
                        webadmin_pass = 'TakserverAtak1!'
                        plog(f"  ⚠ webadmin_password not found in settings.json — using default: TakserverAtak1!")
                else:
                    plog("  ℹ TAK Server not installed — skipping webadmin user (optional; used for TAK Server admin)")

                if webadmin_pass:
                    try:
                        user_data = {'username': 'webadmin', 'name': 'TAK Admin', 'is_active': True,
                            'groups': [group_pk] if group_pk else []}
                        req = urllib.request.Request(f'{ak_url}/api/v3/core/users/',
                            data=json.dumps(user_data).encode(), headers=ak_headers, method='POST')
                        resp = urllib.request.urlopen(req, timeout=10)
                        user = json.loads(resp.read().decode())
                        webadmin_pk = user['pk']
                        plog(f"  ✓ Created webadmin user (pk={webadmin_pk})")
                    except urllib.error.HTTPError as e:
                        if e.code == 400:
                            plog("  ✓ webadmin user already exists")
                            # Get existing user PK and add to group
                            req = urllib.request.Request(f'{ak_url}/api/v3/core/users/?search=webadmin',
                                headers=ak_headers)
                            resp = urllib.request.urlopen(req, timeout=10)
                            results = json.loads(resp.read().decode())['results']
                            webadmin_pk = results[0]['pk'] if results else None
                            if webadmin_pk and group_pk:
                                req = urllib.request.Request(f'{ak_url}/api/v3/core/users/{webadmin_pk}/',
                                    data=json.dumps({'groups': [group_pk]}).encode(),
                                    headers=ak_headers, method='PATCH')
                                try:
                                    urllib.request.urlopen(req, timeout=10)
                                    plog("  ✓ Added webadmin to tak_ROLE_ADMIN group")
                                except Exception:
                                    pass
                        else:
                            plog(f"  ⚠ webadmin user error: {e.code} — continuing")
                            webadmin_pk = None

                    # Set webadmin password
                    if webadmin_pk:
                        try:
                            req = urllib.request.Request(f'{ak_url}/api/v3/core/users/{webadmin_pk}/set_password/',
                                data=json.dumps({'password': webadmin_pass}).encode(),
                                headers=ak_headers, method='POST')
                            urllib.request.urlopen(req, timeout=10)
                            plog(f"  ✓ Set webadmin password")
                        except Exception as e:
                            plog(f"  ⚠ Could not set webadmin password: {str(e)[:100]}")

                    # Create or get adm_ldapservice user
                    ldap_svc_password = ''
                    with open(env_path) as f:
                        for line in f:
                            if line.strip().startswith('AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD='):
                                ldap_svc_password = line.strip().split('=', 1)[1].strip()
                    if not ldap_svc_password:
                        ldap_svc_password = 'B9wobRV8wlFJmnlEWB71gJjD3aoKOBBW'

                    ldap_pk = None
                    try:
                        req = urllib.request.Request(f'{ak_url}/api/v3/core/users/',
                            data=json.dumps({'username': 'adm_ldapservice', 'name': 'LDAP Service Account',
                                'is_active': True, 'type': 'service_account'}).encode(),
                            headers=ak_headers, method='POST')
                        resp = urllib.request.urlopen(req, timeout=10)
                        ldap_pk = json.loads(resp.read().decode())['pk']
                        plog(f"  ✓ Created adm_ldapservice (pk={ldap_pk})")
                    except urllib.error.HTTPError as e:
                        if e.code == 400:
                            req = urllib.request.Request(f'{ak_url}/api/v3/core/users/?search=adm_ldapservice',
                                headers=ak_headers)
                            resp = urllib.request.urlopen(req, timeout=10)
                            results = json.loads(resp.read().decode())['results']
                            ldap_pk = next((u['pk'] for u in results if u['username'] == 'adm_ldapservice'), None)
                            plog(f"  ✓ adm_ldapservice already exists (pk={ldap_pk})")
                        else:
                            plog(f"  ⚠ Could not create adm_ldapservice: {e.code}")

                    if ldap_pk:
                        try:
                            req = urllib.request.Request(f'{ak_url}/api/v3/core/users/{ldap_pk}/set_password/',
                                data=json.dumps({'password': ldap_svc_password}).encode(),
                                headers=ak_headers, method='POST')
                            urllib.request.urlopen(req, timeout=10)
                            plog(f"  ✓ Set adm_ldapservice password")
                        except Exception as e:
                            plog(f"  ⚠ Could not set adm_ldapservice password: {str(e)[:100]}")

                # Create LDAP provider + outpost + inject token — ALWAYS RUN (required for MediaMTX, TAK Server, standalone)
                try:
                    # Get default invalidation flow
                    req = urllib.request.Request(f'{ak_url}/api/v3/flows/instances/?designation=invalidation',
                        headers=ak_headers)
                    resp = urllib.request.urlopen(req, timeout=10)
                    inv_flows = json.loads(resp.read().decode())['results']
                    inv_flow_pk = next((f['pk'] for f in inv_flows if 'invalidation' in f['slug'] and 'provider' not in f['slug']), inv_flows[0]['pk'] if inv_flows else None)
                    plog(f"  ✓ Got invalidation flow: {inv_flow_pk}")

                    # Get default authentication flow - wait until ready
                    auth_flow_pk = None
                    attempt = 0
                    while True:
                        req = urllib.request.Request(f'{ak_url}/api/v3/flows/instances/?designation=authentication',
                            headers=ak_headers)
                        resp = urllib.request.urlopen(req, timeout=10)
                        auth_flows = json.loads(resp.read().decode())['results']
                        auth_flow_pk = next((f['pk'] for f in auth_flows if f['slug'] == 'default-authentication-flow'),
                                           next((f['pk'] for f in auth_flows), None))
                        if auth_flow_pk:
                            plog(f"  ✓ Got authentication flow: {auth_flow_pk}")
                            break
                        if attempt % 6 == 0:
                            plog(f"  ⏳ Waiting for authentication flows... ({attempt * 5}s)")
                        else:
                            authentik_deploy_log.append(f"  ⏳ {attempt * 5 // 60:02d}:{attempt * 5 % 60:02d}")
                        time.sleep(5)
                        attempt += 1

                    if not auth_flow_pk or not inv_flow_pk:
                        plog(f"  ✗ Missing flows — auth={auth_flow_pk} inv={inv_flow_pk}")
                    else:
                        # Create LDAP provider
                        ldap_provider_pk = None
                        try:
                            req = urllib.request.Request(f'{ak_url}/api/v3/providers/ldap/',
                                data=json.dumps({'name': 'LDAP', 'authentication_flow': auth_flow_pk,
                                    'authorization_flow': auth_flow_pk, 'invalidation_flow': inv_flow_pk,
                                    'base_dn': 'DC=takldap', 'bind_mode': 'cached',
                                    'search_mode': 'cached', 'mfa_support': False}).encode(),
                                headers=ak_headers, method='POST')
                            resp = urllib.request.urlopen(req, timeout=10)
                            ldap_provider_pk = json.loads(resp.read().decode())['pk']
                            plog(f"  ✓ Created LDAP provider (pk={ldap_provider_pk})")
                        except urllib.error.HTTPError as e:
                            err = e.read().decode()[:200]
                            if e.code == 400:
                                req = urllib.request.Request(f'{ak_url}/api/v3/providers/ldap/?search=LDAP',
                                    headers=ak_headers)
                                resp = urllib.request.urlopen(req, timeout=10)
                                results = json.loads(resp.read().decode())['results']
                                ldap_provider_pk = results[0]['pk'] if results else None
                                plog(f"  ✓ LDAP provider already exists (pk={ldap_provider_pk})")
                            else:
                                plog(f"  ✗ LDAP provider creation failed: {e.code} {err}")

                        # Create LDAP application
                        if ldap_provider_pk:
                            try:
                                req = urllib.request.Request(f'{ak_url}/api/v3/core/applications/',
                                    data=json.dumps({'name': 'LDAP', 'slug': 'ldap',
                                        'provider': ldap_provider_pk}).encode(),
                                    headers=ak_headers, method='POST')
                                urllib.request.urlopen(req, timeout=10)
                                plog(f"  ✓ Created LDAP application")
                            except urllib.error.HTTPError as e:
                                if e.code == 400:
                                    plog(f"  ✓ LDAP application already exists")
                                else:
                                    plog(f"  ⚠ LDAP application error: {e.code} {e.read().decode()[:100]}")

                            # Get or create LDAP outpost (blueprint may have created it)
                            outpost_token_id = None
                            try:
                                req = urllib.request.Request(f'{ak_url}/api/v3/outposts/instances/?search=LDAP',
                                    headers=ak_headers)
                                resp = urllib.request.urlopen(req, timeout=10)
                                results = json.loads(resp.read().decode())['results']
                                ldap_outpost = next((o for o in results if o.get('name') == 'LDAP' and o.get('type') == 'ldap'), None)
                                if ldap_outpost:
                                    outpost_token_id = ldap_outpost.get('token_identifier', '')
                                    if not outpost_token_id:
                                        req = urllib.request.Request(f'{ak_url}/api/v3/outposts/instances/{ldap_outpost["pk"]}/',
                                            headers=ak_headers)
                                        resp = urllib.request.urlopen(req, timeout=10)
                                        detail = json.loads(resp.read().decode())
                                        outpost_token_id = detail.get('token_identifier', '')
                                    if outpost_token_id:
                                        plog(f"  ✓ Using existing LDAP outpost (blueprint)")
                            except Exception:
                                pass
                            if not outpost_token_id:
                                try:
                                    req = urllib.request.Request(f'{ak_url}/api/v3/outposts/instances/',
                                        data=json.dumps({'name': 'LDAP', 'type': 'ldap',
                                            'providers': [ldap_provider_pk],
                                            'config': {'authentik_host': 'http://authentik-server-1:9000/',
                                                'authentik_host_insecure': True}}).encode(),
                                            headers=ak_headers, method='POST')
                                    resp = urllib.request.urlopen(req, timeout=10)
                                    outpost_data = json.loads(resp.read().decode())
                                    outpost_token_id = outpost_data.get('token_identifier', '')
                                    plog(f"  ✓ Created LDAP outpost (token_id={outpost_token_id})")
                                except urllib.error.HTTPError as e:
                                    err = e.read().decode()[:200]
                                    if e.code == 400:
                                        req = urllib.request.Request(f'{ak_url}/api/v3/outposts/instances/?search=LDAP',
                                            headers=ak_headers)
                                        resp = urllib.request.urlopen(req, timeout=10)
                                        results = json.loads(resp.read().decode())['results']
                                        ldap_outpost = next((o for o in results if o.get('name') == 'LDAP' and o.get('type') == 'ldap'), None)
                                        if ldap_outpost:
                                            outpost_token_id = ldap_outpost.get('token_identifier', '')
                                            if not outpost_token_id:
                                                req = urllib.request.Request(f'{ak_url}/api/v3/outposts/instances/{ldap_outpost["pk"]}/',
                                                    headers=ak_headers)
                                                resp = urllib.request.urlopen(req, timeout=10)
                                                detail = json.loads(resp.read().decode())
                                                outpost_token_id = detail.get('token_identifier', '')
                                            if outpost_token_id:
                                                plog(f"  ✓ LDAP outpost already exists, using token")
                                            if outpost_token_id and ldap_provider_pk:
                                                req = urllib.request.Request(
                                                    f'{ak_url}/api/v3/outposts/instances/{ldap_outpost["pk"]}/',
                                                    data=json.dumps({'name': 'LDAP', 'type': 'ldap',
                                                        'providers': [ldap_provider_pk],
                                                        'config': {'authentik_host': 'http://authentik-server-1:9000/',
                                                            'authentik_host_insecure': True}}).encode(),
                                                    headers=ak_headers, method='PUT')
                                                urllib.request.urlopen(req, timeout=10)
                                        if not outpost_token_id:
                                            plog(f"  ✗ LDAP outpost exists but token not available via API")
                                    else:
                                        plog(f"  ✗ LDAP outpost creation failed: {e.code} {err}")
                                except Exception as ex:
                                    plog(f"  ✗ LDAP outpost error: {str(ex)[:150]}")

                            # Inject token into docker-compose.yml
                            if outpost_token_id:
                                try:
                                    req = urllib.request.Request(
                                        f'{ak_url}/api/v3/core/tokens/{outpost_token_id}/view_key/',
                                        headers=ak_headers, method='GET')
                                    resp = urllib.request.urlopen(req, timeout=10)
                                    response_body = resp.read().decode()
                                    ldap_token_key = json.loads(response_body).get('key', '')
                                    if ldap_token_key:
                                        with open(compose_path, 'r') as f:
                                            compose_text = f.read()
                                        compose_text = compose_text.replace('AUTHENTIK_TOKEN: placeholder', f'AUTHENTIK_TOKEN: {ldap_token_key}')
                                        with open(compose_path, 'w') as f:
                                            f.write(compose_text)
                                        plog(f"  ✓ LDAP outpost token injected into docker-compose.yml")
                                        plog(f"  Recreating LDAP container with new token...")
                                        subprocess.run(f'cd {ak_dir} && docker compose stop ldap && docker compose rm -f ldap && docker compose up -d ldap 2>&1',
                                            shell=True, capture_output=True, timeout=60)
                                        plog(f"  ✓ LDAP container recreated with injected token")
                                        time.sleep(10)
                                        plog(f"  ℹ LDAP may take 30–60s to show healthy in Authentik Outposts")
                                    else:
                                        plog(f"  ⚠ Token key empty — response: {response_body[:200]}")
                                except urllib.error.HTTPError as e:
                                    plog(f"  ✗ Token injection HTTP error: {e.code} {e.read().decode()[:200]}")
                                except Exception as e:
                                    plog(f"  ✗ Token injection error: {str(e)[:200]}")
                            else:
                                plog(f"  ✗ No outpost_token_id — cannot inject token")

                            # Ensure LDAP container is started (even if token inject failed)
                            r = subprocess.run(f'cd {ak_dir} && docker compose up -d ldap 2>&1', shell=True, capture_output=True, text=True, timeout=60)
                            if r.returncode == 0:
                                plog(f"  ✓ LDAP container started")
                            else:
                                plog(f"  ⚠ LDAP start: {r.stderr.strip()[:150] if r.stderr else r.stdout.strip()[:150]}")

                except Exception as e:
                    plog(f"  ✗ LDAP setup error: {str(e)[:200]}")
                    try:
                        subprocess.run(f'cd {ak_dir} && docker compose up -d ldap 2>&1', shell=True, capture_output=True, timeout=60)
                        plog(f"  ℹ LDAP container started (add token in Authentik → Outposts → LDAP, then restart LDAP)")
                    except Exception:
                        pass
                else:
                    if os.path.exists('/opt/tak'):
                        plog("  ⚠ No webadmin password found, skipping user creation")
            else:
                plog("  ⚠ No bootstrap token found, skipping admin setup")
        except Exception as e:
            plog(f"  ⚠ Admin group setup error (non-fatal): {str(e)[:100]}")

        # Unconditionally ensure LDAP container is up (compose has ldap service from Step 6)
        compose_path = os.path.join(ak_dir, 'docker-compose.yml')
        if os.path.exists(compose_path):
            with open(compose_path) as f:
                compose_text = f.read()
            if 'ghcr.io/goauthentik/ldap' in compose_text or '\n  ldap:\n' in compose_text:
                plog("")
                plog("  Ensuring LDAP container is running...")
                r = subprocess.run(f'cd {ak_dir} && docker compose up -d ldap 2>&1', shell=True, capture_output=True, text=True, timeout=90)
                if r.returncode == 0:
                    plog("  ✓ LDAP container is up")
                else:
                    plog(f"  ✗ LDAP start failed: {(r.stderr or r.stdout or '').strip()[:300]}")

        # Step 12: Configure Proxy Provider, Application, Outpost, Brand for TAK Portal
        fqdn = settings.get('fqdn', '')
        if fqdn:
            plog("")
            plog("\u2501\u2501\u2501 Step 12: Configuring Forward Auth for TAK Portal \u2501\u2501\u2501")
            try:
                ak_token = ''
                with open(env_path) as f:
                    for line in f:
                        if line.strip().startswith('AUTHENTIK_BOOTSTRAP_TOKEN='):
                            ak_token = line.strip().split('=', 1)[1].strip()
                if ak_token:
                    ak_headers = {'Authorization': f'Bearer {ak_token}', 'Content-Type': 'application/json'}
                    ak_url = 'http://127.0.0.1:9090'
                    import urllib.request

                    # 12a: Update Brand domain
                    plog("  Updating Authentik brand domain...")
                    try:
                        req = urllib.request.Request(f'{ak_url}/api/v3/core/brands/', headers=ak_headers)
                        resp = urllib.request.urlopen(req, timeout=15)
                        brands = json.loads(resp.read().decode())['results']
                        if brands:
                            brand_id = brands[0]['brand_uuid']
                            req = urllib.request.Request(f'{ak_url}/api/v3/core/brands/{brand_id}/',
                                data=json.dumps({'domain': f'authentik.{fqdn}'}).encode(),
                                headers=ak_headers, method='PATCH')
                            urllib.request.urlopen(req, timeout=10)
                            plog(f"  ✓ Brand domain set to authentik.{fqdn}")
                    except Exception as e:
                        plog(f"  ⚠ Brand update: {str(e)[:100]}")

                    # 12b: Wait for authorization and invalidation flows (first boot can be slow)
                    flow_pk = None
                    inv_flow_pk = None
                    for attempt in range(36):  # up to 3 minutes
                        try:
                            req = urllib.request.Request(f'{ak_url}/api/v3/flows/instances/?designation=authorization&ordering=slug',
                                headers=ak_headers)
                            resp = urllib.request.urlopen(req, timeout=10)
                            flows = json.loads(resp.read().decode())['results']
                            for fl in flows:
                                if 'implicit' in fl.get('slug', ''):
                                    flow_pk = fl['pk']
                                    break
                            if not flow_pk and flows:
                                flow_pk = flows[0]['pk']
                            if flow_pk:
                                req = urllib.request.Request(f'{ak_url}/api/v3/flows/instances/?designation=invalidation',
                                    headers=ak_headers)
                                resp = urllib.request.urlopen(req, timeout=10)
                                inv_flows = json.loads(resp.read().decode())['results']
                                inv_flow_pk = next((f['pk'] for f in inv_flows if 'provider' not in f.get('slug', '')), inv_flows[0]['pk'] if inv_flows else None)
                                if inv_flow_pk:
                                    break
                        except Exception:
                            pass
                        if attempt % 6 == 0:
                            plog(f"  ⏳ Waiting for authorization flow... ({attempt * 5}s)")
                        time.sleep(5)
                    if flow_pk and inv_flow_pk:
                        plog("  ✓ Authorization and invalidation flows ready")
                    elif flow_pk:
                        plog("  ⚠ Invalidation flow not found — proxy may still work")

                    # 12c: Create Proxy Provider (Forward auth single application)
                    provider_pk = None
                    if flow_pk:
                        try:
                            provider_data = {
                                'name': 'TAK Portal Proxy',
                                'authorization_flow': flow_pk,
                                'invalidation_flow': inv_flow_pk or flow_pk,
                                'external_host': f'https://takportal.{fqdn}',
                                'mode': 'forward_single',
                                'token_validity': 'hours=24'
                            }
                            req = urllib.request.Request(f'{ak_url}/api/v3/providers/proxy/',
                                data=json.dumps(provider_data).encode(),
                                headers=ak_headers, method='POST')
                            resp = urllib.request.urlopen(req, timeout=15)
                            provider_pk = json.loads(resp.read().decode())['pk']
                            plog(f"  ✓ Proxy Provider created (pk={provider_pk})")
                        except urllib.error.HTTPError as e:
                            if e.code == 400:
                                plog("  ✓ Proxy Provider already exists")
                                # Find existing
                                req = urllib.request.Request(f'{ak_url}/api/v3/providers/proxy/?search=TAK+Portal',
                                    headers=ak_headers)
                                resp = urllib.request.urlopen(req, timeout=10)
                                results = json.loads(resp.read().decode())['results']
                                if results:
                                    provider_pk = results[0]['pk']
                            else:
                                plog(f"  ⚠ Proxy Provider error: {e.code}")
                    else:
                        plog("  ⚠ No authorization flow found after waiting — create a flow in Authentik and re-run deploy or add proxy provider manually")

                    # 12d: Create Application
                    app_slug = None
                    if provider_pk:
                        try:
                            app_data = {
                                'name': 'TAK Portal',
                                'slug': 'tak-portal',
                                'provider': provider_pk,
                            }
                            req = urllib.request.Request(f'{ak_url}/api/v3/core/applications/',
                                data=json.dumps(app_data).encode(),
                                headers=ak_headers, method='POST')
                            resp = urllib.request.urlopen(req, timeout=15)
                            app_result = json.loads(resp.read().decode())
                            app_slug = app_result.get('slug', 'tak-portal')
                            plog(f"  ✓ Application 'TAK Portal' created")
                        except urllib.error.HTTPError as e:
                            if e.code == 400:
                                plog("  ✓ Application 'TAK Portal' already exists")
                                app_slug = 'tak-portal'
                            else:
                                plog(f"  ⚠ Application error: {e.code}")

                    # 12e: Add to embedded outpost
                    if app_slug:
                        try:
                            # Find embedded outpost
                            req = urllib.request.Request(f'{ak_url}/api/v3/outposts/instances/?search=embedded',
                                headers=ak_headers)
                            resp = urllib.request.urlopen(req, timeout=10)
                            outposts = json.loads(resp.read().decode())['results']
                            embedded = None
                            for op in outposts:
                                if 'embed' in op.get('name', '').lower():
                                    embedded = op
                                    break
                            if not embedded and outposts:
                                # Check for proxy type outpost
                                for op in outposts:
                                    if op.get('type', '') == 'proxy':
                                        embedded = op
                                        break
                            if embedded:
                                outpost_pk = embedded['pk']
                                current_providers = list(embedded.get('providers', []))
                                if provider_pk not in current_providers:
                                    current_providers.append(provider_pk)
                                existing_config = dict(embedded.get('config', {}))
                                existing_config['authentik_host'] = f'https://authentik.{fqdn}'
                                existing_config['authentik_host_insecure'] = False
                                # Single PUT: providers + config (PATCH with only config can 400)
                                put_payload = {
                                    'name': embedded.get('name', 'authentik Embedded Outpost'),
                                    'type': embedded.get('type', 'proxy'),
                                    'providers': current_providers,
                                    'config': existing_config,
                                }
                                req = urllib.request.Request(f'{ak_url}/api/v3/outposts/instances/{outpost_pk}/',
                                    data=json.dumps(put_payload).encode(),
                                    headers=ak_headers, method='PUT')
                                urllib.request.urlopen(req, timeout=15)
                                plog(f"  ✓ TAK Portal added to embedded outpost")
                                plog(f"  ✓ Embedded outpost authentik_host set to https://authentik.{fqdn}")
                            else:
                                plog("  ⚠ No embedded outpost found — create one in Authentik admin")
                        except Exception as e:
                            plog(f"  ⚠ Outpost config: {str(e)[:100]}")

                    plog(f"  ✓ Forward auth ready for takportal.{fqdn}")

                    # If Node-RED is installed, create Node-RED app in Authentik (same as TAK Portal)
                    nodered_installed = (os.path.exists(os.path.expanduser('~/node-red/docker-compose.yml')) or
                        os.path.exists(os.path.expanduser('~/node-red/settings.js')) or os.path.exists('/opt/nodered'))
                    if nodered_installed:
                        plog("")
                        plog("  Configuring Authentik for Node-RED...")
                        _ensure_authentik_nodered_app(fqdn, ak_token, plog, flow_pk=flow_pk, inv_flow_pk=inv_flow_pk)
                    # infra-TAK console (infratak + console subdomains) behind Authentik — reuse same flows, no second fetch
                    plog("")
                    plog("  Configuring Authentik for infra-TAK Console...")
                    _ensure_authentik_console_app(fqdn, ak_token, plog, flow_pk=flow_pk, inv_flow_pk=inv_flow_pk)
                else:
                    plog("  ⚠ No bootstrap token, skipping forward auth setup")
            except Exception as e:
                plog(f"  ⚠ Forward auth setup error (non-fatal): {str(e)[:100]}")
        else:
            plog("")
            plog("  ℹ No domain configured — skipping forward auth setup")
            plog("  Set up a domain in the Caddy module first, then use Update config & reconnect")

        # Read bootstrap password for display
        bootstrap_pass_display = ''
        with open(env_path) as f:
            for line in f:
                if line.strip().startswith('AUTHENTIK_BOOTSTRAP_PASSWORD='):
                    bootstrap_pass_display = line.strip().split('=', 1)[1].strip()

        plog("")
        plog("=" * 50)
        plog("\u2713 Authentik deployed successfully!")
        if fqdn:
            plog(f"  Admin UI: https://authentik.{fqdn}")
        else:
            plog(f"  Admin UI: http://{server_ip}:9090")
        plog(f"  Admin user: akadmin")
        if bootstrap_pass_display:
            plog(f"  Admin password: {bootstrap_pass_display}")
        plog("")
        plog("  LDAP Configuration:")
        plog(f"  - Service account: adm_ldapservice")
        if ldap_svc_pass:
            plog(f"  - Service password: {ldap_svc_pass}")
        plog(f"  - Base DN: DC=takldap")
        plog(f"  - LDAP port: 389")
        # Regenerate Caddyfile if Caddy is configured
        if settings.get('fqdn'):
            generate_caddyfile(settings)
            subprocess.run('systemctl reload caddy 2>/dev/null; true', shell=True, capture_output=True)
            plog(f"  ✓ Caddy config updated for Authentik")
        plog("=" * 50)
        plog("  Next steps:")
        plog("  1. Launch Authentik Admin (link below), then come back and refresh this page to get the akadmin password.")
        plog("     After logging in: Admin interface → Groups → authentik Admins → Users → Add new user, add email, create user.")
        plog("  2. Go to Email Relay and set up SMTP; then use 'Configure Authentik to use these settings'.")
        plog("=" * 50)
        plog("  ✓ Deploy complete.")
        authentik_deploy_status.update({'running': False, 'complete': True})
    except Exception as e:
        plog(f"\u2717 FATAL ERROR: {str(e)}")
        authentik_deploy_status.update({'running': False, 'error': True})
        try:
            import traceback
            error_log_path = os.path.join(CONFIG_DIR, 'authentik_error.log')
            with open(error_log_path, 'w') as f:
                f.write(f"FATAL ERROR: {str(e)}\n\n")
                f.write(traceback.format_exc())
                f.write("\n\nDEPLOY LOG:\n")
                f.write('\n'.join(authentik_deploy_log))
            plog(f"  Error log saved to {error_log_path}")
        except Exception:
            pass

AUTHENTIK_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Authentik</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0" rel="stylesheet">
<style>
:root{--bg-deep:#080b14;--bg-surface:#0f1219;--bg-card:#161b26;--border:#1e2736;--border-hover:#2a3548;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-dim:#94a3b8;--accent:#3b82f6;--cyan:#06b6d4;--green:#10b981;--red:#ef4444;--yellow:#eab308}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'DM Sans',sans-serif;background:var(--bg-deep);color:var(--text-primary);min-height:100vh}
.material-symbols-outlined{font-family:'Material Symbols Outlined';font-weight:400;font-style:normal;font-size:20px;line-height:1;letter-spacing:normal;white-space:nowrap;direction:ltr;-webkit-font-smoothing:antialiased}
.nav-icon.material-symbols-outlined{font-size:22px;width:22px;text-align:center}
.top-bar{height:3px;background:linear-gradient(90deg,var(--accent),var(--cyan),var(--green))}
.header{padding:20px 40px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);background:var(--bg-surface)}
.header-left{display:flex;align-items:center;gap:16px}.header-icon{font-size:28px}.header-title{font-family:'JetBrains Mono',monospace;font-size:20px;font-weight:700;letter-spacing:-0.5px}.header-subtitle{font-size:13px;color:var(--text-dim)}
.header-right{display:flex;align-items:center;gap:12px}
.btn-back{color:var(--text-dim);text-decoration:none;font-size:13px;padding:6px 14px;border:1px solid var(--border);border-radius:6px;transition:all 0.2s}.btn-back:hover{color:var(--text-secondary);border-color:var(--border-hover)}
.btn-logout{color:var(--text-dim);text-decoration:none;font-size:13px;padding:6px 14px;border:1px solid var(--border);border-radius:6px;transition:all 0.2s}.btn-logout:hover{color:var(--red);border-color:rgba(239,68,68,0.3)}
.os-badge{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);padding:4px 10px;background:var(--bg-card);border:1px solid var(--border);border-radius:4px}
.main{max-width:1000px;margin:0 auto;padding:32px 40px}
.section-title{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:2px;text-transform:uppercase;margin-bottom:16px;margin-top:24px}
.status-banner{background:var(--bg-card);border:1px solid var(--border);border-top:none;border-radius:12px;padding:24px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between}
.status-info{display:flex;align-items:center;gap:16px}
.status-icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px}
.status-icon.running{background:rgba(16,185,129,0.1)}.status-icon.stopped{background:rgba(239,68,68,0.1)}.status-icon.not-installed{background:rgba(71,85,105,0.2)}
.status-text{font-family:'JetBrains Mono',monospace;font-size:18px;font-weight:600}
.status-detail{font-size:13px;color:var(--text-dim);margin-top:4px}
.status-logo-wrap{display:flex;align-items:center;gap:10px}
.status-logo{height:36px;width:auto;max-width:100px;max-height:36px;object-fit:contain}
.status-name{font-family:'JetBrains Mono',monospace;font-weight:600;font-size:18px;color:var(--text-primary)}
.controls{display:flex;gap:10px}
.control-btn{padding:10px 20px;border:1px solid var(--border);border-radius:8px;background:var(--bg-card);color:var(--text-secondary);font-family:'JetBrains Mono',monospace;font-size:13px;cursor:pointer;transition:all 0.2s}
.control-btn:hover{border-color:var(--border-hover);color:var(--text-primary)}
.control-btn.btn-stop{border-color:rgba(239,68,68,0.3)}.control-btn.btn-stop:hover{background:rgba(239,68,68,0.1);color:var(--red)}
.control-btn.btn-start{border-color:rgba(16,185,129,0.3)}.control-btn.btn-start:hover{background:rgba(16,185,129,0.1);color:var(--green)}
.control-btn.btn-update{border-color:rgba(59,130,246,0.3)}.control-btn.btn-update:hover{background:rgba(59,130,246,0.1);color:var(--accent)}
.control-btn.btn-remove{border-color:rgba(239,68,68,0.2)}.control-btn.btn-remove:hover{background:rgba(239,68,68,0.1);color:var(--red)}
.cert-btn{padding:10px 20px;border-radius:8px;text-decoration:none;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;transition:all 0.2s}
.cert-btn-primary{background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff}
.cert-btn-secondary{background:rgba(59,130,246,0.1);color:var(--accent);border:1px solid var(--border)}
.deploy-btn{padding:14px 32px;border:none;border-radius:10px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:700;cursor:pointer;transition:all 0.2s;display:block;margin:24px auto}
.deploy-btn:hover{transform:translateY(-1px);box-shadow:0 4px 24px rgba(59,130,246,0.25)}
.deploy-log{background:#0c0f1a;border:1px solid var(--border);border-radius:12px;padding:20px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);max-height:400px;overflow-y:auto;line-height:1.6;white-space:pre-wrap;margin-top:16px}
.svc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-top:8px}
.svc-card{background:var(--bg-surface);border:1px solid var(--border);border-radius:8px;padding:12px;font-family:'JetBrains Mono',monospace;font-size:12px}
.svc-name{color:var(--text-secondary);font-weight:600;margin-bottom:4px}
.svc-status{font-size:11px}
.footer{text-align:center;padding:24px;font-size:12px;color:var(--text-dim);margin-top:40px}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;display:none;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg-card);border:1px solid var(--border);border-radius:14px;padding:28px;width:400px;max-width:90vw}
.modal h3{font-size:16px;font-weight:700;margin-bottom:8px;color:var(--red)}
.modal p{font-size:13px;color:var(--text-secondary);margin-bottom:20px}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}
.form-label{display:block;font-size:12px;font-weight:600;color:var(--text-secondary);margin-bottom:6px}
.form-input{width:100%;padding:10px 14px;background:#0a0e1a;border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-size:13px}
.uninstall-spinner{display:inline-block;width:18px;height:18px;border:2px solid var(--border);border-top-color:var(--cyan);border-radius:50%;animation:uninstall-spin .7s linear infinite;vertical-align:middle;margin-right:8px}
@keyframes uninstall-spin{to{transform:rotate(360deg)}}
.uninstall-progress-row{display:flex;align-items:center;gap:8px;margin-top:10px;font-size:13px;color:var(--text-secondary)}
body{display:flex;min-height:100vh}
.sidebar{width:220px;background:var(--bg-surface);border-right:1px solid var(--border);padding:24px 0;flex-shrink:0}
.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}
.sidebar-logo span{font-size:15px;font-weight:700}.sidebar-logo small{display:block;font-size:10px;color:var(--text-dim);font-family:'JetBrains Mono',monospace;margin-top:2px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 20px;color:var(--text-secondary);text-decoration:none;font-size:13px;font-weight:500;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{color:var(--text-primary);background:rgba(255,255,255,.03)}
.nav-item.active{color:var(--cyan);background:rgba(6,182,212,.06);border-left-color:var(--cyan)}
.nav-icon{font-size:15px;width:18px;text-align:center}
.main{flex:1;min-width:0;overflow-y:auto;padding:32px;max-width:1000px;margin:0 auto}
</style></head><body>
{{ sidebar_html }}
<div class="main">
<div class="status-banner">
{% if deploying %}
<div class="status-info"><div class="status-icon running" style="background:rgba(59,130,246,0.1)">🔄</div><div><div class="status-text" style="color:var(--accent)">Deploying...</div><div class="status-detail">Authentik installation in progress</div></div></div>
{% elif ak.installed and ak.running %}
<div class="status-info"><div class="status-logo-wrap"><img src="{{ authentik_logo_url }}" alt="" class="status-logo"></div><div><div class="status-text" style="color:var(--green)">Running</div><div class="status-detail">Identity provider active</div></div></div>
<div class="controls">
<button class="control-btn btn-stop" onclick="akControl('stop')">⏹ Stop</button>
<button class="control-btn" onclick="akControl('restart')">🔄 Restart</button>
<button class="control-btn btn-update" onclick="akControl('update')">⬆ Update</button>
</div>
{% elif ak.installed %}
<div class="status-info"><div class="status-logo-wrap"><img src="{{ authentik_logo_url }}" alt="" class="status-logo"></div><div><div class="status-text" style="color:var(--red)">Stopped</div><div class="status-detail">Docker containers not running</div></div></div>
<div class="controls">
<button class="control-btn btn-start" onclick="akControl('start')">▶ Start</button>
<button class="control-btn btn-update" onclick="akControl('update')">⬆ Update</button>
</div>
{% else %}
<div class="status-info"><div class="status-logo-wrap"><img src="{{ authentik_logo_url }}" alt="" class="status-logo"></div><div><div class="status-text" style="color:var(--text-dim)">Not Installed</div><div class="status-detail">Deploy Authentik for identity management & SSO</div></div></div>
{% endif %}
</div>

{% if deploying %}
<div class="section-title">Deployment Log</div>
<div class="deploy-log" id="deploy-log">Waiting for deployment to start...</div>
{% elif deploy_error %}
<div class="section-title">Deployment Failed</div>
<div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:12px;padding:24px;margin-bottom:24px;text-align:center">
<div style="font-family:'JetBrains Mono',monospace;font-size:14px;color:var(--red);margin-bottom:16px">✗ Authentik deployment failed</div>
{% if error_log_exists %}
<a href="/api/authentik/error-log" class="cert-btn cert-btn-secondary" style="text-decoration:none;display:inline-block">⬇ Download Error Log</a>
{% endif %}
</div>
{% elif ak.installed and ak.running %}
<div class="section-title">Access</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
<a href="{{ 'https://authentik.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':' + str(ak_port) }}" target="_blank" rel="noopener noreferrer" class="cert-btn cert-btn-primary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px;display:inline-flex;align-items:center;gap:6px" title="Open Authentik admin interface"><img src="{{ authentik_logo_url }}" alt="" style="width:18px;height:18px;object-fit:contain">Authentik{% if not settings.get('fqdn') %} :{{ ak_port }}{% endif %}</a>
<a href="{{ 'https://takportal.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':3000' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">👥 TAK Portal{% if not settings.get('fqdn') %} :3000{% endif %}</a>
<a href="{{ 'https://tak.' + settings.get('fqdn') if settings.get('fqdn') else 'https://' + settings.get('server_ip', '') + ':8443' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔐 WebGUI :8443 (cert)</a>
<a href="{{ 'https://tak.' + settings.get('fqdn') if settings.get('fqdn') else 'https://' + settings.get('server_ip', '') + ':8446' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔑 WebGUI :8446 (password)</a>
</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);margin-top:12px">Admin user: <span style="color:var(--cyan)">akadmin</span> · <button type="button" onclick="showAkPassword()" id="ak-pw-btn" style="background:none;border:1px solid var(--border);color:var(--cyan);padding:2px 10px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:11px;cursor:pointer">🔑 Show Password</button> <span id="ak-pw-display" style="color:var(--green);user-select:all;display:none"></span></div>
</div>
<div class="section-title">LDAP Configuration</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="font-family:'JetBrains Mono',monospace;font-size:12px;line-height:2">
<div><span style="color:var(--text-dim)">Base DN:</span> <span style="color:var(--cyan)">DC=takldap</span></div>
<div><span style="color:var(--text-dim)">Service Account:</span> <span style="color:var(--cyan)">adm_ldapservice</span></div>
<div><span style="color:var(--text-dim)">LDAP Port:</span> <span style="color:var(--cyan)">389</span> <span style="color:var(--text-dim)">(Docker outpost)</span></div>
<div style="margin-top:8px;font-size:11px;color:var(--text-dim)">LDAP configured via blueprint · Check Admin → Outposts to verify</div>
</div>
</div>
{% if container_info.get('containers') %}
<div class="section-title">Services</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div class="svc-grid">
{% for c in container_info.containers %}
<div class="svc-card" onclick="filterLogs('{{ c.name }}')" style="cursor:pointer;border-color:{{ 'var(--red)' if 'unhealthy' in c.status else 'var(--green)' if 'healthy' in c.status else 'var(--border)' }}" id="svc-{{ c.name }}"><div class="svc-name">{{ c.name }}</div><div class="svc-status" style="color:{{ 'var(--red)' if 'unhealthy' in c.status else 'var(--green)' }}">● {{ c.status }}</div></div>
{% endfor %}
<div class="svc-card" onclick="filterLogs('')" style="cursor:pointer" id="svc-all"><div class="svc-name">all containers</div><div class="svc-status" style="color:var(--text-dim)">● combined</div></div>
</div>
</div>
{% endif %}
{% if all_healthy and not portal_installed %}
<div style="background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);border-radius:12px;padding:20px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between">
<div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--green)">✓ Authentik is healthy — ready to deploy TAK Portal</div>
<a href="/takportal" style="padding:8px 20px;background:linear-gradient(135deg,#059669,#0e7490);color:#fff;border-radius:8px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap">→ Deploy TAK Portal</a>
</div>
{% elif all_healthy and portal_running %}
<div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.2);border-radius:12px;padding:20px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between">
<div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--green)">✓ Full stack healthy — Authentik + TAK Portal running</div>
<a href="/takportal" style="padding:8px 20px;background:var(--bg-surface);color:var(--green);border:1px solid rgba(16,185,129,0.3);border-radius:8px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap">→ TAK Portal</a>
</div>
{% endif %}
<div class="section-title">Container Logs <span id="log-filter-label" style="font-size:11px;color:var(--cyan);margin-left:8px"></span></div>
<div class="deploy-log" id="container-log">Loading logs...</div>
<div style="margin-top:24px;text-align:center">
<button class="control-btn" onclick="reconfigureAk()" style="margin-right:12px">🔄 Update config & reconnect</button>
<button class="control-btn btn-remove" onclick="document.getElementById('ak-uninstall-modal').classList.add('open')">🗑 Remove Authentik</button>
</div>
{% elif ak.installed %}
<div style="margin-top:24px;text-align:center">
<button class="control-btn btn-start" onclick="akControl('start')" style="margin-right:12px">▶ Start</button>
<button class="control-btn" onclick="reconfigureAk()" style="margin-right:12px">🔄 Update config & reconnect</button>
<button class="control-btn btn-remove" onclick="document.getElementById('ak-uninstall-modal').classList.add('open')">🗑 Remove Authentik</button>
</div>
{% else %}
<div class="section-title">About Authentik</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--text-secondary);line-height:1.8">
Authentik is an open-source <span style="color:var(--cyan)">Identity Provider</span> supporting SSO, SAML, OAuth2/OIDC, LDAP, and RADIUS.<br><br>
It provides centralized user authentication and management for all your services — including <span style="color:var(--cyan)">TAK Portal</span> for TAK Server user/cert management and <span style="color:var(--cyan)">MediaMTX</span> for stream access and user/group management (with or without TAK Portal).<br><br>
<span style="color:var(--text-dim)">Deploys: PostgreSQL + Redis + Authentik Server + Worker (4 containers)</span><br>
<span style="color:var(--text-dim)">Ports: 9090 (HTTP) · 9443 (HTTPS)</span><br>
<span style="color:var(--text-dim)">Recommended: 2+ CPU cores, 2+ GB RAM</span>
</div>
</div>
<button class="deploy-btn" id="deploy-btn" onclick="deployAk()">🚀 Deploy Authentik</button>
{% if not settings.fqdn %}
<div style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:10px;padding:16px 20px;margin-top:16px;font-size:13px;color:#f87171">
  🔒 <strong>SSL Required</strong> — Authentik requires a domain with SSL configured.<br>
  <span style="color:var(--text-dim)">Go to <a href="/caddy" style="color:var(--cyan)">Caddy SSL</a> and configure your domain first.</span>
</div>
{% endif %}
<div class="deploy-log" id="deploy-log" style="display:none" data-authentik-url="{{ 'https://authentik.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':' + str(ak_port) }}">Waiting for deployment to start...</div>
{% endif %}

{% if deploy_done %}
<div style="background:rgba(16,185,129,0.1);border:1px solid var(--border);border-radius:10px;padding:20px;margin-top:20px;text-align:center">
<div style="font-family:'JetBrains Mono',monospace;font-size:14px;color:var(--green);margin-bottom:8px">✓ Authentik deployed!</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--cyan);margin-bottom:12px">1. Click <strong>Authentik</strong> below to open the admin UI, then come back and <strong>refresh this page</strong> to see/copy the akadmin password. After logging in: <strong>Admin interface → Groups</strong> → <strong>authentik Admins</strong> → <strong>Users</strong> → Add new user, add email, create user.<br>2. Go to <a href="/emailrelay" style="color:var(--cyan)">Email Relay</a> and set up SMTP; then use &quot;Configure Authentik to use these settings&quot;.</div>
<a href="{{ 'https://authentik.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':' + str(ak_port) }}" target="_blank" rel="noopener noreferrer" style="display:inline-block;padding:12px 24px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;margin-right:10px">Authentik</a>
<a href="/emailrelay" style="display:inline-block;padding:10px 24px;background:rgba(30,64,175,0.2);color:var(--cyan);border:1px solid var(--border);border-radius:8px;font-size:14px;font-weight:600;text-decoration:none;margin-right:10px">Email Relay → SMTP</a>
<button onclick="window.location.href='/authentik'" style="padding:10px 24px;background:rgba(30,64,175,0.2);color:var(--cyan);border:1px solid var(--border);border-radius:8px;font-size:14px;font-weight:600;cursor:pointer">Refresh Page</button>
</div>
{% endif %}
</div>
<div class="modal-overlay" id="ak-uninstall-modal">
<div class="modal">
<h3>⚠ Uninstall Authentik?</h3>
<p>This will remove Authentik, all Docker containers, volumes, images, and data. This cannot be undone.</p>
<label class="form-label">Admin Password</label>
<input class="form-input" id="ak-uninstall-password" type="password" placeholder="Confirm your password">
<div class="modal-actions">
<button type="button" class="control-btn" id="ak-uninstall-cancel" onclick="document.getElementById('ak-uninstall-modal').classList.remove('open')">Cancel</button>
<button type="button" class="control-btn btn-remove" id="ak-uninstall-confirm" onclick="doUninstallAk()">Uninstall</button>
</div>
<div id="ak-uninstall-msg" style="margin-top:10px;font-size:12px;color:var(--red)"></div>
<div id="ak-uninstall-progress" class="uninstall-progress-row" style="display:none;margin-top:10px" aria-live="polite"></div>
</div>
</div>
<footer class="footer"></footer>
<script>
async function showAkPassword(){
    var btn=document.getElementById('ak-pw-btn');
    var display=document.getElementById('ak-pw-display');
    if(display.style.display==='inline'){display.style.display='none';btn.textContent='🔑 Show Password';return}
    try{
        var r=await fetch('/api/authentik/password');
        var d=await r.json();
        if(d.password){display.textContent=d.password;display.style.display='inline';btn.textContent='🔑 Hide'}
        else{display.textContent='Not found';display.style.display='inline'}
    }catch(e){display.textContent='Error';display.style.display='inline'}
}
async function akControl(action){
    var btns=document.querySelectorAll('.control-btn');
    btns.forEach(function(b){b.disabled=true;b.style.opacity='0.5'});
    try{
        var r=await fetch('/api/authentik/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:action})});
        var d=await r.json();
        if(d.success)window.location.href='/authentik';
        else alert('Error: '+(d.error||'Unknown'));
    }catch(e){alert('Error: '+e.message)}
    btns.forEach(function(b){b.disabled=false;b.style.opacity='1'});
}

async function deployAk(){
    var btn=document.getElementById('deploy-btn');
    btn.disabled=true;btn.textContent='Deploying...';btn.style.opacity='0.7';btn.style.cursor='wait';
    document.getElementById('deploy-log').style.display='block';
    try{
        var r=await fetch('/api/authentik/deploy',{method:'POST',headers:{'Content-Type':'application/json'}});
        var d=await r.json();
        if(d.success)pollDeployLog();
        else{document.getElementById('deploy-log').textContent='Error: '+d.error;btn.disabled=false;btn.textContent='Deploy Authentik';btn.style.opacity='1';btn.style.cursor='pointer'}
    }catch(e){document.getElementById('deploy-log').textContent='Error: '+e.message}
}
async function reconfigureAk(){
    try{
        var r=await fetch('/api/authentik/reconfigure',{method:'POST',headers:{'Content-Type':'application/json'}});
        var d=await r.json();
        if(d.success)window.location.href='/authentik';
        else alert('Error: '+(d.error||'Reconfigure failed'));
    }catch(e){alert('Error: '+e.message)}
}

var logIndex=0;
function pollDeployLog(){
    fetch('/api/authentik/deploy/log?index='+logIndex).then(function(r){return r.json()}).then(function(d){
        var el=document.getElementById('deploy-log');
        if(d.entries.length>0){
            d.entries.forEach(function(e){
                var isTimer=e.trim().charAt(0)==='\u23f3'&&e.indexOf(':')>0;
                if(isTimer){var prev=el.querySelector('[data-timer]');if(prev){prev.textContent=e;logIndex=d.total;return}}
                if(!isTimer){var old=el.querySelector('[data-timer]');if(old)old.removeAttribute('data-timer')}
                var l=document.createElement('div');
                if(isTimer)l.setAttribute('data-timer','1');
                if(e.indexOf('\u2713')>=0)l.style.color='var(--green)';
                else if(e.indexOf('\u2717')>=0||e.indexOf('FATAL')>=0)l.style.color='var(--red)';
                else if(e.indexOf('\u2501\u2501\u2501')>=0)l.style.color='var(--cyan)';
                else if(e.indexOf('===')>=0)l.style.color='var(--green)';
                l.textContent=e;el.appendChild(l);
            });
            logIndex=d.total;el.scrollTop=el.scrollHeight;
        }
        if(d.running)setTimeout(pollDeployLog,1000);
        else if(d.complete){
            var btn=document.getElementById('deploy-btn');
            if(btn){btn.textContent='\u2713 Deployment Complete';btn.style.background='var(--green)';btn.style.opacity='1';btn.style.cursor='default';}
            var el=document.getElementById('deploy-log');
            var inst=document.createElement('div');
            inst.style.cssText='font-family:JetBrains Mono,monospace;font-size:12px;color:var(--cyan);margin-top:16px;margin-bottom:8px;text-align:left;line-height:1.6';
            inst.textContent='Next: Click \u201cLaunch Authentik Admin\u201d below, then come back here and click \u201cRefresh Authentik Page\u201d to see/copy the akadmin password. After logging in: Admin interface \u2192 Groups \u2192 authentik Admins \u2192 Users \u2192 Add new user, add email, create user.';
            el.appendChild(inst);
            var authUrl=el.getAttribute('data-authentik-url')||'';
            var launchLink=document.createElement('a');
            launchLink.href=authUrl;launchLink.target='_blank';launchLink.rel='noopener noreferrer';
            launchLink.textContent='Launch Authentik Admin';
            launchLink.style.cssText='display:block;width:100%;padding:12px;margin-top:8px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;text-align:center;text-decoration:none;box-sizing:border-box';
            el.appendChild(launchLink);
            var refreshBtn=document.createElement('button');
            refreshBtn.textContent='\u21bb Refresh Authentik Page';
            refreshBtn.style.cssText='display:block;width:100%;padding:10px;margin-top:8px;background:rgba(30,64,175,0.2);color:var(--cyan);border:1px solid var(--border);border-radius:8px;font-size:13px;cursor:pointer;';
            refreshBtn.onclick=function(){window.location.href='/authentik';};
            el.appendChild(refreshBtn);
            el.scrollTop=el.scrollHeight;
        }
    });
}

var activeContainer = '';
function filterLogs(containerName){
    activeContainer = containerName;
    // Highlight selected card
    document.querySelectorAll('.svc-card').forEach(function(c){c.style.borderColor='';c.style.boxShadow=''});
    var id = containerName ? 'svc-'+containerName : 'svc-all';
    var card = document.getElementById(id);
    if(card){card.style.borderColor='var(--cyan)';card.style.boxShadow='0 0 0 1px var(--cyan)'}
    var label = document.getElementById('log-filter-label');
    if(label) label.textContent = containerName ? '— '+containerName : '';
    loadContainerLogs();
}
async function loadContainerLogs(){
    var el=document.getElementById('container-log');
    if(!el)return;
    try{
        var url = activeContainer
            ? '/api/authentik/logs?lines=80&container='+encodeURIComponent(activeContainer)
            : '/api/authentik/logs?lines=80';
        var r=await fetch(url);
        var d=await r.json();
        el.textContent='';
        if(d.entries&&d.entries.length>0){
            d.entries.forEach(function(e){
                var l=document.createElement('div');
                if(e.indexOf('ERROR')>=0||e.indexOf('error')>=0)l.style.color='var(--red)';
                else if(e.indexOf('WARNING')>=0||e.indexOf('warn')>=0)l.style.color='var(--yellow)';
                l.textContent=e;el.appendChild(l);
            });
            el.scrollTop=el.scrollHeight;
        }else{el.textContent='No logs available yet.';}
    }catch(e){el.textContent='Failed to load logs';}
}
if(document.getElementById('container-log')){loadContainerLogs();setInterval(loadContainerLogs,10000)}

function uninstallAk(){
    document.getElementById('ak-uninstall-modal').classList.add('open');
}
async function doUninstallAk(){
    var pw=document.getElementById('ak-uninstall-password').value;
    if(!pw){document.getElementById('ak-uninstall-msg').textContent='Please enter your password';return;}
    var msgEl=document.getElementById('ak-uninstall-msg');
    var progressEl=document.getElementById('ak-uninstall-progress');
    var cancelBtn=document.getElementById('ak-uninstall-cancel');
    var confirmBtn=document.getElementById('ak-uninstall-confirm');
    msgEl.textContent='';
    progressEl.style.display='flex';
    progressEl.innerHTML='<span class="uninstall-spinner"></span><span>Uninstalling…</span>';
    confirmBtn.disabled=true;
    cancelBtn.disabled=true;
    try{
        var r=await fetch('/api/authentik/uninstall',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
        var d=await r.json();
        if(d.success){
            progressEl.innerHTML='<span class="uninstall-spinner"></span><span>Done. Reloading…</span>';
            setTimeout(function(){window.location.href='/authentik';},800);
        }else{
            msgEl.textContent=d.error||'Uninstall failed';
            progressEl.style.display='none';
            progressEl.innerHTML='';
            confirmBtn.disabled=false;
            cancelBtn.disabled=false;
        }
    }catch(e){
        msgEl.textContent='Request failed: '+e.message;
        progressEl.style.display='none';
        progressEl.innerHTML='';
        confirmBtn.disabled=false;
        cancelBtn.disabled=false;
    }
}

{% if deploying %}pollDeployLog();{% endif %}
</script>
</body></html>'''

def _coreconfig_has_ldap():
    """True if CoreConfig.xml exists and already contains the LDAP auth block."""
    path = '/opt/tak/CoreConfig.xml'
    if not os.path.exists(path):
        return False
    try:
        with open(path, 'r') as f:
            content = f.read()
        return 'serviceAccountDN="cn=adm_ldapservice"' in content or '<ldap url="ldap://127.0.0.1:389"' in content
    except Exception:
        return False

def _apply_ldap_to_coreconfig():
    """Patch CoreConfig.xml with LDAP auth and restart TAK Server. Returns (success, message)."""
    import re
    import shutil
    coreconfig_path = '/opt/tak/CoreConfig.xml'
    env_path = os.path.expanduser('~/authentik/.env')
    if not os.path.exists(coreconfig_path):
        return False, 'CoreConfig.xml not found'
    if not os.path.exists(env_path):
        return False, 'Authentik .env not found'
    ldap_pass = ''
    with open(env_path) as f:
        for line in f:
            if line.strip().startswith('AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD='):
                ldap_pass = line.strip().split('=', 1)[1].strip()
                break
    if not ldap_pass:
        return False, 'LDAP service password not found in Authentik .env'
    backup_path = coreconfig_path + '.pre-ldap.bak'
    if not os.path.exists(backup_path):
        shutil.copy2(coreconfig_path, backup_path)
    with open(coreconfig_path, 'r') as f:
        config_content = f.read()
    auth_block = (
        '    <auth default="ldap" x509groups="true" x509addAnonymous="false"'
        ' x509useGroupCache="true" x509useGroupCacheDefaultActive="true"'
        ' x509checkRevocation="true">\n'
        '        <File location="UserAuthenticationFile.xml"/>\n'
        '        <ldap url="ldap://127.0.0.1:389"'
        ' userstring="cn={username},ou=users,dc=takldap"'
        ' updateinterval="60"'
        ' groupprefix="cn=tak_"'
        ' groupNameExtractorRegex="cn=tak_(.*?)(?:,|$)"'
        ' matchGroupInChain="true"'
        f' serviceAccountDN="cn=adm_ldapservice,ou=users,dc=takldap"'
        f' serviceAccountCredential="{ldap_pass}"'
        ' groupBaseRDN="ou=groups,dc=takldap"'
        ' userBaseRDN="ou=users,dc=takldap"'
        ' groupObjectClass="group" userObjectClass="user"'
        ' style="DS" ldapSecurityType="simple"'
        ' dnAttributeName="DN"'
        ' nameAttr="CN" roleAttribute="memberOf" adminGroup="ROLE_ADMIN"/>\n'
        '    </auth>'
    )
    new_content = re.sub(r'    <auth[^>]*>.*?</auth>', auth_block, config_content, flags=re.DOTALL)
    if new_content == config_content:
        return True, 'CoreConfig already has LDAP'
    with open(coreconfig_path, 'w') as f:
        f.write(new_content)
    r = subprocess.run('systemctl restart takserver 2>&1', shell=True, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return False, f'CoreConfig patched but TAK Server restart failed: {r.stderr.strip()[:120]}'
    return True, 'LDAP connected; TAK Server restarted'

@app.route('/api/takserver/connect-ldap', methods=['POST'])
@login_required
def takserver_connect_ldap():
    """One-shot: patch CoreConfig with LDAP and restart TAK Server (when Authentik already deployed)."""
    ok, msg = _apply_ldap_to_coreconfig()
    return jsonify({'success': ok, 'message': msg})

@app.route('/api/takserver/control', methods=['POST'])
@login_required
def takserver_control():
    action = request.json.get('action')
    if action not in ['start', 'stop', 'restart']:
        return jsonify({'error': 'Invalid action'}), 400
    subprocess.run(['systemctl', action, 'takserver'], capture_output=True, text=True, timeout=60)
    time.sleep(3)
    s = subprocess.run(['systemctl', 'is-active', 'takserver'], capture_output=True, text=True)
    return jsonify({'success': True, 'running': s.stdout.strip() == 'active', 'action': action})

@app.route('/api/takserver/log')
@login_required
def takserver_log():
    """Tail the takserver-messaging.log file"""
    log_path = '/opt/tak/logs/takserver-messaging.log'
    offset = request.args.get('offset', 0, type=int)
    lines = request.args.get('lines', 100, type=int)
    if not os.path.exists(log_path):
        return jsonify({'entries': [], 'offset': 0, 'size': 0})
    try:
        size = os.path.getsize(log_path)
        if offset == 0:
            r = subprocess.run(f'tail -n {lines} "{log_path}"', shell=True, capture_output=True, text=True, timeout=10)
            entries = r.stdout.strip().split('\n') if r.stdout.strip() else []
            return jsonify({'entries': entries, 'offset': size, 'size': size})
        elif size > offset:
            with open(log_path, 'r') as f:
                f.seek(offset)
                new_data = f.read()
            entries = new_data.strip().split('\n') if new_data.strip() else []
            return jsonify({'entries': entries, 'offset': size, 'size': size})
        else:
            return jsonify({'entries': [], 'offset': offset, 'size': size})
    except Exception as e:
        return jsonify({'entries': [f'Error reading log: {str(e)}'], 'offset': offset, 'size': 0})

@app.route('/api/takserver/services')
@login_required
def takserver_services():
    """Get TAK Server Java process status"""
    services = []
    try:
        r = subprocess.run("ps aux | grep java | grep -v grep", shell=True, capture_output=True, text=True, timeout=10)
        seen = {}
        for line in r.stdout.strip().split('\n'):
            if not line.strip(): continue
            parts = line.split()
            if len(parts) < 11: continue
            pid = parts[1]
            cpu = parts[2]
            mem_pct = parts[3]
            rss_kb = int(parts[5])
            mem_mb = round(rss_kb / 1024)
            cmd = ' '.join(parts[10:])
            # Identify the service
            if 'profiles.active=messaging' in cmd:
                name = 'Messaging'; icon = '📡'
            elif 'profiles.active=api' in cmd:
                name = 'API'; icon = '🔌'
            elif 'profiles.active=config' in cmd:
                name = 'Config'; icon = '⚙️'
            elif 'takserver-pm.jar' in cmd:
                name = 'Plugin Manager'; icon = '🧩'
            elif 'takserver-retention.jar' in cmd:
                name = 'Retention'; icon = '📦'
            else:
                continue  # skip unknown java processes
            # Keep only one entry per service name (highest mem)
            if name not in seen or mem_mb > seen[name]['mem_mb_raw']:
                seen[name] = {
                    'name': name, 'icon': icon, 'pid': pid,
                    'cpu': f"{cpu}%", 'mem_mb': f"{mem_mb} MB",
                    'mem_pct': f"{mem_pct}%", 'status': 'running',
                    'mem_mb_raw': mem_mb
                }
        for svc in seen.values():
            del svc['mem_mb_raw']
            services.append(svc)
        # Check PostgreSQL
        pg = subprocess.run("systemctl is-active postgresql", shell=True, capture_output=True, text=True, timeout=5)
        services.append({
            'name': 'PostgreSQL', 'icon': '🐘', 'pid': '',
            'cpu': '', 'mem_mb': '', 'mem_pct': '',
            'status': 'running' if pg.stdout.strip() == 'active' else 'stopped'
        })
    except Exception as e:
        services.append({'name': 'Error', 'icon': '❌', 'status': str(e)})
    return jsonify({'services': services, 'count': len([s for s in services if s['status'] == 'running'])})

@app.route('/api/takserver/uninstall', methods=['POST'])
@login_required
def takserver_uninstall():
    """Remove TAK Server, clean up, ready for fresh deploy"""
    data = request.json or {}
    password = data.get('password', '')
    auth = load_auth()
    if not auth.get('password_hash') or not check_password_hash(auth['password_hash'], password):
        return jsonify({'error': 'Invalid admin password'}), 403
    steps = []
    # Stop service
    subprocess.run(['systemctl', 'stop', 'takserver'], capture_output=True, timeout=60)
    subprocess.run(['systemctl', 'disable', 'takserver'], capture_output=True, timeout=30)
    steps.append('Stopped TAK Server')
    # Kill any remaining processes
    subprocess.run('pkill -9 -f takserver 2>/dev/null; true', shell=True, capture_output=True)
    steps.append('Killed remaining processes')
    # Remove package
    pkg_result = subprocess.run('dpkg -l | grep takserver', shell=True, capture_output=True, text=True)
    if 'takserver' in pkg_result.stdout:
        subprocess.run('DEBIAN_FRONTEND=noninteractive apt-get remove -y takserver 2>/dev/null; true', shell=True, capture_output=True, timeout=120)
        steps.append('Removed TAK Server package')
    # Clean up /opt/tak
    if os.path.exists('/opt/tak'):
        subprocess.run('rm -rf /opt/tak', shell=True, capture_output=True)
        steps.append('Removed /opt/tak')
    # Clean up PostgreSQL database and user (so redeploys start clean)
    subprocess.run("sudo -u postgres psql -c \"DROP DATABASE IF EXISTS cot;\" 2>/dev/null; true", shell=True, capture_output=True, timeout=30)
    subprocess.run("sudo -u postgres psql -c \"DROP USER IF EXISTS martiuser;\" 2>/dev/null; true", shell=True, capture_output=True, timeout=30)
    steps.append('Cleaned up PostgreSQL (cot database, martiuser)')
    # Clean up GPG verification artifacts
    subprocess.run('rm -rf /usr/share/debsig/keyrings/* /etc/debsig/policies/* 2>/dev/null; true', shell=True, capture_output=True, timeout=10)
    steps.append('Cleaned up GPG verification artifacts')
    # Clean up uploads so user can upload fresh
    for f in os.listdir(UPLOAD_DIR):
        os.remove(os.path.join(UPLOAD_DIR, f))
    steps.append('Cleared uploads')
    # Reset deploy status
    deploy_log.clear()
    deploy_status.update({'running': False, 'complete': False, 'error': False})
    return jsonify({'success': True, 'steps': steps})

@app.route('/api/upload/takserver', methods=['POST'])
@login_required
def upload_takserver_package():
    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400
    files = request.files.getlist('files')
    if not files or all(f.filename == '' for f in files):
        return jsonify({'error': 'No files selected'}), 400
    os_type = load_settings().get('os_type', '')
    results = {'package': None, 'gpg_key': None, 'policy': None}
    for f in files:
        fn = f.filename
        if not fn: continue
        fp = os.path.join(UPLOAD_DIR, fn)
        f.save(fp)
        sz = round(os.path.getsize(fp) / (1024*1024), 1)
        if fn.endswith('.deb'):
            if 'rocky' in os_type:
                os.remove(fp)
                return jsonify({'error': f'DEB uploaded but system is {os_type}. Need .rpm.'}), 400
            results['package'] = {'filename': fn, 'filepath': fp, 'pkg_type': 'deb', 'size_mb': sz}
        elif fn.endswith('.rpm'):
            if 'ubuntu' in os_type:
                os.remove(fp)
                return jsonify({'error': f'RPM uploaded but system is {os_type}. Need .deb.'}), 400
            results['package'] = {'filename': fn, 'filepath': fp, 'pkg_type': 'rpm', 'size_mb': sz}
        elif fn.endswith('.key') or 'gpg' in fn.lower():
            results['gpg_key'] = {'filename': fn, 'filepath': fp, 'size_mb': sz}
        elif fn.endswith('.pol') or 'policy' in fn.lower():
            results['policy'] = {'filename': fn, 'filepath': fp, 'size_mb': sz}
    return jsonify({'success': True, **results,
        'has_verification': results['gpg_key'] is not None and results['policy'] is not None})

@app.route('/api/upload/takserver/delete', methods=['POST'])
@login_required
def delete_uploaded_file():
    fn = request.json.get('filename', '')
    import re
    if not fn or not re.match(r'^[a-zA-Z0-9._-]+$', fn):
        return jsonify({'error': 'Invalid filename'}), 400
    fp = os.path.join(UPLOAD_DIR, fn)
    if os.path.exists(fp):
        os.remove(fp)
        return jsonify({'success': True, 'filename': fn})
    return jsonify({'error': 'File not found'}), 404

@app.route('/api/upload/takserver/existing')
@login_required
def check_existing_uploads():
    """Check for files already uploaded from a previous session"""
    files = {}
    for fn in os.listdir(UPLOAD_DIR):
        fp = os.path.join(UPLOAD_DIR, fn)
        sz = os.path.getsize(fp)
        sz_mb = round(sz / (1024*1024), 1)
        if fn.endswith('.deb') or fn.endswith('.rpm'):
            files['package'] = {'filename': fn, 'filepath': fp, 'size_mb': sz_mb}
        elif fn.endswith('.key'):
            files['gpg_key'] = {'filename': fn, 'filepath': fp, 'size_mb': sz_mb}
        elif fn.endswith('.pol'):
            files['policy'] = {'filename': fn, 'filepath': fp, 'size_mb': sz_mb}
    return jsonify(files)

# === TAK Server Deployment ===

deploy_log = []
deploy_status = {'running': False, 'complete': False, 'error': False, 'cancelled': False}

@app.route('/api/deploy/cancel', methods=['POST'])
@login_required
def cancel_deploy():
    if not deploy_status['running']:
        return jsonify({'error': 'No deployment in progress'}), 400
    deploy_status['cancelled'] = True
    log_step("⚠ Deployment cancelled by user")
    deploy_status.update({'running': False, 'error': True})
    # Kill any running subprocess children
    subprocess.run('pkill -P $$ 2>/dev/null; true', shell=True, capture_output=True)
    return jsonify({'success': True})

@app.route('/api/deploy/takserver', methods=['POST'])
@login_required
def deploy_takserver():
    if deploy_status['running']:
        return jsonify({'error': 'Deployment already in progress'}), 400
    data = request.json
    if not data: return jsonify({'error': 'No configuration provided'}), 400
    pkg_files = [f for f in os.listdir(UPLOAD_DIR) if f.endswith('.deb') or f.endswith('.rpm')]
    if not pkg_files: return jsonify({'error': 'No package file found.'}), 400
    config = {
        'package_path': os.path.join(UPLOAD_DIR, pkg_files[0]),
        'cert_country': data.get('cert_country', 'US'), 'cert_state': data.get('cert_state', 'CA'),
        'cert_city': data.get('cert_city', ''), 'cert_org': data.get('cert_org', ''),
        'cert_ou': data.get('cert_ou', ''), 'root_ca_name': data.get('root_ca_name', 'ROOT-CA-01'),
        'intermediate_ca_name': data.get('intermediate_ca_name', 'INTERMEDIATE-CA-01'),
        'enable_admin_ui': data.get('enable_admin_ui', False),
        'enable_webtak': data.get('enable_webtak', False),
        'enable_nonadmin_ui': data.get('enable_nonadmin_ui', False),
        'webadmin_password': data.get('webadmin_password', ''),
    }
    for ext, key in [('.key', 'gpg_key_path'), ('.pol', 'policy_path')]:
        matches = [f for f in os.listdir(UPLOAD_DIR) if f.endswith(ext)]
        if matches: config[key] = os.path.join(UPLOAD_DIR, matches[0])
    deploy_log.clear()
    deploy_status.update({'running': True, 'complete': False, 'error': False})
    threading.Thread(target=run_takserver_deploy, args=(config,), daemon=True).start()
    return jsonify({'success': True})

def log_step(msg):
    entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    deploy_log.append(entry)
    print(entry, flush=True)

def run_cmd(cmd, desc=None, check=True, quiet=False):
    if desc: log_step(desc)
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        if not quiet and r.stdout.strip():
            for line in r.stdout.strip().split('\n'):
                if 'NEEDRESTART' not in line:
                    deploy_log.append(f"  {line}")
        if not quiet and r.stderr.strip():
            for line in r.stderr.strip().split('\n'):
                if 'NEEDRESTART' not in line and 'error' in line.lower():
                    deploy_log.append(f"  ✗ {line}")
        if check and r.returncode != 0:
            log_step(f"✗ Command failed (exit {r.returncode})")
            return False
        return True
    except Exception as e:
        log_step(f"✗ {str(e)}")
        return False

def wait_for_package_lock():
    """Wait for unattended-upgrades to finish (common on fresh VPS).
    NO TIMEOUT - waits as long as needed. Ticks every 10 seconds."""
    log_step("Checking for system upgrades in progress...")
    r = subprocess.run('ps aux | grep "/usr/bin/unattended-upgrade" | grep -v shutdown | grep -v grep', shell=True, capture_output=True, text=True)
    if r.stdout.strip() == '':
        log_step("\u2713 No system upgrades in progress, continuing...")
        return True
    log_step("\u23f3 System is running unattended-upgrades, waiting for completion...")
    log_step("  This can take 20-45 minutes on a fresh VPS. Do not cancel.")
    waited = 0
    while True:
        time.sleep(10)
        waited += 10
        if deploy_status.get('cancelled'):
            log_step("⚠ Cancelled during upgrade wait")
            return False
        r = subprocess.run('ps aux | grep "/usr/bin/unattended-upgrade" | grep -v shutdown | grep -v grep', shell=True, capture_output=True, text=True)
        if r.stdout.strip() == '':
            m, s = divmod(waited, 60)
            log_step(f"\u2713 System upgrades complete! (waited {m}m {s}s)")
            time.sleep(5)
            return True
        m, s = divmod(waited, 60)
        deploy_log.append(f"  \u23f3 {m:02d}:{s:02d}")

def run_takserver_deploy(config):
    try:
        deploy_status['cancelled'] = False
        log_step("=" * 50); log_step("TAK Server Deployment Starting"); log_step("=" * 50)
        pkg = config['package_path']; pkg_name = os.path.basename(pkg)

        wait_for_package_lock()
        if deploy_status.get('cancelled'): return

        log_step(""); log_step("━━━ Step 1/9: System Limits ━━━")
        run_cmd('grep -q "soft nofile 32768" /etc/security/limits.conf || echo -e "* soft nofile 32768\\n* hard nofile 32768" >> /etc/security/limits.conf', "Increasing JVM thread limits...")
        log_step("✓ System limits configured")

        log_step(""); log_step("━━━ Step 2/9: PostgreSQL Repository ━━━")
        run_cmd('DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y lsb-release > /dev/null 2>&1', "Installing prerequisites...", check=False)
        run_cmd('install -d /usr/share/postgresql-common/pgdg', check=False)
        run_cmd('curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail https://www.postgresql.org/media/keys/ACCC4CF8.asc 2>/dev/null', "Adding PostgreSQL GPG key...")
        run_cmd('echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list')
        run_cmd('apt-get update -qq > /dev/null 2>&1', "Updating package lists...")
        log_step("✓ PostgreSQL repository configured")

        log_step(""); log_step("━━━ Step 3/9: Package Verification ━━━")
        if config.get('gpg_key_path') and config.get('policy_path'):
            log_step("GPG key and policy found — verifying...")
            run_cmd('DEBIAN_FRONTEND=noninteractive apt-get install -y debsig-verify', check=False)
            r = subprocess.run(f"grep 'id=' {config['policy_path']} | head -1 | sed 's/.*id=\"\\([^\"]*\\)\".*/\\1/'", shell=True, capture_output=True, text=True)
            pid = r.stdout.strip()
            log_step(f"  Policy ID: {pid}")
            if pid:
                run_cmd(f'mkdir -p /usr/share/debsig/keyrings/{pid}')
                run_cmd(f'mkdir -p /etc/debsig/policies/{pid}')
                run_cmd(f'rm -f /usr/share/debsig/keyrings/{pid}/debsig.gpg')
                run_cmd(f'touch /usr/share/debsig/keyrings/{pid}/debsig.gpg')
                run_cmd(f'gpg --no-default-keyring --keyring /usr/share/debsig/keyrings/{pid}/debsig.gpg --import {config["gpg_key_path"]}')
                run_cmd(f'cp {config["policy_path"]} /etc/debsig/policies/{pid}/debsig.pol')
                v = subprocess.run(f'debsig-verify -v {pkg}', shell=True, capture_output=True, text=True)
                if v.returncode == 0: log_step("✓ Package signature VERIFIED")
                else:
                    log_step(f"⚠ Verification exit code {v.returncode} — installing anyway")
                    if v.stdout.strip():
                        for line in v.stdout.strip().split('\n'):
                            if line.strip(): log_step(f"  {line.strip()}")
                    if v.stderr.strip():
                        for line in v.stderr.strip().split('\n'):
                            if line.strip(): log_step(f"  {line.strip()}")
        else:
            log_step("No GPG key/policy — skipping verification")

        log_step(""); log_step("━━━ Step 4/9: Installing TAK Server ━━━")
        log_step(f"Installing {pkg_name}...")
        # Primary: apt-get install handles dependencies automatically
        r1 = run_cmd(f'DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y {pkg} 2>&1', check=False)
        if not r1:
            # Fallback: dpkg + fix-broken (proven chain from Ubuntu script)
            log_step("  apt-get failed, trying dpkg + dependency fix...")
            run_cmd(f'DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l dpkg -i {pkg} 2>&1', check=False)
            run_cmd('DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -f -y 2>&1', "  Resolving dependencies...", check=False)
        # PostgreSQL cluster check (from proven script - sometimes cluster isn't created)
        pg_check = subprocess.run('pg_lsclusters 2>/dev/null | grep -q "15"', shell=True, capture_output=True)
        if pg_check.returncode != 0:
            log_step("  Creating PostgreSQL 15 cluster...")
            run_cmd('pg_createcluster 15 main --start 2>&1', check=False)
        # dpkg --configure if partially installed (from proven script)
        run_cmd('dpkg --configure -a 2>&1', check=False, quiet=True)
        if not os.path.exists('/opt/tak'):
            log_step("✗ FATAL: /opt/tak not found after install"); deploy_status.update({'error': True, 'running': False}); return
        log_step("✓ TAK Server installed")

        log_step(""); log_step("━━━ Step 5/9: Starting TAK Server ━━━")
        run_cmd('systemctl daemon-reload')
        run_cmd('systemctl start takserver', "Starting TAK Server...")
        run_cmd('systemctl enable takserver > /dev/null 2>&1')
        log_step("Waiting 30 seconds...")
        for remaining in range(20, -1, -10):
            time.sleep(10)
            deploy_log.append(f"  \u23f3 {remaining//60:02d}:{remaining%60:02d} remaining")
        log_step("✓ TAK Server started")

        log_step(""); log_step("━━━ Step 6/9: Configuring Firewall ━━━")
        for p in ['22/tcp', '8089/tcp', '8443/tcp', '8446/tcp', '5001/tcp']:
            run_cmd(f'ufw allow {p} > /dev/null 2>&1')
        run_cmd('ufw --force enable > /dev/null 2>&1')
        log_step("✓ Firewall configured (22, 8089, 8443, 8446, 5001)")

        log_step(""); log_step("━━━ Step 7/9: Generating Certificates ━━━")
        root_ca, int_ca = config['root_ca_name'], config['intermediate_ca_name']
        log_step(f"  Root CA: {root_ca} | Intermediate CA: {int_ca}")
        run_cmd('rm -rf /opt/tak/certs/files')
        run_cmd('cd /opt/tak/certs && cp cert-metadata.sh cert-metadata.sh.original 2>/dev/null; true')
        run_cmd('cd /opt/tak/certs && cp cert-metadata.sh.original cert-metadata.sh 2>/dev/null; true')
        subs = [('COUNTRY=US', f'COUNTRY={config["cert_country"]}'),
                ('STATE=${STATE}', f'STATE={config["cert_state"]}'),
                ('CITY=${CITY}', f'CITY={config["cert_city"]}'),
                ('ORGANIZATION=${ORGANIZATION:-TAK}', f'ORGANIZATION={config["cert_org"]}'),
                ('ORGANIZATIONAL_UNIT=${ORGANIZATIONAL_UNIT}', f'ORGANIZATIONAL_UNIT={config["cert_ou"]}')]
        for old, new in subs:
            run_cmd(f'sed -i "s/{old}/{new}/g" /opt/tak/certs/cert-metadata.sh', check=False)
        run_cmd('chown -R tak:tak /opt/tak/certs/')
        log_step(f"Creating Root CA: {root_ca}...")
        run_cmd(f'cd /opt/tak/certs && echo "{root_ca}" | sudo -u tak ./makeRootCa.sh 2>&1', quiet=True)
        log_step(f"Creating Intermediate CA: {int_ca}...")
        run_cmd(f'cd /opt/tak/certs && echo "y" | sudo -u tak ./makeCert.sh ca "{int_ca}" 2>&1', quiet=True)
        log_step("Creating server certificate...")
        run_cmd('cd /opt/tak/certs && sudo -u tak ./makeCert.sh server takserver 2>&1', quiet=True)
        log_step("Creating admin certificate...")
        run_cmd('cd /opt/tak/certs && sudo -u tak ./makeCert.sh client admin 2>&1', quiet=True)
        log_step("Creating user certificate...")
        run_cmd('cd /opt/tak/certs && sudo -u tak ./makeCert.sh client user 2>&1', quiet=True)
        log_step("✓ All certificates created")
        log_step("Importing root CA into enrollment truststore...")
        run_cmd(f'keytool -import -alias root-ca -file /opt/tak/certs/files/root-ca.pem -keystore /opt/tak/certs/files/truststore-{int_ca}.jks -storepass atakatak -noprompt 2>&1', check=False)
        log_step("✓ Root CA imported into truststore (ATAK enrollment trust chain complete)")
        log_step("Restarting TAK Server...")
        run_cmd('systemctl stop takserver'); time.sleep(10)
        run_cmd('pkill -9 -f takserver 2>/dev/null; true', check=False); time.sleep(5)
        run_cmd('systemctl start takserver')
        log_step("Waiting 1.5 minutes...")
        for remaining in range(80, -1, -10):
            time.sleep(10)
            deploy_log.append(f"  \u23f3 {remaining//60:02d}:{remaining%60:02d} remaining")

        log_step(""); log_step("━━━ Step 8/9: Configuring CoreConfig.xml ━━━")
        run_cmd('sed -i \'s|<input auth="anonymous" _name="stdtcp" protocol="tcp" port="8087"/>|<input auth="x509" _name="stdssl" protocol="tls" port="8089"/>|g\' /opt/tak/CoreConfig.xml', "Enabling X.509 auth on 8089...")
        run_cmd(f'sed -i "s|truststoreFile=\\"certs/files/truststore-root.jks|truststoreFile=\\"certs/files/truststore-{int_ca}.jks|g" /opt/tak/CoreConfig.xml', "Setting intermediate CA truststore...")
        cert_block = (f'<certificateSigning CA="TAKServer"><certificateConfig>\\n'
            f'<nameEntries>\\n<nameEntry name="O" value="{config["cert_org"]}"/>\\n'
            f'<nameEntry name="OU" value="{config["cert_ou"]}"/>\\n</nameEntries>\\n'
            f'</certificateConfig>\\n<TAKServerCAConfig keystore="JKS" '
            f'keystoreFile="certs/files/{int_ca}-signing.jks" keystorePass="atakatak" '
            f'validityDays="3650" signatureAlg="SHA256WithRSA" />\\n'
            f'</certificateSigning>\\n<vbm enabled="false"/>')
        run_cmd(f'sed -i \'s|<vbm enabled="false"/>|{cert_block}|g\' /opt/tak/CoreConfig.xml', "Enabling certificate enrollment...")
        run_cmd('sed -i \'s|<auth>|<auth x509useGroupCache="true">|g\' /opt/tak/CoreConfig.xml')
        admin_ui = str(config.get('enable_admin_ui', False)).lower()
        webtak = str(config.get('enable_webtak', False)).lower()
        nonadmin = str(config.get('enable_nonadmin_ui', False)).lower()
        if config.get('enable_admin_ui') or config.get('enable_webtak') or config.get('enable_nonadmin_ui'):
            log_step(f"WebTAK: AdminUI={admin_ui}, WebTAK={webtak}, NonAdminUI={nonadmin}")
            run_cmd(f'sed -i \'s|"cert_https"/|"cert_https" enableAdminUI="{admin_ui}" enableWebtak="{webtak}" enableNonAdminUI="{nonadmin}"/|g\' /opt/tak/CoreConfig.xml')
        log_step("✓ CoreConfig.xml configured")
        log_step("Final restart...")
        run_cmd('systemctl stop takserver'); time.sleep(10)
        run_cmd('pkill -9 -f takserver 2>/dev/null; true', check=False); time.sleep(5)
        run_cmd('systemctl start takserver')
        log_step("Waiting 10 minutes for full initialization before promoting admin...")
        total_wait = 600
        waited = 0
        while waited < total_wait:
            time.sleep(10)
            waited += 10
            if deploy_status.get('cancelled'):
                log_step("\u26a0 Cancelled during initialization wait")
                return
            left = total_wait - waited
            m, s = divmod(left, 60)
            deploy_log.append(f"  \u23f3 {m:02d}:{s:02d} remaining")
        log_step("\u2713 Initialization wait complete")

        log_step(""); log_step("━━━ Step 9/9: Promoting Admin ━━━")
        run_cmd('java -jar /opt/tak/utils/UserManager.jar certmod -A /opt/tak/certs/files/admin.pem 2>&1', "Promoting admin certificate...", check=False)
        webadmin_pass = config.get('webadmin_password', '')
        if webadmin_pass:
            log_step("Creating webadmin user...")
            run_cmd(f"java -jar /opt/tak/utils/UserManager.jar usermod -A -p '{webadmin_pass}' webadmin 2>&1", check=False)
            log_step("✓ webadmin user created")
        run_cmd('systemctl restart takserver')
        log_step("Waiting 30 seconds...")
        for remaining in range(20, -1, -10):
            time.sleep(10)
            deploy_log.append(f"  \u23f3 {remaining//60:02d}:{remaining%60:02d} remaining")
        ip = load_settings().get('server_ip', 'YOUR-IP')
        settings = load_settings()
        # Save webadmin_password to settings so Authentik deploy can read it
        if webadmin_pass:
            settings['webadmin_password'] = webadmin_pass
            save_settings(settings)
        log_step(""); log_step("=" * 50); log_step("✓ DEPLOYMENT COMPLETE!"); log_step("=" * 50); log_step("")
        log_step(f"  WebGUI (cert):     https://{ip}:8443")
        if webadmin_pass:
            log_step(f"  WebGUI (password): https://{ip}:8446")
            log_step(f"  Username: webadmin")
        log_step(f"  Certificate Password: atakatak")
        log_step(f"  Admin cert: /opt/tak/certs/files/admin.p12")
        # Regenerate Caddyfile if Caddy is configured
        if settings.get('fqdn'):
            generate_caddyfile(settings)
            subprocess.run('systemctl reload caddy 2>/dev/null; true', shell=True, capture_output=True)
            log_step(f"  ✓ Caddy config updated for TAK Server")

        # If Caddy is already running with a domain, install LE cert on 8446 now.
        # This handles the case where Caddy was deployed before TAK Server.
        fqdn = settings.get('fqdn', '')
        if fqdn:
            caddy_active = subprocess.run('systemctl is-active caddy', shell=True, capture_output=True, text=True)
            if caddy_active.stdout.strip() == 'active':
                log_step("")
                log_step("━━━ Installing LE Cert on Port 8446 ━━━")
                install_le_cert_on_8446(fqdn, log_step, wait_for_cert=True)

        deploy_status.update({'complete': True, 'running': False})
    except Exception as e:
        log_step(f"✗ FATAL ERROR: {str(e)}")
        deploy_status.update({'error': True, 'running': False})

@app.route('/api/download/admin-cert')
@login_required
def download_admin_cert():
    p = '/opt/tak/certs/files'
    if os.path.exists(os.path.join(p, 'admin.p12')): return send_from_directory(p, 'admin.p12', as_attachment=True)
    return jsonify({'error': 'admin.p12 not found'}), 404

@app.route('/api/download/user-cert')
@login_required
def download_user_cert():
    p = '/opt/tak/certs/files'
    if os.path.exists(os.path.join(p, 'user.p12')): return send_from_directory(p, 'user.p12', as_attachment=True)
    return jsonify({'error': 'user.p12 not found'}), 404

@app.route('/api/download/truststore')
@login_required
def download_truststore():
    p = '/opt/tak/certs/files'
    if os.path.exists(p):
        for f in os.listdir(p):
            if f.startswith('truststore-') and f.endswith('.p12') and 'root' not in f:
                return send_from_directory(p, f, as_attachment=True)
    return jsonify({'error': 'truststore not found'}), 404

@app.route('/api/certs/list')
@login_required
def list_cert_files():
    cert_path = '/opt/tak/certs/files'
    if not os.path.exists(cert_path):
        return jsonify({'files': []})
    files = []
    for f in sorted(os.listdir(cert_path)):
        fp = os.path.join(cert_path, f)
        if os.path.isfile(fp):
            files.append({'name': f, 'size': os.path.getsize(fp),
                'size_display': f"{os.path.getsize(fp)/1024:.1f} KB" if os.path.getsize(fp) < 1024*1024 else f"{os.path.getsize(fp)/(1024*1024):.1f} MB"})
    return jsonify({'files': files})

@app.route('/api/certs/download/<filename>')
@login_required
def download_cert_file(filename):
    import re
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        return jsonify({'error': 'Invalid filename'}), 400
    cert_path = '/opt/tak/certs/files'
    fp = os.path.join(cert_path, filename)
    if os.path.exists(fp) and os.path.isfile(fp):
        return send_from_directory(cert_path, filename, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404

@app.route('/api/deploy/log')
@login_required
def deploy_log_stream():
    last = int(request.args.get('after', 0))
    return jsonify({'entries': deploy_log[last:], 'total': len(deploy_log),
        'running': deploy_status['running'], 'complete': deploy_status['complete'], 'error': deploy_status['error']})

# === Shared CSS ===
BASE_CSS = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');
@import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0');
*{margin:0;padding:0;box-sizing:border-box}
.material-symbols-outlined{font-family:'Material Symbols Outlined';font-weight:400;font-style:normal;font-size:20px;line-height:1;letter-spacing:normal;white-space:nowrap;word-wrap:normal;direction:ltr;-webkit-font-smoothing:antialiased}
.nav-icon.material-symbols-outlined{font-size:22px;width:22px;text-align:center}
:root{--bg-primary:#0a0e17;--bg-card:rgba(15,23,42,0.7);--bg-card-hover:rgba(15,23,42,0.9);--border:rgba(59,130,246,0.1);--border-hover:rgba(59,130,246,0.3);--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-dim:#94a3b8;--accent:#3b82f6;--accent-glow:rgba(59,130,246,0.15);--green:#10b981;--red:#ef4444;--yellow:#f59e0b;--cyan:#06b6d4}
body{font-family:'DM Sans',sans-serif;background:var(--bg-primary);color:var(--text-primary);min-height:100vh}
body::before{content:'';position:fixed;top:0;left:0;right:0;bottom:0;background-image:linear-gradient(rgba(59,130,246,0.02) 1px,transparent 1px),linear-gradient(90deg,rgba(59,130,246,0.02) 1px,transparent 1px);background-size:60px 60px;pointer-events:none;z-index:0}
.top-bar{position:fixed;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent),var(--cyan),transparent);z-index:100}
.header{position:relative;z-index:10;display:flex;align-items:center;justify-content:space-between;padding:20px 32px;border-bottom:1px solid var(--border)}
.header-left{display:flex;align-items:center;gap:14px}
.header-icon{width:40px;height:40px;background:linear-gradient(135deg,#1e40af,#0891b2);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px}
.header-title{font-family:'JetBrains Mono',monospace;font-weight:700;font-size:18px}
.header-subtitle{font-size:12px;color:var(--text-dim);font-family:'JetBrains Mono',monospace}
.header-right{display:flex;align-items:center;gap:16px}
.os-badge{background:var(--bg-card);border:1px solid var(--border);padding:6px 14px;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-dim)}
.btn-logout,.btn-back{color:var(--text-dim);text-decoration:none;font-family:'JetBrains Mono',monospace;font-size:12px;padding:6px 14px;border:1px solid var(--border);border-radius:8px;transition:all 0.2s}
.btn-logout:hover,.btn-back:hover{color:var(--text-secondary);border-color:var(--border-hover)}
.main{position:relative;z-index:10;max-width:1100px;margin:0 auto;padding:32px}
.section-title{font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:16px;font-weight:600}
.metrics-bar{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px}
.metric-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:18px;text-align:center}
.metric-label{font-family:'JetBrains Mono',monospace;font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text-dim);margin-bottom:6px}
.metric-value{font-family:'JetBrains Mono',monospace;font-size:24px;font-weight:700;color:var(--text-primary)}
.metric-detail{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);margin-top:2px}
.footer{text-align:center;padding:24px;color:var(--text-dim);font-family:'JetBrains Mono',monospace;font-size:11px}
.form-field label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);font-weight:600;margin-bottom:6px}
.form-field input[type="text"],.form-field input[type="password"]{width:100%;padding:10px 14px;background:rgba(15,23,42,0.6);border:1px solid rgba(59,130,246,0.2);border-radius:8px;color:var(--text-primary);font-family:'JetBrains Mono',monospace;font-size:14px}
.form-field input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,0.1)}
@media(max-width:768px){.metrics-bar{grid-template-columns:repeat(2,1fr)}.modules-grid{grid-template-columns:1fr}.header{padding:16px 20px}.main{padding:20px}}
"""

# === Login Template ===
LOGIN_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>infra-TAK</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'DM Sans',sans-serif;background:#0a0e17;min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden}
body::before{content:'';position:fixed;top:0;left:0;right:0;bottom:0;background-image:linear-gradient(rgba(59,130,246,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(59,130,246,0.03) 1px,transparent 1px);background-size:60px 60px;z-index:0}
body::after{content:'';position:fixed;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#3b82f6,#06b6d4,transparent);z-index:10}
.lc{position:relative;z-index:1;width:100%;max-width:420px;padding:20px}
.card{background:linear-gradient(145deg,rgba(15,23,42,0.95),rgba(15,23,42,0.8));border:1px solid rgba(59,130,246,0.15);border-radius:16px;padding:48px 40px;backdrop-filter:blur(20px);box-shadow:0 0 0 1px rgba(59,130,246,0.05),0 25px 50px rgba(0,0,0,0.5)}
.logo{text-align:center;margin-bottom:36px}
.logo-icon{width:56px;height:56px;background:linear-gradient(135deg,#1e40af,#0891b2);border-radius:14px;display:inline-flex;align-items:center;justify-content:center;font-size:28px;margin-bottom:16px;box-shadow:0 8px 24px rgba(59,130,246,0.25)}
.logo h1{font-family:'JetBrains Mono',monospace;font-size:22px;font-weight:700;color:#f1f5f9}
.logo p{color:#64748b;font-size:13px;margin-top:6px;letter-spacing:0.5px;text-transform:uppercase}
.logo .built-by{font-size:10px;color:#94a3b8;margin-top:8px;text-transform:none;letter-spacing:0}
.fg{margin-bottom:24px}
.fg label{display:block;color:#cbd5e1;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.fg input{width:100%;padding:14px 16px;background:rgba(15,23,42,0.6);border:1px solid rgba(59,130,246,0.2);border-radius:10px;color:#f1f5f9;font-family:'JetBrains Mono',monospace;font-size:15px;transition:all 0.2s}
.fg input:focus{outline:none;border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,0.1)}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:10px;font-family:'DM Sans',sans-serif;font-size:15px;font-weight:600;cursor:pointer;transition:all 0.2s}
.btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(59,130,246,0.3)}
.err{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);color:#fca5a5;padding:12px 16px;border-radius:8px;font-size:14px;margin-bottom:20px;text-align:center}
.ver{text-align:center;margin-top:20px;color:#64748b;font-family:'JetBrains Mono',monospace;font-size:11px}
</style></head><body>
<div class="lc"><div class="card">
<div class="logo"><div class="logo-icon">⚡</div><h1>infra-TAK</h1><p>TAK Infrastructure Platform</p><p class="built-by">built by TAKWERX</p></div>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<form method="POST"><div class="fg"><label>Password</label><input type="password" name="password" autofocus placeholder="Enter admin password"></div><button type="submit" class="btn">Sign In</button></form>
</div><div class="ver">v{{ version }}</div></div>
</body></html>'''

# === API Routes ===

@app.route('/api/metrics')
@login_required
def api_metrics():
    return jsonify(get_system_metrics())

@app.route('/api/modules')
@login_required
def api_modules():
    """Live module states for dashboard cards (so CLI uninstall/start/stop is reflected)."""
    modules = detect_modules()
    return jsonify({k: {'installed': m.get('installed', False), 'running': m.get('running', False)} for k, m in modules.items()})

# === Console Template (installed services only) ===
CONSOLE_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Console — infra-TAK</title>
<style>
''' + BASE_CSS + '''
body{display:flex;flex-direction:row;min-height:100vh}
.sidebar{width:220px;min-width:220px;background:var(--bg-surface);border-right:1px solid var(--border);padding:24px 0;flex-shrink:0}
.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}
.sidebar-logo span{font-size:15px;font-weight:700}.sidebar-logo small{display:block;font-size:10px;color:var(--text-dim);font-family:'JetBrains Mono',monospace;margin-top:2px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 20px;color:var(--text-secondary);text-decoration:none;font-size:13px;font-weight:500;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{color:var(--text-primary);background:rgba(255,255,255,.03)}
.nav-item.active{color:var(--cyan);background:rgba(6,182,212,.06);border-left-color:var(--cyan)}
.nav-icon{font-size:15px;width:18px;text-align:center}
.main{flex:1;min-width:0;overflow-y:auto;padding:32px;max-width:1000px;margin:0 auto}
.modules-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:32px}
@media(max-width:900px){.modules-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:600px){.modules-grid{grid-template-columns:1fr}}
.module-card{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:12px;cursor:pointer;transition:all 0.3s;text-decoration:none;display:block;color:inherit}
.module-card:hover{border-color:var(--border-hover);background:var(--bg-card-hover);transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,0.3)}
.module-header{display:flex;align-items:flex-end;gap:10px;margin-bottom:8px}
.module-header--logo .module-icon{max-height:36px;width:auto;object-fit:contain}
.module-header .module-icon{flex-shrink:0}
.module-icon{font-size:22px}
.module-header .module-name{font-family:'JetBrains Mono',monospace;font-weight:600;font-size:14px;margin-bottom:0;padding-bottom:2px}
.module-name{font-family:'JetBrains Mono',monospace;font-weight:600;font-size:14px;margin-bottom:4px}
.module-desc{font-size:12px;color:var(--text-dim);line-height:1.35}
.module-status{font-family:'JetBrains Mono',monospace;font-size:10px;padding:3px 8px;border-radius:4px;display:inline-flex;align-items:center;gap:4px;margin-top:8px}
.status-running{background:rgba(16,185,129,0.1);color:var(--green)}
.status-stopped{background:rgba(239,68,68,0.1);color:var(--red)}
.status-not-installed{background:rgba(71,85,105,0.2);color:var(--text-dim)}
.status-dot{width:5px;height:5px;border-radius:50%;background:currentColor}
.status-running .status-dot{animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
.module-action{display:inline-block;margin-top:6px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--accent);opacity:0;transition:opacity 0.2s}
.module-card:hover .module-action{opacity:1}
.meta-line{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);margin-bottom:12px}
</style></head><body>
{{ sidebar_html }}
<div class="main">
{% if not settings.get('fqdn') %}
<div style="background:linear-gradient(135deg,rgba(234,179,8,0.1),rgba(239,68,68,0.05));border:1px solid rgba(234,179,8,0.3);border-radius:12px;padding:20px 24px;margin-bottom:24px;font-family:'JetBrains Mono',monospace">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
<div>
<div style="font-size:13px;font-weight:600;color:var(--yellow)">🔒 No Domain Configured — Running in IP-Only Mode</div>
<div style="font-size:11px;color:var(--text-dim);margin-top:6px;line-height:1.5">Without a domain: no ATAK QR enrollment · no TAK Portal authentication · no trusted SSL · self-signed certs only</div>
</div>
<a href="/caddy" style="padding:8px 18px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;cursor:pointer;text-decoration:none;white-space:nowrap">Set Up Domain →</a>
</div>
</div>
{% endif %}
<div id="update-banner" style="display:none;background:linear-gradient(135deg,rgba(30,64,175,0.15),rgba(14,116,144,0.15));border:1px solid rgba(59,130,246,0.3);border-radius:12px;padding:16px 24px;margin-bottom:24px;font-family:'JetBrains Mono',monospace">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
<div>
<div style="font-size:13px;font-weight:600;color:var(--cyan)">⚡ Update Available</div>
<div style="font-size:12px;color:var(--text-secondary);margin-top:4px"><span id="update-info"></span></div>
</div>
<div style="display:flex;gap:8px">
<button onclick="toggleUpdateDetails()" id="update-details-btn" style="padding:6px 14px;background:none;border:1px solid var(--border);color:var(--text-dim);border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:11px;cursor:pointer">Details</button>
<button onclick="applyUpdate()" id="update-apply-btn" style="padding:6px 14px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600;cursor:pointer">Update Now</button>
</div>
</div>
<div id="update-details" style="display:none;margin-top:12px;padding-top:12px;border-top:1px solid var(--border);font-size:11px;color:var(--text-dim);white-space:pre-wrap;max-height:200px;overflow-y:auto"></div>
<div id="update-status" style="display:none;margin-top:8px;font-size:11px"></div>
</div>
<div class="metrics-bar" id="metrics-bar">
<div class="metric-card"><div class="metric-label">CPU</div><div class="metric-value" id="cpu-value">{{ metrics.cpu_percent }}%</div></div>
<div class="metric-card"><div class="metric-label">Memory</div><div class="metric-value" id="ram-value">{{ metrics.ram_percent }}%</div><div class="metric-detail">{{ metrics.ram_used_gb }}GB / {{ metrics.ram_total_gb }}GB</div></div>
<div class="metric-card"><div class="metric-label">Disk</div><div class="metric-value" id="disk-value">{{ metrics.disk_percent }}%</div><div class="metric-detail">{{ metrics.disk_used_gb }}GB / {{ metrics.disk_total_gb }}GB</div></div>
<div class="metric-card"><div class="metric-label">Uptime</div><div class="metric-value" id="uptime-value" style="font-size:18px">{{ metrics.uptime }}</div></div>
</div>
<div class="section-title">Console</div>
<div class="meta-line">v{{ version }} · {{ settings.get('os_name', 'Unknown OS') }} · {{ settings.get('server_ip', 'N/A') }}{% if settings.get('fqdn') %} · {{ settings.get('fqdn') }}{% endif %}</div>
<div class="modules-grid">
{% if not modules %}
<div style="grid-column:1/-1;background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:48px;text-align:center">
<div style="font-size:15px;color:var(--text-secondary);margin-bottom:12px">No deployed services yet</div>
<div style="font-size:13px;color:var(--text-dim);margin-bottom:20px">Install and deploy from the Marketplace to see them here.</div>
<a href="/marketplace" style="display:inline-block;padding:10px 24px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;text-decoration:none">Go to Marketplace →</a>
</div>
{% else %}
{% for key, mod in modules.items() %}
<a class="module-card" href="{{ mod.route }}" data-module="{{ key }}">
<div class="module-header{% if mod.get('icon_url') %} module-header--logo{% endif %}">{% if mod.icon_data %}<img src="{{ mod.icon_data }}" alt="" class="module-icon" style="width:24px;height:24px;object-fit:contain">{% elif key == 'takportal' %}<span class="module-icon material-symbols-outlined" style="font-size:28px">group</span>{% elif key == 'emailrelay' %}<span class="module-icon material-symbols-outlined" style="font-size:28px">outgoing_mail</span>{% elif mod.get('icon_url') %}<img src="{{ mod.icon_url }}" alt="" class="module-icon" style="height:36px;width:auto;max-width:{% if key == 'takserver' %}72px{% else %}100px{% endif %};object-fit:contain">{% else %}<span class="module-icon">{{ mod.icon }}</span>{% endif %}
{% if not mod.get('icon_url') or key == 'takportal' or key == 'emailrelay' %}<div class="module-name">{{ mod.name }}</div>{% endif %}
</div>
<div class="module-desc">{{ mod.description }}</div>
<span class="module-status status-{% if mod.installed and mod.running %}running{% elif mod.installed %}stopped{% else %}not-installed{% endif %}" id="module-status-{{ key }}" data-module="{{ key }}">{% if mod.installed and mod.running %}<span class="status-dot"></span> Running{% elif mod.installed %}<span class="status-dot"></span> Stopped{% else %}Not Installed{% endif %}</span>
{% if mod.installed %}<span class="module-action">Manage →</span>{% else %}<span class="module-action">Deploy →</span>{% endif %}
</a>
{% endfor %}
{% endif %}
</div>
</div>
<script>
setInterval(async()=>{try{const r=await fetch('/api/metrics');const d=await r.json();document.getElementById('cpu-value').textContent=d.cpu_percent+'%';document.getElementById('ram-value').textContent=d.ram_percent+'%';document.getElementById('disk-value').textContent=d.disk_percent+'%';document.getElementById('uptime-value').textContent=d.uptime}catch(e){}},5000);
function refreshModuleCards(){
    fetch('/api/modules').then(r=>r.json()).then(function(mods){
        for(var k in mods){
            var el=document.getElementById('module-status-'+k);
            if(!el)continue;
            var m=mods[k];
            var cls='module-status status-'+(m.installed&&m.running?'running':m.installed?'stopped':'not-installed');
            var label=m.installed&&m.running?'<span class="status-dot"></span> Running':m.installed?'<span class="status-dot"></span> Stopped':'Not Installed';
            el.className=cls;el.innerHTML=label;
        }
    }).catch(function(){});
}
setInterval(refreshModuleCards,8000);
refreshModuleCards();
var updateBody='';
async function checkUpdate(){
    try{
        var r=await fetch('/api/update/check');var d=await r.json();
        if(d.update_available){
            document.getElementById('update-banner').style.display='block';
            document.getElementById('update-info').textContent='v'+d.current+' → v'+d.latest+(d.notes?' · '+d.notes:'');
            updateBody=d.body||'No details available';
        }
    }catch(e){}
}
function toggleUpdateDetails(){
    var el=document.getElementById('update-details');
    if(el.style.display==='none'){el.textContent=updateBody;el.style.display='block'}
    else{el.style.display='none'}
}
async function applyUpdate(){
    var btn=document.getElementById('update-apply-btn');
    var status=document.getElementById('update-status');
    btn.disabled=true;btn.textContent='Updating...';btn.style.opacity='0.7';
    status.style.display='block';status.style.color='var(--cyan)';status.textContent='Pulling latest from GitHub...';
    try{
        var r=await fetch('/api/update/apply',{method:'POST'});var d=await r.json();
        if(d.success){
            status.style.color='var(--green)';
            status.textContent='✓ Updated! Restarting console...';
            setTimeout(function(){window.location.reload()},5000);
        }else{
            status.style.color='var(--red)';status.textContent='✗ '+d.error;
            btn.disabled=false;btn.textContent='Update Now';btn.style.opacity='1';
        }
    }catch(e){status.style.color='var(--red)';status.textContent='✗ '+e.message;btn.disabled=false;btn.textContent='Update Now';btn.style.opacity='1'}
}
checkUpdate();
</script></body></html>'''

# === Marketplace Template (all services, deploy from here) ===
MARKETPLACE_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Marketplace — infra-TAK</title>
<style>
''' + BASE_CSS + '''
body{display:flex;flex-direction:row;min-height:100vh}
.sidebar{width:220px;min-width:220px;background:var(--bg-surface);border-right:1px solid var(--border);padding:24px 0;flex-shrink:0}
.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}
.sidebar-logo span{font-size:15px;font-weight:700}.sidebar-logo small{display:block;font-size:10px;color:var(--text-dim);font-family:'JetBrains Mono',monospace;margin-top:2px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 20px;color:var(--text-secondary);text-decoration:none;font-size:13px;font-weight:500;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{color:var(--text-primary);background:rgba(255,255,255,.03)}
.nav-item.active{color:var(--cyan);background:rgba(6,182,212,.06);border-left-color:var(--cyan)}
.nav-icon{font-size:15px;width:18px;text-align:center}
.main{flex:1;min-width:0;overflow-y:auto;padding:32px;max-width:1000px;margin:0 auto}
.modules-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:32px}
@media(max-width:900px){.modules-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:600px){.modules-grid{grid-template-columns:1fr}}
.module-card{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:12px;cursor:pointer;transition:all 0.3s;text-decoration:none;display:block;color:inherit}
.module-card:hover{border-color:var(--border-hover);background:var(--bg-card-hover);transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,0.3)}
.module-header{display:flex;align-items:flex-end;gap:10px;margin-bottom:8px}
.module-header--logo .module-icon{max-height:36px;width:auto;object-fit:contain}
.module-header .module-icon{flex-shrink:0}
.module-icon{font-size:22px}
.module-header .module-name{font-family:'JetBrains Mono',monospace;font-weight:600;font-size:14px;margin-bottom:0;padding-bottom:2px}
.module-name{font-family:'JetBrains Mono',monospace;font-weight:600;font-size:14px;margin-bottom:4px}
.module-desc{font-size:12px;color:var(--text-dim);line-height:1.35}
.module-status{font-family:'JetBrains Mono',monospace;font-size:10px;padding:3px 8px;border-radius:4px;display:inline-flex;align-items:center;gap:4px;margin-top:8px}
.status-running{background:rgba(16,185,129,0.1);color:var(--green)}
.status-stopped{background:rgba(239,68,68,0.1);color:var(--red)}
.status-not-installed{background:rgba(71,85,105,0.2);color:var(--text-dim)}
.status-dot{width:5px;height:5px;border-radius:50%;background:currentColor}
.status-running .status-dot{animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
.module-action{display:inline-block;margin-top:6px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--accent);opacity:0;transition:opacity 0.2s}
.module-card:hover .module-action{opacity:1}
.meta-line{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);margin-bottom:12px}
</style></head><body>
{{ sidebar_html }}
<div class="main">
{% if not settings.get('fqdn') %}
<div style="background:linear-gradient(135deg,rgba(234,179,8,0.1),rgba(239,68,68,0.05));border:1px solid rgba(234,179,8,0.3);border-radius:12px;padding:20px 24px;margin-bottom:24px;font-family:'JetBrains Mono',monospace">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
<div>
<div style="font-size:13px;font-weight:600;color:var(--yellow)">🔒 No Domain Configured — Running in IP-Only Mode</div>
<div style="font-size:11px;color:var(--text-dim);margin-top:6px;line-height:1.5">Without a domain: no ATAK QR enrollment · no TAK Portal authentication · no trusted SSL · self-signed certs only</div>
</div>
<a href="/caddy" style="padding:8px 18px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;cursor:pointer;text-decoration:none;white-space:nowrap">Set Up Domain →</a>
</div>
</div>
{% endif %}
<div class="metrics-bar" id="metrics-bar">
<div class="metric-card"><div class="metric-label">CPU</div><div class="metric-value" id="cpu-value">{{ metrics.cpu_percent }}%</div></div>
<div class="metric-card"><div class="metric-label">Memory</div><div class="metric-value" id="ram-value">{{ metrics.ram_percent }}%</div><div class="metric-detail">{{ metrics.ram_used_gb }}GB / {{ metrics.ram_total_gb }}GB</div></div>
<div class="metric-card"><div class="metric-label">Disk</div><div class="metric-value" id="disk-value">{{ metrics.disk_percent }}%</div><div class="metric-detail">{{ metrics.disk_used_gb }}GB / {{ metrics.disk_total_gb }}GB</div></div>
<div class="metric-card"><div class="metric-label">Uptime</div><div class="metric-value" id="uptime-value" style="font-size:18px">{{ metrics.uptime }}</div></div>
</div>
<div class="section-title">Marketplace</div>
<div class="modules-grid">
{% if not modules %}
<div style="grid-column:1/-1;background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:48px;text-align:center">
<div style="font-size:15px;color:var(--text-secondary);margin-bottom:12px">All available services are installed</div>
<div style="font-size:13px;color:var(--text-dim);margin-bottom:20px">Manage and monitor everything from the Console.</div>
<a href="/console" style="display:inline-block;padding:10px 24px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;text-decoration:none">Go to Console →</a>
</div>
{% else %}
{% for key, mod in modules.items() %}
<a class="module-card" href="{{ mod.route }}" data-module="{{ key }}">
<div class="module-header{% if mod.get('icon_url') %} module-header--logo{% endif %}">{% if mod.icon_data %}<img src="{{ mod.icon_data }}" alt="" class="module-icon" style="width:24px;height:24px;object-fit:contain">{% elif key == 'takportal' %}<span class="module-icon material-symbols-outlined" style="font-size:28px">group</span>{% elif key == 'emailrelay' %}<span class="module-icon material-symbols-outlined" style="font-size:28px">outgoing_mail</span>{% elif mod.get('icon_url') %}<img src="{{ mod.icon_url }}" alt="" class="module-icon" style="height:36px;width:auto;max-width:{% if key == 'takserver' %}72px{% else %}100px{% endif %};object-fit:contain">{% else %}<span class="module-icon">{{ mod.icon }}</span>{% endif %}
{% if not mod.get('icon_url') or key == 'takportal' or key == 'emailrelay' %}<div class="module-name">{{ mod.name }}</div>{% endif %}
</div>
<div class="module-desc">{{ mod.description }}</div>
<span class="module-status status-not-installed" id="module-status-{{ key }}" data-module="{{ key }}">Not Installed</span>
<span class="module-action">Deploy →</span>
</a>
{% endfor %}
{% endif %}
</div>
</div>
<script>
setInterval(async()=>{try{const r=await fetch('/api/metrics');const d=await r.json();document.getElementById('cpu-value').textContent=d.cpu_percent+'%';document.getElementById('ram-value').textContent=d.ram_percent+'%';document.getElementById('disk-value').textContent=d.disk_percent+'%';document.getElementById('uptime-value').textContent=d.uptime}catch(e){}},5000);
</script></body></html>'''

# === TAK Server Template ===
TAKSERVER_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>TAK Server</title>
<style>
''' + BASE_CSS + '''
.upload-area{border:2px dashed var(--border);border-radius:12px;padding:40px;text-align:center;cursor:pointer;transition:all 0.3s;background:rgba(15,23,42,0.3);margin-bottom:20px}
.upload-area:hover,.upload-area.dragover{border-color:var(--accent);background:var(--accent-glow)}
.upload-icon{font-size:40px;margin-bottom:12px}.upload-text{font-size:16px;color:var(--text-secondary);margin-bottom:8px}.upload-hint{font-size:13px;color:var(--text-dim);line-height:1.6}
.progress-item{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin-bottom:8px}
.progress-bar-outer{width:100%;height:4px;background:rgba(59,130,246,0.1);border-radius:2px;margin-top:8px;overflow:hidden}
.progress-bar-inner{height:100%;border-radius:2px;background:linear-gradient(90deg,var(--accent),var(--cyan));transition:width 0.3s}
.control-btn{padding:10px 20px;border:1px solid var(--border);border-radius:8px;background:var(--bg-card);color:var(--text-secondary);font-family:'JetBrains Mono',monospace;font-size:13px;cursor:pointer;transition:all 0.2s}
.control-btn:hover{border-color:var(--border-hover);color:var(--text-primary)}
.control-btn.btn-stop{border-color:rgba(239,68,68,0.3)}.control-btn.btn-stop:hover{background:rgba(239,68,68,0.1);color:var(--red)}
.control-btn.btn-start{border-color:rgba(16,185,129,0.3)}.control-btn.btn-start:hover{background:rgba(16,185,129,0.1);color:var(--green)}
.status-banner{background:var(--bg-card);border:1px solid var(--border);border-top:none;border-radius:12px;padding:24px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between}
.status-info{display:flex;align-items:center;gap:16px}
.status-icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px}
.status-icon.running{background:rgba(16,185,129,0.1)}.status-icon.stopped{background:rgba(239,68,68,0.1)}.status-icon.not-installed{background:rgba(71,85,105,0.2)}
.status-text{font-family:'JetBrains Mono',monospace;font-size:18px;font-weight:600}
.status-detail{font-size:13px;color:var(--text-dim);margin-top:4px}
.status-logo-wrap{display:flex;align-items:center;gap:10px}
.status-logo{height:36px;width:auto;max-width:100px;object-fit:contain}
.status-name{font-family:'JetBrains Mono',monospace;font-weight:600;font-size:18px;color:var(--text-primary)}
.controls{display:flex;gap:10px}
.cert-downloads{display:flex;gap:12px;flex-wrap:wrap;margin-top:16px}
.cert-btn{padding:10px 20px;border-radius:8px;text-decoration:none;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;transition:all 0.2s}
.cert-btn-primary{background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff}
.cert-btn-secondary{background:rgba(59,130,246,0.1);color:var(--accent);border:1px solid var(--border)}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;display:none;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg-card);border:1px solid var(--border);border-radius:14px;padding:28px;width:400px;max-width:90vw}
.modal h3{font-size:16px;font-weight:700;margin-bottom:8px;color:var(--red)}
.modal p{font-size:13px;color:var(--text-secondary);margin-bottom:20px}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}
.form-label{display:block;font-size:12px;font-weight:600;color:var(--text-secondary);margin-bottom:6px}
.form-input{width:100%;padding:10px 14px;background:#0a0e1a;border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-size:13px}
.uninstall-spinner{display:inline-block;width:18px;height:18px;border:2px solid var(--border);border-top-color:var(--cyan);border-radius:50%;animation:uninstall-spin .7s linear infinite;vertical-align:middle;margin-right:8px}
@keyframes uninstall-spin{to{transform:rotate(360deg)}}
.uninstall-progress-row{display:flex;align-items:center;gap:8px;margin-top:10px;font-size:13px;color:var(--text-secondary)}
body{display:flex;flex-direction:row;min-height:100vh}
.sidebar{width:220px;min-width:220px;background:var(--bg-surface);border-right:1px solid var(--border);padding:24px 0;display:flex;flex-direction:column;flex-shrink:0}
.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}
.sidebar-logo span{font-size:15px;font-weight:700;letter-spacing:.05em;color:var(--text-primary)}
.sidebar-logo small{display:block;font-size:10px;color:var(--text-dim);font-family:'JetBrains Mono',monospace;margin-top:2px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 20px;color:var(--text-secondary);text-decoration:none;font-size:13px;font-weight:500;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{color:var(--text-primary);background:rgba(255,255,255,.03)}
.nav-item.active{color:var(--cyan);background:rgba(6,182,212,.06);border-left-color:var(--cyan)}
.nav-icon{font-size:15px;width:18px;text-align:center}
.material-symbols-outlined{font-family:'Material Symbols Outlined';font-weight:400;font-style:normal;font-size:20px;line-height:1;letter-spacing:normal;white-space:nowrap;direction:ltr;-webkit-font-smoothing:antialiased}
.nav-icon.material-symbols-outlined{font-size:22px;width:22px;text-align:center}
.page-header{margin-bottom:28px}
.page-header h1{font-size:22px;font-weight:700}
.page-header p{color:var(--text-secondary);font-size:13px;margin-top:4px}
.main{flex:1;min-width:0;overflow-y:auto;padding:32px}
</style></head><body>
{{ sidebar_html }}
<div class="main">
  <div class="page-header"><h1><img src="{{ tak_logo_url }}" alt="" style="height:28px;vertical-align:middle;margin-right:8px;object-fit:contain"> TAK Server</h1><p>Team Awareness Kit server for situational awareness</p></div>
<div class="status-banner" id="status-banner">
{% if deploying %}
<div class="status-info"><div class="status-icon running" style="background:rgba(59,130,246,0.1)">🔄</div><div><div class="status-text" style="color:var(--accent)">Deploying...</div><div class="status-detail">TAK Server installation in progress</div></div></div>
<div class="controls"><button class="control-btn btn-stop" onclick="cancelDeploy()">✗ Cancel</button></div>
{% elif tak.installed and tak.running %}
<div class="status-info"><div><div class="status-text" style="color:var(--green)">Running</div><div class="status-detail">TAK Server is active</div></div></div>
<div class="controls"><button class="control-btn" onclick="takControl('restart')">↻ Restart</button><button class="control-btn btn-stop" onclick="takControl('stop')">■ Stop</button><button class="control-btn btn-stop" onclick="document.getElementById('tak-uninstall-modal').classList.add('open')" style="margin-left:8px">🗑 Remove</button></div>
{% elif tak.installed %}
<div class="status-info"><div><div class="status-text" style="color:var(--red)">Stopped</div><div class="status-detail">TAK Server is installed but not running</div></div></div>
<div class="controls"><button class="control-btn btn-start" onclick="takControl('start')">▶ Start</button><button class="control-btn btn-stop" onclick="document.getElementById('tak-uninstall-modal').classList.add('open')" style="margin-left:8px">🗑 Remove</button></div>
{% else %}
<div class="status-info"><div><div class="status-text" style="color:var(--text-dim)">Not Installed</div><div class="status-detail">Upload package files from tak.gov to deploy</div></div></div>
{% endif %}
</div>

{% if deploying or deploy_done or deploy_error %}
<div class="section-title">Deployment Log</div>
<div id="deploy-log" style="background:#0c0f1a;border:1px solid var(--border);border-radius:12px;padding:20px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-secondary);max-height:500px;overflow-y:auto;line-height:1.7;white-space:pre-wrap">Reconnecting to deployment log...</div>
<div id="deploy-log-area" style="display:block"></div>
{% if deploy_done %}
<div id="cert-download-area" style="margin-top:20px"><div class="section-title">Download Certificates</div><div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px"><div class="cert-downloads"><a href="/api/download/admin-cert" class="cert-btn cert-btn-secondary">⬇ admin.p12</a><a href="/api/download/user-cert" class="cert-btn cert-btn-secondary">⬇ user.p12</a><a href="/api/download/truststore" class="cert-btn cert-btn-secondary">⬇ truststore.p12</a></div><div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-dim);margin-top:12px">Certificate password: <span style="color:var(--cyan)">atakatak</span></div></div></div>
{% endif %}
{% elif tak.installed %}
{% if show_connect_ldap %}
<div class="card" style="border-color:rgba(59,130,246,.35);background:rgba(59,130,246,.06);margin-bottom:24px">
<div class="card-title">🔗 Connect TAK Server to LDAP</div>
<p style="font-size:13px;color:var(--text-secondary);line-height:1.5;margin-bottom:16px">Authentik is deployed. Connect TAK Server to the same LDAP so users can sign in with their Authentik accounts. This patches CoreConfig.xml and restarts TAK Server once.</p>
<button type="button" id="connect-ldap-btn" onclick="connectLdap()" style="padding:12px 24px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:10px;font-family:'DM Sans',sans-serif;font-size:14px;font-weight:600;cursor:pointer">Connect TAK Server to LDAP</button>
<div id="connect-ldap-msg" style="margin-top:12px;font-size:13px;color:var(--text-secondary)"></div>
</div>
{% endif %}
<div class="section-title">Access</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="display:flex;gap:10px;flex-wrap:nowrap;align-items:center">
<a href="{{ 'https://tak.' + settings.get('fqdn') if settings.get('fqdn') else 'https://' + settings.get('server_ip', '') + ':8443' }}" target="_blank" class="cert-btn cert-btn-primary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔐 WebGUI :8443 (cert)</a>
<a href="{{ 'https://tak.' + settings.get('fqdn') if settings.get('fqdn') else 'https://' + settings.get('server_ip', '') + ':8446' }}" target="_blank" class="cert-btn cert-btn-primary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔑 WebGUI :8446 (password)</a>
<a href="{{ 'https://takportal.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':3000' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">👥 TAK Portal{% if not settings.get('fqdn') %} :3000{% endif %}</a>
<a href="{{ 'https://authentik.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':9090' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔐 Authentik{% if not settings.get('fqdn') %} :9090{% endif %}</a>
</div>
</div>
<div class="section-title">Services</div>
<div id="services-panel" style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div id="services-list" style="font-family:'JetBrains Mono',monospace;font-size:13px">Loading services...</div>
</div>
<div class="section-title">Certificates</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="display:flex;align-items:center;justify-content:space-between">
<div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-dim)">Certificate password: <span style="color:var(--cyan)">atakatak</span> &nbsp;&middot;&nbsp; /opt/tak/certs/files/</div>
<a href="/certs" class="cert-btn cert-btn-secondary" style="text-decoration:none">📁 Browse Certificates</a>
</div>
</div>
<div class="section-title">Server Log <span style="font-size:11px;color:var(--text-dim);font-weight:400">takserver-messaging.log</span></div>
<div id="server-log" style="background:#0c0f1a;border:1px solid var(--border);border-radius:12px;padding:20px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);max-height:400px;overflow-y:auto;line-height:1.6;white-space:pre-wrap">Loading log...</div>
{% else %}
<div class="section-title">Deploy TAK Server</div>
<div class="upload-area" id="upload-area" ondrop="handleDrop(event)" ondragover="handleDragOver(event)" ondragleave="handleDragLeave(event)" onclick="document.getElementById('file-input').click()">
<div class="upload-icon">📦</div><div class="upload-text">Drop your TAK Server files here</div>
<div class="upload-hint">
{% if 'ubuntu' in settings.get('os_type', '') %}
<strong style="color:var(--text-secondary)">Ubuntu — upload these files from tak.gov:</strong><br>
Required: <span style="color:var(--cyan)">takserver_X.X_all.deb</span><br>
Optional: <span style="color:var(--text-secondary)">deb_policy.pol</span> + <span style="color:var(--text-secondary)">takserver-public-gpg.key</span>
{% elif 'rocky' in settings.get('os_type', '') or 'rhel' in settings.get('os_type', '') %}
<strong style="color:var(--text-secondary)">Rocky/RHEL — upload these files from tak.gov:</strong><br>
Required: <span style="color:var(--cyan)">takserver-X.X.noarch.rpm</span><br>
Optional: <span style="color:var(--text-secondary)">takserver-public-gpg.key</span>
{% else %}
Required: <span style="color:var(--cyan)">.deb</span> or <span style="color:var(--cyan)">.rpm</span> package
{% endif %}
<br><span style="color:var(--text-dim);font-size:11px">Select all at once or add files one at a time</span>
</div>
<input type="file" id="file-input" style="display:none" multiple {% if 'ubuntu' in settings.get('os_type', '') %}accept=".deb,.key,.pol"{% elif 'rocky' in settings.get('os_type', '') or 'rhel' in settings.get('os_type', '') %}accept=".rpm,.key"{% else %}accept=".deb,.rpm,.key,.pol"{% endif %} onchange="handleFileSelect(event)">
</div>
<div id="progress-area"></div>
<div id="upload-results" style="display:none">
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px">
<div id="upload-files-list" style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--text-secondary)"></div>
<div id="add-more-area" style="margin-top:16px;text-align:center">
<button onclick="document.getElementById('file-input-more').click()" style="padding:8px 20px;background:transparent;color:var(--accent);border:1px solid var(--border);border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:12px;cursor:pointer">+ Add more files</button>
<input type="file" id="file-input-more" style="display:none" multiple {% if 'ubuntu' in settings.get('os_type', '') %}accept=".deb,.key,.pol"{% elif 'rocky' in settings.get('os_type', '') or 'rhel' in settings.get('os_type', '') %}accept=".rpm,.key"{% else %}accept=".deb,.rpm,.key,.pol"{% endif %} onchange="handleAddMore(event)">
</div>
<div id="deploy-btn-area" style="margin-top:20px;text-align:center;display:none">
<button onclick="showDeployConfig()" style="padding:12px 32px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:10px;font-family:'DM Sans',sans-serif;font-size:15px;font-weight:600;cursor:pointer">Configure &amp; Deploy →</button>
</div></div></div>
{% endif %}
</div>
<div class="modal-overlay" id="tak-uninstall-modal">
<div class="modal">
<h3>⚠ Uninstall TAK Server?</h3>
<p>This will remove TAK Server completely: /opt/tak, all certificates, and config. You can redeploy after.</p>
<label class="form-label">Admin Password</label>
<input class="form-input" id="tak-uninstall-password" type="password" placeholder="Confirm your password">
<div class="modal-actions">
<button type="button" class="control-btn" id="tak-uninstall-cancel" onclick="document.getElementById('tak-uninstall-modal').classList.remove('open')">Cancel</button>
<button type="button" class="control-btn btn-stop" id="tak-uninstall-confirm" onclick="doUninstallTak()">Uninstall</button>
</div>
<div id="tak-uninstall-msg" style="margin-top:10px;font-size:12px;color:var(--red)"></div>
<div id="tak-uninstall-progress" class="uninstall-progress-row" style="display:none;margin-top:10px" aria-live="polite"></div>
</div>
</div>
<footer class="footer"></footer>
<script>
async function loadServices(){
    var el=document.getElementById('services-list');
    if(!el)return;
    try{
        var r=await fetch('/api/takserver/services');
        var d=await r.json();
        if(!d.services||d.services.length===0){el.textContent='No services detected';return}
        var h='<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px">';
        d.services.forEach(function(s){
            var color=s.status==='running'?'var(--green)':'var(--red)';
            var dot=s.status==='running'?'●':'○';
            h+='<div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:8px;padding:14px;display:flex;align-items:center;gap:12px">';
            h+='<span style="font-size:20px">'+s.icon+'</span>';
            h+='<div style="flex:1"><div style="display:flex;justify-content:space-between;align-items:center"><span style="color:var(--text-secondary);font-weight:600">'+s.name+'</span>';
            h+='<span style="color:'+color+';font-size:11px">'+dot+' '+s.status+'</span></div>';
            if(s.mem_mb||s.cpu){h+='<div style="color:var(--text-dim);font-size:11px;margin-top:4px">';
            if(s.mem_mb)h+=s.mem_mb;
            if(s.mem_mb&&s.cpu)h+=' · ';
            if(s.cpu)h+='CPU '+s.cpu;
            if(s.pid)h+=' · PID '+s.pid;
            h+='</div>'}
            h+='</div></div>';
        });
        h+='</div>';
        el.innerHTML=h;
    }catch(e){el.textContent='Failed to load services'}
}
if(document.getElementById('services-list')){loadServices();setInterval(loadServices,10000)}

var serverLogOffset=0;
async function pollServerLog(){
    var el=document.getElementById('server-log');
    if(!el)return;
    try{
        var r=await fetch('/api/takserver/log?offset='+serverLogOffset+'&lines=80');
        var d=await r.json();
        if(d.entries&&d.entries.length>0){
            if(serverLogOffset===0)el.textContent='';
            d.entries.forEach(function(e){
                var l=document.createElement('div');
                if(e.indexOf('ERROR')>=0||e.indexOf('SEVERE')>=0)l.style.color='var(--red)';
                else if(e.indexOf('WARN')>=0)l.style.color='var(--yellow)';
                else if(e.indexOf('INFO')>=0)l.style.color='var(--text-secondary)';
                l.textContent=e;
                el.appendChild(l);
            });
            el.scrollTop=el.scrollHeight;
        }else if(serverLogOffset===0){
            el.textContent='No log entries yet. TAK Server may still be starting...';
        }
        serverLogOffset=d.offset||serverLogOffset;
    }catch(e){}
}
if(document.getElementById('server-log')){pollServerLog();setInterval(pollServerLog,5000)}

async function takControl(action){
    const btns=document.querySelectorAll('.control-btn');
    btns.forEach(b=>{b.disabled=true;b.style.opacity='0.5'});
    try{
        await fetch('/api/takserver/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})});
        if(action==='start'||action==='restart'){
            sessionStorage.setItem('tak_just_started','1');
        }
        window.location.reload();
    }
    catch(e){alert('Failed: '+e.message);btns.forEach(b=>{b.disabled=false;b.style.opacity='1'})}
}

async function connectLdap(){
    var btn=document.getElementById('connect-ldap-btn');
    var msg=document.getElementById('connect-ldap-msg');
    if(btn){btn.disabled=true;btn.textContent='Connecting...';btn.style.opacity='0.7';}
    if(msg){msg.textContent='';msg.style.color='var(--text-secondary)';}
    try{
        var r=await fetch('/api/takserver/connect-ldap',{method:'POST',headers:{'Content-Type':'application/json'}});
        var d=await r.json();
        if(d.success){if(msg){msg.textContent=d.message||'Done.';msg.style.color='var(--green)';} setTimeout(function(){window.location.reload();},1200);}
        else{if(msg){msg.textContent=d.message||'Failed';msg.style.color='var(--red)';} if(btn){btn.disabled=false;btn.textContent='Connect TAK Server to LDAP';btn.style.opacity='1';}}}
    }
    catch(e){if(msg){msg.textContent='Error: '+e.message;msg.style.color='var(--red)';} if(btn){btn.disabled=false;btn.textContent='Connect TAK Server to LDAP';btn.style.opacity='1';}}
}

(function(){
    if(sessionStorage.getItem('tak_just_started')==='1'){
        sessionStorage.removeItem('tak_just_started');
        var notice=document.createElement('div');
        notice.style.cssText='background:rgba(59,130,246,0.1);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:20px;text-align:center;font-family:JetBrains Mono,monospace;font-size:13px;color:#06b6d4;transition:opacity 1s';
        notice.textContent='\u23f3 TAK Server needs ~5 minutes to fully initialize before WebGUI login will work.';
        var main=document.querySelector('main');
        var banner=document.getElementById('status-banner');
        if(banner&&banner.nextSibling)main.insertBefore(notice,banner.nextSibling);
        else if(main)main.appendChild(notice);
        setTimeout(function(){notice.style.opacity='0';setTimeout(function(){notice.remove()},1000)},30000);
    }
})();

(function(){
    if(document.getElementById('upload-area')){
        fetch('/api/upload/takserver/existing').then(r=>r.json()).then(d=>{
            if(d.package||d.gpg_key||d.policy){
                if(d.package)uploadedFiles.package=d.package;
                if(d.gpg_key)uploadedFiles.gpg_key=d.gpg_key;
                if(d.policy)uploadedFiles.policy=d.policy;
                var pa=document.getElementById('progress-area');
                if(d.package){pa.insertAdjacentHTML('beforeend','<div class="progress-item"><div style="display:flex;justify-content:space-between;align-items:center"><span style="font-family:JetBrains Mono,monospace;font-size:13px;color:var(--text-secondary)">'+d.package.filename+' ('+d.package.size_mb+' MB)</span><span style="font-family:JetBrains Mono,monospace;font-size:12px;color:var(--green)">\u2713 uploaded</span></div><div class="progress-bar-outer"><div class="progress-bar-inner" style="width:100%;background:var(--green)"></div></div></div>')}
                if(d.gpg_key){pa.insertAdjacentHTML('beforeend','<div class="progress-item"><div style="display:flex;justify-content:space-between;align-items:center"><span style="font-family:JetBrains Mono,monospace;font-size:13px;color:var(--text-secondary)">'+d.gpg_key.filename+'</span><span style="font-family:JetBrains Mono,monospace;font-size:12px;color:var(--green)">\u2713 uploaded</span></div><div class="progress-bar-outer"><div class="progress-bar-inner" style="width:100%;background:var(--green)"></div></div></div>')}
                if(d.policy){pa.insertAdjacentHTML('beforeend','<div class="progress-item"><div style="display:flex;justify-content:space-between;align-items:center"><span style="font-family:JetBrains Mono,monospace;font-size:13px;color:var(--text-secondary)">'+d.policy.filename+'</span><span style="font-family:JetBrains Mono,monospace;font-size:12px;color:var(--green)">\u2713 uploaded</span></div><div class="progress-bar-outer"><div class="progress-bar-inner" style="width:100%;background:var(--green)"></div></div></div>')}
                var a=document.getElementById('upload-area');if(a){a.style.maxHeight='120px';a.style.padding='20px';var ic=a.querySelector('.upload-icon');if(ic)ic.style.display='none'}
                updateUploadSummary();
            }
        }).catch(function(){});
    }
})();

async function takUninstall(){
    document.getElementById('tak-uninstall-modal').classList.add('open');
}
async function doUninstallTak(){
    var pw=document.getElementById('tak-uninstall-password').value;
    if(!pw){document.getElementById('tak-uninstall-msg').textContent='Please enter your password';return;}
    var msgEl=document.getElementById('tak-uninstall-msg');
    var progressEl=document.getElementById('tak-uninstall-progress');
    var cancelBtn=document.getElementById('tak-uninstall-cancel');
    var confirmBtn=document.getElementById('tak-uninstall-confirm');
    msgEl.textContent='';
    progressEl.style.display='flex';
    progressEl.innerHTML='<span class="uninstall-spinner"></span><span>Uninstalling…</span>';
    confirmBtn.disabled=true;
    cancelBtn.disabled=true;
    try{
        var r=await fetch('/api/takserver/uninstall',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
        var d=await r.json();
        if(d.success){
            progressEl.innerHTML='<span class="uninstall-spinner"></span><span>Done. Reloading…</span>';
            setTimeout(function(){window.location.href='/takserver';},800);
        }else{
            msgEl.textContent=d.error||'Uninstall failed';
            progressEl.style.display='none';
            progressEl.innerHTML='';
            confirmBtn.disabled=false;
            cancelBtn.disabled=false;
        }
    }catch(e){
        msgEl.textContent='Request failed: '+e.message;
        progressEl.style.display='none';
        progressEl.innerHTML='';
        confirmBtn.disabled=false;
        cancelBtn.disabled=false;
    }
}

async function cancelDeploy(){
    if(!confirm('Cancel the deployment? You can redeploy after.'))return;
    try{const r=await fetch('/api/deploy/cancel',{method:'POST',headers:{'Content-Type':'application/json'}});const d=await r.json();if(d.success){window.location.href='/takserver'}else{alert('Error: '+(d.error||'Unknown'))}}
    catch(e){alert('Failed: '+e.message)}
}

let uploadedFiles={package:null,gpg_key:null,policy:null};
let uploadsInProgress=0;

function handleDragOver(e){e.preventDefault();document.getElementById('upload-area').classList.add('dragover')}
function handleDragLeave(e){document.getElementById('upload-area').classList.remove('dragover')}
function handleDrop(e){e.preventDefault();document.getElementById('upload-area').classList.remove('dragover');queueFiles(e.dataTransfer.files)}
function handleFileSelect(e){queueFiles(e.target.files);e.target.value=''}
function handleAddMore(e){queueFiles(e.target.files);e.target.value=''}

function formatSize(b){if(b<1024)return b+' B';if(b<1024*1024)return(b/1024).toFixed(1)+' KB';if(b<1024*1024*1024)return(b/(1024*1024)).toFixed(1)+' MB';return(b/(1024*1024*1024)).toFixed(2)+' GB'}

async function removeFile(fn,elId){
    try{await fetch('/api/upload/takserver/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:fn})})}catch(e){}
    var el=document.getElementById(elId);if(el)el.remove();
    if(uploadedFiles.package&&uploadedFiles.package.filename===fn)uploadedFiles.package=null;
    if(uploadedFiles.gpg_key&&uploadedFiles.gpg_key.filename===fn)uploadedFiles.gpg_key=null;
    if(uploadedFiles.policy&&uploadedFiles.policy.filename===fn)uploadedFiles.policy=null;
    updateUploadSummary();
}

function queueFiles(fl){
    const a=document.getElementById('upload-area');if(a){a.style.maxHeight='120px';a.style.padding='20px';const ic=a.querySelector('.upload-icon');if(ic)ic.style.display='none'}
    for(const f of fl){
        var isDupe=false;
        if(uploadedFiles.package&&uploadedFiles.package.filename===f.name)isDupe=true;
        if(uploadedFiles.gpg_key&&uploadedFiles.gpg_key.filename===f.name)isDupe=true;
        if(uploadedFiles.policy&&uploadedFiles.policy.filename===f.name)isDupe=true;
        if(isDupe){var pa=document.getElementById('progress-area');pa.insertAdjacentHTML('beforeend','<div class="progress-item" style="opacity:0.6"><span style="font-family:JetBrains Mono,monospace;font-size:13px;color:var(--yellow)">⚠ '+f.name+' already uploaded — skipped</span></div>');continue}
        uploadFile(f);
    }
}

function uploadFile(file){
    uploadsInProgress++;
    const pa=document.getElementById('progress-area');
    const id='u-'+Date.now()+'-'+Math.random().toString(36).substr(2,5);
    var row=document.createElement('div');row.className='progress-item';row.id=id;
    var top=document.createElement('div');top.style.cssText='display:flex;justify-content:space-between;align-items:center';
    var lbl=document.createElement('span');lbl.style.cssText='font-family:JetBrains Mono,monospace;font-size:13px;color:var(--text-secondary)';lbl.textContent=file.name+' ('+formatSize(file.size)+')';
    var right=document.createElement('span');right.style.cssText='display:flex;align-items:center;gap:8px';
    var pct=document.createElement('span');pct.id=id+'-pct';pct.style.cssText='font-family:JetBrains Mono,monospace;font-size:12px;color:var(--cyan)';pct.textContent='0%';
    var cancelBtn=document.createElement('span');cancelBtn.id=id+'-cancel';cancelBtn.textContent='\u2717';cancelBtn.style.cssText='color:var(--red);cursor:pointer;font-size:14px';cancelBtn.title='Cancel upload';
    right.appendChild(pct);right.appendChild(cancelBtn);top.appendChild(lbl);top.appendChild(right);
    var barOuter=document.createElement('div');barOuter.className='progress-bar-outer';
    var barInner=document.createElement('div');barInner.className='progress-bar-inner';barInner.id=id+'-bar';barInner.style.width='0%';
    barOuter.appendChild(barInner);row.appendChild(top);row.appendChild(barOuter);pa.appendChild(row);
    const fd=new FormData();fd.append('files',file);
    const xhr=new XMLHttpRequest();
    window['xhr_'+id]=xhr;
    cancelBtn.onclick=function(){cancelUpload(id)};
    xhr.upload.onprogress=(e)=>{if(e.lengthComputable){const p=Math.round((e.loaded/e.total)*100);document.getElementById(id+'-bar').style.width=p+'%';document.getElementById(id+'-pct').textContent=p+'%'}};
    xhr.onload=()=>{
        delete window['xhr_'+id];
        const bar=document.getElementById(id+'-bar');const pc=document.getElementById(id+'-pct');bar.style.width='100%';
        var cb=document.getElementById(id+'-cancel');if(cb)cb.remove();
        if(xhr.status===200){const d=JSON.parse(xhr.responseText);bar.style.background='var(--green)';pc.style.color='var(--green)';if(d.package)uploadedFiles.package=d.package;if(d.gpg_key)uploadedFiles.gpg_key=d.gpg_key;if(d.policy)uploadedFiles.policy=d.policy;var rBtn=document.createElement('span');rBtn.textContent=' \u2717';rBtn.style.cssText='color:var(--red);cursor:pointer;margin-left:8px';rBtn.title='Remove';rBtn.onclick=function(ev){ev.stopPropagation();removeFile(file.name,id)};pc.textContent='\u2713 ';pc.appendChild(rBtn)}
        else{bar.style.background='var(--red)';pc.textContent='\u2717';pc.style.color='var(--red)'}
        uploadsInProgress--;if(uploadsInProgress===0)updateUploadSummary()
    };
    xhr.onerror=()=>{delete window['xhr_'+id];document.getElementById(id+'-bar').style.background='var(--red)';document.getElementById(id+'-pct').textContent='\u2717';uploadsInProgress--;if(uploadsInProgress===0)updateUploadSummary()};
    xhr.onabort=()=>{delete window['xhr_'+id];uploadsInProgress--};
    xhr.open('POST','/api/upload/takserver');xhr.send(fd);
}

function cancelUpload(id){
    var xhr=window['xhr_'+id];
    if(xhr){xhr.abort();delete window['xhr_'+id]}
    var el=document.getElementById(id);if(el)el.remove();
}

function updateUploadSummary(){
    const r=document.getElementById('upload-results');const fl=document.getElementById('upload-files-list');r.style.display='block';
    let h='';
    if(uploadedFiles.package)h+='<div style="margin-bottom:8px">✓ <span style="color:var(--green)">'+uploadedFiles.package.filename+'</span> <span style="color:var(--text-dim)">('+uploadedFiles.package.size_mb+' MB)</span></div>';
    if(uploadedFiles.gpg_key)h+='<div style="margin-bottom:8px">✓ <span style="color:var(--green)">'+uploadedFiles.gpg_key.filename+'</span> <span style="color:var(--text-dim)">(GPG key)</span></div>';
    if(uploadedFiles.policy)h+='<div style="margin-bottom:8px">✓ <span style="color:var(--green)">'+uploadedFiles.policy.filename+'</span> <span style="color:var(--text-dim)">(policy)</span></div>';
    if(uploadedFiles.gpg_key&&uploadedFiles.policy)h+='<div style="margin-top:12px;color:var(--green)">🔐 GPG verification enabled</div>';
    else if(!uploadedFiles.gpg_key&&!uploadedFiles.policy)h+='<div style="margin-top:12px;color:var(--text-dim)">ℹ️ No GPG key/policy — verification will be skipped</div>';
    else h+='<div style="margin-top:12px;color:var(--yellow)">⚠️ Need both GPG key + policy for verification</div>';
    fl.innerHTML=h;
    if(uploadedFiles.package)document.getElementById('deploy-btn-area').style.display='block';
}

function showDeployConfig(){
    const ua=document.getElementById('upload-area');const pa=document.getElementById('progress-area');const ur=document.getElementById('upload-results');
    if(ua)ua.style.display='none';if(pa)pa.style.display='none';if(ur)ur.style.display='none';
    const main=document.querySelector('.main');
    main.querySelectorAll('.section-title').forEach(t=>{if(t.textContent.includes('Deploy'))t.remove()});
    const cd=document.createElement('div');
    cd.innerHTML=`
<div class="section-title">Configure Deployment</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:28px;margin-bottom:20px">
<div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--text-dim);margin-bottom:20px;text-transform:uppercase;letter-spacing:1px;font-weight:600">Certificate Information <span style="color:var(--red);font-size:10px;margin-left:8px">ALL FIELDS REQUIRED</span></div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
<div class="form-field"><label>Country (2 letters)</label><input type="text" id="cert_country" placeholder="US" maxlength="2" style="text-transform:uppercase"></div>
<div class="form-field"><label>State/Province</label><input type="text" id="cert_state" placeholder="CA" style="text-transform:uppercase"></div>
<div class="form-field"><label>City</label><input type="text" id="cert_city" placeholder="SACRAMENTO" style="text-transform:uppercase"></div>
<div class="form-field"><label>Organization</label><input type="text" id="cert_org" placeholder="MYAGENCY" style="text-transform:uppercase"></div>
<div class="form-field"><label>Organizational Unit</label><input type="text" id="cert_ou" placeholder="IT" style="text-transform:uppercase"></div>
</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--text-dim);margin:24px 0 20px;text-transform:uppercase;letter-spacing:1px;font-weight:600">Certificate Authority Names</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
<div class="form-field"><label>Root CA Name</label><input type="text" id="root_ca_name" placeholder="ROOT-CA-01" style="text-transform:uppercase"></div>
<div class="form-field"><label>Intermediate CA Name</label><input type="text" id="intermediate_ca_name" placeholder="INTERMEDIATE-CA-01" style="text-transform:uppercase"></div>
</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--text-dim);margin:24px 0 20px;text-transform:uppercase;letter-spacing:1px;font-weight:600">WebTAK Options (Port 8446)</div>
<div style="display:flex;flex-direction:column;gap:14px">
<label style="display:flex;align-items:center;gap:10px;color:var(--text-secondary);cursor:pointer;font-size:14px"><input type="checkbox" id="enable_admin_ui" onchange="toggleWebadminPassword()" style="width:18px;height:18px;accent-color:var(--accent)"> Enable Admin UI <span style="color:var(--text-dim);font-size:12px">— Browser admin (no cert needed)</span></label>
<label style="display:flex;align-items:center;gap:10px;color:var(--text-secondary);cursor:pointer;font-size:14px"><input type="checkbox" id="enable_webtak" style="width:18px;height:18px;accent-color:var(--accent)"> Enable WebTAK <span style="color:var(--text-dim);font-size:12px">— Browser-based TAK client</span></label>
<label style="display:flex;align-items:center;gap:10px;color:var(--text-secondary);cursor:pointer;font-size:14px"><input type="checkbox" id="enable_nonadmin_ui" style="width:18px;height:18px;accent-color:var(--accent)"> Enable Non-Admin UI <span style="color:var(--text-dim);font-size:12px">— Non-admin management</span></label>
</div>
<div id="webadmin-password-area" style="display:none;margin-top:20px;background:rgba(59,130,246,0.05);border:1px solid var(--border);border-radius:10px;padding:18px">
<div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-dim);margin-bottom:12px">Set a password for <span style="color:var(--cyan)">webadmin</span> user on port 8446</div>
<div class="form-field" style="margin-bottom:12px"><label>WebAdmin Password</label><div style="position:relative"><input type="password" id="webadmin_password" placeholder="Min 15 chars: upper, lower, number, special"><button type="button" onclick="toggleShowPassword()" id="pw-toggle" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--text-dim);cursor:pointer;font-size:13px;font-family:JetBrains Mono,monospace">show</button></div></div>
<div class="form-field" style="margin-bottom:12px"><label>Confirm Password</label><input type="password" id="webadmin_password_confirm" placeholder="Re-enter password"></div>
<div id="password-match" style="font-family:'JetBrains Mono',monospace;font-size:12px;margin-bottom:8px"></div>
<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim)">15+ characters, 1 uppercase, 1 lowercase, 1 number, 1 special character</div>
<div id="password-validation" style="font-family:'JetBrains Mono',monospace;font-size:12px;margin-top:8px"></div>
</div>
<div style="margin-top:28px;text-align:center"><button onclick="startDeploy()" id="deploy-btn" style="padding:14px 48px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:10px;font-family:'DM Sans',sans-serif;font-size:16px;font-weight:600;cursor:pointer">🚀 Deploy TAK Server</button></div>
</div>
<div id="deploy-log-area" style="display:none"><div class="section-title">Deployment Log</div><div id="deploy-log" style="background:#0c0f1a;border:1px solid var(--border);border-radius:12px;padding:20px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-secondary);max-height:500px;overflow-y:auto;line-height:1.7;white-space:pre-wrap"></div></div>
<div id="cert-download-area" style="display:none;margin-top:20px"><div class="section-title">Download Certificates</div><div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px"><div class="cert-downloads"><a href="/api/download/admin-cert" class="cert-btn cert-btn-secondary">⬇ admin.p12</a><a href="/api/download/user-cert" class="cert-btn cert-btn-secondary">⬇ user.p12</a><a href="/api/download/truststore" class="cert-btn cert-btn-secondary">⬇ truststore.p12</a></div><div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-dim);margin-top:12px">Certificate password: <span style="color:var(--cyan)">atakatak</span></div></div></div>`;
    main.appendChild(cd);
    const pi=document.getElementById('webadmin_password');if(pi){pi.addEventListener('input',validatePassword);pi.addEventListener('input',checkPasswordMatch)}const pc=document.getElementById('webadmin_password_confirm');if(pc)pc.addEventListener('input',checkPasswordMatch);
}

function toggleWebadminPassword(){const a=document.getElementById('webadmin-password-area');if(a)a.style.display=document.getElementById('enable_admin_ui').checked?'block':'none'}

function toggleShowPassword(){const p=document.getElementById('webadmin_password');const c=document.getElementById('webadmin_password_confirm');const b=document.getElementById('pw-toggle');if(p.type==='password'){p.type='text';c.type='text';b.textContent='hide'}else{p.type='password';c.type='password';b.textContent='show'}}

function checkPasswordMatch(){const p=document.getElementById('webadmin_password').value;const c=document.getElementById('webadmin_password_confirm').value;const el=document.getElementById('password-match');if(!c){el.innerHTML='';return}if(p===c)el.innerHTML='<span style="color:var(--green)">\u2713 Passwords match</span>';else el.innerHTML='<span style="color:var(--red)">\u2717 Passwords do not match</span>'}

function validatePassword(){
    const p=document.getElementById('webadmin_password').value;const el=document.getElementById('password-validation');
    if(!p){el.innerHTML='';return false}
    const c=[{t:p.length>=15,l:'15+ chars'},{t:/[A-Z]/.test(p),l:'1 upper'},{t:/[a-z]/.test(p),l:'1 lower'},{t:/[0-9]/.test(p),l:'1 number'},{t:/[-_!@#$%^&*(){}+=~|:;<>,./\\?]/.test(p),l:'1 special'}];
    var h='';c.forEach(function(x){h+='<span style="color:'+(x.t?'var(--green)':'var(--red)')+';">'+(x.t?'\u2713':'\u2717')+' '+x.l+'</span> &nbsp; '});
    el.innerHTML=h;
    return c.every(function(x){return x.t});
}

async function startDeploy(){
    const rf=[{id:'cert_country',l:'Country'},{id:'cert_state',l:'State'},{id:'cert_city',l:'City'},{id:'cert_org',l:'Organization'},{id:'cert_ou',l:'Org Unit'},{id:'root_ca_name',l:'Root CA'},{id:'intermediate_ca_name',l:'Intermediate CA'}];
    const empty=rf.filter(f=>!document.getElementById(f.id).value.trim());
    if(empty.length>0){alert('Please fill in: '+empty.map(f=>f.l).join(', '));empty.forEach(f=>{const el=document.getElementById(f.id);el.style.borderColor='var(--red)';el.addEventListener('input',()=>el.style.borderColor='',{once:true})});return}
    const aui=document.getElementById('enable_admin_ui').checked;
    if(aui){const p=document.getElementById('webadmin_password').value;const pc=document.getElementById('webadmin_password_confirm').value;if(!p){alert('Please set a webadmin password.');return}if(p!==pc){alert('Passwords do not match.');return}if(!validatePassword()){alert('Password does not meet requirements.');return}}
    const btn=document.getElementById('deploy-btn');btn.disabled=true;btn.textContent='Deploying...';btn.style.opacity='0.6';btn.style.cursor='not-allowed';
    document.querySelectorAll('.form-field input,input[type="checkbox"]').forEach(el=>el.disabled=true);
    const cfg={cert_country:document.getElementById('cert_country').value.toUpperCase(),cert_state:document.getElementById('cert_state').value.toUpperCase(),cert_city:document.getElementById('cert_city').value.toUpperCase(),cert_org:document.getElementById('cert_org').value.toUpperCase(),cert_ou:document.getElementById('cert_ou').value.toUpperCase(),root_ca_name:document.getElementById('root_ca_name').value.toUpperCase(),intermediate_ca_name:document.getElementById('intermediate_ca_name').value.toUpperCase(),enable_admin_ui:document.getElementById('enable_admin_ui').checked,enable_webtak:document.getElementById('enable_webtak').checked,enable_nonadmin_ui:document.getElementById('enable_nonadmin_ui').checked,webadmin_password:aui?document.getElementById('webadmin_password').value:''};
    document.getElementById('deploy-log-area').style.display='block';
    try{const r=await fetch('/api/deploy/takserver',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)});const d=await r.json();if(d.success)pollDeployLog();else{document.getElementById('deploy-log').textContent='✗ '+d.error;btn.disabled=false;btn.textContent='🚀 Deploy TAK Server';btn.style.opacity='1';btn.style.cursor='pointer'}}
    catch(e){document.getElementById('deploy-log').textContent='✗ '+e.message}
}

let logIndex=0,pollFails=0,logCleared=false;
function pollDeployLog(){
    const el=document.getElementById('deploy-log');
    const poll=async()=>{
        try{const r=await fetch('/api/deploy/log?after='+logIndex);const d=await r.json();pollFails=0;
            if(!logCleared&&d.entries.length>0){el.textContent='';logCleared=true}
            if(d.entries.length>0){d.entries.forEach(e=>{var isTimer=e.trim().charAt(0)=='\u23f3'&&e.indexOf(':')>0;if(isTimer){var prev=el.querySelector('[data-timer]');if(prev){prev.textContent=e;logIndex=d.total;return}};if(!isTimer){var old=el.querySelector('[data-timer]');if(old)old.removeAttribute('data-timer')};var l=document.createElement('div');if(isTimer)l.setAttribute('data-timer','1');if(e.indexOf('\u2713')>=0)l.style.color='var(--green)';else if(e.indexOf('\u2717')>=0||e.indexOf('FATAL')>=0)l.style.color='var(--red)';else if(e.indexOf('\u2501\u2501\u2501')>=0)l.style.color='var(--cyan)';else if(e.indexOf('\u26a0')>=0)l.style.color='var(--yellow)';else if(e.indexOf('===')>=0||e.indexOf('WebGUI')>=0||e.indexOf('Username')>=0)l.style.color='var(--green)';l.textContent=e;el.appendChild(l)});logIndex=d.total;el.scrollTop=el.scrollHeight}
            if(d.running)setTimeout(poll,1000);
            else if(d.complete){const b=document.getElementById('deploy-btn');if(b){b.textContent='\u2713 Deployment Complete';b.style.background='var(--green)';b.style.opacity='1'};const dl=document.getElementById('cert-download-area');if(dl)dl.style.display='block';var wa=document.createElement('div');wa.style.cssText='background:rgba(59,130,246,0.1);border:1px solid var(--border);border-radius:10px;padding:20px;margin-top:20px;text-align:center';var wt=document.createElement('div');wt.style.cssText='font-family:JetBrains Mono,monospace;font-size:14px;color:#06b6d4;margin-bottom:12px';wt.textContent='\u23f3 TAK Server needs ~5 minutes to fully initialize before login will work.';var wb=document.createElement('button');wb.textContent='Refresh Page';wb.style.cssText='padding:10px 24px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer';wb.onclick=function(){window.location.href='/takserver'};wa.appendChild(wt);wa.appendChild(wb);document.getElementById('deploy-log-area').after(wa)}
            else if(d.error){const b=document.getElementById('deploy-btn');if(b){b.textContent='\u2717 Deployment Failed';b.style.background='var(--red)';b.style.opacity='1'}}
        }catch(e){pollFails++;if(pollFails<30)setTimeout(poll,2000)}
    };poll();
}
{% if deploying or deploy_done or deploy_error %}
pollDeployLog();
{% endif %}
</script></body></html>'''

# === Main Entry Point ===
if __name__ == '__main__':
    settings = load_settings()
    ssl_mode = settings.get('ssl_mode', 'self-signed')
    port = settings.get('console_port', 5001)
    print("=" * 50)
    print("infra-TAK v" + VERSION)
    print("=" * 50)
    print(f"OS: {settings.get('os_name', 'Unknown')}")
    print(f"SSL Mode: {ssl_mode}")
    fqdn = settings.get('fqdn', '')
    if fqdn:
        print(f"FQDN: {fqdn}")
    print(f"Port: {port}")
    print("=" * 50)
    # Always run with self-signed cert on 0.0.0.0
    # Caddy proxies on top when configured
    cert_dir = os.path.join(CONFIG_DIR, 'ssl')
    cert_file = os.path.join(cert_dir, 'console.crt')
    key_file = os.path.join(cert_dir, 'console.key')
    if os.path.exists(cert_file) and os.path.exists(key_file):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        app.run(host='0.0.0.0', port=port, ssl_context=context, debug=False)
    else:
        print("WARNING: SSL certs not found, running without HTTPS")
        app.run(host='0.0.0.0', port=port, debug=False)
