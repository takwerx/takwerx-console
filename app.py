#!/usr/bin/env python3
"""TAKWERX Console v0.1.5 - Emergency Services Infrastructure Management Platform"""

from flask import (Flask, render_template_string, request, jsonify,
    redirect, url_for, session, send_from_directory)
from werkzeug.security import check_password_hash
from functools import wraps
import os, ssl, json, secrets, subprocess, time, psutil, threading
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, '.config')
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
VERSION = "0.1.5"
GITHUB_REPO = "takwerx/takwerx-console"
CADDYFILE_PATH = "/etc/caddy/Caddyfile"
update_cache = {'latest': None, 'checked': 0, 'notes': ''}
os.makedirs(UPLOAD_DIR, exist_ok=True)

def load_settings():
    p = os.path.join(CONFIG_DIR, 'settings.json')
    return json.load(open(p)) if os.path.exists(p) else {}

def save_settings(s):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    json.dump(s, open(os.path.join(CONFIG_DIR, 'settings.json'), 'w'), indent=2)

def load_auth():
    p = os.path.join(CONFIG_DIR, 'auth.json')
    return json.load(open(p)) if os.path.exists(p) else {}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'): return redirect(url_for('login'))
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
        'icon': '🔒', 'route': '/caddy', 'priority': 0 if not has_fqdn else 10}
    # TAK Server
    tak_installed = os.path.exists('/opt/tak') and os.path.exists('/opt/tak/CoreConfig.xml')
    tak_running = False
    if tak_installed:
        r = subprocess.run(['systemctl', 'is-active', 'takserver'], capture_output=True, text=True)
        tak_running = r.stdout.strip() == 'active'
    modules['takserver'] = {'name': 'TAK Server', 'installed': tak_installed, 'running': tak_running,
        'description': 'Team Awareness Kit server for situational awareness', 'icon': '🗺️', 'route': '/takserver', 'priority': 1}
    # Authentik - Identity Provider
    ak_installed = os.path.exists(os.path.expanduser('~/authentik/docker-compose.yml'))
    ak_running = False
    if ak_installed:
        r = subprocess.run('docker ps --filter name=authentik-server --format "{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True)
        ak_running = 'Up' in r.stdout
    modules['authentik'] = {'name': 'Authentik', 'installed': ak_installed, 'running': ak_running,
        'description': 'Identity provider — SSO, LDAP, user management', 'icon': '🔐', 'route': '/authentik', 'priority': 2}
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
        'description': 'Drone video streaming server (RTSP/SRT/HLS)', 'icon': '📹', 'route': '/mediamtx', 'priority': 4}
    # Guard Dog
    gd_installed = os.path.exists('/opt/tak-guarddog')
    gd_running = False
    if gd_installed:
        r = subprocess.run(['systemctl', 'list-timers', '--no-pager'], capture_output=True, text=True)
        gd_running = 'tak8089guard' in r.stdout
    modules['guarddog'] = {'name': 'Guard Dog', 'installed': gd_installed, 'running': gd_running,
        'description': 'Health monitoring and auto-recovery', 'icon': '🐕', 'route': '/guarddog', 'priority': 5}
    # Node-RED
    nodered_installed = False
    nodered_running = False
    r = subprocess.run('docker ps --filter name=nodered --format "{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True)
    if 'Up' in r.stdout:
        nodered_installed = True
        nodered_running = True
    else:
        r = subprocess.run(['systemctl', 'is-active', 'nodered'], capture_output=True, text=True)
        if r.stdout.strip() == 'active':
            nodered_installed = True
            nodered_running = True
        elif os.path.exists(os.path.expanduser('~/node-red')) or os.path.exists('/opt/nodered'):
            nodered_installed = True
    modules['nodered'] = {'name': 'Node-RED', 'installed': nodered_installed, 'running': nodered_running,
        'description': 'Flow-based automation & integrations', 'icon': '🔴', 'route': '/nodered', 'priority': 6}
    # CloudTAK
    cloudtak_installed = os.path.exists(os.path.expanduser('~/cloudtak')) or os.path.exists('/opt/cloudtak')
    cloudtak_running = False
    if cloudtak_installed:
        r = subprocess.run('docker ps --filter name=cloudtak --format "{{.Status}}" 2>/dev/null', shell=True, capture_output=True, text=True)
        if 'Up' in r.stdout:
            cloudtak_running = True
        else:
            r = subprocess.run(['systemctl', 'is-active', 'cloudtak'], capture_output=True, text=True)
            cloudtak_running = r.stdout.strip() == 'active'
    modules['cloudtak'] = {'name': 'CloudTAK', 'installed': cloudtak_installed, 'running': cloudtak_running,
        'description': 'Web-based TAK client — browser access to TAK', 'icon': '☁️', 'route': '/cloudtak', 'priority': 7}
    return dict(sorted(modules.items(), key=lambda x: x[1].get('priority', 99)))

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
    if request.method == 'POST':
        auth = load_auth()
        if auth.get('password_hash') and check_password_hash(auth['password_hash'], request.form.get('password', '')):
            session['authenticated'] = True
            return redirect(url_for('dashboard'))
        return render_template_string(LOGIN_TEMPLATE, error='Invalid password', version=VERSION)
    return render_template_string(LOGIN_TEMPLATE, error=None, version=VERSION)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    return render_template_string(DASHBOARD_TEMPLATE,
        settings=load_settings(), modules=detect_modules(), metrics=get_system_metrics(), version=VERSION)

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
            headers={'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'TAKWERX-Console'}
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
    console_dir = os.path.expanduser('~/takwerx-console')
    try:
        r = subprocess.run(f'cd {console_dir} && git pull --rebase --autostash 2>&1', shell=True, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return jsonify({'success': False, 'error': r.stderr.strip() or r.stdout.strip()})
        # Clear update cache
        update_cache.update({'latest': None, 'checked': 0})
        return jsonify({'success': True, 'output': r.stdout.strip(), 'restart_required': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/takserver')
@login_required
def takserver_page():
    modules = detect_modules()
    tak = modules.get('takserver', {})
    # Reset deploy_done once TAK Server is running so the running view shows
    if tak.get('installed') and tak.get('running') and not deploy_status.get('running', False):
        deploy_status.update({'complete': False, 'error': False})
    return render_template_string(TAKSERVER_TEMPLATE,
        settings=load_settings(), modules=modules, tak=tak,
        metrics=get_system_metrics(), version=VERSION, deploying=deploy_status.get('running', False),
        deploy_done=deploy_status.get('complete', False), deploy_error=deploy_status.get('error', False))

@app.route('/mediamtx')
@login_required
def mediamtx_page():
    return redirect(url_for('dashboard'))

@app.route('/guarddog')
@login_required
def guarddog_page():
    return redirect(url_for('dashboard'))

@app.route('/nodered')
@login_required
def nodered_page():
    return redirect(url_for('dashboard'))

@app.route('/cloudtak')
@login_required
def cloudtak_page():
    return redirect(url_for('dashboard'))

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
    return render_template_string(CADDY_TEMPLATE,
        settings=settings, caddy=caddy, caddyfile=caddyfile_content,
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
    # Regenerate Caddyfile
    generate_caddyfile(settings)
    # Reload Caddy
    r = subprocess.run('systemctl reload caddy 2>&1', shell=True, capture_output=True, text=True)
    return jsonify({'success': True, 'domain': domain})

@app.route('/api/caddy/caddyfile')
@login_required
def caddy_get_caddyfile():
    if os.path.exists(CADDYFILE_PATH):
        with open(CADDYFILE_PATH) as f:
            return jsonify({'success': True, 'content': f.read()})
    return jsonify({'success': False, 'content': ''})

@app.route('/api/caddy/control', methods=['POST'])
@login_required
def caddy_control():
    data = request.get_json()
    action = data.get('action', '')
    if action == 'restart':
        r = subprocess.run('systemctl restart caddy 2>&1', shell=True, capture_output=True, text=True, timeout=30)
    elif action == 'stop':
        r = subprocess.run('systemctl stop caddy 2>&1', shell=True, capture_output=True, text=True, timeout=30)
    elif action == 'start':
        r = subprocess.run('systemctl start caddy 2>&1', shell=True, capture_output=True, text=True, timeout=30)
    elif action == 'reload':
        r = subprocess.run('systemctl reload caddy 2>&1', shell=True, capture_output=True, text=True, timeout=30)
    else:
        return jsonify({'success': False, 'error': 'Unknown action'})
    return jsonify({'success': r.returncode == 0, 'output': r.stdout.strip()})

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
    Each service gets its own subdomain: console.domain, tak.domain, etc."""
    if settings is None:
        settings = load_settings()
    domain = settings.get('fqdn', '')
    if not domain:
        return
    modules = detect_modules()

    lines = [f"# TAKWERX Console - Auto-generated Caddyfile", f"# Base Domain: {domain}", ""]

    # Console — console.domain
    lines.append(f"console.{domain} {{")
    lines.append(f"    reverse_proxy 127.0.0.1:5001 {{")
    lines.append(f"        transport http {{")
    lines.append(f"            tls_insecure_skip_verify")
    lines.append(f"        }}")
    lines.append(f"    }}")
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

    # Node-RED — nodered.domain
    nodered = modules.get('nodered', {})
    if nodered.get('installed'):
        lines.append(f"# Node-RED")
        lines.append(f"nodered.{domain} {{")
        lines.append(f"    reverse_proxy 127.0.0.1:1880")
        lines.append(f"}}")
        lines.append("")

    # CloudTAK — cloudtak.domain
    cloudtak = modules.get('cloudtak', {})
    if cloudtak.get('installed'):
        lines.append(f"# CloudTAK")
        lines.append(f"cloudtak.{domain} {{")
        lines.append(f"    reverse_proxy 127.0.0.1:5173")
        lines.append(f"}}")
        lines.append("")

    # MediaMTX — separate domain (user-configured)
    mtx_domain = settings.get('mediamtx_domain', '')
    mtx = modules.get('mediamtx', {})
    if mtx_domain and mtx.get('installed'):
        lines.append(f"# MediaMTX Streaming")
        lines.append(f"{mtx_domain} {{")
        lines.append(f"    reverse_proxy 127.0.0.1:8888")
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
        r = subprocess.run('docker ps --filter name=tak-portal --format "{{.Status}}|||{{.Ports}}" 2>/dev/null', shell=True, capture_output=True, text=True)
        if r.stdout.strip():
            parts = r.stdout.strip().split('|||')
            container_info['status'] = parts[0] if len(parts) > 0 else ''
            container_info['ports'] = parts[1] if len(parts) > 1 else ''
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

                # Get authorization flow
                flow_pk = None
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
                except Exception as e:
                    plog(f"  \u26a0 Could not find authorization flow: {str(e)[:80]}")

                # Get invalidation flow
                inv_flow_pk = None
                try:
                    req = _urlreq.Request(f'{_ak_url}/api/v3/flows/instances/?designation=invalidation', headers=_ak_headers)
                    resp = _urlreq.urlopen(req, timeout=10)
                    inv_flows = json_mod.loads(resp.read().decode())['results']
                    inv_flow_pk = next((f['pk'] for f in inv_flows if 'provider' not in f['slug']), inv_flows[0]['pk'] if inv_flows else None)
                except Exception as e:
                    plog(f"  \u26a0 Could not find invalidation flow: {str(e)[:80]}")

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
                    except urllib.error.HTTPError as e:
                        if e.code == 400:
                            plog(f"  \u2713 Application 'TAK Portal' already exists")
                        else:
                            plog(f"  \u26a0 Application error: {e.code}")

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
        plog("=" * 50)
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

CADDY_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Caddy SSL — TAKWERX Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg-deep:#080b14;--bg-surface:#0f1219;--bg-card:#161b26;--border:#1e2736;--border-hover:#2a3548;--text-primary:#e2e8f0;--text-secondary:#94a3b8;--text-dim:#475569;--accent:#3b82f6;--cyan:#06b6d4;--green:#10b981;--red:#ef4444;--yellow:#eab308}
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
.status-banner{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between}
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
.footer{text-align:center;padding:24px;font-size:12px;color:var(--text-dim);border-top:1px solid var(--border);margin-top:40px}
.benefit-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-top:16px}
.benefit-item{background:var(--bg-surface);border:1px solid var(--border);border-radius:8px;padding:14px;font-size:12px}
.benefit-item .icon{font-size:18px;margin-bottom:6px}
.benefit-item .title{font-family:'JetBrains Mono',monospace;font-weight:600;color:var(--text-secondary);margin-bottom:4px}
.benefit-item .desc{color:var(--text-dim);line-height:1.4}
</style></head><body>
<div class="top-bar"></div>
<header class="header"><div class="header-left"><div class="header-icon">⚡</div><div><div class="header-title">TAKWERX Console</div><div class="header-subtitle">Caddy SSL</div></div></div><div class="header-right"><a href="/" class="btn-back">← Dashboard</a><span class="os-badge">{{ settings.get('os_name', 'Unknown OS') }}</span><a href="/logout" class="btn-logout">Sign Out</a></div></header>
<main class="main">
<div class="status-banner">
{% if caddy.installed and caddy.running %}
<div class="status-info"><div class="status-icon running">🔒</div><div><div class="status-text" style="color:var(--green)">Running</div><div class="status-detail">Caddy is active{% if settings.get('fqdn') %} · {{ settings.get('fqdn') }}{% endif %}</div></div></div>
<div class="controls"><button class="control-btn" onclick="caddyControl('reload')">↻ Reload</button><button class="control-btn" onclick="caddyControl('restart')">↻ Restart</button><button class="control-btn btn-stop" onclick="caddyControl('stop')">■ Stop</button><button class="control-btn btn-stop" onclick="caddyUninstall()" style="margin-left:8px">🗑 Remove</button></div>
{% elif caddy.installed %}
<div class="status-info"><div class="status-icon stopped">🔒</div><div><div class="status-text" style="color:var(--red)">Stopped</div><div class="status-detail">Caddy is installed but not running</div></div></div>
<div class="controls"><button class="control-btn btn-start" onclick="caddyControl('start')">▶ Start</button><button class="control-btn btn-stop" onclick="caddyUninstall()" style="margin-left:8px">🗑 Remove</button></div>
{% else %}
<div class="status-info"><div class="status-icon not-installed">🔒</div><div><div class="status-text" style="color:var(--text-dim)">Not Installed</div><div class="status-detail">Set up a domain for full functionality</div></div></div>
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
<div class="section-title">Access Links</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
<a href="https://console.{{ settings.get('fqdn', '') }}" target="_blank" style="padding:8px 14px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:12px;text-decoration:none;font-weight:600">⚡ console</a>
<a href="{{ 'https://tak.' + settings.get('fqdn') if settings.get('fqdn') else 'https://' + settings.get('server_ip', '') + ':8443' }}" target="_blank" style="padding:8px 14px;background:var(--bg-surface);border:1px solid var(--border);color:var(--text-secondary);border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:12px;text-decoration:none">🗺️ tak</a>
<a href="{{ 'https://authentik.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':9090' }}" target="_blank" style="padding:8px 14px;background:var(--bg-surface);border:1px solid var(--border);color:var(--text-secondary);border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:12px;text-decoration:none">🔐 authentik</a>
<a href="{{ 'https://takportal.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':3000' }}" target="_blank" style="padding:8px 14px;background:var(--bg-surface);border:1px solid var(--border);color:var(--text-secondary);border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:12px;text-decoration:none">👥 takportal</a>
<a href="{{ 'https://nodered.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':1880' }}" target="_blank" style="padding:8px 14px;background:var(--bg-surface);border:1px solid var(--border);color:var(--text-secondary);border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:12px;text-decoration:none">🔴 nodered</a>
</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);margin-top:10px">Links activate as services are deployed</div>
</div>
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
<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);margin-bottom:20px">Subdomains auto-configured: console · tak · authentik · portal · nodered · cloudtak<br>Point a wildcard DNS (*.yourdomain.com) or individual A records to <span style="color:var(--cyan)">{{ settings.get('server_ip', '') }}</span></div>
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
<div class="benefit-item"><div class="icon">📹</div><div class="title">Secure Streaming</div><div class="desc">MediaMTX streams over HTTPS with its own subdomain</div></div>
</div>
{% endif %}
</main>
<footer class="footer">TAKWERX Console v{{ version }} · {{ settings.get('os_type', '') }} · {{ settings.get('server_ip', '') }}</footer>
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
    var d=await r.json();setTimeout(()=>location.reload(),2000)}catch(e){alert('Error: '+e.message)}
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
<title>Certificates · TAKWERX Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg-deep:#080b14;--bg-surface:#0f1219;--bg-card:#161b26;--border:#1e2736;--border-hover:#2a3548;--text-primary:#e2e8f0;--text-secondary:#94a3b8;--text-dim:#475569;--accent:#3b82f6;--cyan:#06b6d4;--green:#10b981;--red:#ef4444;--yellow:#eab308}
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
.footer{text-align:center;padding:24px;font-size:12px;color:var(--text-dim);border-top:1px solid var(--border);margin-top:40px}
</style></head><body>
<div class="top-bar"></div>
<header class="header"><div class="header-left"><div class="header-icon">⚡</div><div><div class="header-title">TAKWERX Console</div><div class="header-subtitle">Certificates</div></div></div><div class="header-right"><a href="/takserver" class="btn-back">← TAK Server</a></div></header>
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
<footer class="footer">TAKWERX Console v{{ version }}</footer>
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
<title>TAK Portal — TAKWERX Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg-deep:#080b14;--bg-surface:#0f1219;--bg-card:#161b26;--border:#1e2736;--border-hover:#2a3548;--text-primary:#e2e8f0;--text-secondary:#94a3b8;--text-dim:#475569;--accent:#3b82f6;--cyan:#06b6d4;--green:#10b981;--red:#ef4444;--yellow:#eab308}
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
.status-banner{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between}
.status-info{display:flex;align-items:center;gap:16px}
.status-icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px}
.status-icon.running{background:rgba(16,185,129,0.1)}.status-icon.stopped{background:rgba(239,68,68,0.1)}.status-icon.not-installed{background:rgba(71,85,105,0.2)}
.status-text{font-family:'JetBrains Mono',monospace;font-size:18px;font-weight:600}
.status-detail{font-size:13px;color:var(--text-dim);margin-top:4px}
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
.footer{text-align:center;padding:24px;font-size:12px;color:var(--text-dim);border-top:1px solid var(--border);margin-top:40px}
</style></head><body>
<div class="top-bar"></div>
<header class="header"><div class="header-left"><div class="header-icon">⚡</div><div><div class="header-title">TAKWERX Console</div><div class="header-subtitle">TAK Portal</div></div></div><div class="header-right"><a href="/" class="btn-back">← Dashboard</a><span class="os-badge">{{ settings.get('os_name', 'Unknown OS') }}</span><a href="/logout" class="btn-logout">Sign Out</a></div></header>
<main class="main">
<div class="status-banner">
{% if deploying %}
<div class="status-info"><div class="status-icon running" style="background:rgba(59,130,246,0.1)">🔄</div><div><div class="status-text" style="color:var(--accent)">Deploying...</div><div class="status-detail">TAK Portal installation in progress</div></div></div>
{% elif portal.installed and portal.running %}
<div class="status-info"><div class="status-icon running">👥</div><div><div class="status-text" style="color:var(--green)">Running</div><div class="status-detail">{{ container_info.get('status', 'Docker container active') }}</div></div></div>
<div class="controls">
<button class="control-btn btn-stop" onclick="portalControl('stop')">⏹ Stop</button>
<button class="control-btn" onclick="portalControl('restart')">🔄 Restart</button>
<button class="control-btn btn-update" onclick="portalControl('update')">⬆ Update</button>
</div>
{% elif portal.installed %}
<div class="status-info"><div class="status-icon stopped">👥</div><div><div class="status-text" style="color:var(--red)">Stopped</div><div class="status-detail">Docker container not running</div></div></div>
<div class="controls">
<button class="control-btn btn-start" onclick="portalControl('start')">▶ Start</button>
<button class="control-btn btn-update" onclick="portalControl('update')">⬆ Update</button>
</div>
{% else %}
<div class="status-info"><div class="status-icon not-installed">👥</div><div><div class="status-text" style="color:var(--text-dim)">Not Installed</div><div class="status-detail">Deploy TAK Portal for user & certificate management</div></div></div>
{% endif %}
</div>

{% if deploying %}
<div class="section-title">Deployment Log</div>
<div class="deploy-log" id="deploy-log">Waiting for deployment to start...</div>
{% elif portal.installed and portal.running %}
<div class="section-title">Access</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="display:flex;gap:10px;flex-wrap:nowrap;align-items:center">
<a href="{{ 'https://takportal.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':' + str(portal_port) }}" target="_blank" class="cert-btn cert-btn-primary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">👥 TAK Portal :{{ portal_port }}</a>
<a href="{{ 'https://authentik.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':9090' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔐 Authentik :9090</a>
<a href="{{ 'https://tak.' + settings.get('fqdn') if settings.get('fqdn') else 'https://' + settings.get('server_ip', '') + ':8443' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔐 WebGUI :8443 (cert)</a>
<a href="{{ 'https://tak.' + settings.get('fqdn') if settings.get('fqdn') else 'https://' + settings.get('server_ip', '') + ':8446' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔑 WebGUI :8446 (password)</a>
</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);margin-top:12px">Admin user: <span style="color:var(--cyan)">akadmin</span> · <button type="button" onclick="showAkPassword()" id="ak-pw-btn" style="background:none;border:1px solid var(--border);color:var(--cyan);padding:2px 10px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:11px;cursor:pointer">🔑 Show Password</button> <span id="ak-pw-display" style="color:var(--green);user-select:all;display:none"></span></div>
</div>
<div class="deploy-log" id="container-log">Loading logs...</div>
<div style="margin-top:24px;text-align:center">
<button class="control-btn btn-remove" onclick="uninstallPortal()">🗑 Remove TAK Portal</button>
</div>
{% elif portal.installed %}
<div style="margin-top:24px;text-align:center">
<button class="control-btn btn-remove" onclick="uninstallPortal()">🗑 Remove TAK Portal</button>
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
<div class="deploy-log" id="deploy-log" style="display:none">Waiting for deployment to start...</div>
{% endif %}

{% if deploy_done %}
<div style="background:rgba(16,185,129,0.1);border:1px solid var(--border);border-radius:10px;padding:20px;margin-top:20px;text-align:center">
<div style="font-family:'JetBrains Mono',monospace;font-size:14px;color:var(--green);margin-bottom:12px">✓ TAK Portal deployed! Open Server Settings to configure Authentik & TAK Server.</div>
<button onclick="window.location.href='/takportal'" style="padding:10px 24px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer">Refresh Page</button>
</div>
{% endif %}
</main>
<footer class="footer">TAKWERX Console v{{ version }}</footer>
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
            if(btn){btn.textContent='✓ Deployment Complete';btn.style.background='var(--green)';btn.style.opacity='1';btn.style.cursor='default';}
            var el=document.getElementById('deploy-log');
            var openBtn=document.createElement('button');
            openBtn.textContent='>> Open TAK Portal';
            openBtn.style.cssText='display:block;width:100%;padding:12px;margin-top:16px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;';
            openBtn.onclick=function(){window.open('https://takportal.'+window.location.hostname.replace(/^[^.]+\./,''),'_blank');};
            el.appendChild(openBtn);
            var refreshBtn=document.createElement('button');
            refreshBtn.textContent='↻ Refresh TAK Portal Page';
            refreshBtn.style.cssText='display:block;width:100%;padding:10px;margin-top:8px;background:rgba(30,64,175,0.2);color:var(--cyan);border:1px solid var(--border);border-radius:8px;font-size:13px;cursor:pointer;';
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
    var pw=prompt('Enter admin password to remove TAK Portal:');
    if(!pw)return;
    if(!confirm('This will remove TAK Portal, its Docker containers, volumes, and data. Continue?'))return;
    fetch('/api/takportal/uninstall',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})}).then(function(r){return r.json()}).then(function(d){
        if(d.success){alert('TAK Portal removed.');window.location.href='/takportal'}
        else alert('Error: '+(d.error||'Unknown'));
    });
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
    threading.Thread(target=run_authentik_deploy, daemon=True).start()
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
    subprocess.run(f'cd {ak_dir} && docker compose down -v --rmi all 2>/dev/null; true', shell=True, capture_output=True, timeout=180)
    steps.append('Stopped and removed Docker containers/volumes/images')
    if os.path.exists(ak_dir):
        subprocess.run(f'rm -rf {ak_dir}', shell=True, capture_output=True)
        steps.append('Removed ~/authentik')
    authentik_deploy_log.clear()
    authentik_deploy_status.update({'running': False, 'complete': False, 'error': False})
    return jsonify({'success': True, 'steps': steps})

def run_authentik_deploy():
    def plog(msg):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        authentik_deploy_log.append(entry)
        print(entry, flush=True)
    try:
        ak_dir = os.path.expanduser('~/authentik')
        settings = load_settings()
        server_ip = settings.get('server_ip', 'localhost')

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
        env_path = os.path.join(ak_dir, '.env')
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
        compose_path = os.path.join(ak_dir, 'docker-compose.yml')
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

        # Step 7: Pull and start core services
        plog("")
        plog("\u2501\u2501\u2501 Step 7/10: Pulling Images & Starting Containers \u2501\u2501\u2501")
        plog("  Pulling images (this may take a few minutes)...")
        r = subprocess.run(f'cd {ak_dir} && docker compose pull 2>&1', shell=True, capture_output=True, text=True, timeout=600)
        for line in r.stdout.strip().split('\n'):
            if line.strip() and ('Pulling' in line or 'Pull' in line or 'Downloaded' in line or 'done' in line.lower()):
                authentik_deploy_log.append(f"  {line.strip()}")
        plog("  Starting core services...")
        r = subprocess.run(f'cd {ak_dir} && docker compose up -d postgresql server worker 2>&1', shell=True, capture_output=True, text=True, timeout=120)
        for line in r.stdout.strip().split('\n'):
            if line.strip() and 'NEEDRESTART' not in line:
                authentik_deploy_log.append(f"  {line.strip()}")

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

        # Step 9: Start LDAP outpost
        plog("")
        plog("\u2501\u2501\u2501 Step 9/12: Starting LDAP Outpost \u2501\u2501\u2501")
        r = subprocess.run(f'cd {ak_dir} && docker compose up -d ldap 2>&1', shell=True, capture_output=True, text=True, timeout=120)
        for line in r.stdout.strip().split('\n'):
            if line.strip() and 'NEEDRESTART' not in line:
                authentik_deploy_log.append(f"  {line.strip()}")
        plog("  Waiting for LDAP to start...")
        time.sleep(15)
        r = subprocess.run('docker logs authentik-ldap-1 2>&1 | tail -3', shell=True, capture_output=True, text=True)
        if 'Starting LDAP server' in r.stdout or 'Starting authentik outpost' in r.stdout:
            plog("\u2713 LDAP outpost is running on port 389")
        else:
            plog("\u26a0 LDAP outpost may still be starting")

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
            plog("\u26a0 TAK Server not installed, skipping CoreConfig patch")
            plog("  Deploy TAK Server first, then redeploy Authentik to auto-configure")

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

                # Create webadmin user in Authentik
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

                    # Inject LDAP outpost token from blueprint-created outpost
                    try:
                        plog("  Waiting for blueprint LDAP outpost to be created by worker...")
                        outpost_token_id = None
                        ldap_provider_pk = None
                        attempt = 0
                        while True:
                            try:
                                req = urllib.request.Request(f'{ak_url}/api/v3/outposts/instances/?search=LDAP',
                                    headers=ak_headers)
                                resp = urllib.request.urlopen(req, timeout=10)
                                outposts = json.loads(resp.read().decode())['results']
                                ldap_outpost = next((o for o in outposts if o.get('type') == 'ldap'), None)
                                if ldap_outpost and ldap_outpost.get('token_identifier'):
                                    outpost_token_id = ldap_outpost['token_identifier']
                                    ldap_provider_pk = ldap_outpost.get('providers', [None])[0]
                                    plog(f"  ✓ Blueprint LDAP outpost found (token_id={outpost_token_id})")
                                    break
                            except Exception:
                                pass
                            if attempt % 6 == 0:
                                plog(f"  ⏳ Waiting for LDAP outpost... ({attempt * 5}s)")
                            else:
                                authentik_deploy_log.append(f"  ⏳ {attempt * 5 // 60:02d}:{attempt * 5 % 60:02d}")
                            time.sleep(5)
                            attempt += 1

                        if outpost_token_id:
                            try:
                                req = urllib.request.Request(
                                    f'{ak_url}/api/v3/core/tokens/{outpost_token_id}/view_key/',
                                    headers=ak_headers, method='GET')
                                resp = urllib.request.urlopen(req, timeout=10)
                                ldap_token_key = json.loads(resp.read().decode()).get('key', '')
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
                                else:
                                    plog(f"  ✗ Token key empty from API")
                            except urllib.error.HTTPError as e:
                                plog(f"  ✗ Token injection HTTP error: {e.code} {e.read().decode()[:200]}")
                            except Exception as e:
                                plog(f"  ✗ Token injection error: {str(e)[:200]}")
                        else:
                            plog(f"  ✗ No outpost_token_id — cannot inject token")
                    except Exception as e:
                        plog(f"  ✗ LDAP token injection error: {str(e)[:200]}")
                else:
                    plog("  ⚠ No webadmin password found, skipping user creation")
            else:
                plog("  ⚠ No bootstrap token found, skipping admin setup")
        except Exception as e:
            plog(f"  ⚠ Admin group setup error (non-fatal): {str(e)[:100]}")

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

                    # 12b: Get default authorization flow
                    flow_slug = None
                    try:
                        req = urllib.request.Request(f'{ak_url}/api/v3/flows/instances/?designation=authorization&ordering=slug',
                            headers=ak_headers)
                        resp = urllib.request.urlopen(req, timeout=10)
                        flows = json.loads(resp.read().decode())['results']
                        # Prefer implicit-consent
                        for fl in flows:
                            if 'implicit' in fl.get('slug', ''):
                                flow_slug = fl['pk']
                                break
                        if not flow_slug and flows:
                            flow_slug = flows[0]['pk']
                    except Exception as e:
                        plog(f"  ⚠ Could not find authorization flow: {str(e)[:100]}")

                    # 12c: Create Proxy Provider (Forward auth single application)
                    provider_pk = None
                    if flow_slug:
                        try:
                            provider_data = {
                                'name': 'TAK Portal Proxy',
                                'authentication_flow': flow_slug,
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
                        plog("  ⚠ No authorization flow found, skipping proxy provider")

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
                                # Get current providers list and add ours
                                current_providers = embedded.get('providers', [])
                                if provider_pk not in current_providers:
                                    current_providers.append(provider_pk)
                                # First update providers
                                req = urllib.request.Request(f'{ak_url}/api/v3/outposts/instances/{outpost_pk}/',
                                    data=json.dumps({
                                        'name': embedded['name'],
                                        'type': embedded.get('type', 'proxy'),
                                        'providers': current_providers,
                                    }).encode(),
                                    headers=ak_headers, method='PUT')
                                urllib.request.urlopen(req, timeout=15)
                                plog(f"  ✓ TAK Portal added to embedded outpost")
                                # Then patch config separately
                                existing_config = embedded.get('config', {})
                                existing_config['authentik_host'] = f'https://authentik.{fqdn}'
                                existing_config['authentik_host_insecure'] = False
                                req = urllib.request.Request(f'{ak_url}/api/v3/outposts/instances/{outpost_pk}/',
                                    data=json.dumps({'config': existing_config}).encode(),
                                    headers=ak_headers, method='PATCH')
                                urllib.request.urlopen(req, timeout=15)
                                plog(f"  ✓ Embedded outpost authentik_host set to https://authentik.{fqdn}")
                            else:
                                plog("  ⚠ No embedded outpost found — create one in Authentik admin")
                        except Exception as e:
                            plog(f"  ⚠ Outpost config: {str(e)[:100]}")

                    plog(f"  ✓ Forward auth ready for takportal.{fqdn}")
                else:
                    plog("  ⚠ No bootstrap token, skipping forward auth setup")
            except Exception as e:
                plog(f"  ⚠ Forward auth setup error (non-fatal): {str(e)[:100]}")
        else:
            plog("")
            plog("  ℹ No domain configured — skipping forward auth setup")
            plog("  Set up a domain in the Caddy module first, then redeploy Authentik")

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
<title>Authentik — TAKWERX Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg-deep:#080b14;--bg-surface:#0f1219;--bg-card:#161b26;--border:#1e2736;--border-hover:#2a3548;--text-primary:#e2e8f0;--text-secondary:#94a3b8;--text-dim:#475569;--accent:#3b82f6;--cyan:#06b6d4;--green:#10b981;--red:#ef4444;--yellow:#eab308}
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
.status-banner{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between}
.status-info{display:flex;align-items:center;gap:16px}
.status-icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px}
.status-icon.running{background:rgba(16,185,129,0.1)}.status-icon.stopped{background:rgba(239,68,68,0.1)}.status-icon.not-installed{background:rgba(71,85,105,0.2)}
.status-text{font-family:'JetBrains Mono',monospace;font-size:18px;font-weight:600}
.status-detail{font-size:13px;color:var(--text-dim);margin-top:4px}
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
.footer{text-align:center;padding:24px;font-size:12px;color:var(--text-dim);border-top:1px solid var(--border);margin-top:40px}
</style></head><body>
<div class="top-bar"></div>
<header class="header"><div class="header-left"><div class="header-icon">⚡</div><div><div class="header-title">TAKWERX Console</div><div class="header-subtitle">Authentik</div></div></div><div class="header-right"><a href="/" class="btn-back">← Dashboard</a><span class="os-badge">{{ settings.get('os_name', 'Unknown OS') }}</span><a href="/logout" class="btn-logout">Sign Out</a></div></header>
<main class="main">
<div class="status-banner">
{% if deploying %}
<div class="status-info"><div class="status-icon running" style="background:rgba(59,130,246,0.1)">🔄</div><div><div class="status-text" style="color:var(--accent)">Deploying...</div><div class="status-detail">Authentik installation in progress</div></div></div>
{% elif ak.installed and ak.running %}
<div class="status-info"><div class="status-icon running">🔐</div><div><div class="status-text" style="color:var(--green)">Running</div><div class="status-detail">Identity provider active</div></div></div>
<div class="controls">
<button class="control-btn btn-stop" onclick="akControl('stop')">⏹ Stop</button>
<button class="control-btn" onclick="akControl('restart')">🔄 Restart</button>
<button class="control-btn btn-update" onclick="akControl('update')">⬆ Update</button>
</div>
{% elif ak.installed %}
<div class="status-info"><div class="status-icon stopped">🔐</div><div><div class="status-text" style="color:var(--red)">Stopped</div><div class="status-detail">Docker containers not running</div></div></div>
<div class="controls">
<button class="control-btn btn-start" onclick="akControl('start')">▶ Start</button>
<button class="control-btn btn-update" onclick="akControl('update')">⬆ Update</button>
</div>
{% else %}
<div class="status-info"><div class="status-icon not-installed">🔐</div><div><div class="status-text" style="color:var(--text-dim)">Not Installed</div><div class="status-detail">Deploy Authentik for identity management & SSO</div></div></div>
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
<div style="display:flex;gap:10px;flex-wrap:nowrap;align-items:center">
<a href="{{ 'https://authentik.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':' + str(ak_port) }}" target="_blank" class="cert-btn cert-btn-primary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔐 Authentik :{{ ak_port }}</a>
<a href="{{ 'https://takportal.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':3000' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">👥 TAK Portal :3000</a>
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
<button class="control-btn btn-remove" onclick="uninstallAk()">🗑 Remove Authentik</button>
</div>
{% elif ak.installed %}
<div style="margin-top:24px;text-align:center">
<button class="control-btn btn-start" onclick="akControl('start')" style="margin-right:12px">▶ Start</button>
<button class="control-btn btn-remove" onclick="uninstallAk()">🗑 Remove Authentik</button>
</div>
{% else %}
<div class="section-title">About Authentik</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--text-secondary);line-height:1.8">
Authentik is an open-source <span style="color:var(--cyan)">Identity Provider</span> supporting SSO, SAML, OAuth2/OIDC, LDAP, and RADIUS.<br><br>
It provides centralized user authentication and management for all your services — including <span style="color:var(--cyan)">TAK Portal</span> for TAK Server user/cert management.<br><br>
<span style="color:var(--text-dim)">Deploys: PostgreSQL + Redis + Authentik Server + Worker (4 containers)</span><br>
<span style="color:var(--text-dim)">Ports: 9090 (HTTP) · 9443 (HTTPS)</span><br>
<span style="color:var(--text-dim)">Recommended: 2+ CPU cores, 2+ GB RAM</span>
</div>
</div>
<button class="deploy-btn" id="deploy-btn" onclick="deployAk()">🚀 Deploy Authentik</button>
<div class="deploy-log" id="deploy-log" style="display:none">Waiting for deployment to start...</div>
{% endif %}

{% if deploy_done %}
<div style="background:rgba(16,185,129,0.1);border:1px solid var(--border);border-radius:10px;padding:20px;margin-top:20px;text-align:center">
<div style="font-family:'JetBrains Mono',monospace;font-size:14px;color:var(--green);margin-bottom:8px">✓ Authentik deployed!</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--cyan);margin-bottom:12px">Navigate to Initial Setup to set your akadmin password.</div>
<button onclick="window.location.href='/authentik'" style="padding:10px 24px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer">Refresh Page</button>
</div>
{% endif %}
</main>
<footer class="footer">TAKWERX Console v{{ version }}</footer>
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
            var launchBtn=document.createElement('button');
            launchBtn.textContent='\ud83d\ude80 Launch TAK Portal';
            launchBtn.style.cssText='display:block;width:100%;padding:12px;margin-top:16px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;';
            launchBtn.onclick=function(){window.location.href='/takportal';};
            el.appendChild(launchBtn);
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
    var pw=prompt('Enter admin password to remove Authentik:');
    if(!pw)return;
    if(!confirm('This will remove Authentik, all Docker containers, volumes, images, and data. This cannot be undone. Continue?'))return;
    fetch('/api/authentik/uninstall',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})}).then(function(r){return r.json()}).then(function(d){
        if(d.success){alert('Authentik removed.');window.location.href='/authentik'}
        else alert('Error: '+(d.error||'Unknown'));
    });
}

{% if deploying %}pollDeployLog();{% endif %}
</script>
</body></html>'''

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
    """Tail the takserver-messaging.log file"""
    log_path = '/opt/tak/logs/takserver-messaging.log'
    offset = request.args.get('offset', 0, type=int)
    lines = request.args.get('lines', 100, type=int)
    if not os.path.exists(log_path):
        return jsonify({'entries': [], 'offset': 0, 'size': 0})
    try:
        size = os.path.getsize(log_path)
        if offset == 0:
            # First load: grab last N lines
            r = subprocess.run(f'tail -n {lines} "{log_path}"', shell=True, capture_output=True, text=True, timeout=10)
            entries = r.stdout.strip().split('\n') if r.stdout.strip() else []
            return jsonify({'entries': entries, 'offset': size, 'size': size})
        elif size > offset:
            # New content since last poll
            with open(log_path, 'r') as f:
                f.seek(offset)
                new_data = f.read()
            entries = new_data.strip().split('\n') if new_data.strip() else []
            return jsonify({'entries': entries, 'offset': size, 'size': size})
        else:
            return jsonify({'entries': [], 'offset': offset, 'size': size})
    except Exception as e:
        return jsonify({'entries': [f'Error reading log: {str(e)}'], 'offset': offset, 'size': 0})

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
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg-primary:#0a0e17;--bg-card:rgba(15,23,42,0.7);--bg-card-hover:rgba(15,23,42,0.9);--border:rgba(59,130,246,0.1);--border-hover:rgba(59,130,246,0.3);--text-primary:#e2e8f0;--text-secondary:#94a3b8;--text-dim:#475569;--accent:#3b82f6;--accent-glow:rgba(59,130,246,0.15);--green:#10b981;--red:#ef4444;--yellow:#f59e0b;--cyan:#06b6d4}
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
LOGIN_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>TAKWERX Console</title>
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
.logo h1{font-family:'JetBrains Mono',monospace;font-size:22px;font-weight:700;color:#e2e8f0}
.logo p{color:#64748b;font-size:13px;margin-top:6px;letter-spacing:0.5px;text-transform:uppercase}
.fg{margin-bottom:24px}
.fg label{display:block;color:#94a3b8;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.fg input{width:100%;padding:14px 16px;background:rgba(15,23,42,0.6);border:1px solid rgba(59,130,246,0.2);border-radius:10px;color:#e2e8f0;font-family:'JetBrains Mono',monospace;font-size:15px;transition:all 0.2s}
.fg input:focus{outline:none;border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,0.1)}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff;border:none;border-radius:10px;font-family:'DM Sans',sans-serif;font-size:15px;font-weight:600;cursor:pointer;transition:all 0.2s}
.btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(59,130,246,0.3)}
.err{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);color:#fca5a5;padding:12px 16px;border-radius:8px;font-size:14px;margin-bottom:20px;text-align:center}
.ver{text-align:center;margin-top:20px;color:#334155;font-family:'JetBrains Mono',monospace;font-size:11px}
</style></head><body>
<div class="lc"><div class="card">
<div class="logo"><div class="logo-icon">⚡</div><h1>TAKWERX Console</h1><p>Infrastructure Platform</p></div>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<form method="POST"><div class="fg"><label>Password</label><input type="password" name="password" autofocus placeholder="Enter admin password"></div><button type="submit" class="btn">Sign In</button></form>
</div><div class="ver">v{{ version }}</div></div>
</body></html>'''

# === API Routes ===

@app.route('/api/metrics')
@login_required
def api_metrics():
    return jsonify(get_system_metrics())

# === Dashboard Template ===
DASHBOARD_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>TAKWERX Console</title>
<style>
''' + BASE_CSS + '''
.modules-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px;margin-bottom:32px}
.module-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;cursor:pointer;transition:all 0.3s;text-decoration:none;display:block;color:inherit}
.module-card:hover{border-color:var(--border-hover);background:var(--bg-card-hover);transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,0.3)}
.module-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.module-icon{font-size:28px}
.module-status{font-family:'JetBrains Mono',monospace;font-size:11px;padding:4px 10px;border-radius:6px;display:flex;align-items:center;gap:6px}
.status-running{background:rgba(16,185,129,0.1);color:var(--green)}
.status-stopped{background:rgba(239,68,68,0.1);color:var(--red)}
.status-not-installed{background:rgba(71,85,105,0.2);color:var(--text-dim)}
.status-dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.status-running .status-dot{animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
.module-name{font-family:'JetBrains Mono',monospace;font-weight:600;font-size:16px;margin-bottom:6px}
.module-desc{font-size:13px;color:var(--text-dim);line-height:1.4}
.module-action{display:inline-block;margin-top:14px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent);opacity:0;transition:opacity 0.2s}
.module-card:hover .module-action{opacity:1}
</style></head><body>
<div class="top-bar"></div>
<header class="header"><div class="header-left"><div class="header-icon">⚡</div><div><div class="header-title">TAKWERX Console</div><div class="header-subtitle">Infrastructure Platform</div></div></div><div class="header-right"><span class="os-badge">{{ settings.get('os_name', 'Unknown OS') }}</span><a href="/logout" class="btn-logout">Sign Out</a></div></header>
<main class="main">
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
<div class="section-title">Services</div>
<div class="modules-grid">
{% for key, mod in modules.items() %}
<a class="module-card" href="{{ mod.route }}">
<div class="module-header"><span class="module-icon">{{ mod.icon }}</span>
{% if mod.installed and mod.running %}<span class="module-status status-running"><span class="status-dot"></span> Running</span>
{% elif mod.installed %}<span class="module-status status-stopped"><span class="status-dot"></span> Stopped</span>
{% else %}<span class="module-status status-not-installed">Not Installed</span>{% endif %}
</div>
<div class="module-name">{{ mod.name }}</div>
<div class="module-desc">{{ mod.description }}</div>
{% if mod.installed %}<span class="module-action">Manage →</span>{% else %}<span class="module-action">Deploy →</span>{% endif %}
</a>
{% endfor %}
</div>
</main>
<footer class="footer">TAKWERX Console v{{ version }} · {{ settings.get('os_type', '') }} · {{ settings.get('server_ip', '') }}</footer>
<script>
setInterval(async()=>{try{const r=await fetch('/api/metrics');const d=await r.json();document.getElementById('cpu-value').textContent=d.cpu_percent+'%';document.getElementById('ram-value').textContent=d.ram_percent+'%';document.getElementById('disk-value').textContent=d.disk_percent+'%';document.getElementById('uptime-value').textContent=d.uptime}catch(e){}},5000);
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

# === TAK Server Template ===
TAKSERVER_TEMPLATE = '''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>TAK Server — TAKWERX Console</title>
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
.status-banner{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between}
.status-info{display:flex;align-items:center;gap:16px}
.status-icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px}
.status-icon.running{background:rgba(16,185,129,0.1)}.status-icon.stopped{background:rgba(239,68,68,0.1)}.status-icon.not-installed{background:rgba(71,85,105,0.2)}
.status-text{font-family:'JetBrains Mono',monospace;font-size:18px;font-weight:600}
.status-detail{font-size:13px;color:var(--text-dim);margin-top:4px}
.controls{display:flex;gap:10px}
.cert-downloads{display:flex;gap:12px;flex-wrap:wrap;margin-top:16px}
.cert-btn{padding:10px 20px;border-radius:8px;text-decoration:none;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;transition:all 0.2s}
.cert-btn-primary{background:linear-gradient(135deg,#1e40af,#0e7490);color:#fff}
.cert-btn-secondary{background:rgba(59,130,246,0.1);color:var(--accent);border:1px solid var(--border)}
</style></head><body>
<div class="top-bar"></div>
<header class="header"><div class="header-left"><div class="header-icon">⚡</div><div><div class="header-title">TAKWERX Console</div><div class="header-subtitle">TAK Server</div></div></div><div class="header-right"><a href="/" class="btn-back">← Dashboard</a><span class="os-badge">{{ settings.get('os_name', 'Unknown OS') }}</span><a href="/logout" class="btn-logout">Sign Out</a></div></header>
<main class="main">
<div class="status-banner" id="status-banner">
{% if deploying %}
<div class="status-info"><div class="status-icon running" style="background:rgba(59,130,246,0.1)">🗺️</div><div><div class="status-text" style="color:var(--accent)">Deploying...</div><div class="status-detail">TAK Server installation in progress</div></div></div>
<div class="controls"><button class="control-btn btn-stop" onclick="cancelDeploy()">✗ Cancel</button></div>
{% elif tak.installed and tak.running %}
<div class="status-info"><div class="status-icon running">🗺️</div><div><div class="status-text" style="color:var(--green)">Running</div><div class="status-detail">TAK Server is active</div></div></div>
<div class="controls"><button class="control-btn" onclick="takControl('restart')">↻ Restart</button><button class="control-btn btn-stop" onclick="takControl('stop')">■ Stop</button><button class="control-btn btn-stop" onclick="takUninstall()" style="margin-left:8px">🗑 Remove</button></div>
{% elif tak.installed %}
<div class="status-info"><div class="status-icon stopped">🗺️</div><div><div class="status-text" style="color:var(--red)">Stopped</div><div class="status-detail">TAK Server is installed but not running</div></div></div>
<div class="controls"><button class="control-btn btn-start" onclick="takControl('start')">▶ Start</button><button class="control-btn btn-stop" onclick="takUninstall()" style="margin-left:8px">🗑 Remove</button></div>
{% else %}
<div class="status-info"><div class="status-icon not-installed">🗺️</div><div><div class="status-text" style="color:var(--text-dim)">Not Installed</div><div class="status-detail">Upload package files from tak.gov to deploy</div></div></div>
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
<div class="section-title">Access</div>
<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
<div style="display:flex;gap:10px;flex-wrap:nowrap;align-items:center">
<a href="{{ 'https://tak.' + settings.get('fqdn') if settings.get('fqdn') else 'https://' + settings.get('server_ip', '') + ':8443' }}" target="_blank" class="cert-btn cert-btn-primary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔐 WebGUI :8443 (cert)</a>
<a href="{{ 'https://tak.' + settings.get('fqdn') if settings.get('fqdn') else 'https://' + settings.get('server_ip', '') + ':8446' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔑 WebGUI :8446 (password)</a>
<a href="{{ 'https://takportal.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':3000' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">👥 TAK Portal :3000</a>
<a href="{{ 'https://authentik.' + settings.get('fqdn', '') if settings.get('fqdn') else 'http://' + settings.get('server_ip', '') + ':9090' }}" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none;white-space:nowrap;font-size:12px;padding:8px 14px">🔐 Authentik :9090</a>
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
</main>
<footer class="footer">TAKWERX Console v{{ version }} · {{ settings.get('os_type', '') }} · {{ settings.get('server_ip', '') }}</footer>
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
    if(!confirm('Remove TAK Server completely? This will delete /opt/tak, all certificates, and all config. You can redeploy after.'))return;
    const pw=prompt('Enter admin password to confirm removal:');
    if(!pw)return;
    const btns=document.querySelectorAll('.control-btn');
    btns.forEach(b=>{b.disabled=true;b.style.opacity='0.5'});
    try{const r=await fetch('/api/takserver/uninstall',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});const d=await r.json();if(d.success){alert('TAK Server removed. Page will reload.');window.location.href='/takserver'}else{alert('Error: '+(d.error||'Unknown'))}}
    catch(e){alert('Failed: '+e.message)}
    btns.forEach(b=>{b.disabled=false;b.style.opacity='1'});
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
    print("TAKWERX Console v" + VERSION)
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
