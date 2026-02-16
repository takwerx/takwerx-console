#!/usr/bin/env python3
"""TAKWERX Console v0.2.0 - Emergency Services Infrastructure Management Platform"""

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
VERSION = "0.2.0"
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
    tak_installed = os.path.exists('/opt/tak') and os.path.exists('/opt/tak/CoreConfig.xml')
    tak_running = False
    if tak_installed:
        r = subprocess.run(['systemctl', 'is-active', 'takserver'], capture_output=True, text=True)
        tak_running = r.stdout.strip() == 'active'
    modules['takserver'] = {'name': 'TAK Server', 'installed': tak_installed, 'running': tak_running,
        'description': 'Team Awareness Kit server for situational awareness', 'icon': '🗺️', 'route': '/takserver'}
    mtx_installed = os.path.exists('/usr/local/bin/mediamtx') and os.path.exists('/usr/local/etc/mediamtx.yml')
    mtx_running = False
    if mtx_installed:
        r = subprocess.run(['systemctl', 'is-active', 'mediamtx'], capture_output=True, text=True)
        mtx_running = r.stdout.strip() == 'active'
    modules['mediamtx'] = {'name': 'MediaMTX', 'installed': mtx_installed, 'running': mtx_running,
        'description': 'Drone video streaming server (RTSP/SRT/HLS)', 'icon': '📹', 'route': '/mediamtx'}
    gd_installed = os.path.exists('/opt/tak-guarddog')
    gd_running = False
    if gd_installed:
        r = subprocess.run(['systemctl', 'list-timers', '--no-pager'], capture_output=True, text=True)
        gd_running = 'tak8089guard' in r.stdout
    modules['guarddog'] = {'name': 'Guard Dog', 'installed': gd_installed, 'running': gd_running,
        'description': 'Health monitoring and auto-recovery', 'icon': '🐕', 'route': '/guarddog'}
    caddy_installed = subprocess.run(['which', 'caddy'], capture_output=True).returncode == 0
    caddy_running = False
    if caddy_installed:
        r = subprocess.run(['systemctl', 'is-active', 'caddy'], capture_output=True, text=True)
        caddy_running = r.stdout.strip() == 'active'
    modules['caddy'] = {'name': 'Caddy SSL', 'installed': caddy_installed, 'running': caddy_running,
        'description': "Let's Encrypt SSL and reverse proxy", 'icon': '🔒', 'route': '/caddy'}
    return modules

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

@app.route('/takserver')
@login_required
def takserver_page():
    modules = detect_modules()
    return render_template_string(TAKSERVER_TEMPLATE,
        settings=load_settings(), modules=modules, tak=modules.get('takserver', {}),
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

@app.route('/caddy')
@login_required
def caddy_page():
    return redirect(url_for('dashboard'))

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

# === API Routes ===

@app.route('/api/metrics')
@login_required
def api_metrics():
    return jsonify(get_system_metrics())

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
                name = 'Messaging'
                icon = '📡'
            elif 'profiles.active=api' in cmd:
                name = 'API'
                icon = '🔌'
            elif 'profiles.active=config' in cmd:
                name = 'Config'
                icon = '⚙️'
            elif 'takserver-pm.jar' in cmd:
                name = 'Plugin Manager'
                icon = '🧩'
            elif 'takserver-retention.jar' in cmd:
                name = 'Retention'
                icon = '📦'
            else:
                name = 'Unknown'
                icon = '❓'
            services.append({
                'name': name, 'icon': icon, 'pid': pid,
                'cpu': f"{cpu}%", 'mem_mb': f"{mem_mb} MB",
                'mem_pct': f"{mem_pct}%", 'status': 'running'
            })
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
            run_cmd('DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y debsig-verify > /dev/null 2>&1', check=False)
            r = subprocess.run(f"sed -n 's/.*id=\"\\([^\"]*\\)\".*/\\1/p' {config['policy_path']} | head -1", shell=True, capture_output=True, text=True)
            pid = r.stdout.strip()
            log_step(f"  Policy ID: {pid}")
            if pid:
                run_cmd(f'mkdir -p /usr/share/debsig/keyrings/{pid}')
                run_cmd(f'mkdir -p /etc/debsig/policies/{pid}')
                run_cmd(f'touch /usr/share/debsig/keyrings/{pid}/debsig.gpg')
                run_cmd(f'gpg --no-default-keyring --keyring /usr/share/debsig/keyrings/{pid}/debsig.gpg --import {config["gpg_key_path"]} 2>/dev/null')
                run_cmd(f'cp {config["policy_path"]} /etc/debsig/policies/{pid}/debsig.pol')
                v = subprocess.run(f'debsig-verify -v {pkg}', shell=True, capture_output=True, text=True)
                if v.returncode == 0: log_step("✓ Package signature VERIFIED")
                else: log_step(f"⚠ Verification exit code {v.returncode} — installing anyway")
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
        log_step(""); log_step("=" * 50); log_step("✓ DEPLOYMENT COMPLETE!"); log_step("=" * 50); log_step("")
        log_step(f"  WebGUI (cert):     https://{ip}:8443")
        if webadmin_pass:
            log_step(f"  WebGUI (password): https://{ip}:8446")
            log_step(f"  Username: webadmin")
        log_step(f"  Certificate Password: atakatak")
        log_step(f"  Admin cert: /opt/tak/certs/files/admin.p12")
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
<div style="display:flex;gap:12px;flex-wrap:wrap">
<a href="https://{{ settings.get('server_ip', '') }}:8443" target="_blank" class="cert-btn cert-btn-primary" style="text-decoration:none">🔐 WebGUI :8443 (cert)</a>
<a href="https://{{ settings.get('server_ip', '') }}:8446" target="_blank" class="cert-btn cert-btn-secondary" style="text-decoration:none">🔑 WebGUI :8446 (password)</a>
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
    print(f"Port: {port}")
    print("=" * 50)
    if ssl_mode == 'self-signed':
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
    else:
        app.run(host='127.0.0.1', port=port, debug=False)
