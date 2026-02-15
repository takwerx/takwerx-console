#!/usr/bin/env python3
"""
TAKWERX Console - Emergency Services Infrastructure Management Platform
https://github.com/takwerx

Main application entry point.
Provides a unified web interface for deploying and managing:
  - TAK Server
  - MediaMTX Streaming
  - Guard Dog Monitoring
  - Caddy SSL/Reverse Proxy
"""

from flask import (
    Flask, render_template_string, request, jsonify,
    redirect, url_for, session, send_from_directory
)
from werkzeug.security import check_password_hash
from functools import wraps
import os
import ssl
import json
import secrets
import subprocess
import time
import psutil
from datetime import datetime

# =============================================================================
# App Configuration
# =============================================================================

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2GB upload limit

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, '.config')
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
MODULES_DIR = os.path.join(BASE_DIR, 'modules')

VERSION = "0.1.0"

os.makedirs(UPLOAD_DIR, exist_ok=True)

# =============================================================================
# Configuration Helpers
# =============================================================================

def load_settings():
    """Load settings from .config/settings.json"""
    settings_file = os.path.join(CONFIG_DIR, 'settings.json')
    if os.path.exists(settings_file):
        with open(settings_file, 'r') as f:
            return json.load(f)
    return {}

def save_settings(settings):
    """Save settings to .config/settings.json"""
    settings_file = os.path.join(CONFIG_DIR, 'settings.json')
    with open(settings_file, 'w') as f:
        json.dump(settings, f, indent=2)

def load_auth():
    """Load auth config"""
    auth_file = os.path.join(CONFIG_DIR, 'auth.json')
    if os.path.exists(auth_file):
        with open(auth_file, 'r') as f:
            return json.load(f)
    return {}

# =============================================================================
# Authentication
# =============================================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# =============================================================================
# Module Detection
# =============================================================================

def detect_modules():
    """Detect which services are installed on this system"""
    modules = {}

    # TAK Server
    tak_installed = os.path.exists('/opt/tak') and os.path.exists('/opt/tak/CoreConfig.xml')
    tak_running = False
    if tak_installed:
        result = subprocess.run(['systemctl', 'is-active', 'takserver'],
                                capture_output=True, text=True)
        tak_running = result.stdout.strip() == 'active'
    modules['takserver'] = {
        'name': 'TAK Server',
        'installed': tak_installed,
        'running': tak_running,
        'description': 'Team Awareness Kit server for situational awareness',
        'icon': '🗺️'
    }

    # MediaMTX
    mtx_installed = os.path.exists('/usr/local/bin/mediamtx') and \
                    os.path.exists('/usr/local/etc/mediamtx.yml')
    mtx_running = False
    if mtx_installed:
        result = subprocess.run(['systemctl', 'is-active', 'mediamtx'],
                                capture_output=True, text=True)
        mtx_running = result.stdout.strip() == 'active'
    modules['mediamtx'] = {
        'name': 'MediaMTX',
        'installed': mtx_installed,
        'running': mtx_running,
        'description': 'Drone video streaming server (RTSP/SRT/HLS)',
        'icon': '📹'
    }

    # Guard Dog
    gd_installed = os.path.exists('/opt/tak-guarddog')
    gd_running = False
    if gd_installed:
        result = subprocess.run(['systemctl', 'list-timers', '--no-pager'],
                                capture_output=True, text=True)
        gd_running = 'tak8089guard' in result.stdout
    modules['guarddog'] = {
        'name': 'Guard Dog',
        'installed': gd_installed,
        'running': gd_running,
        'description': 'Health monitoring and auto-recovery for TAK Server',
        'icon': '🐕'
    }

    # Caddy
    caddy_installed = subprocess.run(['which', 'caddy'],
                                     capture_output=True).returncode == 0
    caddy_running = False
    if caddy_installed:
        result = subprocess.run(['systemctl', 'is-active', 'caddy'],
                                capture_output=True, text=True)
        caddy_running = result.stdout.strip() == 'active'
    modules['caddy'] = {
        'name': 'Caddy SSL',
        'installed': caddy_installed,
        'running': caddy_running,
        'description': "Let's Encrypt SSL and reverse proxy",
        'icon': '🔒'
    }

    return modules

# =============================================================================
# System Metrics
# =============================================================================

def get_system_metrics():
    """Get current system resource usage"""
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    uptime_seconds = time.time() - psutil.boot_time()
    days = int(uptime_seconds // 86400)
    hours = int((uptime_seconds % 86400) // 3600)
    mins = int((uptime_seconds % 3600) // 60)

    return {
        'cpu_percent': cpu,
        'ram_percent': mem.percent,
        'ram_used_gb': round(mem.used / (1024**3), 1),
        'ram_total_gb': round(mem.total / (1024**3), 1),
        'disk_percent': disk.percent,
        'disk_used_gb': round(disk.used / (1024**3), 1),
        'disk_total_gb': round(disk.total / (1024**3), 1),
        'uptime': f"{days}d {hours}h {mins}m"
    }

# =============================================================================
# Routes - Authentication
# =============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password', '')
        auth = load_auth()
        stored_hash = auth.get('admin_password_hash', '')

        if check_password_hash(stored_hash, password):
            session['authenticated'] = True
            session['login_time'] = datetime.utcnow().isoformat()
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(LOGIN_TEMPLATE,
                                          error="Invalid password",
                                          version=VERSION)

    return render_template_string(LOGIN_TEMPLATE, error=None, version=VERSION)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# =============================================================================
# Routes - Dashboard
# =============================================================================

@app.route('/')
@login_required
def dashboard():
    settings = load_settings()
    modules = detect_modules()
    metrics = get_system_metrics()

    return render_template_string(
        DASHBOARD_TEMPLATE,
        settings=settings,
        modules=modules,
        metrics=metrics,
        version=VERSION
    )

# =============================================================================
# Routes - API
# =============================================================================

@app.route('/api/metrics')
@login_required
def api_metrics():
    return jsonify(get_system_metrics())

@app.route('/api/modules')
@login_required
def api_modules():
    return jsonify(detect_modules())

@app.route('/api/upload/takserver', methods=['POST'])
@login_required
def upload_takserver_package():
    """Handle TAK Server file uploads (.deb/.rpm, GPG key, policy file)"""
    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400

    files = request.files.getlist('files')
    if not files or all(f.filename == '' for f in files):
        return jsonify({'error': 'No files selected'}), 400

    settings = load_settings()
    os_type = settings.get('os_type', '')

    # Allowed file patterns
    results = {
        'package': None,
        'gpg_key': None,
        'policy': None,
        'unknown': []
    }

    for f in files:
        filename = f.filename
        if not filename:
            continue

        filepath = os.path.join(UPLOAD_DIR, filename)
        f.save(filepath)
        size_mb = round(os.path.getsize(filepath) / (1024*1024), 1)

        if filename.endswith('.deb'):
            # Validate OS match
            if 'rocky' in os_type:
                os.remove(filepath)
                return jsonify({
                    'error': f'DEB package uploaded but system is {os_type}. Need .rpm.'
                }), 400
            results['package'] = {
                'filename': filename, 'filepath': filepath,
                'pkg_type': 'deb', 'size_mb': size_mb
            }

        elif filename.endswith('.rpm'):
            if 'ubuntu' in os_type:
                os.remove(filepath)
                return jsonify({
                    'error': f'RPM package uploaded but system is {os_type}. Need .deb.'
                }), 400
            results['package'] = {
                'filename': filename, 'filepath': filepath,
                'pkg_type': 'rpm', 'size_mb': size_mb
            }

        elif filename.endswith('.key') or 'gpg' in filename.lower():
            results['gpg_key'] = {
                'filename': filename, 'filepath': filepath, 'size_mb': size_mb
            }

        elif filename.endswith('.pol') or 'policy' in filename.lower():
            results['policy'] = {
                'filename': filename, 'filepath': filepath, 'size_mb': size_mb
            }

        else:
            results['unknown'].append(filename)

    if not results['package']:
        return jsonify({
            'error': 'No .deb or .rpm package found in uploaded files'
        }), 400

    return jsonify({
        'success': True,
        'package': results['package'],
        'gpg_key': results['gpg_key'],
        'policy': results['policy'],
        'has_verification': results['gpg_key'] is not None and results['policy'] is not None
    })

# =============================================================================
# HTML Templates
# =============================================================================

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TAKWERX Console</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'DM Sans', sans-serif;
            background: #0a0e17;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }

        /* Animated grid background */
        body::before {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background-image:
                linear-gradient(rgba(59, 130, 246, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(59, 130, 246, 0.03) 1px, transparent 1px);
            background-size: 60px 60px;
            z-index: 0;
        }

        /* Top accent line */
        body::after {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, #3b82f6, #06b6d4, transparent);
            z-index: 10;
        }

        .login-container {
            position: relative;
            z-index: 1;
            width: 100%;
            max-width: 420px;
            padding: 20px;
        }

        .login-card {
            background: linear-gradient(145deg, rgba(15, 23, 42, 0.95), rgba(15, 23, 42, 0.8));
            border: 1px solid rgba(59, 130, 246, 0.15);
            border-radius: 16px;
            padding: 48px 40px;
            backdrop-filter: blur(20px);
            box-shadow:
                0 0 0 1px rgba(59, 130, 246, 0.05),
                0 25px 50px rgba(0, 0, 0, 0.5),
                0 0 100px rgba(59, 130, 246, 0.03);
        }

        .logo-area {
            text-align: center;
            margin-bottom: 36px;
        }

        .logo-icon {
            width: 56px;
            height: 56px;
            background: linear-gradient(135deg, #1e40af, #0891b2);
            border-radius: 14px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            margin-bottom: 16px;
            box-shadow: 0 8px 24px rgba(59, 130, 246, 0.25);
        }

        .logo-area h1 {
            font-family: 'JetBrains Mono', monospace;
            font-size: 22px;
            font-weight: 700;
            color: #e2e8f0;
            letter-spacing: -0.5px;
        }

        .logo-area p {
            color: #64748b;
            font-size: 13px;
            margin-top: 6px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .form-group {
            margin-bottom: 24px;
        }

        .form-group label {
            display: block;
            color: #94a3b8;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }

        .form-group input {
            width: 100%;
            padding: 14px 16px;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(59, 130, 246, 0.2);
            border-radius: 10px;
            color: #e2e8f0;
            font-family: 'JetBrains Mono', monospace;
            font-size: 15px;
            transition: all 0.2s;
        }

        .form-group input:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }

        .btn-login {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #1e40af, #0e7490);
            color: #fff;
            border: none;
            border-radius: 10px;
            font-family: 'DM Sans', sans-serif;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            letter-spacing: 0.3px;
        }

        .btn-login:hover {
            transform: translateY(-1px);
            box-shadow: 0 8px 24px rgba(59, 130, 246, 0.3);
        }

        .btn-login:active { transform: translateY(0); }

        .error-msg {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 14px;
            margin-bottom: 20px;
            text-align: center;
        }

        .version {
            text-align: center;
            margin-top: 20px;
            color: #334155;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-card">
            <div class="logo-area">
                <div class="logo-icon">⚡</div>
                <h1>TAKWERX Console</h1>
                <p>Infrastructure Platform</p>
            </div>

            {% if error %}
            <div class="error-msg">{{ error }}</div>
            {% endif %}

            <form method="POST">
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" autofocus
                           placeholder="Enter admin password">
                </div>
                <button type="submit" class="btn-login">Sign In</button>
            </form>
        </div>
        <div class="version">v{{ version }}</div>
    </div>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TAKWERX Console</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');

        * { margin: 0; padding: 0; box-sizing: border-box; }

        :root {
            --bg-primary: #0a0e17;
            --bg-card: rgba(15, 23, 42, 0.7);
            --bg-card-hover: rgba(15, 23, 42, 0.9);
            --border: rgba(59, 130, 246, 0.1);
            --border-hover: rgba(59, 130, 246, 0.3);
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --text-dim: #475569;
            --accent: #3b82f6;
            --accent-glow: rgba(59, 130, 246, 0.15);
            --green: #10b981;
            --red: #ef4444;
            --yellow: #f59e0b;
            --cyan: #06b6d4;
        }

        body {
            font-family: 'DM Sans', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }

        /* Grid background */
        body::before {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background-image:
                linear-gradient(rgba(59, 130, 246, 0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(59, 130, 246, 0.02) 1px, transparent 1px);
            background-size: 60px 60px;
            pointer-events: none;
            z-index: 0;
        }

        /* Top accent bar */
        .top-bar {
            position: fixed;
            top: 0; left: 0; right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent), var(--cyan), transparent);
            z-index: 100;
        }

        /* Header */
        .header {
            position: relative;
            z-index: 1;
            padding: 24px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .header-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, #1e40af, #0891b2);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.2);
        }

        .header-title {
            font-family: 'JetBrains Mono', monospace;
            font-size: 18px;
            font-weight: 700;
            letter-spacing: -0.3px;
        }

        .header-subtitle {
            font-size: 12px;
            color: var(--text-dim);
            font-family: 'JetBrains Mono', monospace;
        }

        .header-right {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .os-badge {
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            color: var(--text-dim);
            background: rgba(59, 130, 246, 0.05);
            padding: 6px 12px;
            border-radius: 6px;
            border: 1px solid var(--border);
        }

        .btn-logout {
            color: var(--text-dim);
            text-decoration: none;
            font-size: 13px;
            transition: color 0.2s;
        }
        .btn-logout:hover { color: var(--red); }

        /* Main content */
        .main {
            position: relative;
            z-index: 1;
            max-width: 1200px;
            margin: 0 auto;
            padding: 32px 40px;
        }

        /* System metrics bar */
        .metrics-bar {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }

        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            backdrop-filter: blur(10px);
        }

        .metric-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-dim);
            font-weight: 600;
            margin-bottom: 8px;
        }

        .metric-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 24px;
            font-weight: 700;
            color: var(--text-primary);
        }

        .metric-detail {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--text-dim);
            margin-top: 4px;
        }

        /* Section title */
        .section-title {
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: var(--text-dim);
            margin-bottom: 16px;
        }

        /* Module cards */
        .modules-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }

        .module-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            backdrop-filter: blur(10px);
            transition: all 0.2s;
            cursor: pointer;
            position: relative;
            overflow: hidden;
        }

        .module-card:hover {
            border-color: var(--border-hover);
            background: var(--bg-card-hover);
            transform: translateY(-2px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }

        .module-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
        }

        .module-icon {
            font-size: 28px;
            line-height: 1;
        }

        .module-status {
            display: flex;
            align-items: center;
            gap: 6px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 4px 10px;
            border-radius: 6px;
        }

        .status-running {
            color: var(--green);
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
        }

        .status-stopped {
            color: var(--yellow);
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.2);
        }

        .status-not-installed {
            color: var(--text-dim);
            background: rgba(71, 85, 105, 0.1);
            border: 1px solid rgba(71, 85, 105, 0.2);
        }

        .status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: currentColor;
        }

        .status-running .status-dot {
            animation: pulse-green 2s infinite;
        }

        @keyframes pulse-green {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }

        .module-name {
            font-family: 'JetBrains Mono', monospace;
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 6px;
        }

        .module-desc {
            font-size: 13px;
            color: var(--text-secondary);
            line-height: 1.5;
        }

        .module-action {
            display: inline-block;
            margin-top: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            font-weight: 600;
            color: var(--accent);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .module-card:hover .module-action {
            text-decoration: underline;
        }

        /* Upload area */
        .upload-area {
            border: 2px dashed rgba(59, 130, 246, 0.2);
            border-radius: 12px;
            padding: 48px;
            text-align: center;
            transition: all 0.2s;
            cursor: pointer;
            background: rgba(59, 130, 246, 0.02);
        }

        .upload-area:hover,
        .upload-area.dragover {
            border-color: var(--accent);
            background: rgba(59, 130, 246, 0.05);
        }

        .upload-icon { font-size: 48px; margin-bottom: 16px; }

        .upload-text {
            font-size: 16px;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        .upload-hint {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--text-dim);
        }

        /* Progress bars */
        .file-progress {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px 18px;
            margin-bottom: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
        }

        .file-progress-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
            color: var(--text-secondary);
        }

        .file-progress-name {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            max-width: 70%;
        }

        .file-progress-pct {
            color: var(--cyan);
            font-weight: 600;
        }

        .file-progress-bar {
            height: 4px;
            background: rgba(59, 130, 246, 0.1);
            border-radius: 2px;
            overflow: hidden;
        }

        .file-progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent), var(--cyan));
            border-radius: 2px;
            transition: width 0.15s ease;
            width: 0%;
        }

        .file-progress.complete .file-progress-fill {
            background: var(--green);
        }

        .file-progress.complete .file-progress-pct {
            color: var(--green);
        }

        .file-progress.error .file-progress-fill {
            background: var(--red);
        }

        .file-progress.error .file-progress-pct {
            color: var(--red);
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 24px;
            color: var(--text-dim);
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .metrics-bar { grid-template-columns: repeat(2, 1fr); }
            .modules-grid { grid-template-columns: 1fr; }
            .header { padding: 16px 20px; }
            .main { padding: 20px; }
        }
    </style>
</head>
<body>
    <div class="top-bar"></div>

    <header class="header">
        <div class="header-left">
            <div class="header-icon">⚡</div>
            <div>
                <div class="header-title">TAKWERX Console</div>
                <div class="header-subtitle">Infrastructure Platform</div>
            </div>
        </div>
        <div class="header-right">
            <span class="os-badge">{{ settings.get('os_name', 'Unknown OS') }}</span>
            <a href="/logout" class="btn-logout">Sign Out</a>
        </div>
    </header>

    <main class="main">
        <!-- System Metrics -->
        <div class="metrics-bar" id="metrics-bar">
            <div class="metric-card">
                <div class="metric-label">CPU</div>
                <div class="metric-value" id="cpu-value">{{ metrics.cpu_percent }}%</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Memory</div>
                <div class="metric-value" id="ram-value">{{ metrics.ram_percent }}%</div>
                <div class="metric-detail">{{ metrics.ram_used_gb }}GB / {{ metrics.ram_total_gb }}GB</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Disk</div>
                <div class="metric-value" id="disk-value">{{ metrics.disk_percent }}%</div>
                <div class="metric-detail">{{ metrics.disk_used_gb }}GB / {{ metrics.disk_total_gb }}GB</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Uptime</div>
                <div class="metric-value" id="uptime-value" style="font-size: 18px;">{{ metrics.uptime }}</div>
            </div>
        </div>

        <!-- Modules -->
        <div class="section-title">Services</div>
        <div class="modules-grid">
            {% for key, mod in modules.items() %}
            <div class="module-card" onclick="moduleClick('{{ key }}')">
                <div class="module-header">
                    <span class="module-icon">{{ mod.icon }}</span>
                    {% if mod.installed and mod.running %}
                    <span class="module-status status-running">
                        <span class="status-dot"></span> Running
                    </span>
                    {% elif mod.installed %}
                    <span class="module-status status-stopped">
                        <span class="status-dot"></span> Stopped
                    </span>
                    {% else %}
                    <span class="module-status status-not-installed">
                        Not Installed
                    </span>
                    {% endif %}
                </div>
                <div class="module-name">{{ mod.name }}</div>
                <div class="module-desc">{{ mod.description }}</div>
                {% if mod.installed %}
                <span class="module-action">Manage →</span>
                {% else %}
                <span class="module-action">Install →</span>
                {% endif %}
            </div>
            {% endfor %}
        </div>

        <!-- TAK Server Upload (shown when not installed) -->
        {% if not modules.takserver.installed %}
        <div class="section-title">Deploy TAK Server</div>
        <div class="upload-area" id="upload-area"
             ondrop="handleDrop(event)" ondragover="handleDragOver(event)"
             ondragleave="handleDragLeave(event)" onclick="document.getElementById('file-input').click()">
            <div class="upload-icon">📦</div>
            <div class="upload-text">Drop your TAK Server files here</div>
            <div class="upload-hint">
                Required: .deb or .rpm package<br>
                Optional: takserver-public-gpg.key + deb_policy.pol<br>
                <span style="color: var(--text-dim); font-size: 11px;">Select all at once or add files one at a time</span>
            </div>
            <input type="file" id="file-input" style="display:none"
                   multiple accept=".deb,.rpm,.key,.pol" onchange="handleFileSelect(event)">
        </div>

        <!-- Per-file progress bars -->
        <div id="progress-area" style="margin-top: 16px;"></div>

        <!-- Upload results & deploy button -->
        <div id="upload-results" style="margin-top: 16px; display: none;">
            <div style="background: var(--bg-card); border: 1px solid var(--border);
                        border-radius: 12px; padding: 20px;">
                <div id="upload-files-list" style="font-family: 'JetBrains Mono', monospace;
                     font-size: 13px; color: var(--text-secondary);"></div>
                <div id="add-more-area" style="margin-top: 16px; text-align: center;">
                    <button onclick="document.getElementById('file-input-more').click()" style="
                        padding: 8px 20px; background: transparent;
                        color: var(--accent); border: 1px solid var(--border);
                        border-radius: 8px; font-family: 'JetBrains Mono', monospace;
                        font-size: 12px; cursor: pointer; transition: all 0.2s;
                    ">+ Add more files</button>
                    <input type="file" id="file-input-more" style="display:none"
                           multiple accept=".deb,.rpm,.key,.pol" onchange="handleAddMore(event)">
                </div>
                <div id="deploy-btn-area" style="margin-top: 20px; text-align: center; display: none;">
                    <button onclick="showDeployConfig()" style="
                        padding: 12px 32px;
                        background: linear-gradient(135deg, #1e40af, #0e7490);
                        color: #fff; border: none; border-radius: 10px;
                        font-family: 'DM Sans', sans-serif; font-size: 15px;
                        font-weight: 600; cursor: pointer; transition: all 0.2s;
                    ">Configure &amp; Deploy →</button>
                </div>
            </div>
        </div>
        {% endif %}
    </main>

    <footer class="footer">
        TAKWERX Console v{{ version }} &nbsp;·&nbsp; {{ settings.get('os_type', '') }}
        &nbsp;·&nbsp; {{ settings.get('server_ip', '') }}
    </footer>

    <script>
        // Auto-refresh metrics every 5 seconds
        setInterval(async () => {
            try {
                const resp = await fetch('/api/metrics');
                const data = await resp.json();
                document.getElementById('cpu-value').textContent = data.cpu_percent + '%';
                document.getElementById('ram-value').textContent = data.ram_percent + '%';
                document.getElementById('disk-value').textContent = data.disk_percent + '%';
                document.getElementById('uptime-value').textContent = data.uptime;
            } catch(e) {}
        }, 5000);

        // Module click handler
        function moduleClick(key) {
            console.log('Module clicked:', key);
        }

        // Upload state - tracks all uploaded files
        let uploadedFiles = { package: null, gpg_key: null, policy: null };
        let uploadsInProgress = 0;

        function handleDragOver(e) {
            e.preventDefault();
            document.getElementById('upload-area').classList.add('dragover');
        }

        function handleDragLeave(e) {
            document.getElementById('upload-area').classList.remove('dragover');
        }

        function handleDrop(e) {
            e.preventDefault();
            document.getElementById('upload-area').classList.remove('dragover');
            queueFiles(e.dataTransfer.files);
        }

        function handleFileSelect(e) {
            queueFiles(e.target.files);
            e.target.value = '';  // Reset so same file can be re-selected
        }

        function handleAddMore(e) {
            queueFiles(e.target.files);
            e.target.value = '';
        }

        function formatSize(bytes) {
            if (bytes >= 1024 * 1024 * 1024) return (bytes / (1024*1024*1024)).toFixed(1) + ' GB';
            if (bytes >= 1024 * 1024) return (bytes / (1024*1024)).toFixed(1) + ' MB';
            if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return bytes + ' B';
        }

        function queueFiles(fileList) {
            for (let i = 0; i < fileList.length; i++) {
                uploadSingleFile(fileList[i]);
            }
        }

        function uploadSingleFile(file) {
            const progressArea = document.getElementById('progress-area');
            const fileId = 'upload-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5);

            // Create progress bar element
            const progressEl = document.createElement('div');
            progressEl.className = 'file-progress';
            progressEl.id = fileId;
            progressEl.innerHTML = `
                <div class="file-progress-header">
                    <span class="file-progress-name">${file.name}</span>
                    <span class="file-progress-size">${formatSize(file.size)}</span>
                    <span class="file-progress-pct">0%</span>
                </div>
                <div class="file-progress-bar">
                    <div class="file-progress-fill"></div>
                </div>
            `;
            progressArea.appendChild(progressEl);

            // Upload via XHR for progress tracking
            const xhr = new XMLHttpRequest();
            const formData = new FormData();
            formData.append('files', file);

            uploadsInProgress++;

            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const pct = Math.round((e.loaded / e.total) * 100);
                    const el = document.getElementById(fileId);
                    el.querySelector('.file-progress-pct').textContent = pct + '%';
                    el.querySelector('.file-progress-fill').style.width = pct + '%';
                }
            });

            xhr.addEventListener('load', () => {
                uploadsInProgress--;
                const el = document.getElementById(fileId);

                try {
                    const data = JSON.parse(xhr.responseText);

                    if (xhr.status === 200 && data.success) {
                        el.classList.add('complete');
                        el.querySelector('.file-progress-pct').textContent = '✓';
                        el.querySelector('.file-progress-fill').style.width = '100%';

                        // Store results
                        if (data.package) uploadedFiles.package = data.package;
                        if (data.gpg_key) uploadedFiles.gpg_key = data.gpg_key;
                        if (data.policy) uploadedFiles.policy = data.policy;
                    } else {
                        el.classList.add('error');
                        el.querySelector('.file-progress-pct').textContent = '✗';
                        el.querySelector('.file-progress-fill').style.width = '100%';
                        // Show error below the progress bar
                        const errDiv = document.createElement('div');
                        errDiv.style.cssText = 'color: var(--red); font-size: 12px; margin-top: 6px;';
                        errDiv.textContent = data.error || 'Upload failed';
                        el.appendChild(errDiv);
                    }
                } catch(e) {
                    el.classList.add('error');
                    el.querySelector('.file-progress-pct').textContent = '✗';
                }

                updateResultsDisplay();
            });

            xhr.addEventListener('error', () => {
                uploadsInProgress--;
                const el = document.getElementById(fileId);
                el.classList.add('error');
                el.querySelector('.file-progress-pct').textContent = '✗';
                el.querySelector('.file-progress-fill').style.width = '100%';
                updateResultsDisplay();
            });

            xhr.open('POST', '/api/upload/takserver');
            xhr.send(formData);
        }

        function updateResultsDisplay() {
            // Only update when all uploads are done
            if (uploadsInProgress > 0) return;

            const results = document.getElementById('upload-results');
            const filesList = document.getElementById('upload-files-list');
            const deployBtn = document.getElementById('deploy-btn-area');

            if (!uploadedFiles.package) return;

            // Build summary
            let html = '';
            html += '<div style="margin-bottom: 10px;">✅ <span style="color: var(--green);">' +
                    uploadedFiles.package.filename + '</span> <span style="color: var(--text-dim);">(' +
                    uploadedFiles.package.size_mb + ' MB)</span></div>';

            if (uploadedFiles.gpg_key) {
                html += '<div style="margin-bottom: 10px;">✅ <span style="color: var(--green);">' +
                        uploadedFiles.gpg_key.filename + '</span> <span style="color: var(--text-dim);">(GPG key)</span></div>';
            }

            if (uploadedFiles.policy) {
                html += '<div style="margin-bottom: 10px;">✅ <span style="color: var(--green);">' +
                        uploadedFiles.policy.filename + '</span> <span style="color: var(--text-dim);">(Policy)</span></div>';
            }

            if (uploadedFiles.gpg_key && uploadedFiles.policy) {
                html += '<div style="margin-top: 12px; color: var(--green);">🔐 Package signature verification enabled</div>';
            } else if (!uploadedFiles.gpg_key && !uploadedFiles.policy) {
                html += '<div style="margin-top: 12px; color: var(--text-dim);">ℹ️ No GPG key/policy — signature verification will be skipped</div>';
            } else {
                html += '<div style="margin-top: 12px; color: var(--yellow);">⚠️ Need both GPG key + policy for verification — add the missing file or proceed without</div>';
            }

            filesList.innerHTML = html;
            results.style.display = 'block';
            deployBtn.style.display = 'block';

            // Shrink the upload area but keep it available
            const uploadArea = document.getElementById('upload-area');
            uploadArea.style.padding = '20px';
            uploadArea.querySelector('.upload-icon').style.fontSize = '24px';
            uploadArea.querySelector('.upload-text').textContent = 'Drop more files to add';
            uploadArea.querySelector('.upload-hint').style.display = 'none';
        }

        function showDeployConfig() {
            // TODO: Show the deploy configuration form
            alert('Deploy configuration coming next!');
        }
    </script>
</body>
</html>
'''

# =============================================================================
# Main Entry Point
# =============================================================================

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
            print("WARNING: SSL certificates not found, running without HTTPS")
            app.run(host='0.0.0.0', port=port, debug=False)
    else:
        # FQDN mode - Caddy handles SSL, Flask runs plain HTTP
        app.run(host='127.0.0.1', port=port, debug=False)
