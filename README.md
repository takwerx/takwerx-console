# TAKWERX Console

Emergency Services Infrastructure Management Platform.

One clone. One password. One URL. Manage everything from your browser.

## What Is This?

A unified web console for deploying and managing TAK ecosystem infrastructure:

- **TAK Server** — Upload your .deb/.rpm, configure, deploy, manage CoreConfig — all from the browser
- **Authentik** — Identity provider with automated LDAP configuration for TAK Server auth
- **TAK Portal** — User and certificate management portal with auto-configured Authentik + TAK Server integration
- **MediaMTX** — Drone video streaming server with full web configuration editor
- **Guard Dog** — Health monitoring, auto-recovery, email/SMS alerts
- **Caddy SSL** — Let's Encrypt certificates and reverse proxy management

No more SSH. No more editing XML by hand. No more running scripts and hoping.

## Quick Start

```bash
git clone https://github.com/takwerx/takwerx-console.git
cd takwerx-console
chmod +x start.sh
sudo ./start.sh
```

The script will:
1. Detect your OS (Ubuntu 22.04, Rocky 9)
2. Install Python dependencies
3. Ask you to set an admin password
4. Ask if you're using a domain name or IP address
5. Start the web console

Then open your browser to the URL shown and log in.

## Deployment Order

Deploy services in this order — each step auto-configures the next:

```
1. TAK Server        Upload .deb, deploy, configure ports + certs
         ↓
2. Authentik         Identity provider + LDAP outpost (10-step automated deploy)
                     Auto-patches CoreConfig.xml with LDAP auth block
         ↓
3. TAK Portal        User/cert management portal
                     Auto-configures Authentik URL, API token, TAK Server certs
```

**TAK Server must be deployed first.** Authentik auto-configures LDAP auth in CoreConfig.xml and restarts TAK Server. TAK Portal auto-detects the Authentik bootstrap token and TAK Server certificates — zero manual configuration required.

## What Gets Automated

**Authentik Deploy (10 steps, ~7 minutes):**
Bootstrap credentials generated, LDAP blueprint installed, Docker Compose patched with standalone LDAP container, API polled for outpost token, CoreConfig.xml patched with LDAP auth block, TAK Server restarted.

**TAK Portal Deploy (6 steps, ~2 minutes):**
Repository cloned, container built, TAK Server certs (admin.p12, tak-ca.pem) copied into container, settings.json auto-configured with Authentik URL/token and TAK Server connection.

After deployment, create users in TAK Portal — they flow through Authentik → LDAP → TAK Server automatically.

## Requirements

- Ubuntu 22.04 LTS or Rocky Linux 9 (fresh installation recommended)
- Root access
- 8GB+ RAM recommended for TAK Server
- Internet connection for initial setup

## Architecture

```
start.sh                    ← One CLI command to launch everything
├── app.py                  ← Flask web application (HTTPS on :5001)
├── modules/
│   ├── takserver/          ← TAK Server deploy, configure, manage
│   ├── mediamtx/           ← MediaMTX streaming + web config editor
│   ├── guarddog/           ← Health monitoring setup
│   └── caddy/              ← SSL certificate management
├── docs/
│   └── AUTHENTIK_LDAP_SETUP.md  ← Detailed Authentik/LDAP reference
├── uploads/                ← Uploaded .deb/.rpm packages
└── .config/                ← Auth + settings (gitignored)
```

## Ports

| Service | Port | Description |
|---------|------|-------------|
| TAKWERX Console | 5001 | Management web UI |
| TAK Server | 8089 | TCP connections |
| TAK Server | 8443 | WebGUI (cert auth) |
| TAK Server | 8446 | WebGUI (password auth) |
| Authentik | 9090 | Admin UI |
| LDAP | 389 | LDAP auth for TAK Server |
| TAK Portal | 3000 | User management portal |

## Access Modes

**IP Address Mode** — Self-signed certificate, works anywhere (field deployments, no DNS needed)

**FQDN Mode** — Caddy + Let's Encrypt for proper SSL. Can upgrade from IP mode through the web console without SSH.

## Security

- Password required before any access (set during `./start.sh`)
- HTTPS from the start (self-signed or Let's Encrypt)
- Session-based authentication
- All config files are 600 permissions
- Authentik bootstrap credentials auto-generated per deployment

## License

MIT

## Credits

Built by [TAKWERX](https://github.com/takwerx) for emergency services.
