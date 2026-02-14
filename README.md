# TAKWERX Console

Emergency Services Infrastructure Management Platform.

One clone. One password. One URL. Manage everything from your browser.

## What Is This?

A unified web console for deploying and managing TAK ecosystem infrastructure:

- **TAK Server** — Upload your .deb/.rpm, configure, deploy, manage CoreConfig — all from the browser
- **MediaMTX** — Drone video streaming server with full web configuration editor
- **Guard Dog** — Health monitoring, auto-recovery, email/SMS alerts
- **Caddy SSL** — Let's Encrypt certificates and reverse proxy management

No more SSH. No more editing XML by hand. No more running scripts and hoping.

## Quick Start

```bash
git clone https://github.com/takwerx/takwerx-console.git
cd takwerx-console
sudo ./start.sh
```

The script will:
1. Detect your OS (Ubuntu 22.04, Rocky 9)
2. Install Python dependencies
3. Ask you to set an admin password
4. Ask if you're using a domain name or IP address
5. Start the web console

Then open your browser to the URL shown and log in.

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
├── templates/              ← HTML templates
├── static/                 ← CSS, JS, images
├── uploads/                ← Uploaded .deb/.rpm packages
└── .config/                ← Auth + settings (gitignored)
```

## Access Modes

**IP Address Mode** — Self-signed certificate, works anywhere (field deployments, no DNS needed)

**FQDN Mode** — Caddy + Let's Encrypt for proper SSL. Can upgrade from IP mode through the web console without SSH.

## Security

- Password required before any access (set during `./start.sh`)
- HTTPS from the start (self-signed or Let's Encrypt)
- Session-based authentication
- All config files are 600 permissions

## License

MIT

## Credits

Built by [TAKWERX](https://github.com/takwerx) for emergency services.
