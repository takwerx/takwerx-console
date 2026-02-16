# TAKWERX Console

Emergency Services Infrastructure Management Platform.

One clone. One password. One URL. Manage everything from your browser.

> **⚠️ Private Alpha** — This project is in early development and shared with select testers only.

## What It Does

TAKWERX Console is a web-based management platform that deploys and manages TAK Server infrastructure without SSH or command line access. Upload your TAK Server package from tak.gov, set a password, click deploy — done in ~15 minutes.

### Current Features (v0.1.0-alpha)

- **TAK Server Deployment** — Upload .deb package, configure, and deploy through the browser
- **Live Deployment Log** — Watch every step with countdown timers
- **Service Monitoring** — Real-time status of all TAK Server Java processes (Messaging, API, Config, Plugin Manager, Retention, PostgreSQL)
- **Live Server Log** — Streaming `takserver-messaging.log` with color-coded output
- **Certificate Management** — Dedicated `/certs` page to browse and download all cert files
- **Server Controls** — Start, stop, restart, and remove TAK Server from the UI
- **Upload Management** — Duplicate detection, cancel uploads, remove files

### Planned Modules

- MediaMTX (ISR video streaming)
- CloudTAK
- Node-RED
- Caddy reverse proxy management
- Guard Dog monitoring

## Requirements

- Ubuntu 22.04 LTS (Rocky Linux 9 planned)
- Root access
- TAK Server `.deb` package from [tak.gov](https://tak.gov)

## Quick Start

```bash
git clone https://github.com/takwerx/takwerx-console.git
cd takwerx-console
chmod +x start.sh
./start.sh
```

On first run you'll set an admin password. Access the console at:

```
https://<your-server-ip>:5001
```

## Updating

```bash
cd ~/takwerx-console
git pull
systemctl restart takwerx-console
```

## Known Issues

- GPG package verification returns exit code 14 on Ubuntu 22.04 (non-blocking, installs anyway)
- `systemctl status takserver` shows `active (exited)` — this is normal on Ubuntu, use the Services panel for true status

## Feedback

This is a private alpha. Please report bugs and feature requests directly.
