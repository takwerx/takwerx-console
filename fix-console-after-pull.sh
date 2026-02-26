#!/bin/bash
# Run this on the server over SSH when you can't log in after git pull.
# It pins the console config path in the systemd unit and then resets your password.
# Usage: sudo ./fix-console-after-pull.sh
# (Run from the infra-TAK directory you use for git pull, e.g. /root/infra-TAK)
set -e
SERVICE_FILE="/etc/systemd/system/takwerx-console.service"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$SERVICE_FILE" ]; then
    echo "Console service not found. Run start.sh first."
    exit 1
fi

# Ensure CONFIG_DIR is set in the unit so auth is always read from this install dir
if ! grep -q 'Environment=CONFIG_DIR=' "$SERVICE_FILE" 2>/dev/null; then
    echo "Pinning CONFIG_DIR in systemd unit to $INSTALL_DIR/.config"
    sed -i "/^\[Service\]/a Environment=CONFIG_DIR=$INSTALL_DIR/.config" "$SERVICE_FILE"
    systemctl daemon-reload
fi

echo ""
echo "Console config is pinned to: $INSTALL_DIR/.config"
echo "Resetting console password next (use this to log in at https://<server-ip>:5001)."
echo ""
exec bash "$INSTALL_DIR/reset-console-password.sh"
