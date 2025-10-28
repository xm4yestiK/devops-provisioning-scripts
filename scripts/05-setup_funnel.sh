#!/bin/bash

# Exit immediately if a command fails
set -e

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then 
  echo "This script must be run as root. Try: sudo ./03-setup_funnel.sh"
  exit 1
fi

echo "--- [1/2] Installing Tailscale ---"
curl -fsSL https://tailscale.com/install.sh | sh

echo "--- [2/2] Making Jenkins Publicly Accessible (Tailscale Funnel Service) ---"
# Create systemd service file for the permanent funnel
cat << EOF > /etc/systemd/system/tailscale-funnel.service
[Unit]
Description=Tailscale Funnel (Port 8080 for Jenkins)
After=network.target tailscaled.service
Wants=tailscaled.service
[Service]
Type=simple
ExecStart=/usr/bin/tailscale funnel 8080
User=root
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

# Enable and start the funnel service
systemctl daemon-reload
systemctl enable --now tailscale-funnel.service

echo ""
echo "--- FUNNEL SETUP COMPLETE! ---"
echo ""
echo "REQUIRED NEXT STEPS (MANUAL):"
echo "1. This server needs to authenticate with Tailscale."
echo "   Run this command NOW:"
echo ""
echo "   sudo tailscale up"
echo ""
echo "2. Follow the link to log in, then check your public URL with 'tailscale status'."