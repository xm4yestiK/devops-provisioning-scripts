#!/bin/bash

# Exit immediately if a command fails
set -e

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root. Try: sudo ./01-setup_server.sh"
  exit 1
fi

echo "--- [1/3] Starting Server Setup (Update Repositories) ---"
apt-get update

echo "--- [2/3] Applying System Tweaks (Disable Sleep on Lid Close) ---"
sed -i -e 's/^#HandleLidSwitch=.*/HandleLidSwitch=ignore/' -e 's/^HandleLidSwitch=.*/HandleLidSwitch=ignore/' /etc/systemd/logind.conf
systemctl restart systemd-logind.service

echo "--- [3/3] Installing Core Tools & Dimming Screen ---"
apt-get install -y curl nano brightnessctl

# Dim the physical server screen to 1%
if command -v brightnessctl &> /dev/null; then
    brightnessctl set 1%
fi

echo "--- Base Server Setup Complete ---"