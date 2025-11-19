#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root. Try: sudo ./setup_complete.sh"
    exit 1
fi

echo "--- [1/6] Starting Server Setup (Update Repositories) ---"
apt-get update

echo "--- [2/6] Installing Tailscale and OpenSSH Server ---"
apt-get install -y openssh-server

echo "--- [3/6] Applying System Tweaks (Disable Sleep on Lid Close) ---"
sed -i -e 's/^#HandleLidSwitch=.*/HandleLidSwitch=ignore/' -e 's/^HandleLidSwitch=.*/HandleLidSwitch=ignore/' /etc/systemd/logind.conf
systemctl restart systemd-logind.service

echo "--- [4/6] Installing Core Tools & Dimming Screen ---"
# Added ddcutil and i2c-tools packages
apt-get install -y curl nano brightnessctl ddcutil i2c-tools

# Load i2c-dev module required for ddcutil communication
modprobe i2c-dev
# Ensure i2c-dev loads on boot
if ! grep -q "^i2c-dev" /etc/modules; then
    echo "i2c-dev" >> /etc/modules
fi

# Existing logic for laptop backlight
if command -v brightnessctl &> /dev/null; then
    brightnessctl set 5%
fi

# Added logic for external monitor brightness (DDC/CI)
if command -v ddcutil &> /dev/null; then
    # Wait for i2c bus to settle
    sleep 2
    # Set brightness (VCP code 10) to 10. Using --noverify for speed.
    # || true ensures script continues even if monitor doesn't support DDC
    ddcutil setvcp 10 10 --noverify || echo "Warning: External monitor brightness control failed or unsupported."
fi
