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
apt-get install -y curl nano brightnessctl

if command -v brightnessctl &> /dev/null; then
	brightnessctl set 5%
fi

echo "--- [5/6] Starting SSH Service ---"
systemctl enable --now ssh

echo "--- [6/6] Installing and Connecting Tailscale ---"
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up

echo " "
echo "✅ Server Setup Complete."
echo "Please visit the URL displayed above in your browser to authorize this device on your Tailnet."
