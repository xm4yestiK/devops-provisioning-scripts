#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
	echo "This script must be run as root. Try: sudo ./setup_complete.sh"
	exit 1
fi

echo "--- [1/7] Starting Server Setup (Update Repositories) ---"
apt-get update

echo "--- [2/7] Installing Tailscale and OpenSSH Server ---"
apt-get install -y openssh-server

echo "--- [3/7] Installing and Updating Neovim (Latest Stable) ---"
apt-get install -y software-properties-common
add-apt-repository ppa:neovim-ppa/stable -y
apt-get update
apt-get install -y neovim

echo "--- [4/7] Applying System Tweaks (Disable Sleep on Lid Close) ---"
sed -i -e 's/^#HandleLidSwitch=.*/HandleLidSwitch=ignore/' -e 's/^HandleLidSwitch=.*/HandleLidSwitch=ignore/' /etc/systemd/logind.conf
systemctl restart systemd-logind.service

echo "--- [5/7] Installing Core Tools & Dimming Screen ---"
apt-get install -y curl nano brightnessctl

if command -v brightnessctl &> /dev/null; then
	brightnessctl set 5%
fi

echo "--- [6/7] Starting SSH Service ---"
systemctl enable --now ssh

echo "--- [7/7] Installing and Connecting Tailscale ---"
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up

echo " "
echo "✅ Server Setup Complete."
echo "Please visit the URL displayed above in your browser to authorize this device on your Tailnet."
