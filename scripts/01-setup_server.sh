#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
	echo "This script must be run as root. Try: sudo ./setup_complete.sh"
	exit 1
fi

echo "--- [1/8] Starting Server Setup (Update Repositories) ---"
apt-get update

echo "--- [2/8] Installing Tailscale and OpenSSH Server ---"
apt-get install -y openssh-server

echo "--- [3/8] Installing Neovim and Development Runtimes (Go, Node, Java) ---"
apt-get install -y build-essential
apt-get install -y software-properties-common
add-apt-repository ppa:neovim-ppa/stable -y
apt-get update
apt-get install -y neovim
apt-get install -y golang nodejs npm default-jdk

echo "--- [4/8] Applying System Tweaks (Disable Sleep on Lid Close) ---"
sed -i -e 's/^#HandleLidSwitch=.*/HandleLidSwitch=ignore/' -e 's/^HandleLidSwitch=.*/HandleLidSwitch=ignore/' /etc/systemd/logind.conf
systemctl restart systemd-logind.service

echo "--- [5/8] Installing Core Tools & Dimming Screen ---"
apt-get install -y curl nano brightnessctl

if command -v brightnessctl &> /dev/null; then
	brightnessctl set 5%
fi

echo "--- [6/8] Starting SSH Service ---"
systemctl enable --now ssh

echo "--- [7/8] Setting Up JAVA_HOME for Groovy LS ---"
echo "export JAVA_HOME='/usr/lib/jvm/default-java'" | tee -a /etc/environment
source /etc/environment

echo "--- [8/8] Installing and Connecting Tailscale ---"
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up

echo " "
echo "✅ Server Setup Complete."
echo "Neovim LSPs should now install successfully via Mason."
echo "Please visit the URL displayed above in your browser to authorize this device on your Tailnet."
