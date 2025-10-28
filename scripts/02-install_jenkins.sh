#!/bin/bash

# Exit immediately if a command fails
set -e

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then 
  echo "This script must be run as root. Try: sudo ./02-install_jenkins.sh"
  exit 1
fi

echo "--- [1/3] Installing Dependencies (Java 17) ---"
apt-get update
apt-get install -y openjdk-17-jre

echo "--- [2/3] Installing Jenkins (from Official Repository) ---"
# Add Jenkins GPG Key
curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key | tee /usr/share/keyrings/jenkins-keyring.asc > /dev/null

# Add Jenkins Repository
echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \
  https://pkg.jenkins.io/debian-stable binary/ | tee /etc/apt/sources.list.d/jenkins.list > /dev/null

# Install & Enable Jenkins
apt-get update
apt-get install -y jenkins
systemctl enable --now jenkins

echo "--- [3/3] Jenkins Installation Complete ---"
echo "Jenkins is running at http://localhost:8080"
echo "------------------------------------------------------------------"
echo "Your Jenkins Admin Password is:"
cat /var/lib/jenkins/secrets/initialAdminPassword
echo "------------------------------------------------------------------"