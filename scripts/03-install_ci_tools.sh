#!/bin/bash

# Exit immediately if a command fails
set -e

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root. Try: sudo ./05-install_ci_tools.sh"
  exit 1
fi

echo "--- [1/3] Starting Repository Update ---"
apt-get update

echo "--- [2/3] Installing Git & Docker ---"
# docker.io is the Docker package from Ubuntu's repository
apt-get install -y git docker.io

echo "--- [3/3] Configuring Docker Permissions for Jenkins ---"
# REQUIRED: Allow the 'jenkins' user to run Docker commands
if id "jenkins" &>/dev/null; then
    echo "Adding user 'jenkins' to 'docker' group..."
    usermod -aG docker jenkins
    
    echo "Restarting Jenkins to apply new group permissions..."
    # Use 'try-restart' so it doesn't fail if Jenkins isn't installed yet
    systemctl try-restart jenkins
else
    echo "WARNING: User 'jenkins' not found."
    echo "Ensure Jenkins is installed BEFORE running this script."
fi

echo ""
echo "--- Git & Docker Installation Complete ---"