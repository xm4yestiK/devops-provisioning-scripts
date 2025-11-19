#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo ./cleanup_devsecops.sh"
    exit 1
fi

echo "--- [1/5] Terminating and Removing Docker Containers ---"
CONTAINERS=("jenkins-lts" "vault-dev" "owasp-zap" "sonarqube" "prometheus" "grafana" "falco")

for container in "${CONTAINERS[@]}"; do
    if docker ps -a | grep -q "$container"; then
        echo "Stopping and removing: $container"
        docker stop "$container" >/dev/null 2>&1
        docker rm "$container" >/dev/null 2>&1
    else
        echo "$container not found."
    fi
done

echo "--- [2/5] Removing Persistent Volumes (Data Wipe) ---"
VOLUMES=("jenkins_data" "vault_data" "sonarqube_data")

for volume in "${VOLUMES[@]}"; do
    if docker volume ls | grep -q "$volume"; then
        echo "Removing volume: $volume"
        docker volume rm "$volume"
    fi
done

echo "--- [3/5] Removing Custom Docker Image ---"
if docker images | grep -q "my-jenkins-dood"; then
    docker rmi my-jenkins-dood:lts
    echo "Image my-jenkins-dood:lts removed."
fi

echo "--- [4/5] Uninstalling Kubernetes (K3s) ---"
if [ -f /usr/local/bin/k3s-uninstall.sh ]; then
    echo "Running K3s uninstaller..."
    /usr/local/bin/k3s-uninstall.sh >/dev/null 2>&1
    echo "K3s successfully removed."
else
    echo "K3s not detected or already removed."
fi

echo "--- [5/5] Removing Binary Packages (Trivy & Terraform) ---"
apt-get remove -y trivy terraform

rm -f /etc/apt/sources.list.d/trivy.list
rm -f /etc/apt/sources.list.d/hashicorp.list
rm -f /usr/share/keyrings/hashicorp-archive-keyring.gpg

apt-get update >/dev/null 2>&1

echo " "
echo "--- Cleanup Complete. Environment ready for re-installation. ---"
