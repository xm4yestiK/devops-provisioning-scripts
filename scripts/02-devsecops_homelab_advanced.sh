#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
	echo "This script must be run as root. Try: sudo ./02-devsecops_homelab_advanced_final_v2.sh"
	exit 1
fi

echo "--- [1/10] Installing Docker Engine ---"
if ! command -v docker &> /dev/null
then
	apt-get update
	apt-get install -y docker.io
	systemctl enable --now docker
else
	echo "Docker is already installed."
fi

echo "--- [2/10] Installing Minimal Kubernetes (K3s) ---"
curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE="644" sh -

echo "--- [3/10] Deploying Jenkins (LTS Container) ---"
if ! docker volume ls | grep -q jenkins_data; then
	docker volume create jenkins_data
fi

if docker ps -a | grep -q 'jenkins-lts'; then
	docker stop jenkins-lts
	docker rm jenkins-lts
fi

docker run -d \
	--name jenkins-lts \
	--restart=unless-stopped \
	-p 8080:8080 \
	-p 50000:50000 \
	-v jenkins_data:/var/jenkins_home \
	-v /var/run/docker.sock:/var/run/docker.sock \
	jenkins/jenkins:lts

echo "--- [4/10] Installing Trivy and Terraform ---"
sudo apt-get install -y wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update
sudo apt install -y terraform

echo "--- [5/10] Deploying HashiCorp Vault ---"
if ! docker volume ls | grep -q vault_data; then
    docker volume create vault_data
fi

if docker ps -a | grep -q 'vault-dev'; then
	docker stop vault-dev
    docker rm vault-dev
fi
docker run -d \
    --name vault-dev \
    --restart=unless-stopped \
    -p 8200:8200 \
    -e 'VAULT_DEV_ROOT_TOKEN_ID=devsecops-token' \
    -v vault_data:/vault/file \
    hashicorp/vault:latest

echo "--- [6/10] Deploying OWASP ZAP (GitHub Registry) ---"
if docker ps -a | grep -q 'owasp-zap'; then
    docker stop owasp-zap
    docker rm owasp-zap
fi
docker run -d \
    --name owasp-zap \
    --restart=unless-stopped \
    -p 8090:8090 \
    ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -port 8090 -config api.disablekey=true -host 0.0.0.0

echo "--- [7/10] Deploying SonarQube ---"
if ! docker volume ls | grep -q sonarqube_data; then
    docker volume create sonarqube_data
fi
if docker ps -a | grep -q 'sonarqube'; then
	docker stop sonarqube
    docker rm sonarqube
fi
docker run -d \
    --name sonarqube \
    --restart=unless-stopped \
    -p 9000:9000 \
    -v sonarqube_data:/opt/sonarqube/data \
    sonarqube:lts-community

echo "--- [8/10] Deploying Prometheus and Grafana ---"
if docker ps -a | grep -q 'prometheus'; then docker stop prometheus; docker rm prometheus; fi
if docker ps -a | grep -q 'grafana'; then docker stop grafana; docker rm grafana; fi
docker run -d --name prometheus -p 9090:9090 prom/prometheus
docker run -d --name grafana -p 3000:3000 grafana/grafana-oss

echo "--- [9/10] Installing Falco Dependencies ---"
apt-get install -y dkms linux-headers-$(uname -r)

echo "--- [10/10] Deploying Falco ---"
if docker ps -a | grep -q 'falco'; then docker stop falco; docker rm falco; fi
docker run -d \
    --name falco \
    --privileged \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /dev:/dev \
    -v /proc:/host/proc:ro \
    -v /boot:/host/boot:ro \
    -v /lib/modules:/lib/modules:ro \
    -v /usr:/host/usr:ro \
    -v /etc:/host/etc:ro \
    falcosecurity/falco:latest

echo " "
echo "--- DevSecOps Homelab Setup Complete ---"
echo "1. Jenkins Admin Password:"
until docker exec jenkins-lts test -f /var/jenkins_home/secrets/initialAdminPassword 2>/dev/null; do
	echo -n "."
	sleep 2
done
docker exec jenkins-lts cat /var/jenkins_home/secrets/initialAdminPassword
echo "------------------------------------------------------------------"
