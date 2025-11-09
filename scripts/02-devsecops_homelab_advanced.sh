#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
	echo "This script must be run as root. Try: sudo ./02-devsecops_homelab_advanced.sh"
	exit 1
fi

echo "--- [1/10] Installing Docker Engine ---"
if ! command -v docker &> /dev/null
then
	echo "Docker not found. Installing docker.io..."
	apt-get update
	apt-get install -y docker.io
	systemctl enable --now docker
else
	echo "Docker is already installed."
fi

echo "--- [2/10] Installing Minimal Kubernetes (K3s) ---"
curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE="644" sh -

echo "--- [3/10] Deploying Jenkins (LTS Container) ---"
echo "Creating Docker Volume for Jenkins Data..."
if ! docker volume ls | grep -q jenkins_data; then
	docker volume create jenkins_data
fi

if docker ps -a | grep -q 'jenkins-lts'; then
	echo "Stopping and removing existing 'jenkins-lts' container..."
	docker stop jenkins-lts
	docker rm jenkins-lts
fi

echo "Pulling latest LTS image and running container (Ports 8080/50000)..."
docker run -d \
	--name jenkins-lts \
	--restart=unless-stopped \
	-p 8080:8080 \
	-p 50000:50000 \
	-v jenkins_data:/var/jenkins_home \
	-v /var/run/docker.sock:/var/run/docker.sock \
	jenkins/jenkins:lts

echo "--- [4/10] Installing Trivy (Vulnerability Scanner) and Terraform (IaC) ---"
# Install Trivy (SAST/Vulnerability)
sudo apt-get install -y wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy

# Install Terraform (IaC Tool)
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update
sudo apt install -y terraform

echo "--- [5/10] Deploying HashiCorp Vault (Secret Management) ---"
echo "Creating Vault Docker Volume..."
if ! docker volume ls | grep -q vault_data; then
    docker volume create vault_data
fi

echo "Starting Vault in Development Mode..."
if docker ps -a | grep -q 'vault-dev'; then
	docker stop vault-dev; docker rm vault-dev
fi
docker run -d \
    --name vault-dev \
    --restart=unless-stopped \
    -p 8200:8200 \
    -e 'VAULT_DEV_ROOT_TOKEN_ID=devsecops-token' \
    -v vault_data:/vault/file \
    hashicorp/vault:latest

echo "--- [6/10] Deploying OWASP ZAP (DAST/Dynamic Analysis) ---"
echo "Starting ZAP Container (API on port 8090)..."
if docker ps -a | grep -q 'owasp-zap'; then
    docker stop owasp-zap; docker rm owasp-zap
fi
docker run -d \
    --name owasp-zap \
    --restart=unless-stopped \
    -p 8090:8090 \
    owasp/zap2docker-stable zap-webswing.sh

echo "--- [7/10] Deploying SonarQube (SAST Lanjutan) ---"
echo "Starting SonarQube container (Requires significant RAM/CPU)..."
if docker ps -a | grep -q 'sonarqube'; then
	docker stop sonarqube; docker rm sonarqube
fi
docker run -d \
    --name sonarqube \
    --restart=unless-stopped \
    -p 9000:9000 \
    sonarqube:lts-community

echo "--- [8/10] Deploying Prometheus and Grafana (Observability) ---"
# Prometheus and Grafana are run in a combined container setup for simplicity
echo "Starting Prometheus (9090) and Grafana (3000) containers..."
if docker ps -a | grep -q 'prometheus'; then docker stop prometheus; docker rm prometheus; fi
if docker ps -a | grep -q 'grafana'; then docker stop grafana; docker rm grafana; fi
docker run -d --name prometheus -p 9090:9090 prom/prometheus
docker run -d --name grafana -p 3000:3000 grafana/grafana-oss

echo "--- [9/10] Installing Falco (Runtime Security) Dependencies ---"
# Falco requires kernel headers and specific setup. Installing packages.
apt-get install -y dkms linux-headers-$(uname -r)

echo "--- [10/10] Deploying Falco (Runtime Security) ---"
# Running Falco as a Docker container, mounting host kernel modules and resources
echo "Starting Falco container..."
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
echo "--- ✅ Advanced DevSecOps Homelab Setup Complete ---"
echo " "
echo "=================================================================="
echo "                   HOMELAB ACCESS POINTS                          "
echo "=================================================================="
echo "1. CI/CD (Jenkins):      http://<Tailscale IP>:8080"
echo "2. SAST Lanjutan (Sonar): http://<Tailscale IP>:9000 (admin/admin)"
echo "3. Observability (Grafana): http://<Tailscale IP>:3000 (admin/admin)"
echo "4. Secret Mgmt (Vault):  http://<Tailscale IP>:8200 (Token: devsecops-token)"
echo "5. DAST (ZAP API):       http://<Tailscale IP>:8090"
echo "6. IaC Tool:             'terraform' command is ready on the host."
echo "7. Runtime Sec (Falco):  Run 'docker logs falco' to see runtime security alerts."
echo "8. Jenkins Admin Password:"
until docker exec jenkins-lts test -f /var/jenkins_home/secrets/initialAdminPassword 2>/dev/null; do
	echo -n "."
	sleep 2
done
docker exec jenkins-lts cat /var/jenkins_home/secrets/initialAdminPassword
echo "------------------------------------------------------------------"
echo "⚠️ PERINGATAN RAM 8GB: SonarQube, Prometheus, dan Grafana membutuhkan banyak RAM."
echo "   Disarankan untuk menghentikan SonarQube saat tidak digunakan: 'docker stop sonarqube'."
