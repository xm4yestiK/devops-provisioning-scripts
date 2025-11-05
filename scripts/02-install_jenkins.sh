#!/bin/bash

set -e

if ! command -v docker &> /dev/null
then
    echo "Docker not found. Installing docker.io..."
    apt-get update
    apt-get install -y docker.io
    systemctl enable --now docker
else
    echo "Docker is already installed."
fi

echo "--- [1/3] Creating Docker Volume for Jenkins Data ---"
if ! docker volume ls | grep -q jenkins_data; then
    echo "Creating volume 'jenkins_data'..."
    docker volume create jenkins_data
else
    echo "Volume 'jenkins_data' already exists."
fi

echo "--- [2/3] Starting Jenkins (Docker Container) ---"
if docker ps -a | grep -q 'jenkins-lts'; then
    echo "Stopping and removing existing 'jenkins-lts' container..."
    docker stop jenkins-lts
    docker rm jenkins-lts
fi

echo "Pulling latest LTS image and running container..."
docker run -d \
  --name jenkins-lts \
  --restart=unless-stopped \
  -p 8080:8080 \
  -p 50000:50000 \
  -v jenkins_data:/var/jenkins_home \
  jenkins/jenkins:lts

echo "--- [3/3] Jenkins Installation Complete ---"
echo "Jenkins is starting up. Ini mungkin butuh beberapa saat..."

echo "Waiting for password file..."
until docker exec jenkins-lts test -f /var/jenkins_home/secrets/initialAdminPassword 2>/dev/null; do
    echo -n "."
    sleep 2
done

echo "\nJenkins is running at http://localhost:8080"
echo "------------------------------------------------------------------"
echo "Your Jenkins Admin Password is:"
docker exec jenkins-lts cat /var/jenkins_home/secrets/initialAdminPassword
echo "------------------------------------------------------------------"
