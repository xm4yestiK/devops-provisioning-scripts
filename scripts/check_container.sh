#!/bin/bash

set -e

CONTAINERS=("jenkins-lts 8080 Jenkins LTS" "sonarqube 9000 SonarQube" "vault-dev 8200 HashiCorp Vault" "owasp-zap 8090 OWASP ZAP" "prometheus 9090 Prometheus" "grafana 3000 Grafana" "falco N/A Falco_Runtime_Sec")
SERVICES=("ssh")

activate_service() {
    TYPE=$1
    NAME=$2
    if [ "$TYPE" == "systemd" ]; then
        sudo systemctl enable --now $NAME &> /dev/null
        if systemctl is-active --quiet $NAME; then
            echo "✅ Successfully Activated $NAME."
        else
            echo "⚠️ Activation Failed for $NAME. Check logs: 'sudo systemctl status $NAME'."
        fi
    elif [ "$TYPE" == "docker" ]; then
        if docker ps -a --format '{{.Names}}' | grep -q "^$NAME$"; then
            docker start $NAME &> /dev/null
            if docker ps --format '{{.Names}}' | grep -q "^$NAME$"; then
                echo "✅ Successfully Started $NAME."
            else
                echo "⚠️ Start Failed for $NAME. Check logs: 'docker logs $NAME'."
            fi
        else
            echo "⚠️ Container $NAME not found. Run installation script first."
        fi
    fi
}

get_status() {
    TYPE=$1
    NAME=$2
    TOOL_NAME=$3

    if [ "$TYPE" == "systemd" ]; then
        if systemctl is-active --quiet $NAME; then
            echo "✅ $TOOL_NAME: Active"
        else
            echo "❌ $TOOL_NAME: Inactive"
        fi
    elif [ "$TYPE" == "docker" ]; then
        if docker ps --format '{{.Names}}' | grep -q "^$NAME$"; then
            echo "✅ $TOOL_NAME: Running"
        else
            if docker ps -a --format '{{.Names}}' | grep -q "^$NAME$"; then
                echo "🟡 $TOOL_NAME: Stopped"
            else
                echo "❓ $TOOL_NAME: Not Created"
            fi
        fi
    fi
}

check_and_activate_service() {
    TYPE=$1
    NAME=$2
    TOOL_NAME=$3

    if [ "$TYPE" == "systemd" ]; then
        echo -n "Checking $TOOL_NAME status: "
        if systemctl is-active --quiet $NAME && systemctl is-enabled --quiet $NAME; then
            echo "✅ Active and Enabled."
        else
            echo "❌ Inactive/Disabled. Activating..."
            activate_service systemd $NAME
        fi
    elif [ "$TYPE" == "docker" ]; then
        echo -n "Checking $TOOL_NAME status: "
        if docker ps --format '{{.Names}}' | grep -q "^$NAME$"; then
            echo "✅ Running."
        else
            echo "❌ Stopped. Activating..."
            activate_service docker $NAME
        fi
    fi
}

check_all() {
    echo "--- ⚙️ Checking System Services ---"
    for SVC in "${SERVICES[@]}"; do
        check_and_activate_service systemd $SVC $SVC
    done

    echo ""
    echo "--- 🐳 Checking Docker Containers ---"
    for ITEM in "${CONTAINERS[@]}"; do
        read -r CONTAINER PORT TOOL_NAME <<< "$ITEM"
        check_and_activate_service docker $CONTAINER $TOOL_NAME
    done
    echo ""
    echo "--- Activation Attempt Complete ---"
}

show_status() {
    echo ""
    echo "--- ⚙️ Current System Status ---"
    for SVC in "${SERVICES[@]}"; do
        get_status systemd $SVC $SVC
    done

    echo ""
    echo "--- 🐳 Current Container Status ---"
    for ITEM in "${CONTAINERS[@]}"; do
        read -r CONTAINER PORT TOOL_NAME <<< "$ITEM"
        get_status docker $CONTAINER $TOOL_NAME
    done
    echo ""
    echo "--- Status Check Complete ---"
}

show_menu() {
    echo ""
    echo "================================================="
    echo "       DEVSECOPS SERVICE MANAGEMENT"
    echo "================================================="
    echo "S. View Current Service Status"
    echo "0. Activate ALL Services (System & Containers)"
    echo "-------------------------------------------------"
    i=1
    echo "SYSTEM SERVICES (Activation):"
    for SVC in "${SERVICES[@]}"; do
        echo "$i. Activate $SVC"
        i=$((i+1))
    done
    echo "-------------------------------------------------"
    echo "CONTAINER SERVICES (Activation):"
    for ITEM in "${CONTAINERS[@]}"; do
        read -r CONTAINER PORT TOOL_NAME <<< "$ITEM"
        echo "$i. Activate $TOOL_NAME ($PORT)"
        i=$((i+1))
    done
    echo "-------------------------------------------------"
    echo "q. Quit"
    echo "================================================="
    echo -n "Enter choice: "
}

prompt_return() {
    echo ""
    read -p "Press [Enter] to return to the menu..."
}

while true; do
    show_menu
    read choice

    case $choice in
        S|s)
            show_status
            prompt_return
            ;;
        0)
            check_all
            prompt_return
            ;;
        1)
            check_and_activate_service systemd ssh ssh
            prompt_return
            ;;
        2)
            check_and_activate_service docker jenkins-lts "Jenkins LTS"
            prompt_return
            ;;
        3)
            check_and_activate_service docker sonarqube "SonarQube"
            prompt_return
            ;;
        4)
            check_and_activate_service docker vault-dev "HashiCorp Vault"
            prompt_return
            ;;
        5)
            check_and_activate_service docker owasp-zap "OWASP ZAP"
            prompt_return
            ;;
        6)
            check_and_activate_service docker prometheus "Prometheus"
            prompt_return
            ;;
        7)
            check_and_activate_service docker grafana "Grafana"
            prompt_return
            ;;
        8)
            check_and_activate_service docker falco "Falco (Runtime Sec)"
            prompt_return
            ;;
        q|Q)
            echo "Exiting service manager."
            break
            ;;
        *)
            echo "Invalid option. Please try again."
            ;;
    esac
done
