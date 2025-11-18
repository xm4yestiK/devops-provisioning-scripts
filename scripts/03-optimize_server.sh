#!/bin/bash
set -euo pipefail

# Check for root privileges
if [[ "$EUID" -ne 0 ]]; then
  echo "This script must be run as root."
  exit 1
fi

# Set non-interactive mode for package installation
export DEBIAN_FRONTEND=noninteractive

# Install TLP and Powertop
apt-get update
apt-get install -y tlp powertop

# Create TLP configuration for server optimization
cat > /etc/tlp.d/99-server-optim.conf << EOF
TLP_ENABLE=1
TLP_DEFAULT_MODE=AC
TLP_PERSISTENT_DEFAULT=0
CPU_GOVERNOR_ON_AC="schedutil"
CPU_ENERGY_PERF_POLICY_ON_AC="balance_power"
CPU_BOOST_ON_AC=1
DISK_DEVICES="auto"
DISK_APM_LEVEL_ON_AC="254 254"
DISK_SPINDOWN_TIMEOUT_ON_AC=0
DISK_IOSCHED="mq-deadline"
RUNTIME_PM_ALL=1
RUNTIME_PM_DRIVER_BLACKLIST="nouveau"
PCIE_ASPM_ON_AC="performance"
NMI_WATCHDO=0
EOF

# Create kernel tuning (sysctl) configuration
cat > /etc/sysctl.d/99-server-optim.conf << EOF
vm.swappiness=10
vm.vfs_cache_pressure=50
vm.dirty_background_ratio=5
vm.dirty_ratio=15
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
kernel.nmi_watchdog=0
EOF

# Apply sysctl settings immediately
sysctl --system

# Optimize fstab by adding 'noatime'
FSTAB_FILE="/etc/fstab"

if grep -q "ext4.*noatime" "$FSTAB_FILE"; then
  echo "'noatime' already exists on ext4 partitions. Skipping."
else
  echo "Adding 'noatime' to ext4 partitions in $FSTAB_FILE..."
  # Safely add 'noatime' to ext4 mounts, creating a backup
  sed -i.bak '/ext4/!b; /noatime/b; s/defaults/defaults,noatime/' "$FSTAB_FILE"
  echo "fstab backup created at $FSTAB_FILE.bak"
fi

# Create a systemd service to run powertop auto-tune on boot
cat > /etc/systemd/system/powertop-autotune.service << EOF
[Unit]
Description=Powertop auto-tune
After=tlp.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/powertop --auto-tune
[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start all services
systemctl daemon-reload
systemctl enable --now tlp.service
systemctl enable --now powertop-autotune.service
systemctl restart tlp.service

echo ""
echo "--- MAXIMUM OPTIMIZATION COMPLETE ---"
echo "TLP, Powertop, and sysctl (including swappiness) are now ACTIVE."
echo "The 'noatime' optimization will be fully active after REBOOT."
