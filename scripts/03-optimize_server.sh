#!/bin/bash

# Exit immediately if a command fails
set -e

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then 
  echo "This script must be run as root. Try: sudo ./04-optimize_server.sh"
  exit 1
fi

echo "--- [1/2] Optimizing Swappiness (RAM) ---"

SWAP_CONF_FILE="/etc/sysctl.d/99-swappiness.conf"
SWAP_SETTING="vm.swappiness=10"

# Check if swappiness is already set
if [ -f "$SWAP_CONF_FILE" ] && grep -q "$SWAP_SETTING" "$SWAP_CONF_FILE"; then
  echo "Swappiness already set to 10. Skipping."
else
  echo "Setting swappiness to 10..."
  echo "$SWAP_SETTING" > "$SWAP_CONF_FILE"
  
  echo "Applying swappiness settings..."
  sysctl -p "$SWAP_CONF_FILE"
fi

echo "--- [2/2] Optimizing Disk I/O (Adding 'noatime' to fstab) ---"

FSTAB_FILE="/etc/fstab"

# Check if fstab already contains noatime for ext4
if grep -q "ext4.*noatime" "$FSTAB_FILE"; then
  echo "ext4 partitions already have 'noatime'. Skipping."
else
  echo "Creating backup $FSTAB_FILE.bak"
  cp "$FSTAB_FILE" "$FSTAB_FILE.bak"
  
  echo "Adding 'noatime' to ext4 partitions..."
  # Safely add 'noatime' only to ext4 mounts that use 'defaults'
  sed -i.bak '/ext4/!b; /noatime/b; s/defaults/defaults,noatime/' "$FSTAB_FILE"
fi

echo ""
echo "--- OPTIMIZATION COMPLETE ---"
echo "Swappiness (RAM) optimization is now ACTIVE."
echo "'noatime' (Disk I/O) optimization will be active after REBOOT."
echo "Rebooting the server now is recommended: sudo reboot"
