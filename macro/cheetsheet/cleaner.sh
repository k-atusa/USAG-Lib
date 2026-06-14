#!/bin/bash
# source ./cleanup.sh

T_HOME=$HOME

# 1. Remove CLI History (Runs in current user shell)
find "$T_HOME" -maxdepth 1 -name ".*_history" -type f -exec shred -uz {} + 2>/dev/null
export HISTSIZE=0 && export HISTFILESIZE=0 && history -c 2>/dev/null

# 2. Remove Thumbnail Cache
find "$T_HOME/.cache/thumbnails" -type f -exec shred -uz {} + 2>/dev/null

# 3. Remove Snapshots
command -v timeshift >/dev/null && sudo timeshift --delete-all >/dev/null 2>&1

# 4. Trim/Zero-fill free disk space
sudo fstrim -a 2>/dev/null || { sudo dd if=/dev/zero of=/wipe bs=4M status=none 2>/dev/null; sync; sudo rm -f /wipe; sync; }

# 5. Overwrite memory and swap
sudo swapoff -a 2>/dev/null
AV_MEM=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
sudo mkdir -p /mnt/mem_wipe
sudo mount -t tmpfs -o size=${AV_MEM}K tmpfs /mnt/mem_wipe
sudo dd if=/dev/zero of=/mnt/mem_wipe/wipe bs=1M status=none 2>/dev/null || true
sudo rm -f /mnt/mem_wipe/wipe && sudo umount /mnt/mem_wipe && sudo rmdir /mnt/mem_wipe
sudo swapon -a 2>/dev/null
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null

echo "Done."