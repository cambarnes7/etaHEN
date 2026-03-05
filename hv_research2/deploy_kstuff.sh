#!/bin/bash
#
# Deploy kstuff-no-fpkg's kstuff.elf to PS5
#
# etaHEN checks /data/etaHEN/kstuff.elf on boot and loads it
# instead of the built-in kstuff. kstuff-no-fpkg provides the
# kekcall interface needed for kmem_alloc/kproc_create.
#
# Usage: ./deploy_kstuff.sh <ps5_ip> [kstuff.elf path]
#
# After deploying, reboot the PS5 and re-trigger etaHEN.
# Then run hv_research2.elf — kekcall will be detected automatically.
#

set -e

PS5_HOST="${1:?Usage: $0 <ps5_ip> [kstuff.elf]}"
KSTUFF_ELF="${2:-kstuff-no-fpkg-repo/ps5_kernel_research/kstuff-no-fpkg/ps5-kstuff-ldr/kstuff.elf}"

if [ ! -f "$KSTUFF_ELF" ]; then
    echo "[-] kstuff.elf not found at: $KSTUFF_ELF"
    echo "    Build it first: make kstuff"
    exit 1
fi

echo "[*] Deploying kstuff-no-fpkg to $PS5_HOST..."
echo "[*] Source: $KSTUFF_ELF ($(stat -c%s "$KSTUFF_ELF" 2>/dev/null || stat -f%z "$KSTUFF_ELF") bytes)"

# Use FTP to upload (etaHEN runs an FTP server on port 2121)
FTP_PORT="${FTP_PORT:-2121}"

echo "[*] Uploading via FTP to $PS5_HOST:$FTP_PORT -> /data/etaHEN/kstuff.elf"
curl -T "$KSTUFF_ELF" "ftp://$PS5_HOST:$FTP_PORT/data/etaHEN/kstuff.elf" 2>/dev/null && {
    echo "[+] Upload complete!"
    echo "[*] Reboot the PS5 and re-trigger etaHEN to load kstuff-no-fpkg."
} || {
    echo "[-] FTP upload failed. You can manually copy:"
    echo "    $KSTUFF_ELF -> /data/etaHEN/kstuff.elf on PS5"
    echo ""
    echo "    Methods:"
    echo "    - FTP: connect to $PS5_HOST:2121, upload to /data/etaHEN/"
    echo "    - USB: copy to USB drive, then use file manager payload"
    exit 1
}
