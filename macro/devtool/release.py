import os
import stat
import shutil
import subprocess
from datetime import datetime, timezone, timedelta

# get signtool from C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe
CERT_NAME = "test_cert_1"
CERT_PATH = "newCert.pfx"
CERT_PW = "00000000"
CERT_SIZE = 2048
CERT_EXPIRE = 5 * 365

# make new cert in Windows
def newCert():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=CERT_SIZE)
    issuer = x509.Name( [ x509.NameAttribute(NameOID.COMMON_NAME, CERT_NAME) ] )
    subject = issuer
    
    # start and expire time
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=CERT_EXPIRE)
    temp_a = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(x509.random_serial_number())
    temp_b = temp_a.not_valid_before(now).not_valid_after(expire).add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]),critical=True,)

    # get cert data
    cert = temp_b.sign(private_key, hashes.SHA256())
    pfx_data = pkcs12.serialize_key_and_certificates(
        name=CERT_NAME.encode("utf-8"),
        key=private_key,
        cert=cert,
        encryption_algorithm=serialization.BestAvailableEncryption(CERT_PW.encode("utf-8")),
        cas=None
    )
    with open(CERT_PATH, "wb") as f:
        f.write(pfx_data)

# sign with cert in Windows
def signExe(tgtPath):
    cmd = [
        "signtool", "sign",
        "/f", CERT_PATH,
        "/p", CERT_PW,
        "/fd", "SHA256",
        "/tr", "http://timestamp.sectigo.com", # http://timestamp.digicert.com
        "/td", "SHA256",
        "/v", tgtPath
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(result.stdout)
        print("signed successfully")
    except subprocess.CalledProcessError as e:
        print(e.stdout)
        print(e.stderr)
        print("sign failed")

# make desktop link in Linux
# place *.desktop at ~/Desktop/ ~/.local/share/applications/
def newIcon(name, exe, icon, ver=1.0, comment="", cmd=False):
    # make text value
    terminal_val = "true" if cmd else "false"
    exec_dir = os.path.dirname(os.path.abspath(exe))
    content = f"""[Desktop Entry]
Version={ver}
Name={name}
Comment={comment}
Exec={os.path.abspath(exe)}
Icon={os.path.abspath(icon)}
Path={exec_dir}
Terminal={terminal_val}
Type=Application
Categories=Development;
"""

    # make file, give +x
    try:
        path = f"{name.replace(' ', '_')}.desktop"
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        st = os.stat(path)
        os.chmod(path, st.st_mode | stat.S_IEXEC)
        print(f"linked successfully: {path}")
    except Exception as e:
        print(f"failed to make: {e}")

# make app folder in Mac
def newIconMac(name, exe, icon):
    # make directory (AppName.app/Contents/...)
    app_path = f"{name}.app"
    macos_dir = os.path.join(app_path, "Contents", "MacOS")
    resources_dir = os.path.join(app_path, "Contents", "Resources")
    os.makedirs(macos_dir, exist_ok=True)
    os.makedirs(resources_dir, exist_ok=True)

    # copy executable, icon
    if not icon.endswith(".icns"):
        raise Exception("Icon for Mac should be *.icns format")
    shutil.copy(exe, os.path.join(macos_dir, name))
    shutil.copy(icon, os.path.join(resources_dir, "icon.icns"))

    # add +x
    target_exe_path = os.path.join(macos_dir, name)
    st = os.stat(target_exe_path)
    os.chmod(target_exe_path, st.st_mode | stat.S_IEXEC)

    # make Info.plist
    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>{name}</string>
    <key>CFBundleIconFile</key>
    <string>icon.icns</string>
    <key>CFBundleName</key>
    <string>{name}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
</dict>
</plist>
"""
    with open(os.path.join(app_path, "Contents", "Info.plist"), "w") as f:
        f.write(plist_content)
    print(f"Mac app bundle created: {app_path}")
