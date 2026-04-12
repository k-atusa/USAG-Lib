# windows exe sign (old)

make new self-signed certicicate
```bat
makecert -n "CN=MYCERT" -r -sv MYPRIVATE.pvk MYPUBLIC.cer
```

convert cer file to spc file (you can use cer to sign, still)
```bat
cert2spc MYPUBLIC.cer MYPUBLIC.spc
```

certmgr is gui manager of certificates
```bat
certmgr
```

signtool signs program with keys
```bat
signtool signwizard
```

# windows exe sign (new)

use powershell command
```bat
$cert = New-SelfSignedCertificate -Type CodeSigningCert `
    -Subject "CN=MYCERT" `
    -KeyUsage DigitalSignature `
    -FriendlyName "MYCODESIGN" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(5)

$pwd = ConvertTo-SecureString -String "MYPASSWORD" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "MYPRIVATE.pfx" -Password $pwd

$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList "Root", "LocalMachine"
$rootStore.Open("ReadWrite")
$rootStore.Add($cert)
$rootStore.Close()

signtool sign /a /n "MYCERT" /t http://timestamp.digicert.com "MYPROGRAM.exe"
```
