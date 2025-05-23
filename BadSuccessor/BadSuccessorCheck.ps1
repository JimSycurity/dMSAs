# BadSuccessor checks for prerequisits
# Research: https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory
# Original Script: https://github.com/akamai/BadSuccessor/blob/main/Get-BadSuccessorOUPermissions.ps1
# Usage:
# BadSuccessorCheck -DomainController "your.domain" or "your.domain.controller"

function Resolve-ADIdentity {
    param (
        [string]$SID,
        [string]$DomainController
    )
    try {
        $forest = Get-ADForest -Server $DomainController
        $domains = $forest.Domains
    }
    catch {
        $domains = @($DomainController)
    }
    foreach ($domain in $domains) {
        try {
            $user = Get-ADUser -Filter { SID -eq $SID } -Server $domain -ErrorAction SilentlyContinue
            if ($user) {
                return "$domain\$($user.SamAccountName)"
            }
            $group = Get-ADGroup -Filter { SID -eq $SID } -Server $domain -ErrorAction SilentlyContinue
            if ($group) {
                return "$domain\$($group.SamAccountName)"
            }
            $computer = Get-ADComputer -Filter { SID -eq $SID } -Server $domain -ErrorAction SilentlyContinue
            if ($computer) {
                return "$domain\$($computer.Name)$"
            }
        }
        catch {
            # continue to next domain
        }
    }
    # .NET fallback
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $ntAccount = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
        return $ntAccount
    }
    catch {
        return "NOT_RESOLVABLE"
    }
}

function Get-SIDFromIdentity {
    param ($IdentityReference, $DomainController)
    try {
        $user = Get-ADUser -Identity $IdentityReference -Server $DomainController -ErrorAction SilentlyContinue
        if ($user) { return $user.SID.Value }
        $group = Get-ADGroup -Identity $IdentityReference -Server $DomainController -ErrorAction SilentlyContinue
        if ($group) { return $group.SID.Value }
        $computer = Get-ADComputer -Identity $IdentityReference -Server $DomainController -ErrorAction SilentlyContinue
        if ($computer) { return $computer.SID.Value }
    }
    catch {
    }
    return $IdentityReference
}

function BadSuccessorCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainController
    )
    $SidCache = @{}
    $NameCache = @{}

    function Test-IsExcludedSID {
        Param ([string]$IdentityReference)
        if ($SidCache.ContainsKey($IdentityReference)) {
            return $SidCache[$IdentityReference]      # instant hit
        }
        $sid = Get-SIDFromIdentity $IdentityReference $DomainController
        if (-not $sid) {
            $SidCache[$IdentityReference] = $false
            return $false
        }
        if (($excludedSids -contains $sid -or $sid.EndsWith('-519'))) {
            $SidCache[$IdentityReference] = $true
            return $true
        }
        $SidCache[$IdentityReference] = $false
        return $false
    }

    Import-Module ActiveDirectory

    Write-Host "`n[+] Checking for Windows Server 2025 Domain Controllers..." -ForegroundColor Cyan
    $dcs = Get-ADDomainController -Filter * -Server $DomainController
    $dc2025 = $dcs | Where-Object { $_.OperatingSystem -match "2025" }
    if ($dc2025) {
        Write-Host "[!] Windows Server 2025 DCs found. BadSuccessor may be exploitable!" -ForegroundColor Green
        $dc2025 | Select-Object HostName, OperatingSystem | Format-Table
    }
    else {
        Write-Host "[!] No 2025 Domain Controllers found. BadSuccessor not exploitable!" -ForegroundColor Red
        $response = Read-Host "Do you want to continue anyway? (y/N)"
        if ($response -notin @('y', 'Y', 'yes', 'YES')) {
            Write-Host "Aborting script as requested." -ForegroundColor Yellow
            exit 1   # Use `return` if this is inside a function
        }
    }

    $domainSID = (Get-ADDomain -Server $DomainController).DomainSID.Value
    $excludedSids = @(
        "$domainSID-512", # Domain Admins
        "$domainSID-519", # Enterprise Admins
        "S-1-5-32-544", # Builtin Administrators
        "S-1-5-18"              # Local SYSTEM
    )

    $relevantRights = @('CreateChild', 'GenericAll', 'WriteDacl', 'WriteOwner')
    $relevantObjectTypes = @(
        [Guid]::Empty,
        [Guid]'0feb936f-47b3-49f2-9386-1dedc2c23765'
    )

    # Prepare results collection
    $results = @()

    $ous = Get-ADOrganizationalUnit -Filter * -Server $DomainController -Properties DistinguishedName

    foreach ($ou in $ous) {
        $ldapPath = "LDAP://$DomainController/$($ou.DistinguishedName)"
        try {
            $de = [ADSI]$ldapPath
            $sd = $de.psbase.ObjectSecurity
            $aces = $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            foreach ($ace in $aces) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                $matchingRights = @()
                foreach ($r in $relevantRights) {
                    if ($ace.ActiveDirectoryRights.ToString() -match $r) {
                        $matchingRights += $r
                    }
                }
                if ($matchingRights.Count -eq 0) { continue }
                if ($relevantObjectTypes -notcontains $ace.ObjectType) { continue }

                $sid = $ace.IdentityReference.Value
                if (Test-IsExcludedSID $sid) { continue }
                if ($NameCache.ContainsKey($sid)) {
                    $resolvedName = $NameCache[$sid]
                }
                else {
                    $resolvedName = Resolve-ADIdentity $sid $DomainController
                    $NameCache[$sid] = $resolvedName
                }
                foreach ($right in $matchingRights) {
                    $results += [PSCustomObject]@{
                        IdentitySID  = $sid
                        IdentityName = $resolvedName
                        OU           = $ou.DistinguishedName
                        Right        = $right
                    }
                }
            }
            # Also check OU owner
            $ownerSID = $sd.Owner.Value
            if ($ownerSID -and -not (Test-IsExcludedSID $ownerSID)) {
                if ($NameCache.ContainsKey($ownerSID)) {
                    $ownerName = $NameCache[$ownerSID]
                }
                else {
                    $ownerName = Resolve-ADIdentity $ownerSID $DomainController
                    $NameCache[$ownerSID] = $ownerName
                }
                $results += [PSCustomObject]@{
                    IdentitySID  = $ownerSID
                    IdentityName = $ownerName
                    OU           = $ou.DistinguishedName
                    Right        = 'Owner'
                }
            }
        }
        catch {
            Write-Warning "Failed OU: $($ou.DistinguishedName): $_"
            continue
        }
    }

    $results | Sort-Object IdentityName
}