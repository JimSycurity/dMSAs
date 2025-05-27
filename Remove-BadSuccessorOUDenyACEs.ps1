function Remove-BadSuccessorOUDenyACEs {
    <#
    .SYNOPSIS
        Removes targetted deny ACEs to OUs such that were created with Add-BadSuccessorOUDenyACEs

        To cover all OUs in the domain pipe Get-ADOrganizationalUnit -Filter * | Remove-BadSuccessorOUDenyACEs

    .DESCRIPTION
        Optionally takes an Organizational Unit (OU) distinguishedName path for targetted mitigation, or with
        the optional -All parameter can apply the remediations to All OUs in the domain.
        Removes a set of Access Control Entries (ACEs) which:
            - Deny Authenticatead Users the ability to create a delegated Managed Service Account (dMSA) in the OU
            - Implement an OwnerRights ACE that will prevent object ownership abuse of existing dMSA accounts in the OU - When RemoveAll switch is used
            - Add an inheritable Deny Authenticated Users ACE to prevent writing to the msDS-ManagedAccountPrecededByLink attribute on child dMSA objects
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$DistinguishedName,
        [switch]$RemoveAll
    )

    begin {
        $dMSA = [GUID]'0feb936f-47b3-49f2-9386-1dedc2c23765'
        $msDSManagedAccountPrecededByLink = [GUID]'a0945b2b-57a2-43bd-b327-4d112a4e8bd1'
    }

    process {
        if ([ADSI]::Exists("LDAP://$DistinguishedName")) {
            Write-Verbose "OU Exists: $DistinguishedName"
            $OU = [ADSI]"LDAP://$DistinguishedName"
        }
        else {
            Write-Warning "Invalid OU: $DistinguishedName"
            continue
        }

        $OU.PsBase.Options.SecurityMasks = 'Dacl'

        # Remove Deny AuthenticatedUsers CreateChild dMSA ACE
        $GroupSID = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-11")
        $Identity = [System.Security.Principal.IdentityReference] $GroupSID
        $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "CreateChild"
        $Type = [System.Security.AccessControl.AccessControlType] "Deny"
        $DenyCreateRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($Identity, $ADRight, $Type, $dMSA)
        $OU.PsBase.ObjectSecurity.RemoveAccessRuleSpecific($DenyCreateRule)
        # Remove Allow OwnerRights ListContent on Child dMSA ACE
        $GroupSID = [System.Security.Principal.SecurityIdentifier]::new("S-1-3-4")
        $Identity = [System.Security.Principal.IdentityReference] $GroupSID
        $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "ListChildren"
        $Type = [System.Security.AccessControl.AccessControlType] "Allow"
        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
        $OwnerRightsRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($Identity, $ADRight, $Type, $InheritanceType, $dMSA)
        if ($RemoveAll) {
            $OU.PsBase.ObjectSecurity.RemoveAccessRuleSpecific($OwnerRightsRule)
        }
        # Remove Deny AuthenticatedUsers WriteProperty msDS-ManagedAccountPrecededByLink on child dMSA ACE
        $GroupSID = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-11")
        $Identity = [System.Security.Principal.IdentityReference] $GroupSID
        $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "WriteProperty"
        $Type = [System.Security.AccessControl.AccessControlType] "Deny"
        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
        $DenyWriteRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($Identity, $ADRight, $Type, $msDSManagedAccountPrecededByLink, $InheritanceType, $dMSA)
        $OU.PsBase.ObjectSecurity.RemoveAccessRuleSpecific($DenyWriteRule)
        $OU.PsBase.CommitChanges()
    }
}


# Auto-run if script is executed directly
if ($MyInvocation.InvocationName -ne '.') {
    Remove-BadSuccessorOUDenyACEs @PSBoundParameters
}