function Add-BadSuccessorOUDenyACEs {
    <#
    .SYNOPSIS
        Applies targetted deny ACEs to OUs such that the BadSuccessor dMSA abuse will not be available

        To cover all OUs in the domain pipe Get-ADOrganizationalUnit -Filter * | Add-BadSuccessorOUDenyACEs

    .DESCRIPTION
        Optionally takes an Organizational Unit (OU) distinguishedName path for targetted mitigation, or with
        the optional -All parameter can apply the remediations to All OUs in the domain.
        Creates a set of Access Control Entries (ACEs) which:
            - Deny Authenticatead Users the ability to create a delegated Managed Service Account (dMSA) in the OU
            - Implement an OwnerRights ACE that will prevent object ownership abuse of existing dMSA accounts in the OU
            - Add an inheritable Deny Authenticated Users ACE to prevent writing to the msDS-ManagedAccountPrecededByLink attribute on child dMSA objects

        NOTE: The first deny ACE in this set will prevent administrators from creating dMSA objects in the targeted OU(s) as well. To create new dMSA objects,
        an administrator can create them in the Managed Service Accounts container and move the object if necessary.
        The 2nd deny ACE will prevent some administrators from modifying the msDS-ManagedAccountPrecededByLink on dMSAs in the targeted OU(s) as well, but this is an
        inherited ACE in that DACL, so an explicitly defined Allow ACE for the accounts which need to configure that specific dMSA will override it.  Domain Admins
        and Account Operators are both granted explicit Allow GenericAll ACEs by the defaultSecurityDescriptor for the dMSA objectClass.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$DistinguishedName
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

        # Add Deny Authenticated Users Create Child dMSA ACE
        $GroupSID = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-11")
        $Identity = [System.Security.Principal.IdentityReference] $GroupSID
        $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "CreateChild"
        $Type = [System.Security.AccessControl.AccessControlType] "Deny"
        $Rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($Identity, $ADRight, $Type, $dMSA)
        $OU.PsBase.ObjectSecurity.AddAccessRule($Rule)
        # Add Allow OwnerRights ListContent on Child dMSA ACE
        $GroupSID = [System.Security.Principal.SecurityIdentifier]::new("S-1-3-4")
        $Identity = [System.Security.Principal.IdentityReference] $GroupSID
        $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "ListChildren"
        $Type = [System.Security.AccessControl.AccessControlType] "Allow"
        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
        $Rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($Identity, $ADRight, $Type, $InheritanceType, $dMSA)
        $OU.PsBase.ObjectSecurity.AddAccessRule($Rule)
        # Add Deny Authenticated Users WriteProperty msDS-ManagedAccountPrecededByLink on child dMSA ACE
        $GroupSID = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-11")
        $Identity = [System.Security.Principal.IdentityReference] $GroupSID
        $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "WriteProperty"
        $Type = [System.Security.AccessControl.AccessControlType] "Deny"
        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
        $Rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($Identity, $ADRight, $Type, $msDSManagedAccountPrecededByLink, $InheritanceType, $dMSA)
        $OU.PsBase.ObjectSecurity.AddAccessRule($Rule)
        $OU.PsBase.CommitChanges()
    }
}