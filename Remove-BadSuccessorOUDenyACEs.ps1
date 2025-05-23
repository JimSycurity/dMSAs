function Remove-BadSuccessorOUDenyACEs {
    <#
    .SYNOPSIS
        Removes targetted deny ACEs to OUs such that were created with Add-BadSuccessorOUDenyACEs

    .DESCRIPTION
        Optionally takes an Organizational Unit (OU) distinguishedName path for targetted mitigation, or with
        the optional -All parameter can apply the remediations to All OUs in the domain.
        Removes a set of Access Control Entries (ACEs) which:
            - Deny Authenticatead Users the ability to create a delegated Managed Service Account (dMSA) in the OU
            - Implement an OwnerRights ACE that will prevent object ownership abuse of existing dMSA accounts in the OU
            - Add an inheritable Deny Authenticated Users ACE to prevent writing to the msDS-ManagedAccountPrecededByLink attribute on child dMSA objects
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position=0, ValueFromPipeline)]
        [string[]]$TargetOUs,
        [switch]$All
    )

    begin {
        if ($All) {
            $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $domain = [ADSI]"LDAP://$currentDomain"
            $searcher = [System.DirectoryServices.DirectorySearcher]::new($domain)
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $searcher.SecurityMasks = 7
            $searcher.Filter = '(objectclass=organizationalUnit)'
            $TargetOUs = ($searcher.FindAll()).Properties.distinguishedname
        }
        $dMSA = [GUID]'0feb936f-47b3-49f2-9386-1dedc2c23765'
        $msDSManagedAccountPrecededByLink = [GUID]'a0945b2b-57a2-43bd-b327-4d112a4e8bd1'
        $protectedOUs = @()
    }

    process {
        foreach ($DN in $TargetOUs) {
            if ([ADSI]::Exists("LDAP://$DN")) {
                Write-Verbose "OU Exists: $DN"
                $OU = [ADSI]"LDAP://$DN"
            } else {
                Write-Warning "Invalid OU: $DN"
                continue
            }

            $OU.PsBase.Options.SecurityMasks = 'Dacl'

            # Deny Authenticated Users Create Child dMSA
            $GroupSID =  [System.Security.Principal.SecurityIdentifier]::new("S-1-5-11")
            $Identity = [System.Security.Principal.IdentityReference] $GroupSID
            $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "CreateChild"
            $Type = [System.Security.AccessControl.AccessControlType] "Deny"
            $Rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($Identity, $ADRight, $Type, $dMSA)
            $OU.PsBase.ObjectSecurity.RemoveAccessRuleSpecific($Rule)
            # Implement OwnerRights on Child dMSA
            $GroupSID =  [System.Security.Principal.SecurityIdentifier]::new("S-1-3-4")
            $Identity = [System.Security.Principal.IdentityReference] $GroupSID
            $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "ListChildren"
            $Type = [System.Security.AccessControl.AccessControlType] "Allow"
            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
            $Rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($Identity, $ADRight, $Type, $InheritanceType, $dMSA)
            $OU.PsBase.ObjectSecurity.RemoveAccessRuleSpecific($Rule)
            # Deny Authenticated Users WriteProperty msDS-ManagedAccountPrecededByLink on child dMSA
            $GroupSID =  [System.Security.Principal.SecurityIdentifier]::new("S-1-5-11")
            $Identity = [System.Security.Principal.IdentityReference] $GroupSID
            $ADRight = [System.DirectoryServices.ActiveDirectoryRights] "WriteProperty"
            $Type = [System.Security.AccessControl.AccessControlType] "Deny"
            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
            $Rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($Identity, $ADRight, $Type, $msDSManagedAccountPrecededByLink, $InheritanceType, $dMSA)
            $OU.PsBase.ObjectSecurity.RemoveAccessRuleSpecific($Rule)
            $OU.PsBase.CommitChanges()
        }

    }

    end {

    }
}