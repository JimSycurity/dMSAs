# Check the AD Forest Schema to determine if any objectClasses other than organizationalUnit or container allow msDS-DelegatedManagedServiceAccount child objects.
# For instance if CVE-2021-34470 is still in play, it could be possible to create a dMSA nested under a computer object.

<##
Edit: June 5, 2025 - objectClasses inherit their attributes from their parent classes, via both possSuperiors and systemPossSuperiors.
In the case of msDS-DelegatedManagedServiceAccounts that inheritance chain looks like this:
top
    person
        organizationalPerson
            user
                computer
                    msDS-DelegatedManagedServiceAccount

As such, msDS-DelegatedManagedServiceAccount inherits possSuperiors from every parent class, like this:
top: lostAndFound
    person: lostAndFound, container, organizationalUnit
        organizationalPerson: lostAndFound, container, organizationalUnit, organization
            user: lostAndFound, container, organizationalUnit, organization, builtinDomain, domainDNS
                computer: lostAndFound, container, organizationalUnit, organization, builtinDomain, domainDNS
                    msDS-DelegatedManagedServiceAccount: lostAndFound, container, organizationalUnit, organization, builtinDomain, domainDNS
##>

<#
Windows Server 2025 objectClass schema for msDS-DelegatedManagedServiceAccounts:
Getting 1 entries:
Dn: CN=ms-DS-Delegated-Managed-Service-Account,CN=Schema,CN=Configuration,DC=AD2025,DC=lan
adminDescription: The delegated managed service account class is used to create an account which can supersede a legacy service account and shared by different computers.;
adminDisplayName: ms-DS-Delegated-Managed-Service-Account;
cn: ms-DS-Delegated-Managed-Service-Account;
defaultHidingValue: FALSE;
defaultObjectCategory: CN=ms-DS-Delegated-Managed-Service-Account,CN=Schema,CN=Configuration,DC=AD2025,DC=lan;
defaultSecurityDescriptor: D:(OD;;CR;00299570-246d-11d0-a768-00aa006e0529;;WD)(OD;;RP;e362ed86-b728-0842-b27d-2dea7a9df218;;WD)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(OA;;RPWP;77b5b886-944a-11d1-aebd-0000f80367c1;;PS)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AO)(A;;LCRPDTLOCRSDRC;;;CO)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY);
distinguishedName: CN=ms-DS-Delegated-Managed-Service-Account,CN=Schema,CN=Configuration,DC=AD2025,DC=lan;
dSCorePropagationData: 0x0 = (  );
governsID: 1.2.840.113556.1.5.302;
instanceType: 0x4 = ( WRITE );
lDAPDisplayName: msDS-DelegatedManagedServiceAccount;
name: ms-DS-Delegated-Managed-Service-Account;
objectCategory: CN=Class-Schema,CN=Schema,CN=Configuration,DC=AD2025,DC=lan;
objectClass (2): top; classSchema;
objectClassCategory: 1 = ( STRUCTURAL );
objectGUID: 57db26f1-1765-4f70-8498-20f2157a0b7a;
rDNAttID: cn;
schemaIDGUID: 0feb936f-47b3-49f2-9386-1dedc2c23765;
showInAdvancedViewOnly: TRUE;
subClassOf: computer;
systemFlags: 0x10 = ( SCHEMA_BASE_OBJECT );
systemMayContain (5): msDS-GroupMSAMembership; msDS-ManagedPasswordPreviousId; msDS-ManagedPasswordId; msDS-ManagedPassword; msDS-ManagedAccountPrecededByLink;
systemMustContain (2): msDS-DelegatedMSAState; msDS-ManagedPasswordInterval;
systemOnly: FALSE;
systemPossSuperiors (2): container; organizationalUnit;
uSNChanged: 2039;
uSNCreated: 2039;
whenChanged: 7/21/2023 11:03:07 AM Central Daylight Time;
whenCreated: 7/21/2023 11:03:07 AM Central Daylight Time;

-----------
#>

# TODO: Modify to recursively capture possSuperiors and systemPossSuperiors from all parent classes (and auxiliary classes)

Import-Module ActiveDirectory
# Default Schema inherited possSuperiors: lostAndFound, container, organizationalUnit, organization, builtinDomain, domainDNS
$defaultSystemPossSuperiors = @('container', 'organizationalUnit')
$top = 'top'
$defaultState = $true
$rootDSE = Get-ADRootDSE
$schemaPath = $rootDSE.schemanamingContext
$dMSAObjectClass = Get-AdObject -Filter 'lDAPDisplayName -eq "msDS-DelegatedManagedServiceAccount"' -SearchBase $schemaPath -Properties *
if ($null -eq $dMSAObjectClass) {
    Write-Host 'Delegated Managed Service Account object class not present in current AD Schema.' -ForegroundColor DarkGreen
}
else {
    foreach ($class in $dMSAObjectClass.systemPossSuperiors ) {
        if ($class -notin $defaultSystemPossSuperiors) {
            Write-Host "Found non-default objectClass: $class in dMSA systemPossSuperiors."
            $defaultState = $false
        }
    }
    if ($dMSAObjectClass.possSuperiors -ne '') {
        Write-Host "Non-default objectClass(es) in possSuperiors: $($dMSAObjectClass.possSuperiors)"
        $defaultState = $false
    }

    if ($defaultState) {
        Write-Host 'The AD Forest has a default AD Schema of only allowing dMSAs to be created under OUs and containers.' -ForegroundColor DarkGreen
    }
    else {
        Write-Host 'The AD Forest allows dMSA objects to be created as children of more than the default OU and container!' -ForegroundColor DarkRed
    }
}

