# Check the AD Forest Schema to determine if any objectClasses other than organizationalUnit or container allow msDS-DelegatedManagedServiceAccount child objects.
# For instance if CVE-2021-34470 is still in play, it could be possible to create a dMSA nested under a computer object.

Import-Module ActiveDirectory
$defaultSystemPossSuperiors = @('container', 'organizationalUnit')
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

