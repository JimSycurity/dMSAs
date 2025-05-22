
# Build list of OUs in the current domain
$OUList = Get-ADOrganizationalUnit -Filter *

# Create empty arrays
$OUsWithUnexpectedCreateChild = @()
$OUsWithNoCreateChild = @()

# Loop through the OUs
foreach ($ou in $OUList) {

}