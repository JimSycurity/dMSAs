$domain = 'DC=domain,DC=root'
$domainDNS = 'domain.root'
$parentPath = 'OU=dMSAs,OU=Misconfigs,DC=domain,DC=root'
$childName = 'CN=TestdMSA01'
$childClassName = 'msDS-DelegatedManagedServiceAccount'

# [ADSI] is a shortcut for [System.DirectoryServices.DirectoryEntry]
$OU = [ADSI]"LDAP://$parentPath"
$child = $OU.get_Children()
$dMSA = $child.add($childName, $childClassName)
# dMSA schema systemMustContain (2): msDS-DelegatedMSAState; msDS-ManagedPasswordInterval;
$dMSA.Properties['msDS-DelegatedMSAState'].Value = 0 # 0 is the default value
$dMSA.Properties['msDS-ManagedPasswordInterval'].Value = 30  # 30 is the default value
$dMSA.CommitChanges()