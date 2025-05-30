# BadSuccessor Experimentation

After getting a few questions on reddit and seeing a [LinkedIn post by Andrea Pierini](https://www.linkedin.com/posts/andrea-pierini_badsuccessor-activity-7333868453453344770-7dEZ), I decided to redo my lab testing with a more rigorous, repeatable methodology as I missed what Andrea did about the 28th flag of dSHeuristics initially. Back to [KB5008383](https://support.microsoft.com/en-us/topic/kb5008383-active-directory-permissions-updates-cve-2021-42291-536d5555-ffba-4248-a60e-d6cbc849cde1) we go!

First, I (re)set the dSHeuristics value in the 'domain.root' AD Forest I'm testing in

- [AttributeAuthorizationOnLDAPAdd](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ff004f3e-8920-4ba4-aaa7-346710171972), which is flag 28 to 0. This configures Additional Authorization Verification for LDAP Add Operators for computer-derived objects to Audit mode.
- [BlockOwnerImplicitRights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/fb7c101d-ec8b-4fbf-bca8-7d7c2d747d0c), which is flag 29 to 1. This configures the Temporary removal of Implicit Owner privileges on LDAP modify operation of the nTSecurityDescriptor on computer-derived objects to enforcement mode.

I've gone through testing with the Implicit Owner Rights removal flag (29) in my [Owner or Pwned? paper](https://www.hub.trimarcsecurity.com/post/trimarc-whitepaper-owner-or-pwnd) and feel I understand it as it relates to the issues in BadSuccessor so I can go straight to block mode there.
This is a different path than what Adrea chose in his research as he set 28 to 1 and 29 to 0. I just want to audit LDAP Add operations for now.

```PowerShell
Set-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -replace @{dSHeuristics='00000000010000000002000000001'}
```

I created a new Group Policy Object linked to the Domain Controllers OU and ensured the pertinent Advanced Audit Policy categories were enabled for logging.

An Event Viewer Custom View for LDAPAdd-ModifydSHeuristics was next on my list. The .XML to recreate this custom view is in this Experiments folder.

I then rebooted the InheritanceII.domain.root DC and ensured that the appropriate events were created in the Directory Service event log:
![EventID 3053](/Experiments/EventID3053.png "EventID 3053")
![EventID 3051](/Experiments/EventID3051.png "EventID 3051")

Now that I know that the auditing is properly enabled, the dSHeuristics is set to at least audit, if not block anything I do, and I have a simple way to find any events generated, it's time to go BadSuccessor all over this domain, using my Repeat-Methodology.ps1 routine.

## BadSuccessor Check

I decided to use [LuemmelSec's BadSuccessor.ps1 script](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1) for this set of tests. It's fairly well written and does what I want it to in PowerShell, which is my jam.

First I ran it in Check mode:

```PowerShell
PS C:\Scripts\Rubeus> badsuccessor -mode check -Domain domain.root

[+] Checking for Windows Server 2025 Domain Controllers...
[!] Windows Server 2025 DCs found. BadSuccessor may be exploitable!

HostName                  OperatingSystem
--------                  ---------------
InheritanceII.domain.root Windows Server 2025 Standard

PS C:\Scripts\Rubeus>
```

The BadSuccessor function, which doesn't use proper PowerShell Verb-Noun naming standards :P, also outputs to gridview a table of all security principals that can likely create dMSA accounts, in which OUs, and with which permission grants. I filtered it to only include the specific OU I'm going to be testing with:
![BadSuccessor Check Output](/Experiments/BadSuccessorps1%20Output.png)

I'll also take this opportunity to point out the directory hierarchy of domain.root:
![Directory Hierarchy](/Experiments/Directory%20Hierarchy.png)

The security principals I'll be using in the experiments:
![Security Principals](/Experiments/Experiment%20Security%20Principals.png)

And output of the security descriptor for the dMSA OU:
![ADUC Advanced Security](/Experiments/dMSA%20OU%20Advanced%20Security.png)

![LDP Security Descriptor](/Experiments/dMSA%20OU%20LDP%20Security%20Descriptor.png)

Until otherwise stated in future steps, the Add-BadSuccessorOUDenyACEs script has not be run in the domain.root environment for the first series of tests.

On to the various tests!

## StandardUser with No Additional Groups

As a baseline, I ran a test without adding StandardUser to any additional groups, thus meaning it had standard Domain User permissions for this abuse attempt. As expected, the creation of the dMSA failed with Access Denied:
![StandardUserNoGroups](/Experiments/StandardUserNoGroups/BadSuccessorOutput.png)

## StandardUser in CreateChildObjects-dMSA Group

The CreateChildObjects-dMSA security group is granted an Allow CreateChild on ObjectType msDS-DelegatedManagedServiceAccount
![CreateChildObjects-dMSA ACE](/Experiments/StandardUserInCreateChildObjects-dMSA/CreateChildObjects-dMSA%20ACE.png)

I added the StandardUser account to the CreateChildObjects-dMSA group
![StandardUser in CreateChildObjects-dMSA Group](/Experiments/StandardUserInCreateChildObjects-dMSA/StandardUser%20in%20CreateChildObjects-dMSA.png)

I logged out and logged back in as StandardUser on InheritenceIII.domain.root, which is a Windows Server 2025 member server in the domain.root domain.
I then started going through the steps in the Repeat-Methodology.ps1 with $name = 'SU-CCdMSA'. The log from executing the commands in Repeat-Methodology.ps1 for StandardUser in the CreateChildObjects-dMSA group is located here: [StandardUserInCreateChildObjects-dMSA Log](/Experiments/StandardUserInCreateChildObjects-dMSA/AbuseLog.txt)

The abuse was successful and StandardUser gained the privileges of the Administrator account we superseded, demonstarted by being able to list the contents of the domain controller's c$ share.

However, reviewing the event logs on the InheritanceII domain controller via the Custom Views I set up, we can see that an EventID 3047 was logged, the text of which is here: [EventID3047.txt](/Experiments/StandardUserInCreateChildObjects-dMSA/EventID3047.txt)

Let's break this down:

> The directory service detected an LDAP add request for the following object that normally would have been blocked for the following security reasons.
> The client did not have permission to write one or more attributes included in the add request, based on the default merged security descriptor.
> The request was allowed to proceed because the directory is currently configured to be in audit-only mode for this security check.
>
> Object DN: CN=SU-CCdMSA,OU=dMSAs,OU=Misconfigs,DC=domain,DC=root
>
> Object class: msDS-DelegatedManagedServiceAccount
>
> User: DOMAIN\StandardUser
>
> Client IP Address: 10.10.15.201:56394

StandardUser, based on the merged security descriptor in the event is not granted rights to modify some of the attributes of the dMSA without taking the Implicit Owner Rights to WriteDACL into account. We're in Audit mode, so we're not blocking. We've got information on what was created, where it was created, which objectClass, who created it, and from which client it was created.

> Security desc: O:S-1-5-21-3931413440-1750864000-3539657848-1132G:DUD:AI(OD;;CR;00299570-246d-11d0-a768-00aa006e0529;;WD)(OD;;RP;e362ed86-b728-0842-b27d-2dea7a9df218;;WD)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-3931413440-1750864000-3539657848-1132)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-3931413440-1750864000-3539657848-1132)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-3931413440-1750864000-3539657848-1132)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-3931413440-1750864000-3539657848-1132)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;S-1-5-21-3931413440-1750864000-3539657848-1132)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;S-1-5-21-3931413440-1750864000-3539657848-1132)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;S-1-5-21-3931413440-1750864000-3539657848-1132)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77b5b886-944a-11d1-aebd-0000f80367c1;;PS)(A;;LCRPDTLOCRSDRC;;;S-1-5-21-3931413440-1750864000-3539657848-1132)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AO)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(OA;CIID;WP;a0945b2b-57a2-43bd-b327-4d112a4e8bd1;0feb936f-47b3-49f2-9386-1dedc2c23765;S-1-5-21-3931413440-1750864000-3539657848-1126)(OA;CIID;CC;0feb936f-47b3-49f2-9386-1dedc2c23765;;S-1-5-21-3931413440-1750864000-3539657848-1119)(OA;CIID;CC;bf967a9c-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3931413440-1750864000-3539657848-1120)(OA;CIID;SWWPRC;;0feb936f-47b3-49f2-9386-1dedc2c23765;S-1-5-21-3931413440-1750864000-3539657848-1124)(OA;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;0feb936f-47b3-49f2-9386-1dedc2c23765;S-1-5-21-3931413440-1750864000-3539657848-1122)(A;CIID;CC;;;S-1-5-21-3931413440-1750864000-3539657848-1118)(A;CIID;WP;;;S-1-5-21-3931413440-1750864000-3539657848-1125)(A;CIID;SWWPRC;;;S-1-5-21-3931413440-1750864000-3539657848-1123)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-3931413440-1750864000-3539657848-1121)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;KA)(OA;CIID;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-3931413440-1750864000-3539657848-527)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;CIID;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-3931413440-1750864000-3539657848-519)(A;CIID;LC;;;RU)(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;BA)S:AI(OU;CIIOIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIOIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)

This is a long SDDL. So long that when I use LDP to convert it to an editor the entire DACL doesn't fit on the screen of my lab device:
![Merged SecurityDescriptor](/Experiments/StandardUserInCreateChildObjects-dMSA/MergedSD.png)

If we stare at this long enough it becomes apparent to see that StandardUser isn't granted rights to modify some of the attributes of the msDS-DelegatedManagedServiceAccount object. StandardUser is only a member of the 'Domain Users' and 'CreateChildObjects-dMSA' groups and is granted explicit Allow ACEs due to the CreatorOwner ACEs on the DefaultSecurityDescriptor of the [msDS-DelegatedManagedServiceAccount objectClass per the AD Schema](/Experiments/Server2025dMSASchema.txt). The only attributes in the dMSA objectClass's systemMustContain are: msDS-DelegatedMSAState; msDS-ManagedPasswordInterval. That means those attributes MUST be set when the object is created. And since a dMSA object is a sub-class of the computer class, which is a sub-class of the user class, which is a subclass of the organizationalPerson class, which is a subclass of the person class, which is a subclass of the top class it likely inherits a few other required mustContain or systemMustContain attributes as a computer-derived object. Also, the user objectClass has a few systemAuxiliaryClasses which also modify the attributes that a user object can or must have, and thus any user-derived object.

**_Tangent:_** _You can find the computer-derived object classes in your AD Forest like this:_

```PowerShell
Import-Module ActiveDirectory
$schemapath = (Get-ADRootDSE).schemanamingContext
$Schema = Get-AdObject -Filter * -SearchBase $schemapath -Properties *
$Classes = $Schema | Where-Object {$_.ObjectClass -eq 'classSchema'}
$ComputerDerived = $Classes | Where-Object {$_.subClassOf -eq 'Computer'}
$ComputerDerived
```

But the attributes we need to set in order to abuse BadSuccessor are part of the systemMayContain attribute set for the dMSA class. This means they aren't required when an object is created (LDAP Add operation). So per the rules in [3.1.1.5.2.1.1 Per Attribute Authorization for Add Operation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ff004f3e-8920-4ba4-aaa7-346710171972), specifically steps 7-10, the LDAP Add Operation has a set of attributes (A) that the requestor (StandardUser) tried to set during the LDAP Add Operation. In this set of tests I'm using [LuemmelSec's BadSuccessor.ps1 script](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1), so the part of the script with the attributes are here:

```PowerShell
# <SNIP>
    $childName = "CN=$Name"
    $newChild = $parentEntry.Children.Add($childName, "msDS-DelegatedManagedServiceAccount")
    $newChild.Properties["msDS-DelegatedMSAState"].Value = 2
    $newChild.Properties["msDS-ManagedPasswordInterval"].Value = 30
    $newChild.Properties["dnshostname"].Add("$Name.$fqdn")
    $newChild.Properties["samaccountname"].Add("$Name`$")
    $newChild.Properties["msDS-SupportedEncryptionTypes"].Value = 0x1C
    $newChild.Properties["userAccountControl"].Value = 0x1000

    # Resolve DelegateTarget
    try {
        $target = Get-ADUser -Identity $DelegateTarget -Server $Domain -ErrorAction Stop
    } catch {
        $target = Get-ADComputer -Identity $DelegateTarget -Server $Domain -ErrorAction Stop
    }
    $newChild.Properties["msDS-ManagedAccountPrecededByLink"].Add($target.distinguishedName)

    # Resolve DelegatedAdmin SID
    try {
        $admin = Get-ADUser -Identity $DelegatedAdmin -Server $Domain -ErrorAction Stop
    } catch {
        $admin = Get-ADComputer -Identity $DelegatedAdmin -Server $Domain -ErrorAction Stop
    }
    $adminSID = $admin.SID.Value

    # Build Security Descriptor
    $rawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor "O:S-1-5-32-544D:(A;;FA;;;$adminSID)"
    $descriptor = New-Object byte[] $rawSD.BinaryLength
    $rawSD.GetBinaryForm($descriptor, 0)
    $newChild.Properties["msDS-GroupMSAMembership"].Add($descriptor)

    $newChild.CommitChanges()
# <SNIP>
```

For attributes we try to set at object creation we have, which is the set "A":

- msDS-DelegatedMSAState - systemMustContain at msDS-DelegatedManagedServiceAccount - Allowed on MustContain
- msDS-ManagedPasswordInterval - systemMustContain at msDS-DelegatedManagedServiceAccount - Allowed on MustContain
- dnshostname - systemMayContain at computer - Allowed on StandardUser granted WriteProperty
- samaccountname - systemMustContain at securityPrincipal, systemAuxiliaryClass to user - Allowed on MustContain
- msDS-SupportedEncryptionTypes - system**May**Contain at user - **StandardUser Denied**
- userAccountControl - systemMayContain at user - Allowed on StandardUser granted WriteProperty
- msDS-ManagedAccountPrecededByLink - system**May**Contain at msDS-DelegatedManagedServiceAccount - **StandardUser Denied**
- msDS-GroupMSAMembership - system**May**Contain at msDS-DelegatedManagedServiceAccount - **StandardUser Denied**

Step 7 removes any MustContain attributes from "A", which leaves us with dnshostname, samaccountname, userAccountControl, msDS-ManagedAccountPrecededByLink, and msDS-GroupMSAMembership.

Step 8 doesn't apply here, neither does Step 9

Step 10 steps through the remaining attributes in set "A" and does an Access Check where the security context of StandardUser is compared against the merged security descriptor (above). StandardUser is granted WriteProperty on dnshostname, samaccountname, and userAccountControl, so those attributes are allowed to be modified. That leaves us with 3 denied attributes:

> Denied attributes:
> msDS-GroupMSAMembership
> msDS-ManagedAccountPrecededByLink
> msDS-SupportedEncryptionTypes
>
> Extended-write denied attributes:
>
> For more information, please see https://go.microsoft.com/fwlink/?linkid=2174032.

So, if we had instead set the dSHeuristics If AttributeAuthorizationOnLDAPAdd flag (28) to 1, the creation of this dMSA object would have failed, and this specific BadSuccessor abuse wouldn't have been possible. But that doesn't mean configuring dSHeuristics completely solves the BadSuccessor issue...

## StandardUser in CreateChildObjects-All Group

The results of this experiment were no different than the Standard User in CreateChildObjects-dMSA Group, which is the result I expected. A member of this group is able to create any child object in the dMSA OU where it is delegated rights. So it's not limited to only creating a dMSA object. The log of the BadSuccessor abuse with the StandardUser account in this configuration along with the Event ID 3407 it generated are in the Experiments folder structure. No surprises here.

## StandardUser in GenericAll-dMSA Group

The results of this test sequence surprised me and I may re-test them later or dig in further in the future. The [log](/Experiments/StandardUserInGenericAll-dMSA/AbuseLog.txt) shows that StandardUser with this set of delegated rights was unable to create the dMSA object.

```
MethodInvocationException: C:\Scripts\Pentest-Tools-Collection\Tools\ActiveDirectory\BadSuccessor.ps1:221:9
Line |
 221 |          $newChild.CommitChanges()
     |          ~~~~~~~~~~~~~~~~~~~~~~~~~
     | Exception calling "CommitChanges" with "0" argument(s): "Access is denied. "
```

No log was generated by LDAP Add/Modify restrictions. I still feel like this should have worked and I'm needing to double-check my work as this should have granted StandardUser both CreateChild dMSA and WriteProperty dMSA.

## StandardUser in GenericAll-All Group

I'm unsurprised that this configuration worked. The [AbuseLog](/Experiments/StandardUserInGenericAll-All/AbuseLog.txt) shows no issues creating the dMSA or using Rubeus to abuse it.

The thing to note here is that no Event ID 3047 was generated for this LDAP Add Operation. Why? My hypothesis is that the [Per Attribute Authorization for Add Operation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ff004f3e-8920-4ba4-aaa7-346710171972), Step 4 checks if StandardUser has WriteDACL permissions, which it would because GenericAll permissions include WriteDACL. We'll test this further with a combination of permissions.

## StandardUser attacks a Container

For this test, StandardUser is a member of CreateChildObjects-All:
![StandardUserMemberOf](/Experiments/Container/MemberOf.png)

And CreateChildObjects-All has been granted CreateChild permissions on the CN=System,DC=domain,DC=root container. This is not an organizational unit, but rather it is objectClass container.

On the first attempt, we get:

```PowerShell
MethodInvocationException: C:\Scripts\Pentest-Tools-Collection\Tools\ActiveDirectory\BadSuccessor.ps1:221:9
Line |
 221 |          $newChild.CommitChanges()
     |          ~~~~~~~~~~~~~~~~~~~~~~~~~
     | Exception calling "CommitChanges" with "0" argument(s): "The server is unwilling to process the request. "
```

Intersting, but makes sense. We probably shouldn't be creating accounts in the System container. And I'll be curious to understand exactly what the mechanism is that prevents this.

What if we try on the CN=Computers container instead?
![ComputersSecurityDescriptor](/Experiments/Container/ComputersContainerSecurityDescriptor.png)

This worked fine and was [abuseable](/Experiments/Container/AbuseLog.txt). While, as I said in my Understanding & Mitigating BadSuccessor blog, it's more likely to see permissions delegated that allow low-privileged users to CreateChild objects in OUs, it's just as possible for the right to be delegated on a container.
![SU-Container](/Experiments/Container/ComputersContainer.png)

All of my attempts to create a dMSA in a container, even the ones in the System container which met other constraints and failed, generated 3047 events, noting that these would have been prevented if dSHeuristics flag 28 was set to 1.

## StandardUser Mixed Permissions - Mix1

After the GenericAll-All test, I was curious if it was the WriteDACL component of the GenericAll access mask mapping or the WriteProperty bit. Let's find out.

First, creating a new group "WriteDACL" and granting it WriteDACL permissions on the dMSA OU:
![WriteDACL](/Experiments/StandardUserMix1/dMSAADUCSecurityDescriptor.png)

StandardUser will be in CreateChildObject-All and WriteDACL:
![StandardUserMemberOf](/Experiments/StandardUserMix1/MemberOf.png)

And with Mix1 we have a successful creation of the dMSA and abuse of BadSuccessor. Per my hypothesis in the StandardUserInGenericAll-All section, steps 4 & 5 of the [Per Attribute Authorization for Add Operation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ff004f3e-8920-4ba4-aaa7-346710171972) took effect because StandardUser was granted explicit WriteDACL permissions on the dMSA OU.

But there are other rules also...

## Standard User Mixed Permissions - Mix2

## dSHeuristics AttributeAuthorizationOnLDAPAdd = 1

# $user.systemMayContain

These two attributes are included in the user objectClass's systemMayContain attributes:
msDS-SupersededManagedAccountLink
msDS-SupersededServiceAccountState

These relate to dMSA accounts. I presume they are linked attributes to the dMSA. It would be interesting to test if setting a Deny ACE on AdminSDHolder would prevent this attribute from being populated by a dMSA, and thus prevent the BadSuccessor attack.
