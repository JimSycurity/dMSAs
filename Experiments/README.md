# BadSuccessor Experimentation

After getting a few questions on reddit and seeing a [LinkedIn post by Andrea Pierini](https://www.linkedin.com/posts/andrea-pierini_badsuccessor-activity-7333868453453344770-7dEZ), started to question some conclusions I had made earlier this week around the mitigations in [KB5008383](https://support.microsoft.com/en-us/topic/kb5008383-active-directory-permissions-updates-cve-2021-42291-536d5555-ffba-4248-a60e-d6cbc849cde1) in my [Understanding & Mitigating BadSuccessor blog](https://specterops.io/blog/2025/05/27/understanding-mitigating-badsuccessor/).

![Andrea Pierini on LinkedIn](/Experiments/AndreaPieriniLIPost.png)

I decided to redo my lab testing with a more rigorous, repeatable methodology as I missed what Andrea did about the 28th flag of dSHeuristics initially. Back to [KB5008383](https://support.microsoft.com/en-us/topic/kb5008383-active-directory-permissions-updates-cve-2021-42291-536d5555-ffba-4248-a60e-d6cbc849cde1) we go!

First, I (re)set the dSHeuristics value in the 'domain.root' AD Forest I'm testing in

- [AttributeAuthorizationOnLDAPAdd](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ff004f3e-8920-4ba4-aaa7-346710171972), which is flag 28 to 0. This configures Additional Authorization Verification for LDAP Add Operators for computer-derived objects to Audit mode.
- [BlockOwnerImplicitRights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/fb7c101d-ec8b-4fbf-bca8-7d7c2d747d0c), which is flag 29 to 1. This configures the Temporary removal of Implicit Owner privileges on LDAP modify operation of the nTSecurityDescriptor on computer-derived objects to enforcement mode.

I've gone through testing with the Implicit Owner Rights removal flag (29) in my [Owner or Pwned? paper](https://www.hub.trimarcsecurity.com/post/trimarc-whitepaper-owner-or-pwnd) and feel I understand it as it relates to the issues in BadSuccessor so I can go straight to block mode there.
This is a different path than what Adrea chose in his research as he set 28 to 1 and 29 to 0. I just want to audit LDAP Add operations for now.

```PowerShell
### WARNING: Before setting the dSHeuristics attribute, always check to see how it is currently configured first:
#Query Current dSHeuristics in current AD Forest
(Get-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Properties dSHeuristics).dSHeuristics

## Set dSHeuristics to Audit LDAP Add and Block LDAP Modify
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

The results of this test sequence surprised me at first. The [log](/Experiments/StandardUserInGenericAll-dMSA/AbuseLog.txt) shows that StandardUser with this set of delegated rights was unable to create the dMSA object.

```
MethodInvocationException: C:\Scripts\Pentest-Tools-Collection\Tools\ActiveDirectory\BadSuccessor.ps1:221:9
Line |
 221 |          $newChild.CommitChanges()
     |          ~~~~~~~~~~~~~~~~~~~~~~~~~
     | Exception calling "CommitChanges" with "0" argument(s): "Access is denied. "
```

No log was generated by LDAP Add/Modify restrictions. I felt like this should have worked and I'm needing to double-check my work as this should have granted StandardUser both CreateChild dMSA and WriteProperty dMSA.

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

Another thing to note here is that there was no 3047 Event ID Created. This is because the rules were satisfied and this LDAP Add Operation would have worked even if dSHeuristics flag 28 were set.

But there are other rules also...

## StandardUser Mixed Permissions - Mix2

Now we'll ditch the WriteDACL group and permission and add StandardUser to the GenericWrite-All group. GenericWrite is a generic mapping which consists of WriteProperty, ReadControl, and Self (ValidatedWrite) access mask. We'll be keeping the CreateChildObject-All membership with its associated CreateChild permissions grant.

![StandardUserMemberOf](/Experiments/StandardUserMix2/MemberOf.png)

With Mix2 the dMSA was successfully created and the [abuse](/Experiments/StandardUserMix2/AbuseLog.txt) was successful. In the[Per Attribute Authorization for Add Operation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ff004f3e-8920-4ba4-aaa7-346710171972) rules, this combination of permissions would get us all the way to Step 11 successfully because there are no attributes which StandardUser doesn't have WriteProperty to with GenericWrite on all objects.

Additionally, no Event ID 3047 was generated, again because the check succeeds against the rules.

## StandardUser Mixed Permissions - Mix3

We'll keep the CreateChildObject-All group membership, remove the GenericWrite-All group membership, and add StandardUser to the WriteProperty-msDS-ManagedAccountPrecedByLink group.
![StandardUserMemberOf](/Experiments/StandardUserMix3/MemberOf.png)

I expected this to work, with flag 28 set to only audit. The dMSA was created and the [abuse](/Experiments/StandardUserMix3/AbuseLog.txt) was successful.

But we did get an Event ID 3047, which I also expected. And I did this Mix3 just to show this:

> Denied attributes:
> msDS-GroupMSAMembership
> msDS-SupportedEncryptionTypes

Previously, when StandardUser had only CreateChildObject-gMSA or CreateChildObject-All, there were 3 Denied attributes:
![3 Denied Attributes](/Experiments/StandardUserMix3/3deniedattributesfromjustCreateChild.png)

In this latest Mix3 test, StandardUser had rights to WriteProperty on the msDS-ManagedAccountPrecededByLink attribute, which is why it wasn't included in the Denied Attributes on this test.

## StandardUser Mixed Permissions - Mix4

This will be the final test with dSHeuristics flag 28 set to 0 for Audit mode.

StandardUser is now a member of CreateChildObject-All and GenericAll-dMSA.
![StandardUserMemberOf](/Experiments/StandardUserMix4/MemberOf.png)

This test successfully created the dMSA and abused BadSuccessor without generating any 3047 EventID.

The reason why the "StandardUser in GenericAll-dMSA Group" test was unsuccessful in creating the dMSA is because of how this specific ACE is configured:
![GenericAll-dMSA ACE](/Experiments/StandardUserMix4/GenericAll-dMSA%20ACE.png)

This ACE grants GenericAll permissions, which ought to be everything. And it is, but it only applies to Descendent msDS-DelegatedManagedServiceAccounts, not to the dMSA OU where it is defined. So StandardUser had rights to modify all the attributes of the dMSA if it was created, but not actually create it. This is why mixing GenericAll-dMSA and CreateChildObject-All together worked. CreateChildObject-All allowed creating the dMSA and GenericAll-dMSA satisfied the access check requirements for all the attributes.

## dSHeuristics AttributeAuthorizationOnLDAPAdd = 1

Now we're going to set dSHeuristics to block mode for both LDAP Add and LDAP Modify per the full enforcement mode for KB5008383:

```PowerShell
Set-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -replace @{dSHeuristics='00000000010000000002000000011'}
```

After changing the dSHeuristics value, Domain Controllers must be rebooted before the setting takes effect on each individual DC. Then we check for the appropriate event logs:
![EventID3050](/Experiments/dSHeuristicsEnabled/EventID3050.png)
![EventID3053](/Experiments/dSHeuristicsEnabled/EventID3053.png)

### Enforcement Mode Test1

For the Test1 with Enforcement mode we'll try StandardUser in CreateChildObjects-All only:
![Test1MemberOf](/Experiments/dSHeuristicsEnabled/Test1MemberOf.png)

Woot! AttributeAuthorizationOnLDAPAdd Enforcement mode blocks the abuse with straight-up CreateChild permissions. Just as Andrea's LinkedIn post said it would.
![Test1Fail](/Experiments/dSHeuristicsEnabled/Test1Fail.png)

Instead of a 3047 event, we now have a 3044 event:
![Test1EventID3044](/Experiments/dSHeuristicsEnabled/Test1EventID3044.png)

StandardUser doesn't have permissions to write to the 3 Denied attributes, so it's a no-go.

### Enforcement Mode Test2

CreateChild alone is blocked by dSHeuristics, but what if we have CreateChild and WriteDACL?
![Test2MemberOf](/Experiments/dSHeuristicsEnabled/Test2MemberOf.png)

Ope! Now we can create the dMSA and [abuse](/Experiments/dSHeuristicsEnabled/Test2AbuseLog.txt) BadSuccessor again. dSHeuristics Enforcement mode is not a panacea. It will only prevent LDAP Add abuses when the security principal does not also have either explicit WriteDACL (instead of implicit WriteDACL from being the object owner) or permissions to write to all the attributes supplied in the add request.

There is also, unsurprisingly, no event created in the logs, as the add request succeeded on all requirements.

### Enforcement Mode Test3

I'm not going to bother testing again with GenericAll permissions here, because GenericAll permissions include WriteDACL. I'll save that for the final test.

We are going to test with WriteProperty and CreateChild:
![Test3MemberOf](/Experiments/dSHeuristicsEnabled/Test3MemberOf.png)

It's no surprise that this test created the dMSA and [abused](/Experiments/dSHeuristicsEnabled/Test3AbuseLog.txt) BadSuccessor successfully. Also not surprised to see no event created as all tests succeed.

The dSHeuristics Enforcement Mode for KB5008383 is effective when a security principal is only granted CreateChild permissions on an OU or container. It is not effective if the user has WriteDACL, GenericWrite, or WriteProperty in addition to CreateChild. It also isn't effective in instances where a low-privileged user, which is not Tier Zero, is granted GenericAll permissions on an OU or container.

The dSHeuristics Enforcement Mode is more effective than my original DACL-based ACE rules if the only permission we are concerned about is CreateChild. However, the addition of the Deny msDS-ManagedAccountPrecededByLink could be effective in combination with Enforcement mode. Or if the organization is not yet prepared to do the testing and audit collection required to successfully and safely implement the dSHeuristics Enforcement mode, the full 3 ACEs can still provide protection in the interim.

## Enforcement & DACLs

I'm going to do one final test. I'll leave StandardUser in the same WriteProperty and CreateChild groups, but I'm going to use Add-BadSuccessorOUDenyACEs to create these Deny ACEs:
![Deny ACEs](/Experiments/EnforcementAndDACLs/DenyACEs.png)

And this attempt to create a dMSA was denied. No 3044 EventID, because StandardUser was denied by the Deny CreateChild dMSA ACE. Let's remove that and try again.

Access denied again on the dMSA creation, but this time we have an Event ID 3044 to go with it, which explains why StandardUser was denied this time:
![DeniedbymsDS-ManagedAccountPrecededByLink](/Experiments/EnforcementAndDACLs/DeniedAgain.png)

The combination of dSHeuristics Enforcement and Add-BadSuccessorOUDenyACEs prevents BadSuccessor abuse unless the attacker has gained WriteDACL (or GenericAll which includes WriteDACL) permission. This is likely the most secure configuration until Microsoft remediates the issue.

# dSHeuristic Modes

To set the dSHeuristics for LDAP Add and LDAP Modify both to Audit mode for KB5008383, first check what your current dSHeuristics setting:

```PowerShell
#Query Current dSHeuristics in current AD Forest
(Get-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Properties dSHeuristics).dSHeuristics
```

If no other bits are set other than the 10th and 20th bits, you can set it to Audit mode:

```PowerShell
## Configure dSHeuristics to Audit LDAP Add & Modify
Set-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -replace @{dSHeuristics='00000000010000000002000000000'}
```

If you have audited your systems and wish to move to Enforcement mode:

```PowerShell
## Configure dSHeuristics to Enforcement Mode for LDAP Add & Modify
Set-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -replace @{dSHeuristics='00000000010000000002000000011'}
```

Note: Originally, Microsoft was going to automatically enable Enforcement Mode with a Patch Tuesday update in April 2023. It got pushed back to December 2023, and then apparently never? I would love to hear from someone at Microsoft why Enforcement mode for KB5008383 was seemingly delayed indefinately.

# Conclusion

I was incorrect in the Mitigation 2: Disable Implicit Owner Rights section of my Understanding & Mitigating BadSuccessor.

Andrea was correct, the dSHeuristics flag 28 does block dMSA creation for BadSuccessor based only on CreateChild permissions.

As noted in Andrea's LinkedIn post, the LDAP Add Operation restrictions will not prevent abusing BadSuccessor if the attacker-controlled account has WriteDACL or the appropriate WriteProperty (or GenericWrite) permissions such that the LDAP Add Operation checks succeed instead of blocking.

Setting flag 28 to 1 for Enforcement and leaving flag 29 set to 0 or 2 (Audit or Allow) will not resolve the BadSuccessor abuse based only on CreateChild permissions as the attacker would be able to create a dMSA without pre-populating the attributes required for abuse, be the owner on the dMSA, and then using the implicit OwnerRights to WriteDACL to grant the attacker-controlled account GenericAll or WriteProperty All permissions on the dMSA and then make the attribute changes to impart the BadSuccessor abuse.

Configuring dSheuristics to both Block Implicit Owner Rights (flag 29) and Require Additional Authorization on LDAP Add Operations (flag 28) both to Enforcement mode (1) can prevent specific scenarios where a low-privileged principal has been granted only CreateChild rights on an OU or container with no additional rights.

Not much can prevent a low-privileged principal being granted WriteDACL or GenericAll on a container or OU from abusing BadSuccessor as the dSheuristics remediations for KB5008383 will not apply in those scenarios. And, of course, the DACL-based ACEs I've tested and created will not prevent an attacker with WriteDACL permissions from modifying the permissions the Add-BadSuccessorOUDenyACEs will create. Although, it could be a speedbump which could slow down or provide an opportunity for detection in scenarios where an attacker is only utilizing public offensive tooling for BadSuccessor which is not intelliigent enough to investigate the Deny permissions and remove them.

A combination of dSHeuristics and the DACL-based mitigations from Add-BadSuccessorOUDenyACEs will prevent an attacker-controlled principal which has been granted both CreateChild and either GenericWrite or WriteProperty on the OU or container.

As with most forms of defense, layers are multiple controls are the best path forward.

# Bonus: $user.systemMayContain

These two attributes are included in the user objectClass's systemMayContain attributes:
msDS-SupersededManagedAccountLink
msDS-SupersededServiceAccountState

These relate to dMSA accounts. I presume they are linked attributes to the dMSA. It would be interesting to test if setting a Deny ACE on AdminSDHolder would prevent this attribute from being populated by a dMSA, and thus prevent the BadSuccessor attack. Let's try it!
![Deny ACE on AdminSDHolder](/Experiments/AdminSDHolderDeny/AdminSDHolderDenyACE.png)

**Note: Tread lightly on modifying the security descriptor of AdminSDHolder. Whatever security descriptor is present on AdminSDHolder will also be stamped onto highly privileged Admin objects. Messing up the permissions on AdminSDHolder can result in creating attack paths or even potentially a self-DOS.**

I then forced the AdminSDHolder ProtectAdminGroups background task to run and validated that the Administrator account now has the Deny ACE from AdminSDHolder:
![Deny ACE on Administrator](/Experiments/AdminSDHolderDeny/AdministratorDenyACE.png)

We'll give StandardUser more than enough permissions to create the dMSA:
![MemberOf](/Experiments/AdminSDHolderDeny/MemberOf.png)

StandardUser was allowed to create the dMSA.

That didn't go quite as planned, but upon closer inspection of the Administrator account, perhaps this is a hint:
![msDSManagedAccountPrecededByLinkBL](/Experiments/AdminSDHolderDeny/AdministratorPrecededByLinkBL.png)

I created a Deny ACE for msDS-SupersededManagedAccountLink, but in viewing the Administrator object that StandardUser has been abusing the heck out of with BadSuccessor, this particular attribute isn't populated at all. Instead its msDS-ManagedAccountPrecededByLinkBL.

This means that msDS-ManagedAccountPrecededByLinkBL is the link attribute to corresponding to msDS-ManagedAccountPrecededByLink. Let's do some AD Schema archaology.

```PowerShell
# There are more efficient ways to do this but RAM is cheap and I like to keep reusing the same objects.
Import-Module ActiveDirectory
# Get the path of the Schema NC
$schemapath = (Get-ADRootDSE).schemanamingContext
# Grab the entire AD Schema into the $Schema object
$Schema = Get-AdObject -Filter * -SearchBase $schemapath -Properties *

# Sort out ClassSchema and AttributeSchema
$Classes = $Schema | Where-Object {$_.ObjectClass -eq 'classSchema'}
$Attributes = $Schema |  Where-Object {$_.ObjectClass -eq 'attributeSchema'}

# Sort out the dMSA attributes we're interested in
$msDSDelegatedMSAState = $Attributes | Where-Object {$_.ldapDisplayName -eq 'msDS-DelegatedMSAState'}
$msDSManagedAccountPrecededByLink = $Attributes | Where-Object {$_.ldapDisplayName -eq 'msDS-ManagedAccountPrecededByLink'}
$msDSGroupMSAMembership  = $Attributes | Where-Object {$_.ldapDisplayName -eq 'msDS-GroupMSAMembership'}
$msDSSupersededManagedAccountLink = $Attributes | Where-Object {$_.ldapDisplayName -eq 'msDS-SupersededManagedAccountLink'}
$msDSManagedAccountPrecededByLinkBL  = $Attributes | Where-Object {$_.ldapDisplayName -eq 'msDS-ManagedAccountPrecededByLinkBL'}

# Resolve the SchemaIDGUIDs from a bytearray to a GUID object
$msDSDelegatedMSAStateSchemaGuid = $msDSDelegatedMSAState.schemaIDGUID -as [guid]
$msDSManagedAccountPrecededByLinkSchemaGuid = $msDSManagedAccountPrecededByLink.schemaIDGUID -as [guid]
$msDSGroupMSAMembershipSchemaIDGuid = $msDSGroupMSAMembership.schemaIDGUID -as [guid]
$msDSSupersededManagedAccountLinkGUID = $msDSSupersededManagedAccountLink.schemaIDGUID -as [guid]
$msDSManagedAccountPrecededByLinkBLGUID = $msDSManagedAccountPrecededByLinkBL.schemaIDGUID -as [guid]

# Here's the attribute I originally set the Deny ACE on that didn't block anything:
PS C:\Users\Administrator> $msDSSupersededManagedAccountLink


adminDescription                : This attribute is the forward link from a service account to a delegated managed service account object.
adminDisplayName                : ms-DS-Superseded-Managed-Account-Link
attributeID                     : 1.2.840.113556.1.4.2373
attributeSyntax                 : 2.5.5.1
CanonicalName                   : domain.root/Configuration/Schema/ms-DS-Superseded-Managed-Account-Link
CN                              : ms-DS-Superseded-Managed-Account-Link
Created                         : 7/21/2023 11:03:06 AM
createTimeStamp                 : 7/21/2023 11:03:06 AM
Deleted                         :
Description                     :
DisplayName                     :
DistinguishedName               : CN=ms-DS-Superseded-Managed-Account-Link,CN=Schema,CN=Configuration,DC=domain,DC=root
dSCorePropagationData           : {12/31/1600 6:00:00 PM}
instanceType                    : 4
isDeleted                       :
isSingleValued                  : True
LastKnownParent                 :
lDAPDisplayName                 : msDS-SupersededManagedAccountLink
linkID                          : 2222
Modified                        : 7/21/2023 11:03:06 AM
modifyTimeStamp                 : 7/21/2023 11:03:06 AM
Name                            : ms-DS-Superseded-Managed-Account-Link
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Attribute-Schema,CN=Schema,CN=Configuration,DC=domain,DC=root
ObjectClass                     : attributeSchema
ObjectGUID                      : 1f2f2609-1993-495a-9b07-7c0485b6f18b
oMObjectClass                   : {43, 12, 2, 135...}
oMSyntax                        : 127
ProtectedFromAccidentalDeletion : False
schemaIDGUID                    : {2, 224, 82, 55...}
sDRightsEffective               : 15
searchFlags                     : 0
showInAdvancedViewOnly          : True
systemFlags                     : 16
systemOnly                      : False
uSNChanged                      : 1504
uSNCreated                      : 1504
whenChanged                     : 7/21/2023 11:03:06 AM
whenCreated                     : 7/21/2023 11:03:06 AM

# Here's the attribute on the dMSA that allows BadSuccessor to imitate the account:
PS C:\Users\Administrator> $msDSManagedAccountPrecededByLink


adminDescription                : This attribute is the forward link from a delegated managed service account to a service account object.
adminDisplayName                : ms-DS-Managed-Account-Preceded-By-Link
attributeID                     : 1.2.840.113556.1.4.2375
attributeSyntax                 : 2.5.5.1
CanonicalName                   : domain.root/Configuration/Schema/ms-DS-Managed-Account-Preceded-By-Link
CN                              : ms-DS-Managed-Account-Preceded-By-Link
Created                         : 7/21/2023 11:03:06 AM
createTimeStamp                 : 7/21/2023 11:03:06 AM
Deleted                         :
Description                     :
DisplayName                     :
DistinguishedName               : CN=ms-DS-Managed-Account-Preceded-By-Link,CN=Schema,CN=Configuration,DC=domain,DC=root
dSCorePropagationData           : {12/31/1600 6:00:00 PM}
instanceType                    : 4
isDeleted                       :
isSingleValued                  : True
LastKnownParent                 :
lDAPDisplayName                 : msDS-ManagedAccountPrecededByLink
linkID                          : 2224
Modified                        : 7/21/2023 11:03:06 AM
modifyTimeStamp                 : 7/21/2023 11:03:06 AM
Name                            : ms-DS-Managed-Account-Preceded-By-Link
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Attribute-Schema,CN=Schema,CN=Configuration,DC=domain,DC=root
ObjectClass                     : attributeSchema
ObjectGUID                      : 9d0165d9-ccb9-4e1a-8db0-7bb13aa1b5c9
oMObjectClass                   : {43, 12, 2, 135...}
oMSyntax                        : 127
ProtectedFromAccidentalDeletion : False
schemaIDGUID                    : {43, 91, 148, 160...}
sDRightsEffective               : 15
searchFlags                     : 0
showInAdvancedViewOnly          : True
systemFlags                     : 16
systemOnly                      : False
uSNChanged                      : 1506
uSNCreated                      : 1506
whenChanged                     : 7/21/2023 11:03:06 AM
whenCreated                     : 7/21/2023 11:03:06 AM
WriteDebugStream                : {}
WriteErrorStream                : {}
WriteInformationStream          : {}
WriteVerboseStream              : {}
WriteWarningStream              : {}

# And here's the BackLink attribute for msDS-ManagedAccountPrecededByLink, which shows up populated on the Administrator account we've been abusing:
PS C:\Users\Administrator> $msDSManagedAccountPrecededByLinkBL


adminDescription                : This attribute is the back link from a delegated managed service account to a service account object.
adminDisplayName                : ms-DS-Managed-Account-Preceded-By-LinkBL
attributeID                     : 1.2.840.113556.1.4.2376
attributeSyntax                 : 2.5.5.1
CanonicalName                   : domain.root/Configuration/Schema/ms-DS-Managed-Account-Preceded-By-LinkBL
CN                              : ms-DS-Managed-Account-Preceded-By-LinkBL
Created                         : 7/21/2023 11:03:06 AM
createTimeStamp                 : 7/21/2023 11:03:06 AM
Deleted                         :
Description                     :
DisplayName                     :
DistinguishedName               : CN=ms-DS-Managed-Account-Preceded-By-LinkBL,CN=Schema,CN=Configuration,DC=domain,DC=root
dSCorePropagationData           : {12/31/1600 6:00:00 PM}
instanceType                    : 4
isDeleted                       :
isSingleValued                  : True
LastKnownParent                 :
lDAPDisplayName                 : msDS-ManagedAccountPrecededByLinkBL
linkID                          : 2225
Modified                        : 7/21/2023 11:03:06 AM
modifyTimeStamp                 : 7/21/2023 11:03:06 AM
Name                            : ms-DS-Managed-Account-Preceded-By-LinkBL
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Attribute-Schema,CN=Schema,CN=Configuration,DC=domain,DC=root
ObjectClass                     : attributeSchema
ObjectGUID                      : 840258cb-cb28-47f4-bc38-1e2298be2ab1
oMObjectClass                   : {43, 12, 2, 135...}
oMSyntax                        : 127
ProtectedFromAccidentalDeletion : False
schemaIDGUID                    : {240, 74, 119, 148...}
sDRightsEffective               : 15
searchFlags                     : 0
showInAdvancedViewOnly          : True
systemFlags                     : 17
systemOnly                      : False
uSNChanged                      : 1507
uSNCreated                      : 1507
whenChanged                     : 7/21/2023 11:03:06 AM
whenCreated                     : 7/21/2023 11:03:06 AM
```

We can tell that msDS-ManagedAccountPrecededByLinkBL and msDS-ManagedAccountPrecededByLink are Linked Attributes, not just by their name and description but because of their LinkID properties: 2224 & 2225. Why not grab the SchemaIDGuid from msDS-ManagedAccountPrecededByLinkBL and create a new Deny ACE on AdminSDHolder?

```PowerShell
PS C:\Users\Administrator> $msDSManagedAccountPrecededByLinkBLGUID

Guid
----
94774af0-5355-402c-9c9a-12470c873e4a
```

After removing the old Deny ACE on AdminSDHolder, creating the new one, and forcing ProtectAdminGroups to run the Administrator SD looks like this:
![Administrator Security Descriptor Take 2](/Experiments/AdminSDHolderDeny/AdministratorDenyACETake2.png)

That did not block the creation of the dMSA or the abuse of it either. I presume this is because it's not possible to Deny Write access to a BackLink attribute because it's a computed property which doesn't really exist beyond being an entry in the NTDS.dit link table.

Since we can't deny write on a backlink attribute, we probably can't audit on it with a SACL either, but let's try anyway:
![SACL on Administrator account](/Experiments/AdminSDHolderDeny/AdministratorSACLACETake3.png)

The dMSA is created, the abuse is successful. Let's see if we have a SACL log entry.... Nope. Can't appear to audit on backlink attributes either.

While looking for an audit entry, I did find this Event ID 4627 which is interesting:
![Event 4627 Group Membership for SU-ADSHDeny3$](/Experiments/AdminSDHolderDeny/Event4627GroupMembershipTake3.png)

The time of this event corresponds with when I requested a TGS for the dMSA with Rubeus. Note the group memberships, which correspond to the membership of the Administrator user we've superseded, not the SU-ADSHDeny3$ dMSA that we requested a ticket for.

```PowerShell
PS C:\Users\Administrator> $dMSA = Get-ADServiceAccount -Identity SU-ADSHDeny3 -Properties *
$dMSA.MemberOf

PS C:\Users\Administrator>

PS C:\Users\Administrator> $dMSA = Get-ADServiceAccount -Identity SU-ADSHDeny3 -Properties *
$dMSA.MemberOf

PS C:\Users\Administrator>
$Administrator = Get-ADUser -Identity Administrator -Properties *
$Administrator.MemberOf
CN=Group Policy Creator Owners,CN=Users,DC=domain,DC=root
CN=Domain Admins,CN=Users,DC=domain,DC=root
CN=Enterprise Admins,CN=Users,DC=domain,DC=root
CN=Schema Admins,CN=Users,DC=domain,DC=root
CN=Administrators,CN=Builtin,DC=domain,DC=root

PS C:\Users\Administrator>
```
