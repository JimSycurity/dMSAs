# dMSAs
## Exploring Delegated Managed Service Accounts

I've been thinking about Delegated Managed Service Accounts (dMSA) since Windows Server vNext was the pre-release Server 2025 version and included the new msDS-DelegatedManagedServiceAccount object class.  Yuval Gordon at Akamai released his blog [BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory) on May 21, 2025.  The release of Yuval's blog and the subsequent release of attack tooling by several others brought dMSAs back to the top of my TODO list.

In a nutshell, BadSuccessor allows anyone who can create or compromise a Delegated Managed Service Account (dMSA) in any AD Forest where at least 1 Windows Server 2025 Domain Controller (DC) is in place and a KDS Root Key has been generated to abuse the created or compromised dMSA to perform an Escalation of Privilege (EoP) to any security principal, including a member of Domain Admins. BadSuccessor can also be abused to recover the keys of a superseded account, which is a form of credential theft that can also result in full AD Forest compromise. 

## BadSuccessor Mitigations
My blog on [Understanding & Mitigating BadSuccessor](https://specterops.io/blog/2025/05/27/understanding-mitigating-badsuccessor/) is intended to understand BadSuccessor from an attack path point of view, dig into the details of the DACL abuse primitives that allow for an attacker to create or control a dMSA, and some ways to mitigate exposure to BadSuccessor until Microsoft can remediate the issue (hopefully).

As I explained in my [blog](https://specterops.io/blog/2025/05/27/understanding-mitigating-badsuccessor/), only Microsoft has the capability to address the dMSA being able to impersonate any security principal without constraint.  Only Microsoft has the capability to address the issue where there is no further constraint on anyone granted WriteProperty on the msDS-ManagedAccountPrecededByLink attribute of any dMSA objects.

The Mitigations folder of this GitHub repo includes a set of PowerShell scripts, each containing a corresponding function:
- Add-BadSuccessorOUDenyACEs.ps1
- Remove-BadSuccessorOUDenyACEs.ps1

***These PowerShell functions require appropriate privileged access to the environment in order to modify the permissions (WriteDACL) of the target OU(s).***

The Add-BadSuccessorOUDenyACEs.ps1 script contains the Add-BadSuccessorOUDenyACEs function.  This function has a mandatory DistinguishedName parameter, which can also be fed via pipeline.  The DistinguishedName parameter must be the DistinguishedName of an AD OU.  The additional optional NoDenyCreate, NoOwnerRights, and NoDenyWrite switches can control which of the 3 ACEs are created on the target OU.  By default, with no optional switches specified, the function will create all 3 ACEs on the target OU.

To target all OUs in the user's current domain:
```PowerShell
Get-ADOrganizationalUnit -Filter * | Add-BadSuccessorOUDenyACEs
```

The Remove-BadSuccessorOUDenyACEs is a cleanup script to remove these mitigations once Microsoft, hopefully, fully remediates the BadSuccessory issue with a patch.  It uses the same syntax as the Add-BadSuccessorOUDenyaCEs function with the exception that the RemoveAll switch will additionally remove the OwnerRights ACE, whereas by default only the 2 deny ACEs are removed.
To remove the BadSuccessor mitigation on all OUs in the user's current domain:
```PowerShell
Get-ADOrganizationalUnit -Filter * | Remove-BadSuccessorOUDenyACEs -RemoveAll
```

These scripts will not prevent an account which has or can get WriteDACL permissions on an OU from creating or modifying a dMSA.
BloodHound Community Edition and BloodHound Enterprise can map these attack paths for you:
```
MATCH p = (ou:OU)<-[:WriteDacl|Owns|GenericAll|WriteOwner]-(n:Base)
WHERE NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
RETURN p
LIMIT 1000
```

## BadSuccessor Checks
The BadSuccessor-3rdPartyChecks folder contains scripts from [Akamai](https://github.com/akamai/BadSuccessor) and [LuemmelSec](https://github.com/LuemmelSec).  I was in the process of writing a script, but theirs are better than what I was originally doing so I'm including them here with attribution.

## BadSuccessor Experiments
An attempt at cludging together a PowerShell function which doesn't require any AD RSAT tools to create a new dMSA using .NET methods and prepare it for BadSuccessor abuse.
