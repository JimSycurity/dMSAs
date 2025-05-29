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

## Standard User in CreateChildObjects-dMSA Group

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

1. We're in Audit mode, so we're not blocking.
2. StandardUser, based on the merged security descriptor in the event, which is created based on
