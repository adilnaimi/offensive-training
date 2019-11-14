# Goal
Detect artifacts related to DCSYNC operations in the network and how it's being used to credentials

# Categorization
These attempts are categorized as [Credential Dumping / DCsync](https://attack.mitre.org/techniques/T1003/).

# Strategy Abstract
The strategy will function as follows:

* Collect Windows Event Logs related to AD group changes. 
* Compare AD group changes against a list of privileged groups.
* Alert on any unusual changes to privileged groups.

# Technical Context
 DCSYNC is a technique takes advantage of how domain controllers legitimately replicate domain objects. With the right permissions, it allows attackers to impersonate domain controllers and request the hashed credentials for any other users on the domain. It’s also a stealthy option; the attacker doesn’t need to run any malicious code on the domain controller and can selectively target the credentials of specific accounts.


When configured correctly, AD Domain Controllers will record Event IDs for group modifications. The following event IDs are of interest for this ADS: 

|Event Code|Description|
|----------|-----------|
4727|A security-enabled global group was created.|
4728|A member was added to a security-enabled global group.|
4729|A member was removed from a security-enabled global group.|
4730|A security-enabled global group was deleted.|
4754|A security-enabled universal group was created.|
4756|A member was added to a security-enabled universal group.|
4757|A member was removed from a security-enabled universal group.|
4758|A security-enabled universal group was deleted.|
4764|A group's type was changed.|
4662| An operation was performed on an object.|

The following AD builtin groups are monitored for changes: 

|Group Name|Description|
|----------|-----------|
Administrators|Builtin administrators group for the domain|
Domain Admins|Builtin administrators group for the domain|
Enterprise Admins|Builtin administrators group for the domain|
Schema Admins|Highly privileged builtin group|
Account Operators|Highly privileged builtin group|
Backup Operators|Highly privileged builtin group|

# Blind Spots and Assumptions
This strategy relies on the following assumptions:
* Group change event auditing is enabled by GPO.
* Group change events are written to the Windows Event Log.
* The DCs are correctly forwarding the group change events to WEF servers.
* WEF servers are correctly forwarding events to the SIEM.
* SIEM is successfully indexing group change events. 
 
A blind spot will occur if any of the assumptions are violated. For instance, the following would not trip the alert:
* Windows event logging breaks. 
* A group is modified in a manner which does not generate an event log. 
* A legitimate account in a sensitive group is hijacked. 
* A sensitive group is not correctly added to the monitoring list. 

# False Positives
There are several instances where false positives for this ADS could occur:
* Legitimate changes to the group are made as part of sanctioned systems administration activities. 
* Automation scripts remove leavers from privileged groups.

# Priority
The priority is set to high under the following conditions: 
* A new user is added to a builtin Windows group.
* A new user is added to a Tier-0 administration group. 

The priority is set to medium under the following conditions:
* A new user is added to a Tier-1 administration group.

The priority is set to low under the following conditions:
* The group modification event is a removal. 

# Validation
Enumerate members of the domain admins group

Validation can occur for this ADS by performing the following execution on a Windows host with RSAT installed:

```
powershell_execute 'Get-DomainGroupMember -Identity "svc_accts" |select  MemberName,MemberObjectClass'
``` 

# Response
In the event that this alert fires, the following response procedures are recommended:
* Validate the group modified, user added and the user making the change.
  * If the user making the change is not an administrator at the appropriate permissions level, escalate to a security incident.
  * If the user added to the group is not a member of an administratively relevant team, escalate to a security incident. 
  * If the user added to the group is a new account, escalate to a security incident. 
* Validate there is a change management ticket or announcement for the change.
  * If there is no change management ticket or announcement, contact the user who made the change.
  * If the user is unaware of the activity, escalate to a security incident.

# Additional Resources
* [Privileged Groups in AD](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [Securing PAM](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material)
