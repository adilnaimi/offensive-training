# Goal
Detect artifacts related to DCSYNC operations in the network and how it's being used to credentials dumping

# Categorization
These attempts are categorized as [Credential Access using the DCSync Credential Dumping technique DCsync](https://attack.mitre.org/techniques/T1003/).

# Strategy Abstract
The strategy will function as follows:
* Discovers Domain Controller in the specified domain name.
* Requests the Domain Controller replicate the user credentials via [GetNCChanges](https://msdn.microsoft.com/en-us/library/dd207691.aspx) (leveraging [Directory Replication Service (DRS) Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47?redirectedfrom=MSDN))

# Technical Context
DCSYNC is a technique takes advantage of how domain controllers legitimately replicate domain objects. With the right permissions, it allows attackers to impersonate domain controllers and request the hashed credentials for any other users on the domain. It’s also a stealthy option; the attacker doesn’t need to run any malicious code on the domain controller and can selectively target the credentials of specific accounts.


When configured correctly, AD Domain Controllers will record Event IDs for group modifications. The following event IDs are of interest for this ADS: 

|Event ID|Event Name|Log Provider|Audit Category|Audit Subcategory|ATT&CK Data Source|
|----------|-----------|----------|-----------|-----------|-----------|
4662|An operation was performed on an object|Microsoft-Windows-Security-Auditing|Directory Service Access|Audit Directory Service Access|Windows Event Logs|

## DCSync Permissions
The permissions needed vary based on domain functional level, explained in the [DACL required on each directory partition](https://support.microsoft.com/en-us/kb/2022387):

|Attribute Name|Attribute Value|Description|
|----------|-----------|-----------|
Access Mask|0x100|Control Access - “Access allowed only after extended rights checks supported by the object are performed. The right to perform an operation controlled by an extended access right.” - [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584)|
Properties|1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|[DS-Replication-Get-Changes](https://docs.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes?redirectedfrom=MSDN)|
Properties|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|[Replicating Directory Changes All](https://msdn.microsoft.com/en-us/library/ms684355(v=vs.85).aspx)|
Properties|89e95b76-444d-4c62-991a-0facbeda640c|[Replicating Directory Changes In Filtered Set](https://msdn.microsoft.com/en-us/library/hh338663(v=vs.85).aspx)|

By using [HELK](https://github.com/Cyb3rWard0g/HELK) and Leveraging the Kibana query engine KQL using the above attributes, we used following Query to ectract the informtion from the collected data:

```
(event_id:4662 AND NOT user_name.keyword:*$ AND object_operation_type:"Object Access" AND object_access_mask_requested:"0x100" AND object_properties:("*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR "*89e95b76-444d-4c62-991a-0facbeda640c*"))
``

The Kibana Results: 

<img width="1361" alt="Screen Shot 2019-11-13 at 10 59 20 AM" src="https://user-images.githubusercontent.com/1929963/68831341-193a6900-06bf-11ea-98b8-ab4dfdb71aad.png">


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
