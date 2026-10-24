# Windows Security Log Investigation: Failed Logon

**Author:** Michael Bessard  
**Environment:** Windows Server 2025 VM, OT-DC01, Oracle VirtualBox  
**Test event:** October 19, 2026  
**Evidence exported:** October 24, 2026

## Overview

In this guided personal lab, I generated a failed logon attempt, located the corresponding Windows Security event with PowerShell, interpreted its fields, and exported the selected evidence. The investigation demonstrates log filtering, authentication-failure analysis, and evidence documentation.

## Scope and test

I confirmed the server name with `hostname` and checked the effective Logon audit policy:

```powershell
auditpol /get /subcategory:"Logon"
```

The result was **Success and Failure**.

I then attempted to launch a command prompt using a deliberately nonexistent lab account:

```powershell
runas /user:OT-DC01\LabInvalidUser01 cmd
```

I entered a made-up password at the prompt. Windows returned error **1326**, indicating an incorrect username or password. No account was created for this test.

## Investigation findings

| Field | Observed value | Interpretation |
| --- | --- | --- |
| Event ID | 4625 | A logon attempt failed |
| Record ID | 4409 | Identifies this record within the server's Security log |
| Time displayed | October 19, 2026, 3:25:14 AM | Timestamp as displayed by the VM |
| Subject account | OTLAB\Administrator | Account that initiated the request |
| Target account | OT-DC01\LabInvalidUser01 | Account used in the failed authentication attempt |
| Logon Type | 2 | Interactive logon type; consistent with this local runas test |
| Status | 0xC000006D | General invalid username or authentication information |
| Sub Status | 0xC0000064 | Specified username does not exist |
| Caller process | C:\Windows\System32\svchost.exe | Process recorded as the caller |
| Caller Process ID | 0x6c0 | Process identifier at the time of the event |
| Workstation | OT-DC01 | Workstation recorded in the event |
| Source address | ::1 | IPv6 loopback address |
| Source port | 0 | No usable remote source port recorded |
| Logon process | seclogo | Consistent with the Secondary Logon activity in this test |
| Authentication package | Negotiate | Does not alone identify the ultimately selected authentication protocol |

The specific substatus establishes that this attempt failed because the username did not exist. The general failure text alone could also describe an incorrect password.

The loopback address and known local test activity support a local origin. Although I entered `runas`, the event records `svchost.exe` as its caller; the report preserves the observed value.

## PowerShell retrieval

I used a fixed date range to retrieve the original event after returning to the lab several days later:

```powershell
$labEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = [datetime]'2026-10-19'
    EndTime = [datetime]'2026-10-20'
} | Where-Object {
    $_.ToXml() -match 'LabInvalidUser01'
}

$labEvents | Format-List TimeCreated, RecordId, Id, MachineName, Message
```

The event-ID and date filters narrow the search. The XML text match then selects events containing the test username. This is a simple lab filter, not a production detection rule.

## Evidence export

I exported the selected events as readable UTF-8 text:

```powershell
$labFolder = "$env:USERPROFILE\Documents\Windows-Security-Lab"
New-Item -ItemType Directory -Path $labFolder -Force | Out-Null

$labEvents |
    Format-List TimeCreated, RecordId, Id, MachineName, Message |
    Out-File "$labFolder\failed-logon-evidence.txt" -Encoding utf8 -Width 240
```

I opened the file in Notepad and verified Record ID 4409 and Event ID 4625. I transferred it to the host using a dedicated VirtualBox shared folder after installing Guest Additions.

This file is a readable text export, not a native EVTX export or a complete forensic acquisition. The source Security log was not cleared.

## Evidence files

- [Selected failed-logon evidence](failed-logon-evidence.txt)
- [Audit policy](01-audit-policy.png)
- [Failed runas attempt](02-failed-login-test.png)
- [Event account and failure details](03-event-details.png)
- [Process and source information](04-process-and-source.png)

## Conclusion and limits

The reviewed event is explained by the deliberate attempt to authenticate as nonexistent account LabInvalidUser01. It is expected lab activity.

A single failed logon does not establish an attack. This investigation does not establish the absence of compromise elsewhere on the system. In a real investigation, I would review the frequency, targeted accounts, source information, related successful logons, and user activity before deciding whether escalation was warranted.

## Lessons learned

- Distinguish the subject account from the target account.
- Use Status and Sub Status together to explain an authentication failure.
- Treat loopback and process fields as evidence requiring context.
- Verify exported evidence before publishing it.
- Use fixed date ranges when investigating older events.
- Separate observed facts, known test context, and conclusions.

## Reference

[Microsoft Learn: Event 4625 — An account failed to log on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)

This project uses my personal lab VM and contains no employer logs or production configurations.

