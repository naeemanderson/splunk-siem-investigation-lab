# Splunk SIEM Investigation Lab

## Overview

This project documents a hands-on SIEM investigation using Splunk Enterprise and Windows Security Event Logs.

The purpose of the lab was to investigate activity on a Windows endpoint, identify relevant process creation and scheduled task events, and correlate those events to reconstruct what occurred.

During the investigation, I used SPL queries to narrow the timeline and identify PowerShell, `schtasks.exe`, and Windows scheduled task creation activity.

The investigation ultimately identified a scheduled task named `ThreatHuntLab-TestTask` created by the `azureuser` account.

---

## Objectives

The objectives of this investigation were to:

- Analyze Windows Security logs in Splunk
- Practice writing and refining SPL searches
- Investigate Windows process creation events
- Identify parent and child process relationships
- Investigate Windows scheduled task activity
- Correlate multiple security events
- Reconstruct a timeline of endpoint activity
- Determine whether the observed activity was benign or suspicious

---

## Lab Environment

The investigation was performed in a controlled lab environment.

### Technologies Used

- Microsoft Azure
- Windows 11 Virtual Machine
- Splunk Enterprise
- Windows Security Event Logs
- PowerShell
- Windows Task Scheduler

### Relevant Windows Event IDs

| Event ID | Description |
| --- | --- |
| 4688 | A new process has been created |
| 4698 | A scheduled task was created |
| 4699 | A scheduled task was deleted |
| 4700 | A scheduled task was enabled |
| 4701 | A scheduled task was disabled |
| 4702 | A scheduled task was updated |

---
### Log Validation

I first confirmed that Windows Security logs were successfully being ingested into Splunk.

<img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/29427700-9209-495c-9f9a-e4c27f494063" />

# Investigation

## 1. Initial Process Investigation

I began by searching Windows Security logs for process creation activity.

Windows Security **Event ID 4688** records the creation of a new process and can provide useful information such as the account associated with the activity, the process that initiated it, and the newly created process.

### SPL Query

```spl
index=* EventCode=4688
| table _time Account_Name Creator_Process_Name New_Process_Name Process_Command_Line
| sort _time
```

The results displayed process creation activity occurring on the Windows endpoint.

### Evidence

<img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/93d4e24c-1388-4cf2-b274-49e1772564a3" />


### Finding

The initial search provided a broad view of process execution. Because multiple events were present, I narrowed the investigation to the time period surrounding the activity of interest.

---

## 2. Narrowing the Investigation Timeline

I reduced the search window to focus on the events immediately surrounding the suspected scheduled task activity.

### SPL Query

```spl
index=* EventCode=4688
earliest="08/13/2026:23:01:20" latest="08/13/2026:23:03:00"
| table _time Account_Name Creator_Process_Name New_Process_Name Process_Command_Line
| sort _time
```

### Evidence

<img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/a43c5936-e68b-4943-a909-1bfcc94ac5d7" />


### Finding

After narrowing the timeline, the results showed activity involving the `azureuser` account.

Of particular interest was the following process relationship:

```text
powershell.exe
      |
      v
schtasks.exe
```

PowerShell launching `schtasks.exe` warranted additional investigation.

`schtasks.exe` is a legitimate Windows utility used to create, modify, query, and delete scheduled tasks. Because scheduled tasks can also be used to execute programs automatically, the activity was investigated further.

---

## 3. Investigating Command Execution

I also searched the surrounding timeline for `cmd.exe` process creation to better understand command execution occurring on the endpoint.

### SPL Query

```spl
index=* EventCode=4688 New_Process_Name="*cmd.exe"
earliest="08/13/2026:22:55:00" latest="08/13/2026:23:10:00"
| table _time Account_Name Creator_Process_Name New_Process_Name Process_Command_Line
| sort _time
```

### Evidence

<img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/da704e22-1540-4180-b0dc-d1d14823cb47" />


### Finding

The search identified `cmd.exe` process creation events within the surrounding investigation window.

At this point, process telemetry alone showed that command-line and scheduled-task-related utilities were executing, but additional Windows events were needed to determine whether a scheduled task had actually been created.

---

## 4. Searching for Scheduled Task Events

I next searched Windows Security logs for event IDs associated with Windows scheduled task activity.

### SPL Query

```spl
index=* (EventCode=4698 OR EventCode=4699 OR EventCode=4700 OR EventCode=4701 OR EventCode=4702)
"ThreatHuntLab-TestTask"
| table _time EventCode Account_Name Task_Name Message
| sort _time
```

### Evidence

<img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/4e6004ca-26a6-425d-9d9b-9d381c88aa88" />


### Finding

The search returned **Event ID 4698**.

The event indicated:

| Field | Value |
| --- | --- |
| Event ID | 4698 |
| Account | `azureuser` |
| Task Name | `\ThreatHuntLab-TestTask` |
| Activity | A scheduled task was created |

This confirmed that a scheduled task had been created on the endpoint.

---

## 5. Examining the Scheduled Task

Finding the task creation event established that a scheduled task existed, but I wanted to determine exactly what the task was configured to execute.

I expanded the Event ID 4698 record and examined the task configuration contained in the event.

### Evidence

<img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/7cc5f6ab-7ce1-4de6-9c8c-dbd8a0ac1a58" />


The task configuration contained an action similar to:

```xml
<Actions Context="Author">
    <Exec>
        <Command>cmd.exe</Command>
        <Arguments>/c echo ThreatHuntLab &gt; C:\ThreatHuntLab\task-test.txt</Arguments>
    </Exec>
</Actions>
```

### Finding

The scheduled task was configured to execute:

```text
cmd.exe
```

with arguments that wrote the text `ThreatHuntLab` to:

```text
C:\ThreatHuntLab\task-test.txt
```

Examining the event details therefore provided additional context beyond simply knowing that a scheduled task had been created.

---

# Event Correlation

## 6. Correlating Process and Scheduled Task Activity

After identifying the scheduled task, I correlated the task creation event with the process creation activity occurring immediately beforehand.

### SPL Query

```spl
index=* ("ThreatHuntLab-TestTask" OR "schtasks.exe" OR "powershell.exe")
earliest="08/13/2026:23:00:00" latest="08/13/2026:23:02:00"
| table _time EventCode Account_Name Creator_Process_Name New_Process_Name Task_Name
| sort _time
```

### Evidence


<img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/1ca30b1e-bd80-4d1b-bf3f-60a19fb7aab7" />


### Timeline

The correlated events showed the following sequence:

```text
PowerShell activity
        |
        v
schtasks.exe execution
        |
        v
Scheduled task created
        |
        v
Windows Security Event ID 4698
        |
        v
ThreatHuntLab-TestTask
```

The process creation events and scheduled task event occurred within the same investigation window and were associated with the `azureuser` account.

This allowed the activity to be reconstructed rather than analyzing each Windows event independently.

---

# Key Findings

The investigation identified several important pieces of evidence:

1. Windows process creation events were successfully ingested and searchable in Splunk.
2. Event ID 4688 showed process execution occurring on the endpoint.
3. PowerShell activity was observed during the investigation window.
4. PowerShell was associated with the execution of `schtasks.exe`.
5. Windows Security Event ID 4698 confirmed that a scheduled task was created.
6. The task was named `ThreatHuntLab-TestTask`.
7. The activity was associated with the `azureuser` account.
8. Examination of the task configuration revealed that the task executed `cmd.exe`.
9. Multiple Windows events were correlated to reconstruct the sequence of activity.

---

# Analyst Assessment

### Classification: Benign / Lab-Generated Activity

The observed behavior was generated intentionally within my lab environment.

Although the activity was benign in this case, the investigation demonstrates behavior that could warrant further analysis in a production environment.

Scheduled tasks are legitimate Windows functionality, but they can also be abused to execute commands or establish persistence.

An unexpected combination of:

- PowerShell execution
- `schtasks.exe` execution
- Newly created scheduled tasks
- Unusual command-line arguments
- Unknown executables
- Unexpected user accounts

could justify escalation and further endpoint investigation.

Context is therefore important when determining whether individual Windows events represent normal administrative activity or potentially malicious behavior.

---

# MITRE ATT&CK Mapping

The scheduled task behavior observed during this lab relates to the MITRE ATT&CK technique:

### T1053.005 — Scheduled Task/Job: Scheduled Task

Scheduled tasks can be used legitimately by administrators and applications, but adversaries may also use them to execute programs at specified times or establish persistence.

The presence of a scheduled task alone does not establish malicious intent. Additional context from the task configuration, user account, command line, surrounding process activity, and endpoint behavior should be considered.

---

# Skills Demonstrated

This project provided hands-on experience with:

- Splunk Enterprise
- SPL (Search Processing Language)
- SIEM investigation
- Windows Security Event Logs
- Event ID 4688 analysis
- Event ID 4698 analysis
- Windows process analysis
- Parent/child process relationships
- PowerShell investigation
- Scheduled task investigation
- Timeline analysis
- Event correlation
- Security telemetry analysis
- MITRE ATT&CK mapping
- SOC investigation methodology

---

# Conclusion

This lab demonstrated how Splunk can be used to investigate and correlate Windows endpoint telemetry.

I began with Windows process creation events, narrowed the investigation timeline, identified PowerShell and `schtasks.exe` activity, and then searched scheduled task auditing events. Event ID 4698 confirmed the creation of `ThreatHuntLab-TestTask`, while examination of the event details revealed the command configured within the task.

By correlating the process and scheduled task telemetry, I was able to reconstruct the sequence of events and determine the context surrounding the activity.

The lab reinforced the importance of moving beyond individual alerts or event IDs and using multiple pieces of telemetry to develop a complete understanding of endpoint activity.
