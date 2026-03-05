# Warzone 1 — TryHackMe

**Difficulty:** Medium  
**Time:** 26 minutes  
**Platform:** TryHackMe  
**Category:** SOC Core Operations | Network Forensics | Threat Intelligence  
**Status:** Completed ✅

---

## Scenario

As a Tier 1 Security Analyst (L1) at a Managed Security Service Provider 
(MSSP), I received my first network case of the shift:

> *"Potentially Bad Traffic and Malware Command and Control Activity detected"*

My task was to inspect the provided PCAP file (Zone1.pcap), retrieve all 
artifacts, and confirm whether this alert was a true positive.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **Brim** | PCAP analysis, alert filtering, file extraction queries |
| **Wireshark** | Deep packet inspection, TCP stream following, HTTP traffic analysis |
| **CyberChef** | Defanging IP addresses for safe reporting |
| **VirusTotal** | Threat intelligence enrichment, passive DNS, community attribution |

---

## Investigation Process

### Step 1 — Loading the PCAP in Brim
I opened Zone1.pcap in Brim and filtered for alerts using:
```
event_type=="alert"
```
<img width="1909" height="834" alt="Screenshot 2026-03-05 023644" src="https://github.com/user-attachments/assets/5995b465-52d9-4311-bad2-20fd1269b82d" />

This immediately surfaced two repeating alert signatures fired against 
the same source and destination IP pair across multiple ports — confirming 
suspicious C2 beaconing behavior.

**Alert Signatures Identified:**
- `ET MALWARE MirrorBlast CnC Activity M3` — Severity 1 (Critical)
- `ET USER_AGENTS Suspicious User-Agent (REBOL)` — Severity 2

### Step 2 — Identifying Source and Destination IPs
From the Brim alert results, I extracted the communicating IP addresses:

<img width="1909" height="834" alt="Screenshot 2026-03-05 023644" src="https://github.com/user-attachments/assets/ec51df1a-8f24-4a86-bb41-ef0795c7bf10" />

| Role | IP Address (Defanged) |
|------|----------------------|
| Source (Victim) | `172[.]16[.]1[.]102` |
| Destination (C2) | `169[.]239[.]128[.]11` |

All alerts showed the victim machine consistently beaconing outbound to 
the same destination IP over port 80 via HTTP — classic C2 communication 
pattern.

### Step 3 — Threat Intelligence Enrichment via VirusTotal
I submitted the destination IP `169.239.128.11` to VirusTotal for 
threat intelligence analysis.

<img width="1776" height="955" alt="Screenshot 2026-03-05 024005" src="https://github.com/user-attachments/assets/cb5758b6-a99d-41b4-a5cb-cbab7cffc9fd" />

**VirusTotal Results:**
- **9/94** security vendors flagged this IP as malicious
- **ASN:** AS61138 — Zappie Host LLC (South Africa 🇿🇦)
- **Community Score:** -9 (highly negative)
- **Malware Family:** MirrorBlast
- **Threat Group:** TA505 (confirmed via Community tab)

### Step 4 — Passive DNS Analysis
Under the Relations tab in VirusTotal, I reviewed the Passive DNS 
Replication records (41 entries) for the C2 IP. The highest scored 
passive DNS entry was:

<img width="1295" height="949" alt="Screenshot 2026-03-05 024112" src="https://github.com/user-attachments/assets/e8e20858-25f9-456b-a33d-0d4c0ac85bbd" />

| Domain | Detections | Date Resolved |
|--------|-----------|---------------|
| `fidufagios.com` | **16/94** | 2021-09-29 |
| `www.fidufagios.com` | 13/94 | 2021-11-12 |

`fidufagios.com` was identified as the primary malicious domain 
associated with this IP with the highest detection score.

### Step 5 — Communicating Files Analysis
I searched `fidufagios.com` in VirusTotal and reviewed the 
Communicating Files section (9 files total). The majority file 
type was **Windows Installer (.msi)** — confirming MirrorBlast's 
known delivery mechanism of malicious MSI packages.

<img width="1688" height="873" alt="Screenshot 2026-03-05 024149" src="https://github.com/user-attachments/assets/b99f493e-32c4-4b91-80d1-1f2defe77e69" />

### Step 6 — User-Agent Identification
I inspected the web traffic in Wireshark for the flagged C2 IP and 
identified the suspicious user-agent string referenced in the second 
Brim alert signature:

```
REBOL View 2.7.8.3.1
```

REBOL (Relative Expression-Based Object Language) is a scripting 
language abused by MirrorBlast as part of its execution chain. Its 
presence in the user-agent confirmed the malware was actively 
communicating with the C2 server.

### Step 7 — Identifying Additional C2 Infrastructure
I retraced the full attack chain in the PCAP and identified two 
additional IP addresses involved in the attack used as secondary 
C2 servers:

| C2 IP (Defanged) | Role |
|-----------------|------|
| `192[.]36[.]27[.]92` | Secondary C2 / File delivery |
| `185[.]10[.]68[.]235` | Secondary C2 / File delivery |

<img width="1910" height="901" alt="Screenshot 2026-03-05 025301" src="https://github.com/user-attachments/assets/df04d140-ed32-494e-ab13-f18460d0bbb5" />

I defanged these IPs using CyberChef's **Defang IP Addresses** 
operation for safe documentation.

### Step 8 — Malicious File Downloads
I queried Brim for downloaded files using:
```
filename!=null | cut _path, tx_hosts, rx_hosts, conn_uids, 
mime_type, filename, md5, sha1
```
<img width="1909" height="848" alt="Screenshot 2026-03-05 025353" src="https://github.com/user-attachments/assets/942a204b-90b8-423d-a88f-b3c34b52a46c" />

The Brim results confirmed the transmitting host (tx_hosts) for each 
file. Files downloaded through the C2 connections:

| Source IP (tx_hosts) | Filename | Type |
|----------------------|---------|------|
| `185[.]10[.]68[.]235` | `filter.msi` | Windows Installer |
| `192[.]36[.]27[.]92` | `10opd3r_load.msi` | Windows Installer |

### Step 9 — Full File Path Extraction (filter.msi)
I followed the TCP stream in Wireshark for the traffic associated 
with `filter.msi` downloaded from `185[.]10[.]68[.]235`. 

<img width="1915" height="900" alt="Screenshot 2026-03-05 031054" src="https://github.com/user-attachments/assets/855101a6-725b-4630-ae4e-2bb73dfa3c36" />

The stream revealed the MSI installer dropping two files to the 
same directory on the victim machine:

<img width="955" height="659" alt="Screenshot 2026-03-05 031150" src="https://github.com/user-attachments/assets/a66cd59b-edd2-4617-a74c-9291a7c9d5c0" />

```
C:\ProgramData\001\arab.bin
C:\ProgramData\001\arab.exe
```

The `arab.exe` binary and `arab.bin` component were staged in 
`C:\ProgramData\001\` — a non-standard directory used to avoid 
detection in common user-facing paths.

### Step 10 — Full File Path Extraction (10opd3r_load.msi)
I followed the TCP stream for the second downloaded file 
`10opd3r_load.msi` from `192[.]36[.]27[.]92`.

The stream revealed this installer dropping two files to a 
directory masquerading as a legitimate Google folder:

<img width="946" height="620" alt="Screenshot 2026-03-05 031533" src="https://github.com/user-attachments/assets/fcbd0a02-022b-4b83-bcf1-d73f268578be" />

```
C:\ProgramData\Local\Google\rebol-view-278-3-1.exe
C:\ProgramData\Local\Google\exemple.rb
```

The attacker used `C:\ProgramData\Local\Google\` to blend in with 
legitimate Google software paths. The REBOL interpreter 
(`rebol-view-278-3-1.exe`) was paired with a REBOL script 
(`exemple.rb`) — the execution mechanism for MirrorBlast's 
post-infection activity.

---

## Key Findings Summary

| # | Question | Answer |
|---|---------|--------|
| 1 | Alert signature | `ET MALWARE MirrorBlast CnC Activity M3` |
| 2 | Source IP (defanged) | `172[.]16[.]1[.]102` |
| 3 | Destination IP (defanged) | `169[.]239[.]128[.]11` |
| 4 | Threat group | `TA505` |
| 5 | Malware family | `MirrorBlast` |
| 6 | Majority file type (Communicating Files) | `Windows Installer` |
| 7 | User-agent | `REBOL View 2.7.8.3.1` |
| 8 | Additional C2 IPs | `192[.]36[.]27[.]92, 185[.]10[.]68[.]235` |
| 9 | Downloaded files | `filter.msi, 10opd3r_load.msi` |
| 10 | Files from filter.msi | `C:\ProgramData\001\arab.bin, C:\ProgramData\001\arab.exe` |
| 11 | Files from 10opd3r_load.msi | `C:\ProgramData\Local\Google\rebol-view-278-3-1.exe, C:\ProgramData\Local\Google\exemple.rb` |

**Verdict: ✅ TRUE POSITIVE — Active MirrorBlast C2 infection confirmed**

---

## Threat Actor Profile — TA505

TA505 is a financially motivated cybercrime group active since at 
least 2014, known for large-scale malware distribution campaigns.

**Known for:**
- Distributing MirrorBlast, Dridex, FlawedAmmyy RAT
- Deploying Clop ransomware in targeted attacks
- Large-scale phishing campaigns via malicious MSI installers
- Abusing legitimate scripting languages (REBOL) for evasion

**MirrorBlast specifically:**
- Delivered via malicious MSI packages
- Uses REBOL scripting language for execution — rare and 
  difficult to detect
- Drops binaries into non-standard or disguised directories
- Establishes persistent C2 communication over HTTP port 80

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Initial Access | Phishing | T1566 | MirrorBlast delivered via malicious MSI |
| Execution | User Execution: Malicious File | T1204.002 | MSI installer execution |
| Execution | Command & Scripting: REBOL | T1059 | rebol-view-278-3-1.exe + exemple.rb |
| Defense Evasion | Masquerading | T1036 | Files hidden in Google directory path |
| Defense Evasion | Obfuscated Files | T1027 | REBOL script payload |
| Command & Control | Application Layer Protocol: HTTP | T1071.001 | C2 over port 80 |
| Command & Control | Multi-Stage Channels | T1104 | Three C2 IPs identified |
| Persistence | Boot/Logon Autostart | T1547 | Registry key references observed in MSI installer stream (suspected — not fully confirmed from PCAP alone) |

---

## Attack Flow Reconstruction

```
Victim (172.16.1.102)
        │
        ▼
[Initial C2 Contact]
169.239.128.11 — MirrorBlast CnC (fidufagios.com)
        │
        ├──▶ 185.10.68.235 → Downloads filter.msi
        │         └──▶ Drops: C:\ProgramData\001\arab.bin
        │                      C:\ProgramData\001\arab.exe
        │
        └──▶ 192.36.27.92 → Downloads 10opd3r_load.msi
                  └──▶ Drops: C:\ProgramData\Local\Google\rebol-view-278-3-1.exe
                               C:\ProgramData\Local\Google\exemple.rb
```

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| IP | `169[.]239[.]128[.]11` |
| IP | `192[.]36[.]27[.]92` |
| IP | `185[.]10[.]68[.]235` |
| Domain | `fidufagios[.]com` |
| File | `filter.msi` |
| File | `10opd3r_load.msi` |
| File | `arab.bin` |
| File | `arab.exe` |
| File | `rebol-view-278-3-1.exe` |
| File | `exemple.rb` |
| MD5 | `8b6199f5d5465c327c8c30ac9fdfd23a` (filter.msi) |
| User-Agent | `REBOL View 2.7.8.3.1` |
| Path | `C:\ProgramData\001\` |
| Path | `C:\ProgramData\Local\Google\` |

---

## Lessons Learned

- Brim's alert filtering surfaces C2 signatures instantly —
  filtering by `event_type=="alert"` should be the first step
  in any PCAP investigation.
- The `tx_hosts` field in Brim file queries identifies the
  server that transmitted the file — critical for accurately
  mapping files to their source C2 infrastructure.
- Passive DNS in VirusTotal reveals the domain infrastructure
  behind malicious IPs — the highest scored entry points directly
  to the attacker's primary delivery domain.
- Attackers deliberately stage malware in paths mimicking
  legitimate software (Google directory) to evade casual
  inspection of running processes and file paths.
- Three C2 IPs working together is a multi-stage channel —
  identifying one C2 should always trigger a hunt for connected
  infrastructure in the same traffic.
- REBOL is an unusual scripting language that many AV engines
  do not flag — its presence in a user-agent string is an
  immediate red flag worth escalating.
