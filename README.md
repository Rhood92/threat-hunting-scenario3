# Suspected Data Exfiltration from PIPd Employee

**Author:** Richard Hood Jr.  
**Date:** 3/1/25  
**Category:** Threat Hunting  

---

## 🛠️ Scenario Overview
An employee, **John Doe**, who was recently placed on a **Performance Improvement Plan (PIP)**, is suspected of attempting to **steal proprietary company data** before resigning. Given John’s **administrator privileges**, he has unrestricted access to applications and could potentially compress and exfiltrate sensitive files. The security team has been tasked with investigating John’s activities on his corporate device (`rich-mde-test`).

## 🔍 Hypothesis
- Is John attempting **data exfiltration** using **compression tools**?
- Has he executed **PowerShell scripts** to facilitate exfiltration?
- Is there evidence of **network exfiltration attempts**?

---

## 📊 Data Collection

### 📝 Query 1: Search for Archived/Compressed Files
```kql
let VMName = "rich-mde-test";
DeviceFileEvents
| order by Timestamp desc
| where DeviceName == "rich-mde-test"
```
🧐 **Findings:**
- A **compressed file** named `employee-data-20250301183817.zip` was found **in the backup folder** (`C:\ProgramData\backup`).
- This suggests **data was archived for potential exfiltration.**

### 📝 Query 2: Identify Processes Related to Compression
```kql
let archive_applications = dynamic(["winrar.exe", "7z.exe", "winzip32.exe", "peazip.exe", "Bandizip.exe", "UniExtract.exe"]);
DeviceProcessEvents
| where FileName has_any(archive_applications)
| order by Timestamp desc
| where DeviceName == "rich-mde-test"
```
🧐 **Findings:**
- **7-Zip (`7z.exe`) was executed multiple times**, suggesting **manual or scripted file compression.**
- The process was triggered **shortly before the ZIP file appeared.**

### 📝 Query 3: Timeline Analysis of Compression and Execution
```kql
let specificTime = datetime(2025-03-01T18:38:26.3235392Z);
let VMName = "rich-mde-test";
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, ActionType, FileName, ProcessCommandLine
```
🧐 **Findings:**
- **A PowerShell script (`exfiltratedata.ps1`) was executed with `ExecutionPolicy Bypass`**, indicating **an attempt to override security policies.**
- **7-Zip was installed (`7z2408-x64.exe`) and executed**, likely to **compress company files**.
- The presence of **PowerShell execution suggests automation**, meaning John may have **scripted the process**.

### 📝 Query 4: Checking for Network Exfiltration
```kql
let specificTime = datetime(2025-03-01T18:38:26.3235392Z);
let VMName = "rich-mde-test";
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```
🧐 **Findings:**
- No **immediate signs of data exfiltration** over the network.
- **Possibility:** John may have used **offline exfiltration methods (USB, external storage)**.

---

## ⚡ Investigation Insights

### 🔎 How Did This Happen?
- **PowerShell script (`exfiltratedata.ps1`) was executed**, likely **automating the compression process.**
- **7-Zip (`7z.exe`) was executed multiple times**, compressing `employee-data-20250301183817.zip`.
- **The archived file was moved into a backup folder**, possibly **preparing for exfiltration.**
- **No immediate network activity** was detected, meaning **offline exfiltration is likely**.

### 🔎 **Relevant MITRE ATT&CK TTPs**
| **TTP ID** | **Technique** | **Description** |
|------------|--------------|----------------|
| **T1059.001** | **PowerShell Execution** | PowerShell script executed with `Bypass` flag, avoiding restrictions. |
| **T1548.002** | **Bypass User Account Control** | Script executed with **high integrity**, possibly bypassing UAC. |
| **T1036.003** | **Masquerading: Rename System Utilities** | **Renamed `7z2408-x64.exe`**, likely to evade detection. |
| **T1560.001** | **Archive Collected Data** | **7-Zip used to compress data**, indicating preparation for exfiltration. |
| **T1567.002** | **Exfiltration Over Web Service (Potential)** | No network exfiltration detected, but compression suggests intent. |
| **T1048** | **Exfiltration Over Alternative Protocols (Potential)** | Offline transfer (USB, external drive) is a possibility. |

---

## 🛡️ Response & Mitigation

### ✅ **Actions Taken**
✔️ **Informed John’s manager and security team** of the findings.  
✔️ **Monitored further activity** on John’s device (`rich-mde-test`).  
✔️ **Analyzed logs for signs of USB or offline data transfers**.  
✔️ **Recommended restricting PowerShell execution policies**.  
✔️ **Proposed blocking unapproved applications like 7-Zip from running**.  

### 🔹 **Preventative & Hardening Measures**
✔️ Enforce **PowerShell logging and execution policy restrictions**.  
✔️ Restrict **installation and execution of unapproved software**.  
✔️ Implement **DLP (Data Loss Prevention) policies** to detect file transfers.  
✔️ Monitor for **unauthorized file compression activities**.  

---

## 📚 Areas for Improvement

### 🔹 **Security Enhancements**
- **Improve monitoring** for abnormal file compression behavior.  
- **Enforce application whitelisting** to prevent unauthorized software execution.  

### 🔹 **Threat Hunting Improvements**
- **Enhance SIEM alerting** for suspicious PowerShell and compression activities.  
- Automate detection of **LOLBins (Living-Off-The-Land Binaries) abuse**, such as PowerShell and 7-Zip.  

---

## 📖 Final Summary
✅ **Suspicious PowerShell execution detected (`exfiltratedata.ps1`).**  
✅ **7-Zip used to archive `employee-data-20250301183817.zip`, suggesting exfiltration intent.**  
✅ **No immediate network exfiltration detected—potential offline exfiltration (USB, external drive).**  
✅ **Preventative measures recommended: PowerShell restrictions, DLP enforcement, and app control.**  

🔐 **Next Steps:** **Monitor John's device**, **implement tighter controls**, and **investigate potential offline exfiltration methods.**  

---

### 📌 **Repository Information**
💡 This project is designed for **educational & security research purposes**. If you're interested in **threat hunting**, **data exfiltration detection**, or **PowerShell security**, feel free to explore and contribute! 🚀
