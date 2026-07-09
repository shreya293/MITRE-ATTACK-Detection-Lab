<details>
<summary><b>📅 Day 5 — More Attack Simulations + Detection Rules Part 2</b></summary>

<br>

### 🎯 Objective
Extend ATT&CK detection coverage by simulating 4 additional MITRE techniques covering the post-exploitation phase of the attacker kill chain — persistence via scheduled tasks, process injection for evasion, account discovery for privilege escalation targeting, and file discovery for pre-exfiltration reconnaissance. Write automated Splunk Alerts for each technique, bringing total detection coverage to 7 ATT&CK techniques across the full kill chain.

---

### 🧠 The Attacker Kill Chain — Where Day 5 Fits

By the end of Day 5, this lab detects attacks across every major phase of the kill chain:

```
Initial Access → Execution → Persistence → Discovery → Collection → Exfiltration
                    ↑             ↑            ↑            ↑
                T1059.001     T1547.001     T1082        T1083
                             T1053.005     T1087.001
                              T1055
```

**Why this matters in a SOC:**
Real attacks don't happen in one step — they follow a sequence of techniques that build on each other. An attacker who gains initial access will immediately run discovery (T1082, T1087), establish multiple persistence mechanisms (T1547.001, T1053.005), hide their presence using injection (T1055), and then map the file system before stealing data (T1083). Detecting each stage independently means the SOC has multiple opportunities to catch and stop the attack before data loss occurs.

---

### ⚔️ Attack Simulation 1 — Scheduled Task Persistence (T1053.005)

**MITRE ATT&CK Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task
**Tactic:** Persistence, Privilege Escalation
**Sysmon Event ID:** 1 (Process Creation)
**Alert Severity:** Critical
**Command run:**
```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
```

**What this technique is:**
Windows Task Scheduler is a built-in Windows service that allows programs to run automatically at specific times or system events — login, startup, idle, network connection etc. While designed for legitimate automation (backups, updates, maintenance scripts), attackers extensively abuse it to create persistent malware execution that survives reboots, user logoffs, and even basic incident response cleanup attempts.

**Why T1053.005 is more dangerous than T1547.001 (Registry Run Keys):**

| Factor | T1547.001 Registry Run Keys | T1053.005 Scheduled Tasks |
|--------|----------------------------|--------------------------|
| Visibility | Registry editors show it | Task Scheduler UI — less commonly checked |
| Privilege | User-level persistence | Can run as SYSTEM — highest privilege |
| Trigger flexibility | Only on login/boot | Any trigger: hourly, on network connect, on idle |
| Cleanup resistance | Deleted by registry cleaners | Survives most basic IR cleanup procedures |
| Detection difficulty | Well known, many tools check it | Less commonly monitored by basic security tools |

**Real world context:**
T1053.005 has been observed in attacks by Lazarus Group (North Korea), APT32 (Vietnam), FIN7 (financially motivated), and virtually every major ransomware operation including REvil, Conti, and LockBit. It consistently ranks in the top 10 most observed ATT&CK techniques in real incident response engagements.

**What the simulation created on the VM:**

The atomic test created two scheduled tasks simultaneously — a common attacker strategy of creating redundant persistence so if one is found and deleted, the other survives:

**Task 1:**
```
schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"
```

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `/tn` | `T1053_005_OnStartup` | Task name (attacker would use legitimate-sounding name) |
| `/sc onstart` | On system startup | Runs every time Windows boots |
| `/ru system` | Run as SYSTEM | Highest privilege — full machine control |
| `/tr "cmd.exe /c calc.exe"` | Task action | In real attack: path to malware instead of calc.exe |

**Task 2:**
```
schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
```

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `/sc onlogon` | On user logon | Runs every time any user logs in |
| `/tr "cmd.exe /c calc.exe"` | Task action | Malware executes on every login |

**The attacker strategy of dual persistence:**
By creating both an OnStartup (SYSTEM level) and OnLogon (user level) task, the attacker ensures their malware runs regardless of whether the machine reboots without user login or a user logs in without rebooting. This redundancy is a hallmark of sophisticated threat actors who plan for partial detection and cleanup.

**How it was detected in Splunk:**

SPL Detection Query:
```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)(schtasks)")
| table _time, ComputerName, User, Image, ParentImage, CommandLine
```

**Result: 3 events captured**

| Event | CommandLine | Significance |
|-------|-------------|-------------|
| 1 | `schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"` | SYSTEM-level startup persistence created |
| 2 | `schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"` | User logon persistence created |
| 3 | `cmd.exe /c schtasks /create /tn "T1053_005_OnLogon"... & schtasks /create /tn "T1053_005_OnStartup"...` | Parent chained command — both tasks created in one PowerShell execution |

**Critical observation — ParentImage:**
All 3 events show `powershell.exe` as the ParentImage — confirming this was script-based attack execution, not a human administrator manually creating tasks through the Task Scheduler UI. A real IT admin creating a scheduled task would use the Task Scheduler GUI (parent: `taskschd.msc`) or a known deployment tool — never raw `schtasks.exe` commands launched from PowerShell.

**Legitimate vs Malicious — decision framework:**

| Indicator | Legitimate scheduled task | Malicious scheduled task |
|-----------|--------------------------|-------------------------|
| Creator process | `taskschd.msc`, known deployment tools | `powershell.exe`, `cmd.exe`, `wscript.exe` |
| Task name | Descriptive, company-standard naming | Random string, or fake Windows-sounding name |
| Executable path | `C:\Program Files\...` known software | `C:\Temp\`, `C:\Users\Public\`, `%appdata%\` |
| Run as | Specific service account | `SYSTEM` — maximum privilege |
| Trigger | Scheduled time, maintenance window | OnLogon + OnStartup simultaneously |
| Documentation | Corresponding change ticket | No scheduled maintenance activity |

**SOC response to this alert:**
1. Run `schtasks /query /fo LIST /v` to list all scheduled tasks and find the malicious ones
2. Check the `/tr` (task run) parameter — what executable is being persisted?
3. Check if that executable exists on disk — if yes, submit to sandbox analysis
4. Check EventCode 11 (file creation) for when that executable appeared
5. Delete the malicious tasks and the executable, then hunt for other persistence mechanisms

**Alert configuration:**
- **Type:** Real-time
- **Trigger:** Number of results greater than 0
- **Severity:** Critical

<details>
<summary>📸 Screenshots — T1053.005 Detection</summary>
<br>

**Screenshot 2 — Splunk catching 3 scheduled task creation events**
> SPL detection query returning 3 events showing both scheduled tasks created by the T1053.005 simulation. The CommandLine column shows the complete schtasks commands including task names (T1053_005_OnLogon, T1053_005_OnStartup), trigger types (onlogon, onstart), privilege level (/ru system), and the action to execute. ParentImage shows powershell.exe for all events — confirming script-based attack execution rather than legitimate admin activity.

![Screenshot2](day%205%20screenshots/Screenshot2.png)

---

**Screenshot 6 — PowerShell showing T1053.005 execution complete**
> Administrator PowerShell showing successful completion of T1053.005 simulation with green SUCCESS messages confirming both scheduled tasks were created: "The scheduled task T1053_005_OnLogon has successfully been created" and "The scheduled task T1053_005_OnStartup has successfully been created." This confirms the persistence mechanism was fully established before Sysmon and Splunk captured the evidence.

![Screenshot6](day%205%20screenshots/Screenshot6.png)

</details>

---

### ⚔️ Attack Simulation 2 — Process Injection (T1055)

**MITRE ATT&CK Technique:** T1055 — Process Injection
**Tactic:** Defense Evasion, Privilege Escalation
**Sysmon Event ID:** 8 (CreateRemoteThread)
**Alert Severity:** Critical
**Command run:**
```powershell
Invoke-AtomicTest T1055 -TestNumbers 1
```

**What this technique is:**
Process injection is one of the most sophisticated and dangerous techniques in the attacker toolkit. Instead of running malicious code as a separate, visible process that security tools can easily identify and kill, the attacker injects their malicious code directly into the memory of a legitimate, trusted Windows process — like `explorer.exe`, `svchost.exe`, or `lsass.exe`. From the outside the system looks completely clean: only known, trusted processes are visible. But inside one of those processes, the attacker's payload is secretly executing with all the privileges of the host process.

**Why process injection is so dangerous:**

| Attack capability | How injection achieves it |
|------------------|--------------------------|
| Antivirus evasion | Malware runs inside a trusted process — AV tools trust it |
| Privilege escalation | Inject into a SYSTEM process — inherit SYSTEM privileges |
| Network evasion | Trusted process makes network connections — firewalls allow it |
| Forensic evasion | No malicious file on disk — runs entirely in memory |
| Persistence bypass | Even if malware file is deleted, running injection continues |

**Real world context:**
Process injection is used by the most sophisticated threat actors in the world including all major nation-state APT groups. Cobalt Strike — the most commonly used penetration testing and attack framework — uses process injection as its primary execution method. Malware families that use T1055 include Emotet, TrickBot, Ryuk ransomware dropper, and virtually every advanced RAT.

**What the simulation did:**
Test 1 attempted shellcode execution via VBA (Visual Basic for Applications) — simulating a malicious Office macro that injects shellcode into another process. Windows Defender partially blocked the full shellcode execution ("Access is denied") but Sysmon captured the injection attempt at the kernel level before Defender could intervene.

**This is a realistic SOC scenario:** In real environments, security tools don't always fully block attacks — they may block the final payload while the initial technique still executes and gets logged. A good SOC investigates ALL injection attempts regardless of whether the payload was blocked, because "blocked" doesn't always mean "fully contained."

**How it was detected in Splunk:**

SPL Detection Query:
```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8 earliest=-5m
| table _time, ComputerName, User, SourceImage, TargetImage, StartAddress
```

**Result: 1 event captured**

| Field | Value | Significance |
|-------|-------|-------------|
| EventCode | 8 — CreateRemoteThread | Sysmon detected one process creating a thread in another |
| SourceImage | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | PowerShell is the injector |
| TargetImage | `<unknown process>` | Target process identity concealed — advanced evasion |
| StartAddress | `0x00007FF692C35500` | Memory address where injected code begins execution |

**Why `<unknown process>` as TargetImage is a Critical red flag:**
In all legitimate Windows operations, every process has a known, identifiable name and path. When Sysmon records an EventCode 8 where the target is listed as `<unknown process>`, it means one of two things — both serious:
1. The target process was created specifically for injection and terminated immediately after execution, before Sysmon could identify it — a sophisticated memory evasion technique
2. The attacker used a reflective injection technique that deliberately obscures the target process identity from monitoring tools

Either scenario warrants immediate Priority 1 investigation in a real SOC.

**The three stages of a process injection attack:**

```
Stage 1: Allocate        Stage 2: Write          Stage 3: Execute
         memory in  →             malicious   →           injected
         target process           code into it            code
         (VirtualAllocEx)         (WriteProcessMemory)    (CreateRemoteThread) ← Sysmon EventCode 8 catches this
```

Sysmon's EventCode 8 specifically catches Stage 3 — the CreateRemoteThread call — which is the moment the injected code begins executing in the target process.

**Legitimate vs Malicious — decision framework:**

| Indicator | Legitimate CreateRemoteThread | Malicious process injection |
|-----------|------------------------------|----------------------------|
| SourceImage | Known debuggers, AV software, profilers | `powershell.exe`, `cmd.exe`, `wscript.exe`, `rundll32.exe` |
| TargetImage | Specific known process being debugged | `<unknown process>`, `explorer.exe`, `svchost.exe`, `lsass.exe` |
| StartAddress | Known module address ranges | Unknown/unusual memory address ranges |
| Context | Developer debugging session | No development activity in progress |
| Frequency | Rare, during active debugging | Unexpected, during normal operations |

**Alert configuration:**
- **Type:** Real-time
- **Trigger:** Number of results greater than 0
- **Severity:** Critical

<details>
<summary>📸 Screenshots — T1055 Detection</summary>
<br>

**Screenshot 3 — Splunk catching process injection EventCode 8**
> SPL detection query returning 1 EventCode 8 (CreateRemoteThread) event showing PowerShell as the SourceImage attempting to inject into an unknown target process at memory address 0x00007FF692C35500. The `<unknown process>` TargetImage is a critical indicator — legitimate Windows operations always have identifiable target processes. This event would be classified as Priority 1 in any SOC environment regardless of whether the final payload was blocked by Defender.

![Screenshot3](day%205%20screenshots/Screenshot3.png)

</details>

---

### ⚔️ Attack Simulation 3 — Account Discovery (T1087.001)

**MITRE ATT&CK Technique:** T1087.001 — Account Discovery: Local Account
**Tactic:** Discovery
**Sysmon Event ID:** 1 (Process Creation)
**Alert Severity:** High
**Commands run (manual simulation):**
```powershell
net user
net localgroup administrators
whoami /groups
query user
```

**What this technique is:**
Account discovery is the attacker's intelligence gathering phase focused specifically on user accounts and privileges. After gaining initial access, an attacker needs to answer critical questions: What user am I running as? Do I have admin rights? Who else has admin rights? Are there service accounts with special privileges? Is this machine joined to a domain with a Domain Admin account I can target?

The answers to these questions determine the attacker's entire next phase — whether they need to escalate privileges, which accounts to target for lateral movement, and whether they already have enough access to accomplish their goal.

**Why T1087.001 is simulated manually:**
The Atomic Red Team test file for T1087.001 was not available on the Windows platform in this lab environment (found 0 atomic tests applicable). The manual simulation uses the exact same commands Atomic Red Team would have executed — achieving the identical Sysmon detection with the same forensic evidence in Splunk.

**What each discovery command reveals to the attacker:**

| Command | What it shows | What attacker does with this info |
|---------|--------------|----------------------------------|
| `net user` | All local user accounts on the machine | Find accounts to target — especially admin or service accounts |
| `net localgroup administrators` | All members of the local Administrators group | Identify privileged accounts for targeting |
| `whoami /groups` | All security groups current user belongs to | Confirm own privilege level and available permissions |
| `query user` | All currently logged-in users and their session info | Find active sessions to hijack or users to target |

**How it was detected in Splunk:**

SPL Detection Query:
```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-5m
| where match(CommandLine, "(?i)(net user|net localgroup|whoami|query user)")
| table _time, ComputerName, User, Image, ParentImage, CommandLine
```

**Result: 3 events captured**

| Time | CommandLine | Significance |
|------|-------------|-------------|
| 15:36:39 | `whoami.exe` | Initial identity check |
| 15:37:37 | `whoami.exe` | Repeated check — confirming user context |
| 15:40:24 | `whoami.exe /groups` | Group membership enumeration — privilege assessment |

**Key pattern — ParentImage is powershell.exe for all 3 events:**
Every single account discovery command was launched from PowerShell — not from an administrator manually typing in a command prompt. This parent-child relationship (PowerShell → whoami/net commands) is the definitive attacker pattern. A real IT admin checking user accounts would open CMD from the Start menu (parent: explorer.exe), not script it from PowerShell.

**The `whoami /groups` output and what it means to an attacker:**
When an attacker runs `whoami /groups` and sees `BUILTIN\Administrators` in the output, they know they already have full local admin control — no privilege escalation needed. If they see only standard user groups, they know they need to escalate before attempting any high-privilege operations like credential dumping or installing services.

**Account discovery in the broader attack context:**
T1087.001 is almost never the final goal — it's a stepping stone. The information gathered feeds directly into the next technique:
- Found admin account → Target for credential dumping (T1003)
- Found domain accounts → Target for lateral movement (T1021)
- Confirmed own admin rights → Proceed to high-privilege operations
- Found service accounts → Potential for privilege escalation

**Legitimate vs Malicious — decision framework:**

| Indicator | Legitimate admin activity | Malicious account discovery |
|-----------|--------------------------|----------------------------|
| ParentImage | `explorer.exe` (manual CMD) | `powershell.exe`, `wscript.exe`, `mshta.exe` |
| Timing | During known maintenance window | Unexpected time, or immediately after other suspicious activity |
| Frequency | 1-2 commands during troubleshooting | Multiple discovery commands in rapid succession |
| User running it | Known IT admin account | Standard user account or unknown service account |
| Combination | Single command for specific purpose | Multiple discovery commands chained together |

**Alert configuration:**
- **Type:** Real-time
- **Trigger:** Number of results greater than 0
- **Severity:** High

<details>
<summary>📸 Screenshots — T1087.001 Detection</summary>
<br>

**Screenshot 4 — Splunk catching 3 account discovery events**
> SPL detection query returning 3 events showing account discovery commands executed during the manual T1087.001 simulation. All three events show whoami.exe as the Image with powershell.exe as the ParentImage — the definitive attacker pattern of scripted account enumeration. The third event shows whoami.exe /groups — the most critical command, revealing whether the attacker has administrator privileges and what security groups they can leverage for further attack progression.

![Screenshot4](day%205%20screenshots/Screenshot4.png)

</details>

---

### ⚔️ Attack Simulation 4 — File and Directory Discovery (T1083)

**MITRE ATT&CK Technique:** T1083 — File and Directory Discovery
**Tactic:** Discovery
**Sysmon Event ID:** 1 (Process Creation)
**Alert Severity:** High
**Command run:**
```powershell
Invoke-AtomicTest T1083 -TestNumbers 1
```

**What this technique is:**
File and Directory Discovery is the attacker's reconnaissance of the file system — systematically mapping what data exists on the compromised machine before deciding what to steal. This is the bridge between the discovery phase and the collection/exfiltration phase of the attack. Attackers specifically look for documents, password files, SSH keys, database files, configuration files, source code, and any other data with value.

**Why T1083 is the pre-exfiltration warning sign:**
When a SOC analyst sees T1083 activity, it means the attacker is no longer just exploring the system — they've moved into active data targeting. T1083 detections should be treated as an urgent signal that data theft is imminent if the attacker isn't stopped immediately.

**What the simulation ran and why each command matters:**

The atomic test created a comprehensive file system map using a chained command:

```
cmd.exe /c dir /s c:\ >> %temp%\T1083Test1.txt
         "c:\Documents and Settings" >> %temp%\T1083Test1.txt
         dir /s "c:\Program Files" >> %temp%\T1083Test1.txt
         "%systemdrive%\Users\*.*" >> %temp%\T1083Test1.txt
         "%userprofile%\AppData\Roaming\Microsoft\Windows..." >> %temp%\T1083Test1.txt
         tree /F >> %temp%\T1083Test1.txt
```

**Breaking down each command:**

| Command | What it discovers | Attacker value |
|---------|------------------|----------------|
| `dir /s c:\` | Recursive listing of entire C drive | Complete inventory of all files on machine |
| `dir "c:\Documents and Settings"` | Legacy user profile location | Older Windows user data and documents |
| `dir /s "c:\Program Files"` | All installed software | Find exploitable applications, security tools installed |
| `%systemdrive%\Users\*.*` | All user profile folders | Identify all users — find high-value targets |
| `%userprofile%\AppData\Roaming` | Application data folder | Saved passwords, browser data, app configs |
| `tree /F` | Full directory tree with all filenames | Complete visual map of file system structure |

**The most critical indicator — output redirection to temp file:**
Every command redirects output to `%temp%\T1083Test1.txt` using the `>>` operator. This is the attacker **collecting and staging data** for later exfiltration. Instead of just browsing files interactively, they're saving a complete file inventory to a temp file that they'll later compress and send to their C2 server. This `>>` redirection pattern combined with file discovery commands is a very high-confidence pre-exfiltration indicator.

**How it was detected in Splunk:**

SPL Detection Query:
```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-5m
| where match(CommandLine, "(?i)(dir |Get-ChildItem|gci |ls |tree |attrib)")
| table _time, ComputerName, User, Image, ParentImage, CommandLine
```

**Result: 1 event captured — complete file discovery chain visible in single CommandLine**

The entire multi-command file discovery operation was captured in one Sysmon event because the attacker chained all commands together in a single `cmd.exe /c` execution. This is actually more forensically valuable than multiple events — it shows the complete attack operation in one log entry.

**T1083 in the full attack narrative:**
```
T1082 (What OS/hardware?)  →  T1087 (Who has access?)  →  T1083 (What data exists?)  →  Next: Exfiltration
"Map the terrain"              "Find the keys"              "Find the treasure"              "Steal it"
```

This progression is exactly what every major data breach investigation documents in its timeline — discovery leading to collection leading to exfiltration. Detecting T1083 in real-time means the SOC can intervene before the final exfiltration step occurs.

**What attackers specifically search for in real breaches:**

| File type | Why attackers want it |
|-----------|----------------------|
| `*.docx`, `*.xlsx`, `*.pdf` | Business documents, financial data, IP |
| `*.key`, `*.pem`, `id_rsa` | SSH private keys for server access |
| `*.config`, `web.config` | Application configs with credentials |
| `password*`, `credential*` | Password files or credential stores |
| `*.sql`, `*.db`, `*.mdb` | Database files with customer data |
| `*.py`, `*.java`, `*.cs` | Source code — intellectual property theft |

**Legitimate vs Malicious — decision framework:**

| Indicator | Legitimate file search | Malicious file discovery |
|-----------|----------------------|-------------------------|
| Scope | Searching specific folder for specific file | Recursive search of entire drive (`/s c:\`) |
| Output | Results shown in terminal | Results redirected to file (`>>`) for collection |
| ParentImage | `explorer.exe` or known backup tool | `powershell.exe`, `cmd.exe` from script |
| Timing | During known backup or audit | Unexpected, or following other suspicious activity |
| Breadth | Targeted specific location | Multiple drives, user folders, program files |

**Alert configuration:**
- **Type:** Real-time
- **Trigger:** Number of results greater than 0
- **Severity:** High

<details>
<summary>📸 Screenshots — T1083 Detection</summary>
<br>

**Screenshot 5 — Splunk catching file and directory discovery event**
> SPL detection query returning 1 event showing the complete T1083 file discovery operation captured in a single Sysmon EventCode 1 event. The CommandLine column shows the full chained command including recursive dir commands across C drive, Program Files, user profiles, and AppData — all redirected to a temp file using >> operator. The output redirection to %temp%\T1083Test1.txt is the definitive pre-exfiltration indicator, showing the attacker is staging file inventory data for theft.

![Screenshot5](day%205%20screenshots/Screenshot5.png)

</details>

---

### 🚨 Complete Alert Library — All 7 Alerts Active

<details>
<summary>📸 Screenshots — Full Alert Dashboard</summary>
<br>

**Screenshot 1 — Splunk Alerts page showing all 7 active detection rules**
> Splunk Alerts page showing the complete detection library built across Days 4 and 5 — 7 automated real-time alerts covering the full attacker kill chain from execution through discovery. Each alert runs continuously in the background, monitoring all incoming Sysmon events and firing automatically the moment a matching attack pattern appears. This is a functioning automated threat detection system equivalent to what enterprise SOC teams deploy across thousands of endpoints.

![Screenshot1](day%205%20screenshots/Screenshot1.png)

</details>

---

### 📊 Complete Detection Coverage — All 7 ATT&CK Techniques

| Alert | Technique ID | Technique Name | Tactic | Event ID | Severity | Coverage |
|-------|-------------|---------------|--------|----------|----------|----------|
| T1082 System Discovery | T1082 | System Information Discovery | Discovery | EventCode 1 | High | whoami, systeminfo, hostname, ipconfig |
| T1059.001 PowerShell | T1059.001 | PowerShell Execution | Execution | EventCode 1 | Critical | EncodedCommand, Bypass, Hidden |
| T1547.001 Registry | T1547.001 | Registry Run Key Persistence | Persistence | EventCode 13 | Critical | CurrentVersion\Run, RunOnce, Winlogon |
| T1053.005 Schtasks | T1053.005 | Scheduled Task Persistence | Persistence | EventCode 1 | Critical | schtasks /create with suspicious triggers |
| T1055 Injection | T1055 | Process Injection | Defense Evasion | EventCode 8 | Critical | CreateRemoteThread, unknown target process |
| T1087.001 Accounts | T1087.001 | Local Account Discovery | Discovery | EventCode 1 | High | net user, net localgroup, whoami /groups |
| T1083 File Discovery | T1083 | File and Directory Discovery | Discovery | EventCode 1 | High | dir /s, tree /F, output redirection to temp |

---

### 🔑 Key Lessons from Day 5

**Lesson 1 — Manual simulation is equal to automated simulation:**
When Atomic Red Team couldn't run specific tests (T1087.001 not available for Windows platform, T1021.001 requiring a second machine), manual PowerShell commands produced identical Sysmon detection events with the same forensic value. In real SOC work, understanding the technique well enough to simulate it manually is more valuable than blindly running tools.

**Lesson 2 — Partial blocks are still full detections:**
T1055 was partially blocked by Windows Defender (shellcode execution denied) but Sysmon still recorded the injection attempt at the kernel level. A blocked attack is NOT a closed case — the SOC must still investigate fully because partial blocks indicate the attacker is present and may try different techniques.

**Lesson 3 — CommandLine chaining is a high-confidence attacker indicator:**
Both T1053.005 (chained schtasks commands) and T1083 (chained dir commands with output redirection) showed attackers combining multiple operations in single command executions. Legitimate administrators run individual commands one at a time — attackers script and chain commands for speed and efficiency.

**Lesson 4 — The kill chain builds on itself:**
Every technique detected today feeds into the next phase. Discovery (T1082, T1087, T1083) provides the intelligence needed for the attacker's next moves. Detecting any single technique should trigger investigation of all related techniques — because where there's one, there are always others.

**What Day 6 delivers:**
Day 6 builds the Splunk threat detection dashboard — a visual real-time interface showing all 7 detection alerts, attack timeline, technique frequency, and ATT&CK matrix coverage. This transforms the raw detection rules into a professional SOC monitoring interface that showcases the complete project in one screen.

</details>
