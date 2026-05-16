# Windows Hardening Scripts

Standalone PowerShell hardening scripts for Windows 10, Windows 11, and Windows Server. Built by practitioners, for practitioners. Every control is sourced, every decision is documented.

**Hans Study, CISSP** -- independent network and security expert, consultant, and advisor.
[hans.study](https://hans.study) | [contact@hans.study](mailto:contact@hans.study)
LinkedIn: [hans-study](https://linkedin.com/in/hans-study) | Instagram: [@StudyByt3s](https://instagram.com/studybyt3s) | X: [@StudyByt3s](https://x.com/studybyt3s) | YouTube: [@StudyByt3s](https://youtube.com/@studybyt3s) | GitHub: [tsglabs](https://github.com/tsglabs)

---

## What These Scripts Do

Each script applies a hardening baseline to a Windows workstation or server. Every control includes an inline comment explaining what it does, why it matters, and the official standard it comes from. That standard is one of: a DISA STIG rule ID, a CIS section number, an NSA/CISA publication, or a CCCS ITSP document section.

Every script requires administrator privileges, creates a system restore point before making any change, logs all output to `C:\Logs\` with a dated filename, detects OS edition at runtime and skips Enterprise-only controls on Pro with a logged warning, and prompts for restart when controls require one. Drop a single `.ps1` on any machine and run it. No other files needed.

Source-available. Personal and internal organizational use permitted, including internal commercial use. Redistribution requires written authorization from Hans Study. See [LICENSE](LICENSE) for full terms.

---

## Standards Referenced

Every command and registry path has been verified against official sources before inclusion.

| Standard | Publisher | URL |
|---|---|---|
| DISA STIG Windows 11 V2R2 / Windows 10 V2R7 | Defense Information Systems Agency | [public.cyber.mil](https://public.cyber.mil) |
| CIS Microsoft Windows 11/10 Benchmark v3.0 | Center for Internet Security | [cisecurity.org](https://cisecurity.org) |
| NSA/CISA Cybersecurity Information Sheets | NSA / CISA | [media.defense.gov](https://media.defense.gov) |
| NSA/CISA Keeping PowerShell Security Measures (June 2022) | NSA / CISA | [media.defense.gov](https://media.defense.gov) |
| ITSP.70.012 Hardening Microsoft Windows 10 Enterprise | CSE / CCCS | [cyber.gc.ca](https://cyber.gc.ca) |
| CPCSC ITSP.10.171 Protecting Specified Information | CCCS | [cyber.gc.ca](https://cyber.gc.ca) |
| CMMC 2.0 (NIST SP 800-171 Rev 2) | US DoD | [dodcio.defense.gov/cmmc](https://dodcio.defense.gov/cmmc) |
| Genetec Security Center Hardening Guide | Genetec | [publications.genetec.com](https://publications.genetec.com) |

---

## Scripts

### Helper Functions (embedded in every script)

Each script is fully standalone. Six helper functions are embedded directly: `Write-TSGSection`, `Set-TSGRegistry`, `Remove-TSGAppx`, `Test-TSGEnterprise`, `New-TSGRestorePoint`, and `Disable-TSGNetBIOS`. No module, no dependency, no separate file. Copy any script to a machine and run it.

---

### Genetec-SecurityCenter-Workstation.ps1

**Use when:** Deploying a Genetec Security Center workstation, Archiver, or Directory server.

Applies CCCS/NSA/CISA-level hardening with specific tuning for Genetec SC 6.x. Every decision that deviates from a standard baseline is documented inline with the reason.

Key Genetec-specific decisions:

**Controlled Folder Access is not enabled.** Genetec writes continuously to AppData and archive paths. CFA blocks these writes until whitelisted. Use AuditMode first to build the exclusion list before enabling.

**Windows Search Indexing is disabled.** Genetec has its own media index. WSearch generates competing I/O on archive volumes with no benefit.

**SysMain (Superfetch) is disabled.** RAM should go to the Archiver buffer and SQL cache, not application pre-loading.

**Cloud-delivered Defender protection is disabled.** Most VMS networks are isolated. Outbound sample submission is not appropriate and can cause latency on restricted networks.

**RDP is left enabled with NLA enforced.** SC administrators need remote Config Tool access. Disable it if your environment does not require remote administration.

**High Performance power plan is on.** CPU throttling causes frame drops and recording gaps on Archiver servers.

**Hibernation is disabled.** Recording servers must never hibernate. It causes recording gaps that cannot be recovered.

Defender exclusions are added for G64, G64x, MDF, LDF, and NDF file extensions and Genetec installation paths. Firewall rules are added for TCP 5500 (SDK), 443 (HTTPS), 554 (RTSP), 555 (stream), and 8888 (Unit Assistant).

**Why Genetec Security Center needs its own hardening script**

Generic Windows hardening baselines break Genetec deployments in predictable ways. Controlled Folder Access blocks video archive writes and causes recording gaps. Aggressive Defender scanning of G64 files on the Archiver volume creates I/O contention that shows up as dropped frames and buffering delays in Security Desk. Hibernation on a server running the Genetec Directory causes all connected clients to lose their session. The standard hardening advice (apply DISA STIG, enable all Defender features, set the strictest power plan) gets applied without understanding what Genetec actually does at the OS level, and then the integrator spends hours troubleshooting symptoms that trace directly back to the hardening script.

This script is built from direct experience hardening Genetec Security Center deployments across government, law enforcement, airports, and critical infrastructure sites. The goal is a workstation that passes a security audit and keeps cameras recording. Both are achievable. They just require different settings than a standard endpoint.

**Genetec Security Center default communication ports**

The script adds inbound firewall rules for the following Genetec default ports. If your deployment uses custom port assignments configured in Config Tool, update the `$genetecRules` array in the script before running.

| Port | Protocol | Purpose |
|---|---|---|
| 5500 | TCP | Genetec Directory SDK. Client connections from Security Desk and Config Tool |
| 443 | TCP | Genetec Web Client and REST API (HTTPS) |
| 554 | TCP | Genetec Archiver RTSP. Live stream and playback |
| 555 | TCP | Genetec Archiver proprietary stream protocol |
| 8888 | TCP | Genetec Unit Assistant. Camera unit management and firmware updates |

**Genetec Windows Defender exclusions**

The following exclusions are added by the script. Scanning these paths and file extensions with real-time protection causes measurable throughput reduction on the Archiver, particularly on high-camera-count or high-bitrate deployments.

- `C:\Program Files (x86)\Genetec Security Center`. SC installation directory
- `C:\Program Files\Genetec Security Center`. SC installation directory (64-bit path)
- `.g64`. Genetec proprietary video container format
- `.g64x`. Genetec extended video container format
- `.mdf`, `.ldf`, `.ndf`. SQL Server database files used by the Genetec Directory

If your Genetec archive is stored on a non-default path, add an exclusion for it manually after running the script:
```powershell
Add-MpPreference -ExclusionPath "D:\GenetecArchive"
```

**Tested against:** Genetec Security Center 6.x on Windows Server 2019, Windows Server 2022, Windows 10 Enterprise, and Windows 11 Enterprise. Validate in a lab environment before applying to a production Archiver or Directory.

---

### CCCS-NSA-CISA-Baseline.ps1

**Use when:** Hardening a Canadian government contractor, healthcare, or enterprise workstation. Recommended starting point for Canadian deployments.

Aligns with CSE/CCCS ITSP.70.012, the NSA/CISA June 2022 PowerShell security guidance, and CPCSC endpoint requirements. Covers WDigest removal, NTLMv2 enforcement, LLMNR and NetBIOS disable, SMBv1 removal, PS v2 removal, Script Block Logging, and PS Transcription. Less disruptive than DISA STIG. No mandatory Always Notify UAC, no forced AppLocker.

---

### DISA-STIG-Baseline.ps1

**Use when:** You need DoD-level hardening or your contract, insurance, or compliance program requires DISA STIG compliance.

Addresses all CAT I (critical) and most CAT II (medium) DISA STIG findings for standalone, non-domain-joined Windows 10 and 11 systems. Every registry key and command cites its DISA STIG rule ID (for example, `WN11-CC-000040`, `WN11-SO-000195`) for direct traceability against the official STIG checklist.

Be aware before deploying: UAC is set to Always Notify (required by WN11-SO-000251), RDP is disabled by default, WSH is disabled which will break .vbs and .js automation, and AppLocker service is started on Enterprise but rule configuration via Group Policy is required separately. Comment out any block that conflicts with your operational requirements.

---

### CIS-Benchmark-L1.ps1

**Use when:** You want an industry-standard baseline accepted for compliance audits and vendor security assessments.

CIS Microsoft Windows 11/10 Benchmark Level 1. Designed to deploy without significant operational impact. Level 2 controls (AppLocker, mandatory BitLocker PIN, Credential Guard enforcement) are not included. Use the DISA STIG script if Level 2 coverage is required. Every registry key and command cites its CIS section number.

---

### Minimum-Viable-Security.ps1

**Use when:** Hardening a legacy environment where compatibility is a concern, or you want a verified low-risk starting point before going further.

Curated minimum baseline. Every control works on Windows 10/11 Pro without additional licensing and is unlikely to break existing applications. Apply `CCCS-NSA-CISA-Baseline.ps1` or `DISA-STIG-Baseline.ps1` after this for full coverage.

---

### Security-Analyst-Workstation.ps1

**Use when:** Setting up a workstation for a SOC analyst, threat hunter, DFIR practitioner, or incident responder.

DISA STIG-level hardening with analyst-specific carve-outs. IPv6 and RDP are left enabled. Cloud-delivered Defender protection is disabled for air-gapped analysis and sandbox work. Controlled Folder Access is not enabled because forensic tools write to too many locations to whitelist reliably. Security event log is set to 2GB, PS Operational log to 200MB.

---

### Kiosk-ThinClient-Lockdown.ps1

**Use when:** Setting up a guard terminal, reception kiosk, lobby access control console, or any other single-purpose machine.

Maximum restriction. RDP, NetBIOS, LLMNR, and IPv6 are all disabled. UAC is set to Always Notify and standard user elevation is auto-denied. WSH is disabled. BitLocker is enabled. AppLocker service is started on Enterprise. Rules require Group Policy. High Performance power plan is on, hibernation is off, SysMain and WSearch are disabled, and all consumer apps are removed.

Verify the kiosk application works correctly after applying. If Controlled Folder Access blocks it:
```powershell
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Path\To\KioskApp.exe"
```

---

### CMMC-CPCSC-ITSP10171.ps1

**Use when:** Your organization handles US DoD Controlled Unclassified Information (CUI) under CMMC, or Canadian government Specified Information (SI) under CPCSC.

Controls are cited with both the CMMC 2.0 practice ID (for example, `AC.L1-3.1.1`) and the CPCSC/ITSP.10.171 equivalent (for example, `CPCSC A.03.01.01`). Controls required at Level 1 are marked `[LEVEL 1]`. One script serves both programs.

**Timelines:**

| Program | Level | Requirement | When |
|---|---|---|---|
| CPCSC | Level 1 | 13 controls, self-assessment | Summer 2026 |
| CPCSC | Level 2 | 98 controls, third-party assessment | Spring 2027 |
| CMMC | Level 2 | 110 practices, third-party assessed | Active now for DoD contracts with CUI |

CMMC uses NIST SP 800-171 Rev 2 (110 controls). CPCSC uses Rev 3 (97 controls). The technical requirements are functionally identical. The terminology differs (CUI under CMMC, Specified Information under CPCSC), as does the governing authority, but a single hardened workstation satisfies both.

This script covers technical OS controls: UAC, firewall, audit logging, encryption, malware protection, credential protection, FIPS mode, BitLocker, and BitLocker To Go for removable drives. It does not cover written policies, incident response plans, risk assessments, or key management procedures. Those are organizational controls. The script prints a full checklist of required documentation at the end.

The log file it generates is technical implementation evidence for your System Security Plan (SSP). For formal assessment, engage a C3PAO (CMMC) or an accredited 3PAO through the Standards Council of Canada (CPCSC).

---

## Edition Requirements

Credential Guard and AppLocker enforcement require Windows Enterprise or Education licensing. Both are detected at runtime and auto-skipped on Pro with a logged warning. Source: [learn.microsoft.com/windows/security/licensing-and-edition-requirements](https://learn.microsoft.com/en-us/windows/security/licensing-and-edition-requirements)

Everything else (BitLocker, DEP, ASLR, SEHOP, LSA Protection, all audit controls, and all Defender controls) works on Pro and Enterprise.

---

## How to Run

Download the script for your use case. Open PowerShell as Administrator.

```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\CCCS-NSA-CISA-Baseline.ps1
```

Or right-click the .ps1 and choose **Run with PowerShell** (as Administrator).

The script creates a restore point, applies all controls, logs everything to `C:\Logs\`, reports any skipped Enterprise-only controls, and prompts for restart. Review the log for `[FAIL]` entries before restarting.

---

## Accuracy Notes

A few behaviors that look wrong but are correct:

**SEHOP:** `DisableExceptionChainValidation = 0` enables SEHOP. Setting it to 0 turns protection on. The registry name is counterintuitive. Confirmed correct in DISA STIG WN11-00-000025.

**Firewall profile list:** `Set-NetFirewallProfile -Profile Domain,Public,Private` (no spaces in the profile list). `Domain, Public, Private` with spaces is a common error in other scripts and can cause unexpected behavior.

**NetBIOS disable:** Uses `Win32_NetworkAdapterConfiguration.SetTcpipNetbios(2)` via WMI. Value 2 = disable. There is no native PowerShell cmdlet for this.

**FIPS mode (CMMC/CPCSC script):** Required by CMMC SC.L1-3.13.8 and CPCSC A.03.13.08. Some applications using non-FIPS cryptographic APIs will fail after this is enabled. Test before production deployment.

**BitLocker To Go (CMMC/CPCSC script):** `RDVDenyWriteAccess = 1` blocks write access to removable drives until they are encrypted. Users see a prompt to encrypt the USB drive before they can write to it.

---

## Helper Functions Reference

These functions are embedded in every script. Copy the definitions into your own scripts if needed.

```powershell
# Idempotent registry write. Creates key path if missing, logs OK or FAIL
Set-TSGRegistry -Path "HKLM:\Software\..." -Name "ValueName" -Value 1

# Section header with optional source reference subtitle
Write-TSGSection "SECTION TITLE" "DISA WN11-XX-000000 | CIS 18.x.x"

# AppX removal. Provisioned (new users) and per-user (existing accounts)
Remove-TSGAppx -PackageName "Microsoft.BingNews" -FriendlyName "Bing News"

# Enterprise license check. Returns $true or $false, logs warning on Pro
if (Test-TSGEnterprise -ControlName "Credential Guard") { ... }

# System restore point before any changes
New-TSGRestorePoint -Description "Pre-hardening snapshot"

# Disable NetBIOS over TCP/IP on all IPv4 adapters via WMI
Disable-TSGNetBIOS
```

---

## Generate Custom Scripts

These scripts were produced using the **Study Workstation Configurator**, a free tool on hans.study that generates a documented PowerShell script from your selected baseline, OS, and individual controls. CMMC/CPCSC mode adds dual practice ID citations to every control in the generated output.

[hans.study/tools/workstation-config](https://hans.study/tools/workstation-config)

---

## About

Hans Study, CISSP. Independent network and security expert, consultant, and advisor based in the Greater Toronto Area, Ontario, Canada. Government, law enforcement, defense, airports, healthcare, and enterprise clients across Canada and the US. Work includes physical security system integration (Genetec, Milestone, C-CURE, Avigilon, Axis, Bosch), secure network architecture, OT/IT convergence, and cybersecurity consulting for physical security environments.

[hans.study](https://hans.study) | [contact@hans.study](mailto:contact@hans.study)

---

## License

Source-available. See [LICENSE](LICENSE) for the full terms.

**Permitted without prior authorization:**
- Personal use.
- Internal organizational use, including internal commercial use (running the scripts on systems your organization owns, leases, or is authorized to administer).
- Local modifications for your own internal use.

**Requires written authorization from Hans Study:**
- Redistribution, republishing, mirroring, hosting, or sublicensing.
- Selling, leasing, renting, or providing the scripts as a paid product or hosted service.
- Including the scripts in another product, repository, or distribution channel.
- Distributing derivative works.

Authorization requests: [contact@hans.study](mailto:contact@hans.study).

**Attribution required in every authorized use:**
- Keep the [LICENSE](LICENSE) file intact.
- Keep the POWER_HEADER `.NOTES` block at the top of each `.ps1` file.
- Keep the console banner that prints during script execution (`Hans Study, CISSP | https://hans.study`).
- Visibly credit Hans Study (hans.study) in any derivative work, screenshot, blog post, video, presentation, or other public communication that incorporates or demonstrates the scripts.

No warranty. Test before production deployment. Hans Study accepts no liability for unintended consequences.
