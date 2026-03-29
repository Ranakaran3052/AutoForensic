# AutoForenX — Enterprise Forensic Automation Framework

> A modular, CLI-driven digital forensics platform for RAM analysis, mobile device examination, DNS investigation, ML-based anomaly detection, and automated PDF report generation.

---

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Modules](#modules)
- [CLI Usage](#cli-usage)
- [Case ID Format](#case-id-format)
- [Output Files](#output-files)
- [Acquisition Sources](#acquisition-sources)
- [Legal Notice](#legal-notice)

---

## Overview

AutoForenX automates the most time-consuming phases of a digital forensics investigation. Feed it a memory dump, a mobile backup, or a log file — it extracts, correlates, and reports evidence across all sources under a single case ID with full SHA-256 integrity verification.

**What it does:**

- Computes SHA-256 integrity hash of every evidence source
- Parses RAM dumps for processes, IPs, URLs, domains, emails, NTLM hashes, cleartext credentials, deleted file artifacts, and more
- Extracts call logs, messages, location data, app inventory, and device identifiers from Android and iOS acquisitions
- Runs a forensic DNS pipeline across dump files
- Detects anomalies using an ML model fed from log and DNS findings
- Generates a structured PDF report and persists case metadata to a local database
- Optionally launches an interactive forensic dashboard

---


## Requirements
- RAM 8GB Minimum
- Python 3.8+
- No mandatory third-party packages for core analysis (stdlib only)
- Optional packages for enhanced features:

```
reportlab       # PDF report generation
sqlite3         # built-in
argparse        # built-in
```

Install optional dependencies:

```bash
pip install reportlab
```

---

## Installation

```bash
git clone https://github.com/yourname/autoforenx.git
cd autoforenx
pip install -r requirements.txt
```

---

## Modules

### `ram_analyzer.py` — RAM Dump Forensics

Scans memory dumps in 40 MB chunks with 1 KB overlap to avoid missing cross-boundary artifacts.

**Extracts:**

| Category | Details |
|---|---|
| Processes | `.exe` names resident in memory |
| Network | IP addresses, URLs, domains |
| Email addresses | RFC-compliant patterns |
| Suspicious commands | PowerShell, Mimikatz, Cobalt Strike, Meterpreter, netcat, and 15+ others |
| NTLM hashes | `LM:NT` 32-hex pairs |
| Net-NTLMv2 blobs | `NTLMSSP\x00` signature captures |
| LSASS / DPAPI strings | SAMKey, MasterKey, NL$KM, CryptProtect |
| Cleartext credentials | Keyword-context scan (password, token, api_key, Authorization, etc.) |
| Browser credentials | logins.json, key4.db, Login Data, Cookies |
| Base64 credential blobs | JWT, PE, and common token prefixes |
| Deleted file magic bytes | PE/EXE, ZIP, PDF, JPEG, PNG, OLE, RAR, 7z, GZIP, BMP, GIF, SQLite, LNK |
| MFT entries | NTFS `FILE\x00\x00` signatures with byte offset |
| Recycle Bin paths | `$Recycle.Bin` / `RECYCLER` remnants |
| Shadow copy references | `HarddiskVolumeShadowCopy*` strings |
| Deleted file paths | Full paths ending in forensically relevant extensions |
| Contact numbers | E.164 and local phone number patterns |

---

### `mobile_forensics.py` — Android / iOS Evidence Extraction

Supports directory extractions, Android Backup (`.ab`), ZIP archives, and raw binary dumps.

**Extracts:**

| Category | Android Source | iOS Source |
|---|---|---|
| Device identifiers | `build.prop`, binary scan | `Info.plist`, `Manifest.plist`, binary scan |
| IMEI / IMSI / ICCID | Binary pattern scan | Plist key extraction |
| Serial / Build fingerprint | `ro.serialno`, `ro.build.fingerprint` | `SerialNumber` plist key |
| Call logs | `calllog.db`, `contacts2.db` | `CallHistory.storedata` |
| VoIP artifacts | Pattern scan across all files | Pattern scan across all files |
| SMS / MMS | `mmssms.db` | `sms.db` |
| iMessage | — | `sms.db` (service field) |
| WhatsApp | `msgstore.db` | `ChatStorage.sqlite` |
| Telegram | `cache4.db` | — |
| Signal | `signal.db` | — |
| GPS location | Location DBs, EXIF tags, text scan | `consolidated.db`, `significant_location.db`, EXIF |
| Installed apps | `packages.xml` | `Manifest.plist`, bundle ID scan |
| Uninstalled apps | `usage_stats.xml` ghost entries | — |
| App permissions | `packages.xml` `<perms>` blocks | — |
| Suspicious apps | Matched against known stalkerware / RAT / malware package list | Same |

**Call log fields captured:**

- Phone number / contact name
- Direction: `INCOMING` / `OUTGOING` / `MISSED`
- Timestamp (ISO-8601 UTC)
- Duration in seconds
- VoIP flag and service provider
- Geocoded location (Android)
- Country code (iOS)

---

### `dns_pipeline.py` — DNS Forensic Pipeline

Runs forensic DNS analysis across dump files, extracting and evaluating domains for suspicious indicators.

---

### `ml_detector.py` — ML Anomaly Detection

Scores investigation risk using suspicious log event count and DNS anomaly count as features. Returns a status (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`) and a numeric risk score out of 100.

---

### `log_parser.py` — Log File Parsing

Parses structured and unstructured log files. Extracts suspicious events and email addresses for correlation with RAM and DNS findings.

---

### `report.py` — PDF Report Generation

Generates a structured evidence report at `reports/{CASE_ID}_report.pdf` containing all findings, metadata, risk score, and case chain-of-custody fields.

---

### `database.py` — Case Database

Persists case metadata to a local SQLite database including case ID, file hash, suspicious event count, and risk score for longitudinal tracking.

---

### `dashboard.py` — Forensic Dashboard

Interactive terminal or GUI dashboard for reviewing active and historical case findings.

---

## CLI Usage

### Help

```bash
python main.py --help
```

### Arguments

| Argument | Value | Description |
|---|---|---|
| `--case` | `CASE-YYYYMMDD-XXXX` | Case ID — required for all investigation modes |
| `--file` | path | Evidence file to hash and extract metadata from |
| `--log` | path | Log file to parse for suspicious events and emails |
| `--dump` | path | RAM dump for DNS pipeline + RAM forensic analysis |
| `--mobile` | path | Mobile acquisition (dir / `.ab` / `.zip` / `.img`) |
| `--platform` | `auto` `android` `ios` | Mobile platform hint (default: `auto`) |
| `--dashboard` | flag | Launch forensic dashboard (no case required) |

---

### Commands

**File hash and metadata only:**
```bash
python main.py --case CASE-20260329-077F --file evidence.bin
```

**Add log parsing:**
```bash
python main.py --case CASE-20260329-077F --file evidence.bin --log system.log
```

**RAM dump analysis (DNS + RAM forensics):**
```bash
python main.py --case CASE-20260329-077F --dump charlie-2009-11-16.mddramimage
```

**RAM dump with mobile acquisition (auto-detect platform):**
```bash
python main.py --case CASE-20260329-077F --dump memory.img --mobile backup.ab
```

**RAM dump with explicit Android mobile acquisition:**
```bash
python main.py --case CASE-20260329-077F --dump memory.img --mobile backup.ab --platform android
```

**iOS mobile acquisition only (no RAM dump):**
```bash
python main.py --case CASE-20260329-077F --mobile ios_backup/ --platform ios
```

**Full investigation — all sources combined:**
```bash
python main.py --case CASE-20260329-077F \
  --file evidence.bin \
  --log system.log \
  --dump memory.img \
  --mobile backup.ab \
  --platform android
```

**Dashboard mode:**
```bash
python main.py --dashboard
```

---

## Case ID Format

All investigations require a valid Case ID in the following format:

```
CASE-YYYYMMDD-XXXX
```

| Part | Description |
|---|---|
| `CASE` | Literal prefix |
| `YYYYMMDD` | Date of case creation |
| `XXXX` | 3–6 alphanumeric unique identifier |

**Examples:**
```
CASE-20260329-077F
CASE-20240115-0042
CASE-20251201-AB3C
```

If no case ID is provided or the format is invalid, AutoForenX will auto-generate a valid one and prompt for confirmation before proceeding.

---

## Output Files

| File | Location | Description |
|---|---|---|
| PDF report | `reports/{CASE_ID}_report.pdf` | Full investigation report |
| RAM JSON | `{CASE_ID}_ram.json` | Raw RAM findings |
| Mobile JSON | `mobile_reports/{CASE_ID}_mobile_{TIMESTAMP}.json` | Mobile evidence findings |
| Case database | `forensics.db` (or configured path) | SQLite case history |

---

## Acquisition Sources

AutoForenX does **not** include any device access, unlocking, or credential attack tooling. All analysis is performed on pre-acquired evidence files obtained through lawful means.

**Supported acquisition formats:**

| Format | Description |
|---|---|
| `.mddramimage` / `.img` / `.bin` | Raw physical or RAM dump |
| `.ab` | Android Backup (ADB) |
| `.zip` | iTunes backup export or packaged acquisition |
| Directory | Extracted ADB tar, iTunes backup folder, or manual extraction |

**Recommended acquisition tools (external):**
- Android: ADB (`adb backup`), Cellebrite UFED, Oxygen Forensics
- iOS: iTunes / Finder backup, Cellebrite UFED, libimobiledevice
- RAM: WinPmem, DumpIt, Magnet RAM Capture, LiME (Linux)

---

## Legal Notice

AutoForenX is intended for use by **authorized digital forensics professionals, law enforcement, and security researchers** operating under proper legal authority.

- Only analyze devices and data you are legally authorized to examine.
- Obtain proper warrants, consent, or authorization before acquiring evidence.
- Maintain a documented chain of custody for all evidence sources.
- The authors accept no liability for unauthorized or unlawful use of this tool.
