<p align="center">
  <h1 align="center">usb-verifier</h1>
  <p align="center">🔐 Windows 11 USB integrity & tamper scanner (v1.0)</p>
  <p align="center">
    <img alt="OS" src="https://img.shields.io/badge/Windows-11-0078D6?logo=windows&logoColor=white">
    <img alt="Shell" src="https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white">
    <img alt="Status" src="https://img.shields.io/badge/Status-Stable%20v1.0-brightgreen">
    <img alt="License" src="https://img.shields.io/badge/License-MIT-lightgrey">
  </p>
</p>

---

`usb-verifier` is a PowerShell-based tool to **verify Windows 11 USB installation media** against a known-good ISO.

It performs layered integrity checks:

- Root-level (non-WIM) file comparison
- Deep inspection of internal `boot.wim`, `install.wim`, `.esd`, and split `.swm` files
- Authenticode signature verification
- XML and string-level difference analysis

Results are classified into **GREEN**, **YELLOW**, or **RED** threat levels — making it easy to tell if a USB installer is clean, customized, or potentially tampered with.

---

## 🧩 Scope & Tested Versions

- **Supported media:** Windows 11 installation media only
- **Tested on:** Windows 11 consumer editions, **version 25H2**
  - `en-us_windows_11_consumer_editions_version_25h2_x64_dvd_9934ee4c.iso`
  - `en-gb_windows_11_consumer_editions_version_25h2_x64_dvd_f18d2cbd.iso`
  - `*_windows_11_consumer_editions_version_25h2_updated_nov_2025_x64_*.iso`

Other Windows 11 ISOs _may_ work, but Windows 10 and older are **not supported or tested**.

---

## ✨ What’s new in v1.0

- ✅ **ISO hash verification** against a built-in database of known-good 25H2 ISOs
- ✅ **Persistent ISO lifecycle tracking** with optional reuse of existing mounts
- ✅ **Cross-run cleanup** of script-mounted ISOs (`usb-verifier.state.json`)
- ✅ **Graceful Ctrl+C handling** (cancels DISM, cleans up mounts, exits cleanly)
- ✅ **More robust temp mount cleanup**, with optional aggressive mode using `handle.exe`
- ✅ **Structured ROOT / BOOT / INSTALL summaries** with per-section threat levels

---

## ⚙️ Features

### ✅ ISO Authenticity

- Built-in SHA-256 database for official Windows 11 25H2 consumer ISOs
- Optional `-KnownHashesFile` parameter for your own JSON of known-good hashes
- Logs a **GREEN** “verified authentic” message if the hash matches

### ✅ Root Comparison (Surface Files)

- Compares all ISO vs USB files (excluding WIM/ESD)
- Detects and reports **Modified**, **Extra**, and **Missing** files
- Extra and modified files are analysed by:
  - File type (executables, scripts, configs, text, payload blobs)
  - Signature status (valid Microsoft, unsigned, invalid)
  - XML / string differences (for smaller files)

### ✅ Deep Image Scanning (Internal WIM/ESD/SWM)

- Optional `-DeepScanWIM` mounts and compares the internal contents of:
  - `boot.wim`
  - `install.wim`, `.esd`, or split `.swm`
- Optional `-ReassembleWIM` merges `install*.swm` into a temp WIM before scanning
- Optional `-FullDeepScan` hashes _all_ internal files (instead of only critical types)
- Uses whole-image hashing first: if ISO/USB images are byte-identical, deep scan short-circuits as **clean**

### ✅ Threat-based Classification

- **GREEN:** Matches or benign Microsoft-signed files
- **YELLOW:** Configuration/text differences, missing/extra non-executables, version drift
- **RED:** Modified/extra unsigned binaries, drivers, scripts or payload-style blobs

Final output includes:

- Overall verdict: **GREEN / YELLOW / RED**
- Per-section status for:
  - `ROOT (Surface files)`
  - `BOOT (Internal image)`
  - `INSTALL (Internal image)`

### ✅ Clean Reporting & Lifecycle

- Structured log sections for **ENVIRONMENT**, **ISO**, **ROOT**, **BOOT**, and **INSTALL**
- Final **“USB Verification Summary”** with:
  - Per-section Modified/Extra/Missing counts
  - Green/Yellow/Red breakdown
  - Short explanation of why a section is marked RED/YELLOW (by file type)
- Automatic mount and temp cleanup:
  - Uses `DISM /Cleanup-Mountpoints`
  - Cleans up `C:\Temp\mount_*` and temporary WIMs
  - Cleans up script-mounted ISOs across runs while respecting user-mounted ones

---

## 🧱 Requirements

| Requirement    | Notes                                                                |
| -------------- | -------------------------------------------------------------------- |
| **Host OS**    | Windows 11 (may run on 10, untested)                                 |
| **PowerShell** | ≥ 5.1 (7+ recommended for parallel hashing)                          |
| **Privileges** | Admin rights strongly recommended for image mounting and deep scans  |
| **Tools**      | Built-in `DISM`; optional Sysinternals `handle.exe` for lock tracing |
| **Temp Path**  | Uses `C:\Temp` for DISM logs, mounts, and temporary WIM files        |

> ℹ️ Some features (deep WIM scan, SWM reassembly, aggressive cleanup) will skip or downgrade gracefully if not running as admin.

---

## 🚀 Basic Usage

Run in **PowerShell as Administrator**:

```powershell
.\verifyusb.ps1 -ISOPath "C:\ISOs\Win11_25H2.iso" -USBDrive "E:"
```

This performs:

1. Environment validation
2. ISO hash check against the known-good list (plus optional -KnownHashesFile)
3. Root-level file hashing and comparison
4. Summary verdict (no deep WIM scanning by default)

---

## 🧭 Full Usage Example

```powershell
.\verifyusb.ps1 `
  -ISOPath "C:\ISOs\Win11_25H2.iso" `
  -USBDrive "E:" `
  -LogFile "C:\logs\usb_report.txt" `
  -MaxAnalysisSizeMB 10 `
  -VerboseDiffs `
  -IgnoreFiles @("\sources\appraiser.sdb") `
  -ReassembleWIM `
  -DeepScanWIM `
  -FullDeepScan `
  -KnownHashesFile "C:\known-iso-hashes.json"
```

---

## 🔧 Parameter Reference

| Parameter                | Description                                           |
| ------------------------ | ----------------------------------------------------- |
| **`-ISOPath`**           | _(Required)_ Path to the Windows 11 ISO               |
| **`-USBDrive`**          | _(Required)_ USB drive letter, e.g. `"E:"`            |
| **`-LogFile`**           | Output log location (default `usb_report.txt`)        |
| **`-MaxAnalysisSizeMB`** | Max file size for XML/string diffing (default 10 MB)  |
| **`-VerboseDiffs`**      | Show full string/XML differences instead of summaries |
| **`-IgnoreFiles`**       | Array of relative paths to ignore entirely            |
| **`-ReassembleWIM`**     | Reassemble split `install*.swm` into temp WIM         |
| **`-DeepScanWIM`**       | Enable deep internal WIM/ESD/SWM scanning             |
| **`-FullDeepScan`**      | Hash and compare _all_ internal files                 |
| **`-KnownHashesFile`**   | Path to custom JSON file of known-good ISO hashes     |

Example JSON for `-KnownHashesFile`:

```json
{
  "custom_win11_25h2.iso": "ABCDEF0123456789...",
  "lab_build.iso": "0123456789ABCDEF..."
}
```

---

## 🧩 Example Output

```text
===== [SUMMARY] ===== Overall Threat Summary
[RESULT] USB Verification Summary
[RESULT] ==================== FINAL RESULT ====================
[RESULT] [ OK ] Overall verdict: GREEN
[RESULT] ------------------------------------------------------
[RESULT] [ OK ] ROOT (Surface files): GREEN | Modified: 0, Extra: 0, Missing: 0
[RESULT]        Breakdown: Green=12, Yellow=0, Red=0
[RESULT] [ OK ] BOOT (Internal image): GREEN | No differences
[RESULT] [ OK ] INSTALL (Internal image): GREEN | No differences
[RESULT] ======================================================

Example with a warning:
[RESULT] [WARN] Overall verdict: YELLOW
[RESULT] [FAIL] ROOT (Surface files): RED | Modified: 2, Extra: 1, Missing: 0
[RESULT]        Files: \autorun.inf, \sources\offline.xml, \__chunk_data\chunk1.bin
[RESULT]        Reason (RED): includes script/executable changes; includes binary payload-style files.

```

---

## 🧠 Interpretation

| Level      | Meaning                           | Typical Causes                                            |
| ---------- | --------------------------------- | --------------------------------------------------------- |
| **GREEN**  | All critical files match; safe    | Clean ISO or known tool-generated media                   |
| **YELLOW** | Minor or expected differences     | Config/log/docs changes, benign XML edits, MCT variations |
| **RED**    | High-risk or suspicious tampering | Unsigned binaries, altered drivers, injected payloads     |

⚠️ Important: “GREEN” means “matches your ISO source”, not “cryptographically blessed by Microsoft forever”. If your ISO is compromised, your USB will faithfully match that compromise.

---

## ⚠️ Limitations

- Only validated for **Windows 11 25H2 consumer** ISOs
- Requires `C:\Temp` for mounts/logs
- DISM or locked files may occasionally need manual cleanup
- Network shares, heavily locked files, or AV interference may affect results

---

## 🪪 License

MIT License  
© 2025
See `LICENSE` for full details.
