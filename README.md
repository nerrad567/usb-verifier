# usb-verifier

`usb-verifier` is a PowerShell-based tool to **verify Windows 11 USB installation media** against a known-good ISO.

It performs layered integrity checks:

- Root-level (non-WIM) file comparison
- Deep inspection of internal `boot.wim`, `install.wim`, `.esd`, and split `.swm` files
- Authenticode signature verification
- XML and string-level difference analysis

Results are classified into **GREEN**, **ORANGE**, or **RED** threat levels — making it easy to tell if a USB installer is clean, customized, or potentially tampered with.

---

## 🧩 Scope & Tested Versions

- **Supported OS:** Windows 11 installation media only
- **Tested on:** Windows 11 consumer editions, **version 25H2**
  - `en-us_windows_11_consumer_editions_version_25h2_x64_dvd_9934ee4c.iso`
  - `en-gb_windows_11_consumer_editions_version_25h2_x64_dvd_f18d2cbd.iso`
  - `*_windows_11_consumer_editions_version_25h2_updated_nov_2025_x64_*.iso`

Other Windows 11 ISOs _may_ work, but Windows 10 and older are **not supported or tested**.

---

## ⚙️ Features

### ✅ ISO Authenticity

- Built-in SHA-256 database for official Windows 11 25H2 consumer ISOs
- Optional `-KnownHashesFile` parameter for your own JSON of known-good hashes

### ✅ Root Comparison

- Compares all ISO vs USB files (excluding WIM/ESD)
- Detects and reports **Modified**, **Extra**, and **Missing** files

### ✅ Deep Image Scanning

- Optional `-DeepScanWIM` mounts and compares the internal contents of:
  - `boot.wim`
  - `install.wim`, `.esd`, or split `.swm`
- Optional `-ReassembleWIM` merges `install*.swm` before scanning
- Optional `-FullDeepScan` hashes _all_ internal files (instead of only critical types)

### ✅ Threat-based Classification

- **GREEN:** Matches or benign Microsoft-signed files
- **ORANGE:** Benign configuration or text differences
- **RED:** Modified/extra unsigned binaries, drivers, or unknown files

### ✅ Clean Reporting

- Structured log sections for **BOOT**, **INSTALL**, and **ROOT**
- Final summary with color-coded verdict
- Automatic mount cleanup and temporary file removal

---

## 🧱 Requirements

| Requirement    | Notes                                                |
| -------------- | ---------------------------------------------------- |
| **Host OS**    | Windows 11 (may run on 10, untested)                 |
| **PowerShell** | ≥ 5.1 (7+ recommended for parallel hashing)          |
| **Privileges** | Admin rights required for image mounting and cleanup |
| **Tools**      | Built-in `DISM`; optional Sysinternals `handle.exe`  |

---

## 🚀 Basic Usage

Run in **PowerShell as Administrator**:

```powershell
.\verifyusb.ps1 -ISOPath "C:\ISOs\Win11_25H2.iso" -USBDrive "E:"
```

This performs:

1. Environment and ISO validation
2. Root-level file hashing and comparison
3. Summary verdict (no deep WIM scanning by default)

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
[SUMMARY] BOOT    : GREEN   – No internal differences
[SUMMARY] INSTALL : GREEN   – No internal differences
[SUMMARY] ROOT    : ORANGE  – 5 modified or extra files (docs/configs)
[SUMMARY] Verdict : ORANGE WARNING – Likely benign (e.g. MCT customizations)
```

---

## 🧠 Interpretation

| Level      | Meaning                        | Typical Causes                                     |
| ---------- | ------------------------------ | -------------------------------------------------- |
| **GREEN**  | All critical files match; safe | Clean ISO or known tool-generated media            |
| **ORANGE** | Minor differences              | Config/log/docs changes, benign XML edits          |
| **RED**    | High-risk tampering            | Unsigned binaries, altered drivers, injected files |

---

## ⚠️ Limitations

- Only validated for **Windows 11 25H2 consumer** ISOs
- Requires `C:\Temp` for mounts/logs
- DISM or locked files may occasionally need manual cleanup
- “GREEN” means _identical to source_, not _trusted in absolute security terms_

---

## 🧰 Roadmap

- JSON / HTML structured report output
- Multi-USB comparison mode
- Additional language ISO hash support
- Extended signature metadata analysis

---

## 🪪 License

MIT License  
© 2025
See `LICENSE` for full details.
