# Windows USB Integrity Verifier & Resource Analyzer - PARANOID EDITION

**Version:** Updated / Paranoid Edition  
**Author:** GL
**Purpose:** Combines USB integrity verification with detailed analysis of modified resources. Ideal for checking Windows installation media and critical USB distributions.

---

## Overview

This PowerShell script performs a comprehensive comparison between a Windows ISO and a USB drive, detecting:

- Hash mismatches between files
- Modified code files (executables, DLLs, drivers)
- Modified resource files (XML, MUI, configuration)
- Extra or missing files on the USB
- Validity of Microsoft digital signatures on modified code files
- Detailed analysis of resource-only modifications (strings, PE headers, XML diffs)

It provides a **Final Safety Assessment** indicating whether the USB is safe or requires review.

---

## Features

1. **Essentials Check**
   - Ensures script is run as **Administrator**
   - Verifies PowerShell version = 5.1
   - Provides guidance if requirements are not met

2. **File Hashing**
   - Computes SHA-256 hashes for all ISO and USB files
   - Builds dictionaries for efficient comparison

3. **Comparison & Categorization**
   - Identifies files that are identical, modified, missing, or extra
   - Separates **code** vs **resource** modifications
   - Detects split WIMs common in FAT32 USBs

4. **Code File Analysis**
   - Checks Authenticode signatures on modified code files
   - Flags non-Microsoft or invalid signatures as suspicious

5. **Resource File Analysis**
   - Extracts and diffs printable strings (>20 characters)
   - Performs XML line-by-line comparison
   - Displays PE headers for resource-only files

6. **Reporting**
   - Detailed summary of:
     - Total ISO & USB files
     - Matched files
     - Extra/missing files
     - Modified code and resource files
   - Final safety verdict: **Safe** or **STOP**

7. **Cleanup**
   - Dismounts ISO automatically after analysis
   - Reports execution duration

---

## Requirements

- **Windows OS**
- **PowerShell 5.1+**
- **Administrator privileges** (needed for ISO mounting)
- No third-party modules required; fully built-in

---

## Usage

1. Open PowerShell **as Administrator**.
2. Set variables at the top of `verifyusb.ps1`:

    $ISOPath = "C:\path\to\windows.iso"
    $USBDrive = "E:\"  # USB drive letter

3. Run the script:

    .\verifyusb.ps1

4. Optional: Redirect output to a file:

    .\verifyusb.ps1 | Out-File "usb_report.txt" -Encoding UTF8

---

## Output

The script displays:

- Progress of hashing ISO and USB files
- Summary of identical, extra, missing, and modified files
- Signature validation results for modified code files
- Resource file analysis (strings, XML diffs, PE headers)
- Final safety assessment

---

## Notes

- Modified resources are often benign (translations, metadata) but are displayed for review.
- Split WIM detection is handled for FAT32 USB drives.
- Script execution may take several minutes depending on USB size and number of files.

---

## License

This script is released under the MIT License.

---

## References

- PowerShell Get-FileHash, Get-AuthenticodeSignature, Mount-DiskImage
- [PowerShell Administrator guide](https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/starting-windows-powershell)
- [Installing PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows)

