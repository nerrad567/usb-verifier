# USB Verifier

A PowerShell script to verify and report the presence of USB storage devices connected to a Windows system.

## ?? Contents

- `verifyusb.ps1` - the main PowerShell script that checks for connected USB drives and outputs relevant device information.

## ?? Purpose

This tool is designed for system administrators, security engineers, or IT professionals who need to:

- Detect when a USB storage device is connected.  
- Audit USB devices for compliance or security purposes.  
- Log or report detailed properties of attached USB drives (e.g., serial number, partitions).

## ?? How It Works

1. The script queries the system for disk drives using PowerShell's CIM / WMI classes.  
2. It filters the drives to only include those whose `InterfaceType` equals `USB`.  
3. For each detected USB drive, the script gathers:
   - Disk index  
   - Caption / model name  
   - Serial number  
   - Partition details (drive letters, volume info)  
4. It outputs this information in a readable format, which can be logged or captured for further reporting.

## ?? Usage

1. Open **PowerShell** with administrative privileges (if required).  
2. Navigate to the directory where `verifyusb.ps1` is located:  
   ```powershell
   cd path\to\usb-verifier

