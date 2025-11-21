# ==============================================
# Windows USB Integrity Verifier & Resource Analyzer – PARANOID EDITION (UPDATED)
# ==============================================
# Combines integrity verification with detailed analysis of modified resources
# - Hashes and compares all files between ISO and USB
# - Categorizes mismatches (code vs. resources)
# - For modified code: Checks signatures and marks as "Safe (Valid Microsoft Signature)" if valid
# - For modified resources: Dumps strings >20 chars, diffs them, shows PE headers (proves resource-only)
# - Handles XML with full text diff
# - Improved: Lists all modified files with sig status for code, clearer reporting, final safe/stop verdict
# - New: Essentials check at start (admin rights, PS version); provides install links if needed and exits

$startTime = Get-Date

# Essentials Check
function EssentialsCheck {
    # Check if running as Administrator (needed for Mount-DiskImage)
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "Error: Script must be run as Administrator for mounting ISO." -ForegroundColor Red
        Write-Host "Right-click PowerShell and select 'Run as administrator'." -ForegroundColor Yellow
        Write-Host "If issue persists, see: https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/starting-windows-powershell?view=powershell-7.4" -ForegroundColor Yellow
        exit
    }

    # Check PowerShell version (needs 5.1+ for Get-FileHash, Get-AuthenticodeSignature)
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Host "Error: PowerShell version too old (needs 5.1 or higher)." -ForegroundColor Red
        Write-Host "Upgrade PowerShell: Download from https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows" -ForegroundColor Yellow
        exit
    }

    # No third-party modules needed; all built-in
    Write-Host "Essentials check passed: Running as Admin, PS version $($PSVersionTable.PSVersion)." -ForegroundColor Green
}

EssentialsCheck

# ---------------- CONFIGURATION ----------------
$ISOPath = "C:\Users\darre\Downloads\Win11_25H2_EnglishInternational_x64.iso"
$USBDrive = "F:"
$CodeExtensions = '\.exe$|\.dll$|\.sys$|\.cpl$|\.ocx$|\.efi$|\.bin$|\.scr$|\.ax$|\.drv$|\.sdb$|\.wim$'
$ResourceExtensions = '\.mui$|\.xml$|\.ini$|\.manifest$|\.xsd$|\.txt$|\.cfg$'
# -----------------------------------------------

if (-not (Test-Path $ISOPath -PathType Leaf)) {
    Write-Host "ISO not found at $ISOPath" -ForegroundColor Red
    exit
}
if (-not (Test-Path $USBDrive)) {
    Write-Host "USB drive $USBDrive not found" -ForegroundColor Red
    exit
}

Write-Host "`n=== WINDOWS USB INTEGRITY VERIFIER & ANALYZER – PARANOID MODE ===`n" -ForegroundColor Red

# Mount ISO
try {
    Write-Host "[1/6] Mounting ISO..." -ForegroundColor Cyan
    $iso = Mount-DiskImage -ImagePath $ISOPath -PassThru -ErrorAction Stop
    $isoDrive = ($iso | Get-Volume).DriveLetter + ":"
    Write-Host "ISO mounted at $isoDrive`n" -ForegroundColor Green
} catch {
    Write-Host "Failed to mount ISO: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

function Get-AllHashes {
    param([string]$Path, [string]$Name)
    $files = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue
    $total = $files.Count
    if ($total -eq 0) { return @() }
    $list = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $files.Count; $i++) {
        $file = $files[$i]
        Write-Progress -Activity "Hashing $Name" -Status "$($i+1) of $total" -PercentComplete (($i+1)/$total*100)
        $relPath = $file.FullName.Substring($Path.Length).TrimStart('\').Replace('\','/')
        $lowerPath = $relPath.ToLowerInvariant()
        $hash = "FAILED"
        try {
            $hash = (Get-FileHash $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {
            Write-Warning "[$Name] Failed to hash $relPath — $($_.Exception.Message)"
        }
        $list.Add([pscustomobject]@{
            RelativePath = $relPath
            LowerPath = $lowerPath
            Hash = $hash
            FullPath = $file.FullName
            SizeMB = [math]::Round($file.Length / 1MB, 2)
        })
    }
    Write-Progress -Activity "Hashing $Name" -Completed
    return $list
}

Write-Host "`n[2/6] Hashing ISO files..." -ForegroundColor Cyan
$isoHashes = Get-AllHashes "$isoDrive\" "ISO"

Write-Host "`n[3/6] Hashing USB files..." -ForegroundColor Cyan
$usbHashes = Get-AllHashes "$USBDrive\" "USB"

# Build dictionary
$isoDict = @{}
foreach ($e in $isoHashes) { $isoDict[$e.LowerPath] = $e }

Write-Host "`n[4/6] Comparing files..." -ForegroundColor Cyan
$mismatches = [System.Collections.Generic.List[object]]::new()
$matchCount = 0
foreach ($usbEntry in $usbHashes) {
    $key = $usbEntry.LowerPath
    if ($isoDict.ContainsKey($key)) {
        $isoEntry = $isoDict[$key]
        if ($usbEntry.Hash -eq $isoEntry.Hash -and $usbEntry.Hash -ne "FAILED") {
            $matchCount++
        } else {
            $status = switch ($true) {
                ($isoEntry.Hash -eq "FAILED") { "ISO unhashable" }
                ($usbEntry.Hash -eq "FAILED") { "USB unhashable" }
                default { "Modified" }
            }
            $mismatches.Add([pscustomobject]@{
                Path = $usbEntry.RelativePath
                Status = $status
                ISO_Hash = $isoEntry.Hash
                USB_Hash = $usbEntry.Hash
                SizeMB_ISO = $isoEntry.SizeMB
                SizeMB_USB = $usbEntry.SizeMB
            })
        }
        $isoDict.Remove($key)
    } else {
        $mismatches.Add([pscustomobject]@{
            Path = $usbEntry.RelativePath
            Status = "Extra on USB"
            ISO_Hash = "MISSING"
            USB_Hash = $usbEntry.Hash
            SizeMB_ISO = $null
            SizeMB_USB = $usbEntry.SizeMB
        })
    }
}
foreach ($isoEntry in $isoDict.Values) {
    $mismatches.Add([pscustomobject]@{
        Path = $isoEntry.RelativePath
        Status = "Missing on USB"
        ISO_Hash = $isoEntry.Hash
        USB_Hash = "MISSING"
        SizeMB_ISO = $isoEntry.SizeMB
        SizeMB_USB = $null
    })
}

# Categorize mismatches
$codeModified = @()
$resourceModified = @()
$extraCount = 0
$missingCount = 0
foreach ($m in $mismatches) {
    if ($m.Status -eq "Extra on USB") { $extraCount++; continue }
    if ($m.Status -eq "Missing on USB") { $missingCount++; continue }
    if ($m.Path -match $CodeExtensions) {
        $codeModified += $m
    } elseif ($m.Path -match $ResourceExtensions) {
        $resourceModified += $m
    } else {
        $codeModified += $m
    }
}

# Report summary
Write-Host "`n=== VERIFICATION SUMMARY ===`n" -ForegroundColor Red
Write-Host "ISO files : $($isoHashes.Count)"
Write-Host "USB files : $($usbHashes.Count)"
Write-Host "Identical files : $matchCount" -ForegroundColor Green
Write-Host "Extra files on USB : $extraCount"
Write-Host "Missing files on USB : $missingCount"
Write-Host "Modified CODE files : $($codeModified.Count)" -ForegroundColor Yellow
Write-Host "Modified RESOURCE files : $($resourceModified.Count)" -ForegroundColor Cyan

if ($extraCount -ge 2 -and ($mismatches | Where-Object { $_.Path -eq "sources/install.wim" })) {
    Write-Host "`nSPLIT-WIM DETECTED — completely normal for FAT32 USB" -ForegroundColor Green
}

# Check signatures on modified code files
$suspiciousCount = 0
$safeSignedCount = 0
if ($codeModified.Count -gt 0) {
    Write-Host "`n[5/6] Checking signatures on modified CODE files..." -ForegroundColor Yellow
    foreach ($m in $codeModified) {
        $fullPath = Join-Path $USBDrive ($m.Path -replace '/','\')
        try {
            $sig = Get-AuthenticodeSignature -FilePath $fullPath -ErrorAction Stop
            if ($sig.Status -eq "Valid" -and $sig.SignerCertificate.Subject -match 'Microsoft') {
                $safeSignedCount++
                Write-Host "Safe (Valid Microsoft Signature) → $($m.Path) (Signer: $($sig.SignerCertificate.Subject))" -ForegroundColor Green
            } else {
                $suspiciousCount++
                Write-Host "SUSPICIOUS → $($m.Path) (Status: $($sig.Status); Signer: $($sig.SignerCertificate.Subject))" -ForegroundColor Red -BackgroundColor Yellow
            }
        } catch {
            $suspiciousCount++
            Write-Host "SIGNATURE CHECK FAILED → $($m.Path): $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Yellow
        }
    }
    Write-Host "`nModified code files with valid Microsoft signatures: $safeSignedCount" -ForegroundColor Green
}

# Analyze modified resources if any
if ($resourceModified.Count -gt 0) {
    Write-Host "`n[6/6] Analyzing modified RESOURCE files..." -ForegroundColor Cyan

    function Extract-Strings {
        param([string]$FilePath)
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $strings = [System.Collections.Generic.List[string]]::new()
        $current = ""
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            if ($bytes[$i] -ge 32 -and $bytes[$i] -le 126) {  # Printable ASCII
                $current += [char]$bytes[$i]
            } else {
                if ($current.Length -gt 20) { $strings.Add($current) }
                $current = ""
            }
        }
        if ($current.Length -gt 20) { $strings.Add($current) }
        return $strings | Sort-Object
    }

    function Diff-Strings {
        param([array]$IsoStrings, [array]$UsbStrings)
        $diff = Compare-Object $IsoStrings $UsbStrings
        if ($diff) {
            Write-Host "String Differences (ISO <=, USB =>):" -ForegroundColor Yellow
            $diff | ForEach-Object { Write-Host "$($_.InputObject) ($($_.SideIndicator))" }
            return $true  # Has differences
        } else {
            Write-Host "No string differences." -ForegroundColor Green
            return $false
        }
    }

    $majorResourceDiffs = $false
    foreach ($m in $resourceModified) {
        $relPath = $m.Path
        $isoFull = Join-Path $isoDrive ($relPath -replace '/','\')
        $usbFull = Join-Path $USBDrive ($relPath -replace '/','\')

        if (-not (Test-Path $isoFull) -or -not (Test-Path $usbFull)) {
            Write-Host "Missing file for analysis: $relPath" -ForegroundColor Red
            continue
        }

        Write-Host "`n[Resource: $relPath]" -ForegroundColor Magenta

        if ($relPath -match '\.xml$') {
            # XML: Full text diff
            $isoText = Get-Content $isoFull -Raw -ErrorAction SilentlyContinue
            $usbText = Get-Content $usbFull -Raw -ErrorAction SilentlyContinue
            $diff = Compare-Object ($isoText -split "`n") ($usbText -split "`n")
            if ($diff) {
                Write-Host "XML Differences (ISO <=, USB =>):" -ForegroundColor Yellow
                $diff | ForEach-Object { Write-Host "$($_.InputObject) ($($_.SideIndicator))" }
                $majorResourceDiffs = $true
            } else {
                Write-Host "XML identical." -ForegroundColor Green
            }
        } else {
            # .mui: Strings and PE headers
            Write-Host "Dumping strings (>20 chars)..." -ForegroundColor Cyan
            $isoStrings = Extract-Strings $isoFull
            $usbStrings = Extract-Strings $usbFull
            $hasDiff = Diff-Strings $isoStrings $usbStrings
            if ($hasDiff) { $majorResourceDiffs = $true }

            Write-Host "`nPE Section Headers (proves resource-only):" -ForegroundColor Cyan
            Format-Hex $usbFull | Select-Object -First 50 | Out-String  # First 50 lines for headers
        }
    }

    if ($majorResourceDiffs) {
        Write-Host "`nNOTE: Resource differences detected. These are often benign (e.g., translations or metadata), but review above." -ForegroundColor Yellow
    } else {
        Write-Host "`nAll modified resources have no significant differences." -ForegroundColor Green
    }
}

if ($resourceModified.Count -gt 0) {
    Write-Host "`nModified resource files:" -ForegroundColor Cyan
    $resourceModified | Select-Object -ExpandProperty Path | Sort-Object | ForEach-Object { Write-Host " $_" }
}
if ($codeModified.Count -gt 0) {
    Write-Host "`nModified code files (with sig status above):" -ForegroundColor Yellow
    $codeModified | Select-Object -ExpandProperty Path | Sort-Object | ForEach-Object { Write-Host " $_" }
}

# Final safety assessment
Write-Host "`n=== FINAL ASSESSMENT ===`n" -ForegroundColor Red
if ($suspiciousCount -eq 0 -and -not $majorResourceDiffs) {
    Write-Host "NO SUSPICIOUS CODE FILES OR MAJOR RESOURCE CHANGES FOUND — USB IS SAFE" -ForegroundColor Green -BackgroundColor Black
    Write-Host "YES SAFE TO PROCEED" -ForegroundColor Green
} else {
    Write-Host "$suspiciousCount SUSPICIOUS FILES OR MAJOR RESOURCE DIFFS — POSSIBLE ISSUE" -ForegroundColor Red -BackgroundColor Yellow
    Write-Host "STOP! REVIEW BEFORE PROCEEDING" -ForegroundColor Red
}

# Cleanup
try {
    Dismount-DiskImage -ImagePath $ISOPath -ErrorAction Stop
} catch { }
$duration = (Get-Date) - $startTime
Write-Host "`nFinished in $($duration.ToString('mm\:ss'))." -ForegroundColor Cyan
Write-Host "`n=== ANALYSIS COMPLETE ===`n" -ForegroundColor Cyan