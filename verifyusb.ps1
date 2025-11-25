<#
.SYNOPSIS
    Verifies the integrity of a USB drive against a Windows ISO, checking for modifications, signatures, and resources with threat levels.

.PARAMETER ISOPath
    Path to the Windows ISO file.

.PARAMETER USBDrive
    Drive letter of the USB (e.g., "E:").

.PARAMETER LogFile
    Path to output log file (default: "usb_report.txt" in current directory).

.PARAMETER MaxAnalysisSizeMB
    Maximum file size (in MB) for deep analysis like string extraction (default: 10).

.PARAMETER VerboseDiffs
    If set, show full string differences; otherwise, summarize (default: $false).

.PARAMETER IgnoreFiles
    Array of relative file paths to ignore (e.g., @('\sources\appraiser.sdb')).

.PARAMETER ReassembleWIM
    If set, reassemble split SWM files to WIM for analysis (requires admin and temp space).

.PARAMETER DeepScanWIM
    If set, perform deep scan on WIM/ESD/SWM files by mounting and checking internal signatures and hashes.

.PARAMETER FullDeepScan
    If set, hash ALL internal files during deep scan; otherwise, only critical ones (faster).

.PARAMETER KnownHashesFile
    Optional path to external file with known ISO hashes (JSON format: {"filename": "hash"}).

.EXAMPLE
    .\verifyusb.ps1 -ISOPath "C:\Downloads\windows.iso" -USBDrive "E:" -DeepScanWIM -ReassembleWIM
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$ISOPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Z]:$')]
    [string]$USBDrive,

    [string]$LogFile = (Join-Path $PSScriptRoot "usb_report.txt"),

    [int]$MaxAnalysisSizeMB = 10,

    [switch]$VerboseDiffs,

    [string[]]$IgnoreFiles = @(),

    [switch]$ReassembleWIM,

    [switch]$DeepScanWIM,

    [switch]$FullDeepScan,

    [string]$KnownHashesFile  # Optional external hashes
)

$script:HashAlgorithm = 'SHA256'

# Track ISO lifecycle for safe cleanup
$script:ISOContext = @{
    FullPath        = $null   # Resolved absolute path to the ISO
    DriveLetter     = $null   # e.g. 'F:'
    MountedByScript = $false  # True if this script mounted it
}

$script:ISOHashInfo = @{
    Hash        = $null   # SHA256 of the ISO
    Status      = 'Unknown'  # 'KnownGood' / 'Unknown' / 'Error'
    MatchedName = $null   # ISO filename key if it matched
}


# CTRL C tracker
$script:Cancelled = $false


# Persistent state on disk for cross-run ISO tracking
$script:StateFilePath = Join-Path $PSScriptRoot 'usb-verifier.state.json'

# Structured summary for final report
$script:ScanSummary = @{}
$script:SectionDetails = @{}


# Functions

function Show-StartupBanner {
    param(
        [datetime]$StartTime
    )

    # Tiny spinner just for some flair (doesn't slow things much)
    $spinner = @('|','/','-','\')
    $phrase  = "Initialising usb-verifier..."
    for ($i = 0; $i -lt 16; $i++) {
        $frame = $spinner[$i % $spinner.Length]
        Write-Host ("`r{0} {1}" -f $frame, $phrase) -NoNewline -ForegroundColor Yellow
        Start-Sleep -Milliseconds 80
    }
    Write-Host "`r  $phrase" -ForegroundColor Yellow
    Write-Host ""

    $timeStr = $StartTime.ToString("yyyy-MM-dd HH:mm:ss")

    # Fancy banner
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  usb-verifier                                                ║" -ForegroundColor Cyan
    Write-Host "║  Windows install USB integrity & threat scanner              ║" -ForegroundColor Cyan
    Write-Host "║                                                              ║" -ForegroundColor Cyan
    Write-Host ("║  Start time : {0,-44}   ║" -f $timeStr) -ForegroundColor Cyan
    Write-Host "║  Press Ctrl+C at any time to abort                           ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Still record a clean line in the log file
    Write-Log "Starting Operations - Press Ctrl+C to interrupt." -Level "IMPORTANT"
}


function Get-ISOState {
    if (Test-Path $script:StateFilePath) {
        try {
            $raw = Get-Content -LiteralPath $script:StateFilePath | Out-String
            $state = $raw | ConvertFrom-Json
            if (-not $state.MountedISOs) {
                $state | Add-Member -MemberType NoteProperty -Name MountedISOs -Value @() -Force
            }
            return $state
        } catch {
            Write-Log "Failed to read ISO state file: $($_.Exception.Message) - resetting state." -Level "WARNING"
            return @{ MountedISOs = @() }
        }
    } else {
        return @{ MountedISOs = @() }
    }
}


function Save-ISOState {
    param(
        [Parameter(Mandatory = $true)]
        $State
    )
    try {
        $json = $State | ConvertTo-Json -Depth 4
        Set-Content -Path $script:StateFilePath -Value $json -Encoding UTF8
    } catch {
        Write-Log "Failed to save ISO state file: $($_.Exception.Message)" -Level "WARNING"
    }
}

function Cleanup-PreviousScriptISOs {
    Write-Log "Previous-run ISO Cleanup" -NoTimestamp -Level "IMPORTANT" -Header -Context "OPERATION"
    Write-Log "Checking for ISOs left mounted by previous runs..." -Level "INFO" -Context "OPERATION"

    $state = Get-ISOState
    if (-not $state.MountedISOs -or $state.MountedISOs.Count -eq 0) {
        Write-Log "No previously tracked script-mounted ISOs." -Level "INFO" -Context "OPERATION"
        return
    }


    $remaining = @()

    foreach ($path in $state.MountedISOs) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }

        $img = Get-DiskImage -ImagePath $path -ErrorAction SilentlyContinue
        if (-not $img -or -not $img.Attached) {
            # Not attached anymore -> silently drop from state
            Write-Log "Previously tracked ISO not currently mounted: $path" -Level "INFO"
            continue
        }

        try {
            $prompt = "usb-verifier previously mounted ISO `"$path`". Dismount it now? (Y/N, default Y)"
            $choice = Read-Host $prompt

            if ($choice -eq '' -or $choice -eq 'Y' -or $choice -eq 'y') {
                Dismount-DiskImage -ImagePath $path -ErrorAction Stop | Out-Null
                Write-Log "Dismounted leftover ISO from earlier run: $path"
            } else {
                Write-Log "User chose to keep previously mounted ISO attached: $path"
                $remaining += $path
            }
        } catch {
            Write-Log "Failed to dismount previously mounted ISO ${path}: $($_.Exception.Message)" -Level "WARNING"
            # Keep it in state so we can retry next run
            $remaining += $path
        }
    }

    $state.MountedISOs = $remaining
    Save-ISOState -State $state

    Write-Log "Previous-run ISO cleanup check complete." -Level "INFO" -Context "OPERATION"

}


function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO",
        [switch]$NoTimestamp,
        [string]$Context = "General",
        [switch]$Header
    )

    # Special handling for blank lines: Output nothing but a true empty line
    if ([string]::IsNullOrWhiteSpace($Message)) {
        Write-Host ""
        Add-Content -Path $LogFile -Value "" -Encoding UTF8
        return
    }

    $prefix = if ($Header) { "===== [$Context] =====" } else { "[$Context]" }
    $logMessage = if ($NoTimestamp) { "$prefix $Message" } else { "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")] $prefix $Message" }

    switch ($Level) {
        "ERROR"     { Write-Host $logMessage -ForegroundColor Red }
        "WARNING"   { Write-Host $logMessage -ForegroundColor Yellow }
        "IMPORTANT" { Write-Host $logMessage -ForegroundColor Magenta }
        "GREEN"     { Write-Host $logMessage -ForegroundColor Green }
        "RED"       { Write-Host $logMessage -ForegroundColor Red }
        default     { Write-Host $logMessage }
    }

    Add-Content -Path $LogFile -Value $logMessage -Encoding UTF8
}



function Test-Environment {
    param(
        [switch]$ReassembleWIM,
        [switch]$DeepScanWIM
    )
    
    Write-Log "Environment Validation" -NoTimestamp -Level "IMPORTANT" -Header -Context "OPERATION"
    $isAdmin = ([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    $osProductType = (Get-CimInstance Win32_OperatingSystem).ProductType

    if ($osProductType -ne 1 -or ($ReassembleWIM -or $DeepScanWIM -and -not $isAdmin)) {
        Write-Log "WARNING: Not running as admin. Features like WIM reassembly, deep scans, and temp cleanup may be skipped or limited." -Level "WARNING"
        Write-Log "WARNING: Run as admin for full functionality." -Level "WARNING"
        if (-not $isAdmin) {
            $ReassembleWIM = $false
            $DeepScanWIM   = $false
        }
    }

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Log "PS 5+ required." -Level "RED"
        exit 1
    }

    # Check for handle.exe in common locations
    $commonPaths = @(
        "C:\Sysinternals\handle.exe",
        "C:\Tools\handle.exe",
        "C:\Windows\System32\handle.exe"
    )
    $HandleExePath = $commonPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($HandleExePath) {
        Write-Log "Found handle.exe at $HandleExePath"
        $script:HandleExePath = $HandleExePath
        $script:HasHandleExe = $true
    } else {
        Write-Log "handle.exe not found. Locked-process detection will be skipped unless installed." -Level "WARNING"
        $choice = Read-Host "handle.exe not found. Do you want to download and install it now? (Y/N)"
        if ($choice -eq 'Y') {
            try {
                $zipPath = "C:\handle.zip"
                $extractPath = "C:\Sysinternals"
                Write-Log "Downloading Sysinternals Handle tool..."
                Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Handle.zip' -OutFile $zipPath -UseBasicParsing
                Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
                Remove-Item $zipPath -Force
                $HandleExePath = Join-Path $extractPath "handle.exe"
                if (Test-Path $HandleExePath) {
                    Write-Log "handle.exe installed at $HandleExePath"
                    $script:HandleExePath = $HandleExePath
                    $script:HasHandleExe = $true
                } else {
                    Write-Log "Download completed but handle.exe not found in $extractPath" -Level "RED"
                    $script:HasHandleExe = $false
                }
            } catch {
                Write-Log "Failed to download handle.exe: $($_.Exception.Message)" -Level "RED"
                $script:HasHandleExe = $false
            }
        } else {
            Write-Log "User declined to download handle.exe. Locked-process detection will be skipped." -Level "WARNING"
            $script:HasHandleExe = $false
        }
    }
    Write-Log "Environment validation complete." -Level "INFO" -Context "OPERATION"

    return @{
        ReassembleWIM = $ReassembleWIM
        DeepScanWIM   = $DeepScanWIM
        HasHandleExe  = $script:HasHandleExe
    }
}


function Get-LockingProcesses {
    param([string]$Path)

    if (-not $HasHandleExe) { return @() }
    if (-not (Test-Path $Path)) { return @() }

    $output = & $HandleExePath $Path /accepteula 2>$null
    $procs = @()
    foreach ($line in $output) {
        if ($line -match 'pid:\s+(\d+)') {
            $procId = [int]$matches[1]   # <-- use $procId instead of $pid
            $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($proc) { $procs += $proc }
        }
    }
    if ($procs.Count -eq 0 -and $output) {
        Write-Log "handle.exe output (no PIDs parsed): $($output -join ' | ')" -Level "WARNING"
    }
    return $procs
}


function Check-ForInterrupt {
    # If we've already seen Ctrl+C once, just honour it everywhere
    if ($script:Cancelled) {
        throw [System.OperationCanceledException]::new("User cancelled (Ctrl+C).")
    }

    if ([Console]::KeyAvailable) {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq "C" -and $key.Modifiers -band [ConsoleModifiers]::Control) {
            $script:Cancelled = $true
            Write-Log "Ctrl+C detected – attempting graceful cancellation..." -Level "WARNING"
            throw [System.OperationCanceledException]::new("User cancelled (Ctrl+C).")
        }
    }
}


function Is-MountDirMounted {
    param([string]$MountDir)

    $dismArgs = @('/Get-MountedImageInfo')
    $tempOut = "C:\Temp\dism_mounted_$(Get-Random).txt"
    $proc = Start-Process "Dism.exe" -ArgumentList $dismArgs -NoNewWindow -RedirectStandardOutput $tempOut -PassThru -Wait
    if ($proc.ExitCode -ne 0) {
        Write-Log "Failed to get mounted image info." -Level "WARNING"
        Remove-Item $tempOut -Force -ErrorAction SilentlyContinue
        return $false
    }

    $content = Get-Content $tempOut -Raw
    Remove-Item $tempOut -Force -ErrorAction SilentlyContinue

    # Normalize paths
    $normalizedMountDir = [IO.Path]::GetFullPath($MountDir).TrimEnd('\') + '\'
    $escapedMountDir = [regex]::Escape($normalizedMountDir)
    $isMounted = $content -match "(?m)Mount\s+Dir\s*:\s*$escapedMountDir"

    return $isMounted
}

function Clean-TempMounts {
    Write-Log "Temp Cleanup" -NoTimestamp -Level "IMPORTANT" -Header -Context "OPERATION"
    try {
        Write-Log "Ensure temp dir exists (we always want C:\Temp)..."
        if (-not (Test-Path "C:\Temp")) {
            New-Item "C:\Temp" -ItemType Directory -Force | Out-Null
        }

        Write-Log "Cleaning up any orphaned mount points..."
        $dismArgs = @('/Cleanup-Mountpoints')
        Run-DismWithProgress -DismArgs $dismArgs -Activity "Cleanup Mountpoints"

        # Progress during sleep
        Write-Progress -Activity "Waiting for locks to release after DISM cleanup" -Status "Pausing for 5 seconds..." -PercentComplete 0
        Start-Sleep -Seconds 5
        Write-Progress -Activity "Waiting for locks to release after DISM cleanup" -Completed

        $mountFolders = Get-ChildItem "C:\Temp\mount_*", "C:\Temp\iso_temp_*" -Directory -ErrorAction SilentlyContinue
        $total = $mountFolders.Count
        Write-Log "Found $total mount folders to clean up."

        if ($total -gt 0) {
            $emptyDir = "C:\Temp\empty_$(Get-Random -Minimum 10000 -Maximum 99999)"
            New-Item $emptyDir -ItemType Directory -Force | Out-Null

            $removedCount = 0
            $removedBytes = 0
            for ($i = 0; $i -lt $total; $i++) {
                $folder = $mountFolders[$i]
                Write-Log "Starting cleanup for folder $($i+1)/${total}: $($folder.Name)"

                $folderPercent = [math]::Round((($i / $total) * 100))
                Write-Progress -Activity "Deleting mount folders" -Status "Processing $($i+1)/${total}: $($folder.Name)" -PercentComplete $folderPercent

                # Check if folder looks "big/broken"
                $fileCount = 0
                try {
                    $fileCount = (Get-ChildItem $folder.FullName -Recurse -File -ErrorAction Stop | Measure-Object).Count
                } catch {
                    $fileCount = -1  # Error, perhaps access denied
                }

                if ($fileCount -gt 10 -or $fileCount -eq -1) {
                    Write-Log "Folder $($folder.Name) appears populated or inaccessible ($fileCount files), likely failed unmount or in-use image." -Level "WARNING"

                    $choice = Read-Host "Attempt AGGRESSIVE cleanup of $($folder.Name)? This may kill locking processes, retry unmount and delete the folder. (Y/N, default N)"
                    if ($choice -ne 'Y' -and $choice -ne 'y') {
                        Write-Log "User chose to skip aggressive cleanup for $($folder.Name). Manual cleanup recommended." -Level "WARNING"
                        continue
                    }

                    Write-Log "User requested aggressive cleanup for $($folder.Name). This may take some time..." -Level "WARNING"

                    # 1) Use handle.exe FIRST to find/kill lockers if available
                    if ($HasHandleExe) {
                        Write-Log "Checking for locking processes on $($folder.FullName) before unmount..." -Level "WARNING"
                        $procs = Get-LockingProcesses -Path $folder.FullName
                        if ($procs.Count -gt 0) {
                            Write-Log "Processes locking $($folder.FullName):" -Level "WARNING"
                            $procs | ForEach-Object { Write-Log " - $($_.ProcessName) (PID $($_.Id))" -Level "WARNING" }

                            $killChoice = Read-Host "Kill these locking processes before retrying unmount? (Y/N, default N)"
                            if ($killChoice -eq 'Y' -or $killChoice -eq 'y') {
                                foreach ($proc in $procs) {
                                    try {
                                        Stop-Process -Id $proc.Id -Force
                                        Write-Log "Killed $($proc.ProcessName) (PID $($proc.Id))"
                                    } catch {
                                        Write-Log "Failed to kill $($proc.ProcessName): $($_.Exception.Message)" -Level "WARNING"
                                    }
                                }
                                Start-Sleep -Seconds 2
                            } else {
                                Write-Log "User chose not to kill locking processes for $($folder.FullName) before unmount."
                            }
                        } else {
                            Write-Log "No locking processes reported by handle.exe for $($folder.FullName) before unmount."
                        }
                    } else {
                        Write-Log "handle.exe not available; skipping pre-unmount lock inspection." -Level "WARNING"
                    }

                    # 2) After dealing with lockers, *then* retry a clean DISM unmount if it still looks mounted
                    if (Is-MountDirMounted -MountDir $folder.FullName) {
                        Write-Log "Folder $($folder.Name) still appears mounted. Attempting another force-unmount via DISM." -Level "WARNING"
                        $dismArgs = @('/Unmount-Image', "/MountDir:$($folder.FullName)", '/Discard')
                        try {
                            Run-DismWithProgress -DismArgs $dismArgs -Activity "Force-unmount stuck mount $($folder.Name)"
                        } catch {
                            Write-Log "Second unmount attempt failed for $($folder.Name): $($_.Exception.Message)" -Level "WARNING"
                        }
                        Start-Sleep -Seconds 5
                    }
                }

                # 3) Nuclear-ish delete loop (with retries + handle.exe inside on failure)
                $retryAttempts = 3
                $ownershipApplied = $false
                $deleted = $false
                for ($attempt = 1; $attempt -le $retryAttempts; $attempt++) {
                    $attemptStatus = "Attempt $attempt/$retryAttempts on $($folder.Name)"
                    Write-Progress -Activity "Deleting mount folders" -Status $attemptStatus -PercentComplete $folderPercent -SecondsRemaining (($retryAttempts - $attempt + 1) * 5)

                    try {
                        if ($ownershipApplied) {
                            $startTime = Get-Date
                            takeown /F $folder.FullName /R /D Y /A | Out-Null
                            Write-Log "takeown completed in $((Get-Date) - $startTime).TotalSeconds seconds"

                            $startTime = Get-Date
                            icacls $folder.FullName /reset /T | Out-Null
                            Write-Log "icacls reset completed in $((Get-Date) - $startTime).TotalSeconds seconds"

                            $startTime = Get-Date
                            icacls $folder.FullName /grant "Administrators:(OI)(CI)(F)" /T | Out-Null
                            Write-Log "icacls grant completed in $((Get-Date) - $startTime).TotalSeconds seconds"
                        }

                        $startTime = Get-Date
                        robocopy $emptyDir $folder.FullName /mir /r:1 /w:1 | Out-Null
                        Write-Log "Robocopy empty completed in $((Get-Date) - $startTime).TotalSeconds seconds"

                        $startTime = Get-Date
                        $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c rd /s /q `"$($folder.FullName)`"" -NoNewWindow -PassThru -Wait
                        if ($process.ExitCode -ne 0) {
                            throw "rd failed with exit code $($process.ExitCode)"
                        }
                        Write-Log "rd removal completed in $((Get-Date) - $startTime).TotalSeconds seconds"

                        if (Test-Path $folder.FullName) {
                            throw "Deletion failed - folder still exists after rd"
                        }

                        $deleted = $true
                        Write-Log "Successfully deleted $($folder.Name) on attempt $attempt."
                        break
                    } catch {
                        Write-Log "Attempt $attempt/$retryAttempts failed to delete $($folder.FullName): $($_.Exception.Message)" -Level "WARNING"

                        if ($HasHandleExe) {
                            Write-Log "Checking for locking processes on $($folder.FullName) after delete failure..." -Level "WARNING"
                            $procs = Get-LockingProcesses -Path $folder.FullName
                            if ($procs.Count -gt 0) {
                                Write-Log "Processes locking $($folder.FullName):" -Level "WARNING"
                                $procs | ForEach-Object { Write-Log " - $($_.ProcessName) (PID $($_.Id))" -Level "WARNING" }

                                $killChoice = Read-Host "Do you want to kill these processes before next delete attempt? (Y/N, default N)"
                                if ($killChoice -eq 'Y' -or $killChoice -eq 'y') {
                                    foreach ($proc in $procs) {
                                        try {
                                            Stop-Process -Id $proc.Id -Force
                                            Write-Log "Killed $($proc.ProcessName) (PID $($proc.Id))"
                                        } catch {
                                            Write-Log "Failed to kill $($proc.ProcessName): $($_.Exception.Message)" -Level "WARNING"
                                        }
                                    }
                                    Start-Sleep -Seconds 2
                                } else {
                                    Write-Log "User chose not to kill locking processes for $($folder.FullName) on this attempt."
                                }
                            } else {
                                Write-Log "No locking processes found for $($folder.FullName) after delete failure."
                            }
                        } else {
                            Write-Log "Skipping locked-process detection (handle.exe not available)" -Level "WARNING"
                        }

                        $ownershipApplied = $true  # Flag to apply ownership on next retry

                        Write-Progress -Activity "Deleting mount folders" -Status "$attemptStatus - Waiting for locks to release (5s)" -PercentComplete $folderPercent
                        Start-Sleep -Seconds 5
                    }
                }

                if ($deleted) {
                    $removedCount++
                    $folderSize = (Get-ChildItem $folder.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
                    $removedBytes += $folderSize
                } else {
                    Write-Log "Gave up deleting $($folder.FullName) after $retryAttempts attempts." -Level "WARNING"
                }
            }
            Remove-Item $emptyDir -Force -ErrorAction SilentlyContinue

            Write-Progress -Activity "Deleting mount folders" -Completed
            Start-Sleep -Milliseconds 500
            Write-Host ' ' -NoNewline
        }

        try {
            $retryAttempts = 3
            $logsDeleted = $false
            for ($attempt = 1; $attempt -le $retryAttempts; $attempt++) {
                try {
                    Get-ChildItem "C:\Temp\dism_out_*.txt","C:\Temp\dism_err_*.txt","C:\Temp\dism_*.log" -ErrorAction Stop | Remove-Item -Force -ErrorAction Stop
                    $logsDeleted = $true
                    break
                } catch {
                    Write-Log "Log deletion attempt $attempt failed: $($_.Exception.Message)" -Level "WARNING"
                    Start-Sleep -Seconds 2
                }
            }
            if (-not $logsDeleted) {
                Write-Log "Gave up deleting DISM logs after $retryAttempts attempts." -Level "WARNING"
            }
        } catch {
            Write-Log "Failed to delete dism files: $($_.Exception.Message)" -Level "WARNING"
        }

        try {
            $oldPref = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            Get-ChildItem "C:\Temp\usb_*.wim" -ErrorAction SilentlyContinue | Remove-Item -Force
            Get-ChildItem "C:\Temp\iso_*.wim" -ErrorAction SilentlyContinue | Remove-Item -Force
            $ProgressPreference = $oldPref
        } catch {
            Write-Log "Failed to delete temp *.wim files: $($_.Exception.Message)" -Level "WARNING"
        }

        Write-Log "Temp cleanup complete." -Level "INFO" -Context "OPERATION"

    } catch {
        Write-Log "Temp cleanup failed: $($_.Exception.Message)" -Level "WARNING"
    }
}



function Get-FileHashes {
    param (
        [string]$RootPath,
        [string[]]$FileFilter = @('*'),
        [string]$SourceType = "General",
        [switch]$SuppressHeader
    )

    if (-not $SuppressHeader) {
        Write-Log "Hashing $SourceType files in $RootPath" -NoTimestamp -Level "IMPORTANT" -Header -Context "OPERATION"
    }

    $hashes = @{}
    $files = Get-ChildItem -Path $RootPath -Recurse -File -Include $FileFilter -ErrorAction SilentlyContinue
    $total = $files.Count

    if (-not $SuppressHeader) {
        Write-Log "Hashing $total files..."
    } else {
        # Optional: still log a lighter line if you want
        Write-Log "Hashing $total $SourceType files in $RootPath" -Level "INFO"
    }
    
    if ($PSVersionTable.PSVersion.Major -ge 7 -and $total -gt 100) {  # Use parallel for large sets
        $results = $files | ForEach-Object -Parallel {
            $localFile = $_
            $relPath = $localFile.FullName.Replace($using:RootPath, '')
            if ($using:IgnoreFiles -contains $relPath) { return $null }
            try {
                $hash = (Get-FileHash $localFile.FullName -Algorithm $using:HashAlgorithm -ErrorAction Stop).Hash
                return [pscustomobject]@{ RelPath = $relPath; Hash = $hash }
            } catch {
                Write-Host "Failed to hash ${relPath}: $($_.Exception.Message)"  # Console output since Write-Log may not be thread-safe
                return $null
            }
        } -ThrottleLimit 8
        
        foreach ($result in $results) {
            if ($result) {
                $hashes[$result.RelPath] = $result.Hash
            }
        }
    } else {
        # Fallback sequential with progress
        for ($i = 0; $i -lt $total; $i++) {
            Check-ForInterrupt
            $file = $files[$i]
            $percent = if ($total -gt 0) { [math]::Round(($i / $total) * 100) } else { 100 }
            Write-Progress -Activity "Hashing $RootPath" -Status "$percent%" -PercentComplete $percent
            $relPath = $file.FullName.Replace($RootPath, '')
            if ($IgnoreFiles -contains $relPath) { continue }
            try {
                $hashes[$relPath] = (Get-FileHash $file.FullName -Algorithm $HashAlgorithm -ErrorAction Stop).Hash
            } catch {
                Write-Log "Failed to hash ${relPath}: $($_.Exception.Message)" -Level "WARNING"
            }
        }
        Write-Progress -Activity "Hashing $RootPath" -Completed
    }

    return $hashes
}

   

function Get-FileHashWithProgress {
    param ([string]$Path)
    try {
        $hashAlgo = [System.Security.Cryptography.HashAlgorithm]::Create($HashAlgorithm)
        $stream = [System.IO.File]::OpenRead($Path)
        $buffer = New-Object byte[] 4MB
        $total = $stream.Length
        $read = 0
        while (($bytes = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            Check-ForInterrupt
            $hashAlgo.TransformBlock($buffer, 0, $bytes, $buffer, 0)
            $read += $bytes
            $percent = if ($total -gt 0) { [math]::Round(($read / $total) * 100) } else { 100 }
            Write-Progress -Activity "Hashing large file $Path" -PercentComplete $percent
        }
        $hashAlgo.TransformFinalBlock($buffer, 0, 0)
        $stream.Close()
        Write-Progress -Activity "Hashing large file $Path" -Completed
        return [BitConverter]::ToString($hashAlgo.Hash) -replace '-', ''
    } catch {
        Write-Log "Failed hashing large file ${Path}: $($_.Exception.Message)" -Level "WARNING"
        return $null
    }
}

function Run-DismWithProgress {
    param (
        [string[]]$DismArgs,
        [string]$Activity,
        [string]$Context = "General"
    )

    $tempOut = $null
    $tempErr = $null
    $dismLog = $null
    $proc    = $null

    try {
        $tempOut = "C:\Temp\dism_out_$(Get-Random).txt"
        $tempErr = "C:\Temp\dism_err_$(Get-Random).txt"
        $dismLog = "C:\Temp\dism_$(Get-Random).log"

        $DismArgs = @('/English', "/LogPath:$dismLog", '/LogLevel:2') + $DismArgs

        Write-Log "Running DISM with args: $($DismArgs -join ' ')" -Level "INFO" -Context $Context

        $proc = Start-Process "Dism.exe" -ArgumentList $DismArgs -NoNewWindow -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr -PassThru -ErrorAction Stop
        
        $lastPercent = 0
        $startTime   = Get-Date

        while (-not $proc.HasExited) {
            Check-ForInterrupt   # <-- Ctrl+C respected even while DISM is running

            $lines = Get-Content $tempOut -Tail 5 -ErrorAction SilentlyContinue
            $percentFound = $false
            foreach ($line in $lines) {
                if ($line -match '(\d+\.\d+)%') {
                    $percent = [double]$matches[1]
                    if ($percent -gt $lastPercent) {
                        Write-Progress -Activity $Activity -PercentComplete $percent
                        $lastPercent = $percent
                    }
                    $percentFound = $true
                    break
                }
            }
            if (-not $percentFound) {
                $elapsed = ((Get-Date) - $startTime).TotalSeconds
                Write-Progress -Activity $Activity -Status "Processing... ($elapsed sec)" -PercentComplete $lastPercent
            }
            Start-Sleep -Milliseconds 500
        }
        Write-Progress -Activity $Activity -Completed
        
        $outContent = ""
        $errContent = ""

        if (Test-Path $tempOut) {
            $outContent = Get-Content -LiteralPath $tempOut | Out-String
        }
        if (Test-Path $tempErr) {
            $errContent = Get-Content -LiteralPath $tempErr | Out-String
        }

        $outLines = $outContent -split "`n"
        $filteredOut = $outLines | Where-Object { $_.Trim() -ne '' -and $_ -notmatch '%' }

        Write-Log "Dism output summary for ${Activity}: $($filteredOut -join "`n")" -Level "INFO" -Context $Context

        if ($proc.ExitCode -eq 0) {
            Write-Log "Dism completed successfully for ${Activity}." -Level "INFO" -Context $Context
        } else {
            Write-Log "Dism failed (code $($proc.ExitCode)) for ${Activity}." -Level "ERROR" -Context $Context
            if ($errContent) {
                Write-Log "Dism error for ${Activity}: $errContent" -Level "ERROR" -Context $Context
            }
            throw "Dism failed (code $($proc.ExitCode)): $outContent $errContent"
        }

        if ((Test-Path $dismLog) -and ($proc.ExitCode -ne 0)) {
            $logText = Get-Content -LiteralPath $dismLog | Out-String
            Write-Log "DISM internal log: $logText" -Level "ERROR" -Context $Context
        }

        Remove-Item $tempOut, $tempErr, $dismLog -Force -ErrorAction SilentlyContinue

    } catch {
        # If this is our Ctrl+C cancellation, kill DISM and bubble up cleanly
        if ($_.Exception -is [System.OperationCanceledException]) {
            Write-Log "DISM operation '${Activity}' cancelled by user – terminating process and cleaning up." -Level "WARNING" -Context $Context

            if ($proc -and -not $proc.HasExited) {
                try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
            }

            if ($tempOut -or $tempErr -or $dismLog) {
                Remove-Item $tempOut, $tempErr, $dismLog -Force -ErrorAction SilentlyContinue
            }

            Write-Progress -Activity $Activity -Completed
            throw   # rethrow so main flow can see it's a cancellation, not a hard error
        }

        Write-Log "Dism error in ${Activity}: $($_.Exception.Message)" -Level "ERROR" -Context $Context
        if (Test-Path $tempOut) {
            Write-Log (Get-Content -LiteralPath $tempOut | Out-String) -Level "ERROR" -Context $Context
        }
        if (Test-Path $tempErr) {
            Write-Log (Get-Content -LiteralPath $tempErr | Out-String) -Level "ERROR" -Context $Context
        }
        Remove-Item $tempOut, $tempErr, $dismLog -Force -ErrorAction SilentlyContinue
        Write-Progress -Activity $Activity -Completed
        throw
    }
}



function Mount-Image {
    param ([string]$ImageFile, [int]$Index = 1, [string]$MountDir, [switch]$ReadOnly, [switch]$IsSplit, [string]$SwmPattern = $null)
    if (-not (Test-Path $MountDir)) { New-Item $MountDir -ItemType Directory -Force | Out-Null }
    else {
        $oldPref = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        Get-ChildItem $MountDir -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        $ProgressPreference = $oldPref
    }
    
    $dismArgs = @(
        '/Mount-Image',
        "/ImageFile:$ImageFile",
        "/Index:$Index",
        "/MountDir:$MountDir"
    )
    if ($IsSplit -and $SwmPattern) { $dismArgs += "/SWMFile:$SwmPattern" }
    if ($ReadOnly) { $dismArgs += '/ReadOnly' }
    
    $retryCount = 0
    do {
        try {
            Run-DismWithProgress -DismArgs $dismArgs -Activity "Mounting $ImageFile"
            Start-Sleep -Seconds 2
            $fileCount = (Get-ChildItem $MountDir -Recurse -File -ErrorAction SilentlyContinue).Count
            if ($fileCount -eq 0) {
                throw "Mount failed: Mount directory $MountDir is empty after attempt."
            }
            break
        } catch {
            Write-Log "Mount attempt failed: $($_.Exception.Message). Cleaning up..." -Level "WARNING"
            Unmount-Image $MountDir -Force
            if ($retryCount -lt 1) {
                $retryCount++
                Write-Log "Retrying mount ($retryCount/1)..."
            } else {
                throw
            }
        }
    } while ($retryCount -lt 1)
}

function Unmount-Image {
    param ([string]$MountDir, [switch]$Force)
    $dismArgs = @(
        '/Unmount-Image',
        "/MountDir:$MountDir",
        '/Discard'
    )
    try {
        Run-DismWithProgress -DismArgs $dismArgs -Activity "Unmounting from $MountDir"
    } catch {
        Write-Log "Unmount failed: $($_.Exception.Message)" -Level "WARNING"
        if ($Force) {
            Write-Log "Force mode: Attempting cleanup despite failure."
        } else {
            throw
        }
    }

    # Progress during sleep
    Write-Progress -Activity "Waiting for locks to release after unmount" -Status "Pausing for 5 seconds..." -PercentComplete 0
    Start-Sleep -Seconds 5
    Write-Progress -Activity "Waiting for locks to release after unmount" -Completed

    if (Test-Path $MountDir) {
        Write-Log "Deleting mount directory $MountDir after unmount."  # Added log
        Write-Progress -Activity "Deleting mount directory" -Status "Removing $MountDir..." -PercentComplete 0

        $oldPref = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        Remove-Item $MountDir -Recurse -Force -ErrorAction SilentlyContinue
        $ProgressPreference = $oldPref

        Write-Progress -Activity "Deleting mount directory" -Completed
    }
}

function Reassemble-SWMToTemp {
    param ([string]$SourcePath, [string]$TempPath)
    Write-Log "SWM Reassembly Start" -NoTimestamp -Level "IMPORTANT" -Header -Context "OPERATION"
    try {
        if ((Get-PSDrive C).Free / 1GB -lt 7) { throw "Low space on C: for reassembly." }
        Write-Log "Reassembling SWM: $SourcePath"
        $swmDir = [IO.Path]::GetDirectoryName($SourcePath)
        $swmFiles = Get-ChildItem -Path $swmDir -Filter "install*.swm" | Sort-Object Name
        Write-Log "SWM files found: $($swmFiles.Count) ($($swmFiles.Name -join ', '))"
        
        if ($swmFiles.Count -lt 2) { throw "Insufficient SWM files for reassembly (need at least 2)." }
        for ($i = 1; $i -le $swmFiles.Count; $i++) {
            $expected = if ($i -eq 1) { "install.swm" } else { "install$i.swm" }
            if ($swmFiles[$i-1].Name -ne $expected) { throw "Non-sequential SWM files: missing or mismatched $expected." }
        }
        
        $swmPattern = "$swmDir\install*.swm"
        $dismArgs = @(
            '/Export-Image',
            "/SourceImageFile:$SourcePath",
            "/SWMFile:$swmPattern",
            '/SourceIndex:1',
            "/DestinationImageFile:$TempPath",
            '/Compress:fast',
            '/CheckIntegrity'
        )
        Run-DismWithProgress -DismArgs $dismArgs -Activity "Reassembling SWM to WIM"
        if (-not (Test-Path $TempPath)) { throw "Temp WIM not created: $TempPath" }
        Write-Log "Reassembled WIM prepared: $TempPath"
        return $TempPath
    } catch {
        Write-Log "Reassembly failed: $($_.Exception.Message)" -Level "RED"
        return $null
    }
    Write-Log "SWM Reassembly End" -NoTimestamp -Level "IMPORTANT" -Header -Context "USB"

}

function Decompress-ESDToTemp {
    param ([string]$SourcePath, [string]$TempPath)
    Write-Log "ESD Decompression Start" -NoTimestamp -Level "IMPORTANT" -Header -Context "ISO"
    try {
        if ((Get-PSDrive C).Free / 1GB -lt 7) { throw "Low space on C: for decompression." }
        Write-Log "Decompressing ESD: $SourcePath"
        $dismArgs = @(
            '/Export-Image',
            "/SourceImageFile:$SourcePath",
            '/SourceIndex:1',
            "/DestinationImageFile:$TempPath",
            '/Compress:fast',
            '/CheckIntegrity'
        )
        Run-DismWithProgress -DismArgs $dismArgs -Activity "Decompressing ESD to WIM"
        if (-not (Test-Path $TempPath)) { throw "Temp WIM not created: $TempPath" }
        Write-Log "Decompressed WIM prepared: $TempPath"
        return $TempPath
    } catch {
        if ($_.Exception -is [System.OperationCanceledException]) {
            Write-Log "ESD decompression for $SourcePath cancelled by user." -Level "WARNING"
            throw
        }
        Write-Log "Decompression failed: $($_.Exception.Message)" -Level "RED"
        return $null
    }
    Write-Log "ESD Decompression End" -NoTimestamp -Level "IMPORTANT" -Header -Context "ISO"
}

function Extract-PrintableStrings {
    param (
        [string]$Path,
        [int]$MinLength = 4
    )
    if ([string]::IsNullOrEmpty($Path) -or -not (Test-Path $Path)) {
        Write-Log "Skipping string extraction: Invalid or empty path '$Path'." -Level "WARNING"
        return @()
    }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $current = New-Object System.Text.StringBuilder
        $result = @()
        foreach ($b in $bytes) {
            if ($b -ge 32 -and $b -le 126) {
                $null = $current.Append([char]$b)
            } else {
                if ($current.Length -ge $MinLength) {
                    $result += $current.ToString()
                }
                $current.Length = 0
            }
        }
        if ($current.Length -ge $MinLength) {
            $result += $current.ToString()
        }
        return $result
    } catch {
        Write-Log "Failed to extract strings from '$Path': $($_.Exception.Message)" -Level "WARNING"
        return @()
    }
}

function Analyze-File {
    param (
        [string]$FilePath,
        [string]$IsoFilePath = $null,
        [string]$Context,
        [string]$Status,
        [object]$IsoData = $null
    )

    $threatLevel = 0
    $threat      = "GREEN"
    $note        = "$Status "
    $fileSizeMB  = (Get-Item $FilePath).Length / 1MB
    $ext         = [IO.Path]::GetExtension($FilePath).ToLower()

    # Extension groups
    $codeExt     = @('.exe', '.dll', '.sys', '.drv', '.ocx', '.scr', '.efi')                   # PE-style / boot code
    $scriptExt   = @('.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.js', '.jse', '.wsf')           # scriptable
    $resourceExt = @('.xml', '.mui', '.inf', '.sdb', '.manifest', '.cfg', '.ini', '.cat')
    $docExt      = @('.txt', '.rtf', '.log', '.md')
    $binExt      = @('.bin', '.dat', '.pak', '.cab')                                           # payload-style binaries

    # Everything we explicitly know about
    $knownExt    = $codeExt + $scriptExt + $resourceExt + $docExt + $binExt


    # Only these get Authenticode checks
    $signedExt   = $codeExt + '.cat'

    $validMsSig  = $false

    if ([string]::IsNullOrEmpty($FilePath) -or -not (Test-Path $FilePath)) {
        $note += "Invalid file path; skipping analysis."
        return @{ Threat = "WARNING"; Note = $note }
    }

    # 1) Signature analysis (for PE-like files only)
    if ($ext -in $signedExt) {
        try {
            $sig = Get-AuthenticodeSignature $FilePath -ErrorAction Stop
            if ($sig.Status -eq "Valid" -and $sig.SignerCertificate.Subject -match 'Microsoft') {
                $validMsSig = $true
                $note += "Valid Microsoft signature ($($sig.SignerCertificate.Subject))"
            } elseif ($sig.Status -eq "NotSigned") {
                $note += "Not signed"
                $threatLevel = [math]::Max($threatLevel, 1)
            } else {
                $note += "Invalid signature: $($sig.StatusMessage)"
                $threatLevel = [math]::Max($threatLevel, 2)
            }
        } catch {
            $note += "Signature check failed: $($_.Exception.Message)"
            $threatLevel = [math]::Max($threatLevel, 1)
        }
    }
    # NOTE: we *do not* attempt Authenticode on $binExt (e.g. .bin) because they are
    # not normally signed this way; their integrity comes from higher-level structures.

    # 2) Deep comparison for MODIFIED files (strings/XML)
    if ($Status -eq 'Modified' -and $fileSizeMB -le $MaxAnalysisSizeMB) {
        try {
            $usbStrings = Extract-PrintableStrings $FilePath

            $isoStrings = $null
            $haveIsoData = $false

            # Prefer pre-supplied IsoData if we got it
            if ($IsoData -ne $null) {
                $isoStrings = $IsoData
                $haveIsoData = $true
            }
            elseif (-not [string]::IsNullOrEmpty($IsoFilePath) -and (Test-Path $IsoFilePath)) {
                if ($ext -eq '.xml') {
                    $isoContent = Get-Content -LiteralPath $IsoFilePath -Raw
                    $isoXml = [xml]$isoContent
                    $isoStrings = $isoXml.OuterXml
                } else {
                    $isoStrings = Extract-PrintableStrings $IsoFilePath
                }
                $haveIsoData = $true
            }
            else {
                # No ISO-side data available at all
                $note += "No ISO data available for comparison; skipping deep analysis"
                $threatLevel = [math]::Max($threatLevel, 1)
            }

            if ($haveIsoData) {
                if ($ext -eq '.xml') {
                    $usbContent = Get-Content -LiteralPath $FilePath -Raw
                    $usbXml = [xml]$usbContent
                    $usbStr = $usbXml.OuterXml
                    $isoStr = [string]$isoStrings

                    if ($usbStr -ne $isoStr) {
                        $diff = Compare-Object ($isoStr -split "`n") ($usbStr -split "`n")
                        $note += "XML differences: "
                        if ($VerboseDiffs) {
                            $note += ($diff | Out-String)
                        } else {
                            $note += "$($diff.Count) changes detected"
                        }
                        $threatLevel = [math]::Max($threatLevel, 1)
                    }
                } else {
                    $diff = Compare-Object $isoStrings $usbStrings
                    if ($diff) {
                        $note += "String differences: "
                        if ($VerboseDiffs) {
                            $note += ($diff | Out-String)
                        } else {
                            $note += "$($diff.Count) changes (added/removed strings)"
                        }
                        $threatLevel = [math]::Max($threatLevel, 1)
                    }
                }
            }
        } catch {
            $note += "Deep comparison failed: $($_.Exception.Message)"
            $threatLevel = [math]::Max($threatLevel, 1)
        }
    }
    elseif ($Status -eq 'Modified' -and $fileSizeMB -gt $MaxAnalysisSizeMB) {
        $note += "Large file, skipped deep analysis"
        $threatLevel = [math]::Max($threatLevel, 1)
    }

    # 3) EXTRA files
    if ($Status -eq 'Extra') {
        $threatLevel = [math]::Max($threatLevel, 1)
        $note += "Extra file"
        if ($fileSizeMB -le $MaxAnalysisSizeMB) {
            $strings = Extract-PrintableStrings $FilePath
            if ($strings) {
                $note += "; Sample strings: $($strings[0..[math]::Min(4, $strings.Count-1)] -join ', ')..."
            }
        }
    }

    # 4) Extension-driven tweaks
    # High-risk: executables without valid Microsoft signature
    if ($ext -in $codeExt -and -not $validMsSig -and ($Status -eq 'Modified' -or $Status -eq 'Extra')) {
        $threatLevel = 2
        if ($note -notmatch "Executable without valid Microsoft signature") {
            $note += "; Executable without valid Microsoft signature (high risk)"
        }
    }

    # High-risk: script files (can execute payloads even though they aren't Authenticode-signed)
    if ($ext -in $scriptExt -and ($Status -eq 'Modified' -or $Status -eq 'Extra')) {
        $threatLevel = 2
        if ($note -notmatch "Script file capable of executing code") {
            $note += "; Script file capable of executing code (high risk)"
        }
    }

    # Medium-risk: config / metadata changes
    if ($Status -eq 'Modified' -and $ext -in $resourceExt) {
        $threatLevel = [math]::Max($threatLevel, 1)
        # (Note text already added in deep comparison section if diffs exist)
    }

    # Low-risk: tiny text/log extras
    if ($Status -eq 'Extra' -and $ext -in $docExt -and $fileSizeMB -le 1) {
        if ($threatLevel -lt 2) {
            $threatLevel = 1
        }
    }

    # High-risk: binary payload files that don't match the ISO (no certs expected)
    if ($ext -in $binExt -and ($Status -eq 'Modified' -or $Status -eq 'Extra')) {
        # Force high severity for payload blobs
        $threatLevel = 2
        if ($note -notmatch "Binary payload-style file differs from ISO") {
            $note += "; Binary payload-style file differs from ISO (high risk; signatures not expected for this type)"
        }
    }

    # Catch-all: any unknown/other extension (including none) is high-risk if it differs
    if (($Status -eq 'Modified' -or $Status -eq 'Extra') -and -not [string]::IsNullOrWhiteSpace($FilePath)) {
        if (-not $knownExt.Contains($ext)) {
            $threatLevel = 2
            if ($note -notmatch "Unknown or non-standard file type differs from ISO") {
                $note += "; Unknown or non-standard file type differs from ISO (conservative high-risk classification)"
            }
        }
    }


    # 5) Map level → label
    $threat = if ($threatLevel -ge 2) { "RED" }
              elseif ($threatLevel -eq 1) { "WARNING" }
              else { "GREEN" }

    return @{ Threat = $threat; Note = $note }
}




function New-DeepWIMScanContext {
    param(
        [Parameter(Mandatory)]
        [string]$Type,       # "boot" / "install"
        [Parameter(Mandatory)]
        [string]$UsbPath,
        [Parameter(Mandatory)]
        [string]$IsoPath,
        [switch]$IsSplit
    )

    $ctx = [ordered]@{
        Type           = $Type
        UsbPathOriginal = $UsbPath
        IsoPathOriginal = $IsoPath

        UsbImagePath   = $UsbPath
        IsoImagePath   = $IsoPath

        UsbTempPath    = $null
        IsoTempPath    = $null

        IsSplit        = [bool]$IsSplit
        UsbSwmPattern  = if ($IsSplit) { [IO.Path]::GetDirectoryName($UsbPath) + "\install*.swm" } else { $null }

        UsbWholeHash   = $null
        IsoWholeHash   = $null

        IsoMountDir    = $null
        UsbMountDir    = $null

        IsoInternalHashes = @{}
        UsbInternalHashes = @{}
        Missing           = @()
        Extra             = @()
        Modified          = @{}
    }

    # Optimise for ESD → temp WIM (ISO side)
    if ([IO.Path]::GetExtension($ctx.IsoImagePath).ToLower() -eq '.esd') {
        $tempIso = "C:\Temp\iso_$($Type).wim"
        $tempIso = Decompress-ESDToTemp -SourcePath $ctx.IsoImagePath -TempPath $tempIso
        if ($tempIso) {
            $ctx.IsoImagePath = $tempIso
            $ctx.IsoTempPath  = $tempIso
        } else {
            Write-Log "ESD decompression failed for ISO $Type – falling back to direct ESD." -Level "WARNING"
        }
    }

    # Optimise for ESD → temp WIM (USB side)
    if ([IO.Path]::GetExtension($ctx.UsbImagePath).ToLower() -eq '.esd') {
        $tempUsb = "C:\Temp\usb_$($Type).wim"
        $tempUsb = Decompress-ESDToTemp -SourcePath $ctx.UsbImagePath -TempPath $tempUsb
        if ($tempUsb) {
            $ctx.UsbImagePath = $tempUsb
            $ctx.UsbTempPath  = $tempUsb
        } else {
            Write-Log "ESD decompression failed for USB $Type – falling back to direct ESD." -Level "WARNING"
        }
    }

    # SWM → WIM reassembly (USB) if requested
    if ($script:ReassembleWIM -and $ctx.IsSplit) {
        $tempUsb = Reassemble-SWMToTemp -SourcePath $ctx.UsbPathOriginal -TempPath "C:\Temp\usb_$($Type).wim"
        if ($tempUsb) {
            $ctx.UsbImagePath = $tempUsb
            $ctx.UsbTempPath  = $tempUsb
            $ctx.IsSplit      = $false
            $ctx.UsbSwmPattern = $null
        } else {
            Write-Log "SWM reassembly failed for $Type – falling back to direct SWM mount for deep scan." -Level "WARNING"
        }
    }

    # Whole-file hashes (no mount required)
    $ctx.IsoWholeHash = Get-FileHashWithProgress $ctx.IsoImagePath
    $ctx.UsbWholeHash = Get-FileHashWithProgress $ctx.UsbImagePath

    return $ctx
}

function Mount-DeepImagePair {
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string[]]$Filter
    )

    $type = $Context.Type.ToUpper()

    $Context.IsoMountDir = "C:\Temp\mount_iso_${type}_$(Get-Random -Minimum 10000 -Maximum 99999)"
    $Context.UsbMountDir = "C:\Temp\mount_usb_${type}_$(Get-Random -Minimum 10000 -Maximum 99999)"

    Write-Log "ISO side: mounting and hashing internal $type image..." -Level "INFO" -Context "ISO"
    Write-Progress -Id 0 -Activity "Deep Scan on $type" -Status "Mounting ISO image" -PercentComplete 10

    Mount-Image -ImageFile $Context.IsoImagePath -MountDir $Context.IsoMountDir -ReadOnly
    Write-Progress -Id 0 -Activity "Deep Scan on $type" -Status "Hashing ISO files" -PercentComplete 30
    $Context.IsoInternalHashes = Get-FileHashes -RootPath $Context.IsoMountDir -FileFilter $Filter -SourceType "ISO $type"  -SuppressHeader

    Write-Log "USB side: mounting and hashing internal $type image..." -Level "INFO" -Context "USB"
    Write-Progress -Id 0 -Activity "Deep Scan on $type" -Status "Mounting USB image" -PercentComplete 50
    Mount-Image -ImageFile $Context.UsbImagePath -MountDir $Context.UsbMountDir -ReadOnly -IsSplit:$Context.IsSplit -SwmPattern $Context.UsbSwmPattern
    Write-Progress -Id 0 -Activity "Deep Scan on $type" -Status "Hashing USB files" -PercentComplete 70
    $Context.UsbInternalHashes = Get-FileHashes -RootPath $Context.UsbMountDir -FileFilter $Filter -SourceType "USB $type" -SuppressHeader

    # Diff sets (non-mounting work)
    $Context.Modified = @{}
    $Context.Missing  = @()
    $Context.Extra    = @()

    foreach ($key in $Context.IsoInternalHashes.Keys) {
        if (-not $Context.UsbInternalHashes.ContainsKey($key)) {
            $Context.Missing += $key
        }
        elseif ($Context.IsoInternalHashes[$key] -ne $Context.UsbInternalHashes[$key]) {
            $Context.Modified[$key] = 'Modified'
        }
    }

    $Context.Extra = $Context.UsbInternalHashes.Keys | Where-Object { -not $Context.IsoInternalHashes.ContainsKey($_) }

    # Record internal summary for final reporting (no per-phase log here;
    # we print a BOOT/INSTALL section once at the end based on ScanSummary)
    $t = $Context.Type.ToUpper()

    if (-not $script:ScanSummary) { $script:ScanSummary = @{} }
    $script:ScanSummary[$t] = @{
        Modified = $Context.Modified.Count
        Extra    = $Context.Extra.Count
        Missing  = $Context.Missing.Count
        Green    = 0
        Yellow   = 0
        Red      = 0
    }

    return $Context
}

function Analyze-DeepImageDifferences {
    param(
        [Parameter(Mandatory)] $Context
    )
    if (-not $Context.UsbMountDir -or -not $Context.IsoMountDir) {
        throw "Analyze-DeepImageDifferences: Context mount dirs not set (UsbMountDir/IsoMountDir null)."
    }

    $type = $Context.Type.ToUpper()
    $modified = $Context.Modified
    $missing  = $Context.Missing
    $extra    = $Context.Extra

    $greenInt = 0; $yellowInt = 0; $redInt = 0
    $validCertCount = 0; $noCertCount = 0; $resCount = 0

    $diffFiles = ($modified.Keys + $extra) |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    $results = @{ Green = @(); Yellow = @(); Red = @() }

    if ($diffFiles.Count -eq 0) {
        if (-not $script:ScanSummary) { $script:ScanSummary = @{} }

        $totalInternal = $Context.IsoInternalHashes.Count

        $script:ScanSummary[$type] = @{
            Modified = 0
            Extra    = 0
            Missing  = 0
            Green    = $totalInternal   # all internal files matched
            Yellow   = 0
            Red      = 0
        }

        $results.Green += "Internal $($type): No differences"
        return $results
    }


    # Normal case (there ARE differences)
    Write-Log "Batch-checking signatures for $($diffFiles.Count) differing files in $type..."


    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $sigResults = $diffFiles | ForEach-Object -Parallel {
            if ([string]::IsNullOrWhiteSpace($_)) { return }

            $rel     = $_.TrimStart('\')
            $usbPath = Join-Path $using:Context.UsbMountDir $rel
            $ext     = [IO.Path]::GetExtension($usbPath).ToLower()

           $payloadSigExt = @(
            '.exe','.dll','.sys','.drv','.ocx','.scr','.cpl','.com',
            '.msi','.cab','.jar',
            '.ps1','.psm1','.bat','.cmd','.vbs','.js','.jse','.wsf','.wsh','.hta',
            '.bin','.dat','.pak',
            '.cat','.mui',
            '.efi'
            )

            if ($payloadSigExt -contains $ext) {
                $sig = Get-AuthenticodeSignature -LiteralPath $usbPath -ErrorAction SilentlyContinue
                @{
                    File   = $_
                    Status = $sig.Status
                    Signer = $sig.SignerCertificate.Subject
                }
            } else {
                @{
                    File   = $_
                    Status = "NonPE"
                    Signer = $null
                }
            }
        } -ThrottleLimit 8
    } else {
        $sigResults = $diffFiles | ForEach-Object {
            if ([string]::IsNullOrWhiteSpace($_)) { return }

            $rel     = $_.TrimStart('\')
            $usbPath = Join-Path $Context.UsbMountDir $rel
            $ext     = [IO.Path]::GetExtension($usbPath).ToLower()

            $payloadSigExt = @(
                '.exe','.dll','.sys','.drv','.ocx','.scr','.cpl','.com',
                '.msi','.cab','.jar',
                '.ps1','.psm1','.bat','.cmd','.vbs','.js','.jse','.wsf','.wsh','.hta',
                '.bin','.dat','.pak',
                '.cat','.mui'
            )

            if ($payloadSigExt -contains $ext) {
                $sig = Get-AuthenticodeSignature -LiteralPath $usbPath -ErrorAction SilentlyContinue
                @{
                    File   = $_
                    Status = $sig.Status
                    Signer = $sig.SignerCertificate.Subject
                }
            } else {
                @{
                    File   = $_
                    Status = "NonPE"
                    Signer = $null
                }
            }
        }
    }


    Write-Log "Identifying suspicious modified files in $type that lack valid Microsoft signatures for deeper analysis."

    $suspiciousModified = @()
    foreach ($result in $sigResults) {
        if (-not $result) { continue }
        $file   = $result.File
        $status = if ($modified.ContainsKey($file)) { 'Modified' } else { 'Extra' }
        if ($status -eq 'Modified' -and -not ($result.Status -eq 'Valid' -and $result.Signer -match 'Microsoft')) {
            $suspiciousModified += $file
        }
    }

    # Pre-load ISO-side strings/XML from the existing ISO mount (no remount)
    $isoData = @{}
    foreach ($file in $suspiciousModified) {
        $isoTempPath = Join-Path $Context.IsoMountDir $file.TrimStart('\')
        if (-not (Test-Path $isoTempPath)) { continue }

        $ext = [IO.Path]::GetExtension($file).ToLower()
        if ($ext -eq '.xml') {
            try {
                $isoText = Get-Content -LiteralPath $isoTempPath | Out-String
                $isoXml = [xml]$isoText
                $isoData[$file] = $isoXml.OuterXml

            } catch {
                Write-Log "Failed to extract XML from ISO '${file}': $($_.Exception.Message)" -Level "WARNING"
            }
        } else {
            $isoData[$file] = Extract-PrintableStrings $isoTempPath
        }
    }

    Write-Log "" -NoTimestamp
    Write-Log "Performing detailed analysis on suspicious differing files in $type (string/XML comparisons, threat assessment)." -NoTimestamp -Level "IMPORTANT" -Header -Context $type
    Write-Log "" -NoTimestamp

    $totalDiff = $sigResults.Count
    $i = 0
    $validSigDiffCount = 0

    foreach ($result in $sigResults) {
        if (-not $result) { continue }   # guard against null entries
        $i++
        $percent = if ($totalDiff -gt 0) { [math]::Round(($i / $totalDiff) * 100) } else { 100 }
        Write-Progress -Activity "Analyzing differences in $type" -Status "$percent%" -PercentComplete $percent

        $file = $result.File
        if ([string]::IsNullOrEmpty($file)) {
            Write-Log "Skipping analysis: Empty file path encountered." -Level "WARNING"
            continue
        }

        $status    = if ($modified.ContainsKey($file)) { 'Modified' } else { 'Extra' }
        $usbIntPath = Join-Path $Context.UsbMountDir $file.TrimStart('\')

        if ($result.Status -eq 'Valid' -and $result.Signer -match 'Microsoft') {
            $greenInt++
            $validCertCount++
            $validSigDiffCount++
        } else {
            $isoDataForFile = if ($status -eq 'Modified') { $isoData[$file] } else { $null }
            $resultAnalysis = Analyze-File -FilePath $usbIntPath -IsoFilePath $null -Context "Internal $type" -Status $status -IsoData $isoDataForFile

            switch ($resultAnalysis.Threat) {
                "GREEN" {
                    $greenInt++
                    if ($resultAnalysis.Note -match "Valid") { $validCertCount++ }
                }
                "WARNING" {
                    $yellowInt++
                    if ($resultAnalysis.Note -match "Resource") { $resCount++ }
                }
                "RED" {
                    $redInt++
                    if ($resultAnalysis.Note -match "Invalid|Not signed") { $noCertCount++ }
                }
            }

            if ($resultAnalysis.Threat -ne "GREEN") {
                Write-Log "Internal $type ${file}: $($resultAnalysis.Note)" -Level $resultAnalysis.Threat
                Write-Log "" -NoTimestamp
            }
        }
    }

    Write-Progress -Activity "Analyzing differences in $type" -Completed

    if ($validSigDiffCount -gt 0) {
        Write-Log "$validSigDiffCount of $($diffFiles.Count) differing files in $type have valid Microsoft signatures but differ from ISO (likely benign)." -Level "GREEN"
    }

    if (-not $script:ScanSummary) { $script:ScanSummary = @{} }
    if (-not $script:ScanSummary[$type]) {
        $script:ScanSummary[$type] = @{
            Modified = $modified.Count
            Extra    = $extra.Count
            Missing  = $missing.Count
            Green    = 0
            Yellow   = 0
            Red      = 0
        }
    }

    $script:ScanSummary[$type].Modified = $modified.Count
    $script:ScanSummary[$type].Extra    = $extra.Count
    $script:ScanSummary[$type].Missing  = $missing.Count

    # Compute how many internal files matched exactly
    $totalInternal  = $Context.IsoInternalHashes.Count
    $diffCount      = $modified.Count + $missing.Count   # extra files are USB-only
    $matchingCount  = $totalInternal - $diffCount
    if ($matchingCount -lt 0) { $matchingCount = 0 }

    $greenTotal = $matchingCount + $greenInt   # clean matches + "green" diffs

    $script:ScanSummary[$type].Green  = $greenTotal
    $script:ScanSummary[$type].Yellow = $yellowInt
    $script:ScanSummary[$type].Red    = $redInt


    if (-not $script:SectionDetails) { $script:SectionDetails = @{} }
    $script:SectionDetails[$type] = @{
        Modified = $modified.Keys
        Extra    = $extra
        Missing  = $missing
    }



    Write-Log "Internal ${type}: $greenInt GREEN (incl $validCertCount valid certs), $yellowInt YELLOW (incl $resCount resources), $redInt RED (incl $noCertCount no/invalid cert)"


    if ($missing.Count -gt 0) {
        Write-Log "$($missing.Count) internal files in ISO $type missing on USB (likely version diffs)." -Level "WARNING"
        $yellowInt += $missing.Count
    }
    if ($extra.Count -gt 0) {
        Write-Log "$($extra.Count) extra internal files in USB $type (likely version diffs)." -Level "WARNING"
        $yellowInt += $extra.Count
    }

    if ($redInt -gt 0)   { $results.Red    += "Internal $($type): $redInt high threat" }
    if ($yellowInt -gt 0){ $results.Yellow += "Internal $($type): $yellowInt medium" }
    if ($greenInt -gt 0) { $results.Green  += "Internal $($type): $greenInt low" }
    if ($greenInt + $yellowInt + $redInt -eq 0) { $results.Green += "Internal $($type): No differences" }

    Write-Log "Internal ${type}: $greenInt GREEN (incl $validCertCount valid certs), $yellowInt YELLOW (incl $resCount resources), $redInt RED (incl $noCertCount no/invalid cert)" -Context $type


    return $results
}

function Cleanup-DeepImageContext {
    param(
        [Parameter(Mandatory)] $Context
    )

    try {
        if ($Context.UsbMountDir) {
            Unmount-Image $Context.UsbMountDir -Force
        }
    } catch {
        Write-Log "Failed to unmount USB $($Context.Type) image: $($_.Exception.Message)" -Level "WARNING"
    }

    try {
        if ($Context.IsoMountDir) {
            Unmount-Image $Context.IsoMountDir -Force
        }
    } catch {
        Write-Log "Failed to unmount ISO $($Context.Type) image: $($_.Exception.Message)" -Level "WARNING"
    }

    if ($Context.UsbTempPath -and (Test-Path $Context.UsbTempPath)) {
        Remove-Item $Context.UsbTempPath -Force -ErrorAction SilentlyContinue
    }
    if ($Context.IsoTempPath -and (Test-Path $Context.IsoTempPath)) {
        Remove-Item $Context.IsoTempPath -Force -ErrorAction SilentlyContinue
    }
}


function Perform-DeepWIMScan {
    param (
        [string]$Type,
        [string]$UsbPath,
        [string]$IsoPath,
        [switch]$IsSplit
    )

    $label = $Type.ToUpper()   # BOOT / INSTALL

    # Overall deep scan progress (id 0)
    Write-Progress -Id 0 -Activity "Deep Scan on $label" -Status "Preparing..." -PercentComplete 0

    $ctx = New-DeepWIMScanContext -Type $Type -UsbPath $UsbPath -IsoPath $IsoPath -IsSplit:$IsSplit
    Write-Log "$label (Internal image) Processing" -NoTimestamp -Level "IMPORTANT" -Header -Context "OPERATION"
    # Short-circuit if the assembled images are byte-identical
    if ($ctx.UsbWholeHash -and $ctx.IsoWholeHash -and $ctx.UsbWholeHash -eq $ctx.IsoWholeHash) {
        Write-Log "$label hashes match - clean." -Level "GREEN"
        Cleanup-DeepImageContext -Context $ctx
        Write-Progress -Id 0 -Activity "Deep Scan on $label" -Completed
        return @{ Green = @("\sources\$Type.* (Match)") ; Yellow = @(); Red = @() }
    } else {
        Write-Log "$label hashes differ or couldn't compute - deep scan enabled." -Level "WARNING"
    }

    $filter = if ($FullDeepScan) {
        @('*')
    } else {
        @('*.exe', '*.dll', '*.sys', '*.drv', '*.inf', '*.cat', '*.xml', '*.mui', '*.sdb')
    }

    try {
        Write-Progress -Id 0 -Activity "Deep Scan on $label" -Status "Mounting and hashing internal files" -PercentComplete 25
        $ctx = Mount-DeepImagePair -Context $ctx -Filter $filter

        Write-Progress -Id 0 -Activity "Deep Scan on $label" -Status "Analyzing differences" -PercentComplete 75
        $results = Analyze-DeepImageDifferences -Context $ctx

        Write-Progress -Id 0 -Activity "Deep Scan on $label" -Completed
        Cleanup-DeepImageContext -Context $ctx

        return $results

    } catch {
        if ($_.Exception -is [System.OperationCanceledException]) {
            Write-Log "Deep WIM scan for ${Type} cancelled by user – cleaning up and aborting." -Level "WARNING"

            # Ensure cleanup, but don't treat as a failure – rethrow so top-level handler runs
            Cleanup-DeepImageContext -Context $ctx
            Write-Progress -Id 0 -Activity "Deep Scan on $label" -Completed
            throw
        }

        Write-Log "Deep scan failed for ${Type}: $($_.Exception.Message)" -Level "RED"

        # Ensure cleanup even on failure
        Cleanup-DeepImageContext -Context $ctx
        Write-Progress -Id 0 -Activity "Deep Scan on $label" -Completed

        return @{ Red = @("\sources\$Type.* (Scan failed)") ; Yellow = @(); Green = @() }
    }
}



function Verify-ISOHash {
    param (
        [string]$ISOPath,
        [string]$KnownHashesFile
    )
    Write-Log "ISO Verification" -NoTimestamp -Level "IMPORTANT" -Header -Context "ISO"

    # Load known hashes (hardcoded + optional external)
    $knownISOHashes = @{
        "en-us_windows_11_consumer_editions_version_25h2_updated_nov_2025_x64_dvd_4ace2901.iso" = "AD0D85002B8F6B6A009C335F8AD9A3606D224D215039220E92C390D4C7B5A8CA"
        "en-gb_windows_11_consumer_editions_version_25h2_updated_nov_2025_x64_dvd_4ace2901.iso" = "96D8F01A13874B398A931423E7697A183E9F8436B20BA89B1761B00FF1617B2C"
        "en-us_windows_11_consumer_editions_version_25h2_x64_dvd_9934ee4c.iso"                  = "D141F6030FED50F75E2B03E1EB2E53646C4B21E5386047CB860AF5223F102A32"
        "en-gb_windows_11_consumer_editions_version_25h2_x64_dvd_f18d2cbd.iso"                  = "BAAEB6C90DD51648154B64C40C9E0C14D93A427F611A1BB49C8077FA2FF73364"
    }

    if ($KnownHashesFile -and (Test-Path $KnownHashesFile)) {
        try {
            $externalHashes = Get-Content $KnownHashesFile | ConvertFrom-Json
            $knownISOHashes += $externalHashes
        } catch {
            Write-Log "Failed to parse external known-hashes file '$KnownHashesFile': $($_.Exception.Message)" -Level "WARNING"
        }
    }

    try {
        $isoHash = (Get-FileHash $ISOPath -Algorithm 'SHA256').Hash.ToUpper()
        $script:ISOHashInfo.Hash = $isoHash

        $matchingKey = $null
        if ($knownISOHashes.Count -gt 0) {
            $matchingKey = $knownISOHashes.GetEnumerator() |
                           Where-Object { $_.Value -eq $isoHash } |
                           Select-Object -ExpandProperty Key -First 1
        }

        if ($matchingKey) {
            $script:ISOHashInfo.Status      = 'KnownGood'
            $script:ISOHashInfo.MatchedName = $matchingKey

            Write-Log "ISO verified as authentic (matches known hash for '$matchingKey')." -Level "GREEN"
            Write-Log "ISO SHA256: $isoHash" -Level "INFO"
        } else {
            $script:ISOHashInfo.Status      = 'Unknown'
            $script:ISOHashInfo.MatchedName = $null

            Write-Log "WARNING: ISO SHA256 does not match any built-in known-good hash." -Level "WARNING"
            Write-Log "ISO SHA256: $isoHash" -Level "INFO"
            Write-Log "If this ISO was not downloaded directly from Microsoft, double-check the source or compare against official hashes." -Level "WARNING"
        }
    } catch {
        $script:ISOHashInfo.Status      = 'Error'
        $script:ISOHashInfo.MatchedName = $null
        $script:ISOHashInfo.Hash        = $null

        Write-Log "Failed to compute ISO hash: $($_.Exception.Message)" -Level "RED"
    }

    # Return the trimmed ISOPath for use in main script
    return $ISOPath
}



function Close-ExplorerForDrive {
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Z]:$')]
        [string]$Drive
    )

    try {
        $driveRoot = $Drive.ToUpper().TrimEnd('\')  # "F:"
        Write-Log "Attempting to close Explorer windows for drive $driveRoot..." -Level "INFO"

        # Try for up to ~5 seconds to catch the auto-open window
        for ($attempt = 1; $attempt -le 10; $attempt++) {
            $closedAny = $false

            $shell   = New-Object -ComObject Shell.Application
            $windows = $shell.Windows()
            if (-not $windows) {
                Start-Sleep -Milliseconds 500
                continue
            }

            foreach ($w in $windows) {
                try {
                    $folder = $w.Document.Folder
                    if (-not $folder) { continue }

                    $path = $folder.Self.Path  # e.g. "F:\" or "F:\Sources"
                    if ([string]::IsNullOrWhiteSpace($path)) { continue }

                    $norm = $path.ToUpper().TrimEnd('\')  # Normalise "F:\" -> "F:"
                    if ($norm -match '^[A-Z]:$') {
                        Write-Log "Explorer window candidate: '$path'" -Level "INFO"
                    }

                    # Match exact drive root or anything under it
                    if ($norm -eq $driveRoot -or $norm.StartsWith($driveRoot + "\")) {
                        Write-Log "Closing Explorer window for mounted ISO path: $path (attempt $attempt)" -Level "INFO"
                        $w.Quit()
                        $closedAny = $true
                    }
                } catch {
                    # Ignore weird COM windows
                    continue
                }
            }

            if ($closedAny) {
                Write-Log "Finished closing Explorer windows for $driveRoot." -Level "INFO"
                break
            }

            # Nothing matched this time – wait a bit and let Explorer catch up
            Start-Sleep -Milliseconds 500
        }
    } catch {
        Write-Log "Failed to inspect/close Explorer windows: $($_.Exception.Message)" -Level "WARNING"
    }
}



function Mount-ISO {
    param (
        [string]$ISOPath
    )

    # Resolve to a full path so ImagePath comparisons are reliable
    $fullPath = (Resolve-Path $ISOPath).Path
    $script:ISOContext.FullPath = $fullPath
    $script:ISOContext.MountedByScript = $false
    $script:ISOContext.DriveLetter = $null

    Write-Log "ISO Mounting" -NoTimestamp -Level "IMPORTANT" -Header -Context "OPERATION"
    Write-Log "Using ISO: $fullPath"

    try {
        # See if this ISO is already mounted
        $existing = Get-DiskImage -ImagePath $fullPath -ErrorAction SilentlyContinue
        if ($existing -and $existing.Attached) {
            $vol = $existing | Get-Volume
            $drive = $vol.DriveLetter + ':'
            $script:ISOContext.DriveLetter = $drive

            Write-Log "ISO is already mounted at $drive. Reusing existing mount (will ask before dismounting later)."
            return $drive
        }

        # Not mounted yet: mount it ourselves
        $mountResult = Mount-DiskImage -ImagePath $fullPath -StorageType ISO -PassThru -ErrorAction Stop
        $isoDrive = ($mountResult | Get-Volume).DriveLetter + ':'

        $script:ISOContext.DriveLetter = $isoDrive
        $script:ISOContext.MountedByScript = $true

        Start-Sleep -Milliseconds 500   # let autoplay/Explorer react
        Close-ExplorerForDrive -Drive $isoDrive

        # Politely ask Windows to give focus back to this console
        Focus-ConsoleWindow
        
        # Record this ISO as script-mounted in persistent state
        $state = Get-ISOState
        if (-not $state.MountedISOs) { $state.MountedISOs = @() }
        if (-not ($state.MountedISOs -contains $fullPath)) {
            $state.MountedISOs += $fullPath
            Save-ISOState -State $state
        }


        Write-Log "ISO mounted at $isoDrive." -Context "ISO"

    } catch {
        Write-Log "Failed to mount ISO ${fullPath}: $($_.Exception.Message)" -Level "RED"
        exit 1
    }

    return $script:ISOContext.DriveLetter
}

function Focus-ConsoleWindow {
    try {
        $sig = @"
using System;
using System.Runtime.InteropServices;

public static class ConsoleFocus {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
}
"@

        # Only add the type once per session
        if (-not ("ConsoleFocus" -as [type])) {
            Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue | Out-Null
        }

        $hWnd = [ConsoleFocus]::GetConsoleWindow()
        if ($hWnd -ne [IntPtr]::Zero) {
            [ConsoleFocus]::SetForegroundWindow($hWnd) | Out-Null
        }
    } catch {
        Write-Log "Failed to refocus console window: $($_.Exception.Message)" -Level "WARNING"
    }
}


function Dismount-ISO {
    param(
        [switch]$Quiet
    )

    # Safely dismount only the ISO we know about
    if (-not $script:ISOContext.FullPath) {
        # Nothing tracked, nothing to do
        return
    }

    $isoPath = $script:ISOContext.FullPath
    $drive   = $script:ISOContext.DriveLetter

    try {
        $img = Get-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue
        if (-not $img -or -not $img.Attached) {
            if (-not $Quiet) {
                Write-Log "No attached ISO found for $isoPath (maybe already dismounted)." -Level "WARNING"
            }
            return
        }

        # If we didn't mount it, ask the user before touching it
        if (-not $script:ISOContext.MountedByScript) {
            $prompt = "The ISO `"$isoPath`" is mounted as drive $drive but was not mounted by this script. Do you want to dismount it now? (Y/N, default N)"
            $choice = Read-Host $prompt
            if ($choice -ne 'Y' -and $choice -ne 'y') {
                if (-not $Quiet) {
                    Write-Log "Leaving ISO mounted at $drive at user request."
                }
                return
            }
        }

        Dismount-DiskImage -ImagePath $isoPath -ErrorAction Stop | Out-Null

        if (-not $Quiet) {
            Write-Log "ISO dismounted: $isoPath"
        }

        # Remove from persistent state (if present)
        $state = Get-ISOState
        if ($state.MountedISOs) {
            $state.MountedISOs = $state.MountedISOs | Where-Object { $_ -ne $isoPath }
            Save-ISOState -State $state
        }

    } catch {
        # Dismount failure is *always* interesting – keep this loud
        Write-Log "Dismount failed for ${isoPath}: $($_.Exception.Message)" -Level "WARNING"
    } finally {
        # Clear tracked context
        $script:ISOContext = @{
            FullPath        = $null
            DriveLetter     = $null
            MountedByScript = $false
        }
    }
}



function Write-FinalSummary {
    param(
        [array]$RedItems,
        [array]$YellowItems,
        [array]$GreenItems,
        [int]$MissingRootCount
    )

    # Build per-section threat from ScanSummary
    $sections = @('ROOT','BOOT','INSTALL')
    $sectionResults = @{}

    foreach ($key in $sections) {
        if (-not $script:ScanSummary.ContainsKey($key)) { continue }
        $s = $script:ScanSummary[$key]

        $threat =
            if ($s.Red -gt 0 -or ($key -eq 'ROOT' -and $MissingRootCount -gt 0)) { 'RED' }
            elseif ($s.Yellow -gt 0) { 'YELLOW' }
            elseif ($s.Modified -eq 0 -and $s.Extra -eq 0 -and $s.Missing -eq 0) { 'GREEN' }
            else { 'GREEN' }

        $sectionResults[$key] = @{
            Threat   = $threat
            Modified = $s.Modified
            Extra    = $s.Extra
            Missing  = $s.Missing
        }
    }

    # Overall verdict: max severity across sections
    $severityRank = @{ 'GREEN' = 0; 'YELLOW' = 1; 'RED' = 2 }
    $overall = 'GREEN'
    foreach ($sec in $sectionResults.Keys) {
        $t = $sectionResults[$sec].Threat
        if ($severityRank[$t] -gt $severityRank[$overall]) {
            $overall = $t
        }
    }

    $overallLevel = switch ($overall) {
        'RED'    { 'RED' }
        'YELLOW' { 'WARNING' }
        default  { 'GREEN' }
    }

    $overallIcon = switch ($overall) {
        'RED'    { '[FAIL]' }
        'YELLOW' { '[WARN]' }
        default  { '[ OK ]' }
    }

    Write-Log "" -NoTimestamp
    Write-Log "USB Verification Summary" -NoTimestamp -Level "IMPORTANT" -Header -Context "RESULT"
    Write-Log "==================== FINAL RESULT ====================" -Level "INFO" -Context "RESULT"

    # ISO hash / integrity summary (if we managed to compute it)
    if ($script:ISOHashInfo.Hash) {
        $isoStatusText = switch ($script:ISOHashInfo.Status) {
            'KnownGood' { "KNOWN GOOD (matches '$($script:ISOHashInfo.MatchedName)')" }
            'Unknown'   { "UNKNOWN – hash not in known-good list" }
            'Error'     { "HASH ERROR – see earlier log entries" }
            default     { $script:ISOHashInfo.Status }
        }

        $isoLevel = switch ($script:ISOHashInfo.Status) {
            'KnownGood' { 'GREEN' }
            'Unknown'   { 'WARNING' }
            'Error'     { 'RED' }
            default     { 'INFO' }
        }

        Write-Log ("ISO SHA256: {0}" -f $script:ISOHashInfo.Hash) -Level "INFO" -Context "RESULT"
        Write-Log ("ISO integrity: {0}" -f $isoStatusText) -Level $isoLevel -Context "RESULT"

        if ($script:ISOHashInfo.Status -eq 'Unknown') {
            Write-Log "Note: ISO hash is not in the built-in known-good list. If you did not download this ISO directly from Microsoft, re-check the download source or compare with official Microsoft hashes." -Level "WARNING" -Context "RESULT"
        }
    }

    Write-Log "$overallIcon Overall verdict: $overall" -Level $overallLevel -Context "RESULT"
    Write-Log "------------------------------------------------------" -Level "INFO" -Context "RESULT"

    foreach ($key in @('ROOT','BOOT','INSTALL')) {
        if (-not $sectionResults.ContainsKey($key)) { continue }
        $r = $sectionResults[$key]

        $label = switch ($key) {
            'ROOT'    { 'ROOT (Surface files)' }
            'BOOT'    { 'BOOT (Internal image)' }
            'INSTALL' { 'INSTALL (Internal image)' }
        }

        $icon = switch ($r.Threat) {
            'RED'    { '[FAIL]' }
            'YELLOW' { '[WARN]' }
            default  { '[ OK ]' }
        }

        $baseLine =
            if ($r.Modified -eq 0 -and $r.Extra -eq 0 -and $r.Missing -eq 0) {
                "$icon ${label}: $($r.Threat) | No differences"
            } else {
                "$icon ${label}: $($r.Threat) | Modified: $($r.Modified), Extra: $($r.Extra), Missing: $($r.Missing)"
            }

        $level = switch ($r.Threat) {
            'RED'    { 'RED' }
            'YELLOW' { 'WARNING' }
            default  { 'GREEN' }
        }

        Write-Log $baseLine -Level $level -Context "RESULT"
        # Show per-section colour breakdown if available (so Yellow is visible in FINAL RESULT)
        if ($script:ScanSummary.ContainsKey($key)) {
            $s = $script:ScanSummary[$key]

            if ($key -eq 'ROOT') {
                $imageCount = if ($s.ContainsKey('Images')) { $s.Images } else { 0 }

                if ($imageCount -gt 0) {
                    Write-Log ("           Breakdown: Green={0}, Yellow={1}, Red={2}, Images={3}" -f $s.Green, $s.Yellow, $s.Red, $imageCount) -Level "INFO" -Context "RESULT"
                } else {
                    Write-Log ("           Breakdown: Green={0}, Yellow={1}, Red={2}" -f $s.Green, $s.Yellow, $s.Red) -Level "INFO" -Context "RESULT"
                }
            } else {
                Write-Log ("           Breakdown: Green={0}, Yellow={1}, Red={2}" -f $s.Green, $s.Yellow, $s.Red) -Level "INFO" -Context "RESULT"
            }
        }

        # Extra explanation & filenames only if there ARE differences
        if ($r.Modified -ne 0 -or $r.Extra -ne 0 -or $r.Missing -ne 0) {
            $files = @()
            if ($script:SectionDetails.ContainsKey($key)) {
                $d = $script:SectionDetails[$key]
                $files = @($d.Modified + $d.Extra + $d.Missing | Where-Object { $_ -and $_.Trim() -ne '' } | Select-Object -Unique)
            }

            if ($files.Count -gt 0) {
                $maxShow = [math]::Min(5, $files.Count)
                $preview = $files[0..($maxShow-1)] -join ', '
                if ($files.Count -gt $maxShow) {
                    $preview += ", +$($files.Count - $maxShow) more"
                }
                Write-Log ("           Files: {0}" -f $preview) -Level "INFO" -Context "RESULT"

                # Simple type-based reason
                # Detailed type-based reason tuned by severity
                $execExt   = @('.exe','.dll','.sys','.drv','.ocx','.scr')
                $scriptExt = @('.ps1','.psm1','.bat','.cmd','.vbs','.js','.jse','.wsf')
                $binExt    = @('.bin','.dat','.pak','.cab')
                $configExt = @('.xml','.inf','.ini','.cfg','.sdb','.manifest','.mui','.cat')
                $docExt    = @('.txt','.log','.md','.rtf')

                $allExts = $files | ForEach-Object { [IO.Path]::GetExtension($_).ToLower() } |
                           Where-Object { $_ -ne '' } | Select-Object -Unique

                $execHit   = @($allExts | Where-Object { $execExt   -contains $_ })
                $scriptHit = @($allExts | Where-Object { $scriptExt -contains $_ })
                $binHit    = @($allExts | Where-Object { $binExt    -contains $_ })
                $configHit = @($allExts | Where-Object { $configExt -contains $_ })
                $docHit    = @($allExts | Where-Object { $docExt    -contains $_ })

                $reasonParts = @()

                if ($execHit.Count -gt 0) {
                    $sample = $execHit[0..([math]::Min(1, $execHit.Count-1))] -join ', '
                    $reasonParts += "includes executable/driver files (e.g. $sample)"
                }
                if ($scriptHit.Count -gt 0) {
                    $sample = $scriptHit[0..([math]::Min(1, $scriptHit.Count-1))] -join ', '
                    $reasonParts += "includes script files (e.g. $sample)"
                }
                if ($binHit.Count -gt 0) {
                    $sample = $binHit[0..([math]::Min(1, $binHit.Count-1))] -join ', '
                    $reasonParts += "includes binary payload-style files (e.g. $sample)"
                }

                # Lower-risk categories (only if we don't already have a wall of high-risk parts)
                if ($configHit.Count -gt 0) {
                    $sample = $configHit[0..([math]::Min(1, $configHit.Count-1))] -join ', '
                    $reasonParts += "has configuration/metadata changes (e.g. $sample)"
                }
                if ($docHit.Count -gt 0 -and $execHit.Count -eq 0 -and $scriptHit.Count -eq 0 -and $binHit.Count -eq 0) {
                    # Only call out docs explicitly when there’s nothing scarier present
                    $sample = $docHit[0..([math]::Min(1, $docHit.Count-1))] -join ', '
                    $reasonParts += "only affects text/log-style files (e.g. $sample)"
                }

                if ($reasonParts.Count -eq 0) {
                    $reasonParts += "involves miscellaneous file types (no clear category)"
                }

                # Keep the message tight: at most 2 parts
                if ($reasonParts.Count -gt 2) {
                    $reasonParts = $reasonParts[0..1]
                }

                $reason = "Reason ($($r.Threat)): " + ($reasonParts -join '; ') + "."
                Write-Log ("           {0}" -f $reason) -Level "INFO" -Context "RESULT"

            }
        }
    }

    if ($MissingRootCount -gt 0) {
        Write-Log "Note: $MissingRootCount surface files are missing from USB compared with ISO (may be expected for customised media)." -Level "WARNING" -Context "RESULT"
    }

    Write-Log "======================================================" -Level "INFO" -Context "RESULT"
}






##########################################################################################
##########################################################################################
########################################################################################## Main flow
##########################################################################################
##########################################################################################


$startTime = Get-Date
Show-StartupBanner -StartTime $startTime

# Treat Ctrl+C as keystroke so our Check-ForInterrupt can see it
[Console]::TreatControlCAsInput = $true

try {
    # ===== MAIN BODY START =====

    $ISOPath = $ISOPath.Trim('"', "'")

    if (-not (Test-Path $ISOPath -PathType Leaf)) {
        Write-Log "Invalid ISOPath: $ISOPath" -Level "ERROR"
        exit 1
    }

    $ISOPath = (Resolve-Path -LiteralPath $ISOPath).ProviderPath
    Write-Log "Using ISO: $ISOPath"

    # Environment check first so cleanup has $HasHandleExe
    $envCheck = Test-Environment -ReassembleWIM:$ReassembleWIM -DeepScanWIM:$DeepScanWIM
    $ReassembleWIM = $envCheck.ReassembleWIM
    $DeepScanWIM   = $envCheck.DeepScanWIM
    $HasHandleExe  = $envCheck.HasHandleExe

    # Initial cleanup
    Clean-TempMounts

    # clean up leftover ISOs from previous usb-verifier runs (if any)
    Cleanup-PreviousScriptISOs

    # Add this call in the main flow, right after Clean-TempMounts:
    $ISOPath = Verify-ISOHash -ISOPath $ISOPath -KnownHashesFile $KnownHashesFile
    $isoDrive = Mount-ISO -ISOPath $ISOPath

# Hash ISO and USB
$isoHashes = Get-FileHashes -RootPath $isoDrive -SourceType "ISO"
$usbHashes = Get-FileHashes -RootPath $USBDrive -SourceType "USB"

# Detect split
Write-Log "Checking for multiple files" -NoTimestamp -Level "IMPORTANT" -Header -Context "OPERATION"
$isSplit = ($usbHashes.Keys -match '\\sources\\install\d*\.swm$').Count -gt 0 -and -not $usbHashes.ContainsKey('\sources\install.wim')
Write-Log "Split detected: $isSplit"

# Ensure temp dir
if (-not (Test-Path "C:\Temp")) { New-Item "C:\Temp" -ItemType Directory -Force | Out-Null }

# WIM paths detection (handle variations)
$isoBoot = if (Test-Path "$isoDrive\sources\boot.wim") { "$isoDrive\sources\boot.wim" } else { $null }
$usbBoot = if (Test-Path "$USBDrive\sources\boot.wim") { "$USBDrive\sources\boot.wim" } else { $null }
$isoInstallExt = if (Test-Path "$isoDrive\sources\install.wim") { ".wim" } elseif (Test-Path "$isoDrive\sources\install.esd") { ".esd" } else { $null }
$usbInstallExt = if (Test-Path "$USBDrive\sources\install.wim") { ".wim" } elseif (Test-Path "$USBDrive\sources\install.esd") { ".esd" } elseif ($isSplit) { ".swm" } else { $null }
$isoInstall = "$isoDrive\sources\install$isoInstallExt"
$usbInstall = "$USBDrive\sources\install$usbInstallExt"

$redFiles = @()
$yellowFiles = @()
$greenFiles = @()

if ($DeepScanWIM) {
    if ($isoBoot -and $usbBoot) {
        $bootResults = Perform-DeepWIMScan -Type "boot" -UsbPath $usbBoot -IsoPath $isoBoot
        $greenFiles += $bootResults.Green
        $yellowFiles += $bootResults.Yellow
        $redFiles += $bootResults.Red
    } else {
        Write-Log "boot.wim missing in ISO or USB." -Level "RED"
        $redFiles += "\sources\boot.wim (Missing)"
    }
    if ($isoInstallExt -and $usbInstallExt) {
        $installResults = Perform-DeepWIMScan -Type "install" -UsbPath $usbInstall -IsoPath $isoInstall -IsSplit:$isSplit
        $greenFiles += $installResults.Green
        $yellowFiles += $installResults.Yellow
        $redFiles += $installResults.Red
    } else {
        Write-Log "install.* missing in ISO or USB." -Level "RED"
        $redFiles += "\sources\install.* (Missing)"
    }
} else {
    Write-Log "NOTICE: DeepScanWIM not enabled. WIM/ESD/SWM may differ (common for MCT). Use -DeepScanWIM for full check." -Level "IMPORTANT"
    if ($usbBoot -and $isoHashes['\sources\boot.wim'] -ne $usbHashes['\sources\boot.wim']) { $yellowFiles += "\sources\boot.wim (Mismatch - typical for MCT)" }
    if ($isSplit) { $yellowFiles += "\sources\install*.swm (Split detected - typical for MCT on FAT32)" }
    elseif ($usbInstallExt -and $isoHashes["\sources\install$isoInstallExt"] -ne $usbHashes["\sources\install$usbInstallExt"]) { $yellowFiles += "\sources\install$usbInstallExt (Mismatch - typical for MCT)" }
}

# Cleanup
Clean-TempMounts


# ROOT (Surface files) comparison
# We exclude image containers here:
#   - \sources\boot.wim
#   - \sources\install.wim / install.esd / install*.swm
# because their contents are analysed in the BOOT/INSTALL deep scan.
$wimExcludes = @(
    '\sources\boot.wim',
    '\sources\install.wim',
    '\sources\install.esd',
    '\sources\install*.swm'
)

$filteredIsoHashes = @{}
$isoHashes.GetEnumerator() | Where-Object {
    $exclude = $false
    foreach ($ex in $wimExcludes) {
        if ($_.Key -like $ex) { $exclude = $true; break }
    }
    -not $exclude
} | ForEach-Object {
    $filteredIsoHashes[$_.Key] = $_.Value
}

$filteredUsbHashes = @{}
$usbHashes.GetEnumerator() | Where-Object {
    $exclude = $false
    foreach ($ex in $wimExcludes) {
        if ($_.Key -like $ex) { $exclude = $true; break }
    }
    -not $exclude
} | ForEach-Object {
    $filteredUsbHashes[$_.Key] = $_.Value
}

# How many USB files did we exclude from ROOT comparison (WIM/ESD/SWM containers)?
$script:RootImageContainerCount = $usbHashes.Count - $filteredUsbHashes.Count
if ($script:RootImageContainerCount -gt 0) {
    Write-Log "Note: $($script:RootImageContainerCount) image container file(s) (boot/install WIM/ESD/SWM) were excluded from surface ROOT comparison and analysed via deep WIM scan instead." -Context "ROOT"
}

$modifiedFiles = @{}
$missingFiles = @()
$extraFiles = @($filteredUsbHashes.Keys | Where-Object { -not $filteredIsoHashes.ContainsKey($_) })
foreach ($key in $filteredIsoHashes.Keys) {
    if (-not $filteredUsbHashes.ContainsKey($key)) { $missingFiles += $key }
    elseif ($filteredIsoHashes[$key] -ne $filteredUsbHashes[$key]) { $modifiedFiles[$key] = 'Modified' }
}


# Header
Write-Log "ROOT (Surface files) Analysis" -NoTimestamp -Level "IMPORTANT" -Header -Context "OPERATION"
Write-Log "Non-WIM summary: ISO files $($filteredIsoHashes.Count), USB $($filteredUsbHashes.Count), Modified $($modifiedFiles.Count), Extra $($extraFiles.Count), Missing $($missingFiles.Count)" -Context "ROOT"

if ($missingFiles.Count -gt 0) {
    if ($missingFiles.Count -le 10) {
        Write-Log "Missing files (in ISO, not on USB): $($missingFiles -join ', ')" -Level "WARNING"
    } else {
        Write-Log "Missing files (in ISO, not on USB): $($missingFiles.Count) total (first 10: $($missingFiles[0..9] -join ', '); see log for full list if needed)" -Level "WARNING"
    }
}

# Tiered analysis for root modified/extra
$greenRoot = 0; $yellowRoot = 0; $redRoot = 0
$validCertRoot = 0; $noCertRoot = 0; $resRoot = 0
$filesToAnalyze = $modifiedFiles.Keys + $extraFiles

if ($filesToAnalyze.Count -gt 0) {
    Write-Log "Batch-checking signatures for $($filesToAnalyze.Count) differing root files..."
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $sigResults = $filesToAnalyze | ForEach-Object -Parallel {
            $usbPath = "$using:USBDrive$_"
            $ext = [IO.Path]::GetExtension($usbPath).ToLower()

            $payloadSigExt = @(
                '.exe','.dll','.sys','.drv','.ocx','.scr','.cpl','.com',
                '.msi','.cab','.jar',
                '.ps1','.psm1','.bat','.cmd','.vbs','.js','.jse','.wsf','.wsh','.hta',
                '.bin','.dat','.pak',
                '.cat','.mui',
                '.efi'
            )




            if ($payloadSigExt -contains $ext) {
                $sig = Get-AuthenticodeSignature -LiteralPath $usbPath -ErrorAction SilentlyContinue
                @{
                    File   = $_
                    Status = $sig.Status
                    Signer = $sig.SignerCertificate.Subject
                }
            } else {
                @{
                    File   = $_
                    Status = "NonPE"
                    Signer = $null
                }
            }
        } -ThrottleLimit 8
    } else {
        $sigResults = $filesToAnalyze | ForEach-Object {
            $usbPath = "$USBDrive$_"
            $ext = [IO.Path]::GetExtension($usbPath).ToLower()

           $payloadSigExt = @(
                '.exe','.dll','.sys','.drv','.ocx','.scr','.cpl','.com',
                '.msi','.cab','.jar',
                '.ps1','.psm1','.bat','.cmd','.vbs','.js','.jse','.wsf','.wsh','.hta',
                '.bin','.dat','.pak',
                '.cat','.mui',
                '.efi'
            )

            if ($payloadSigExt -contains $ext) {
                $sig = Get-AuthenticodeSignature -LiteralPath $usbPath -ErrorAction SilentlyContinue
                @{
                    File   = $_
                    Status = $sig.Status
                    Signer = $sig.SignerCertificate.Subject
                }
            } else {
                @{
                    File   = $_
                    Status = "NonPE"
                    Signer = $null
                }
            }
        }
    }

    $totalDiff = $sigResults.Count
    $i = 0
    $validSigDiffCountRoot = 0  # New counter for root
    foreach ($result in $sigResults) {
        $i++
        $percent = if ($totalDiff -gt 0) { [math]::Round(($i / $totalDiff) * 100) } else { 100 }
        Write-Progress -Activity "Analyzing root differences" -Status "$percent%" -PercentComplete $percent

        $file   = $result.File
        $status = if ($modifiedFiles.ContainsKey($file)) { 'Modified' } else { 'Extra' }
        $usbPath = "$USBDrive$file"
        $isoPath = if ($status -eq 'Modified') { "$isoDrive$file" } else { $null }

        if ($result.Status -eq 'Valid' -and $result.Signer -match 'Microsoft') {
            $greenRoot++
            $validCertRoot++
            $validSigDiffCountRoot++  # Increment new counter
        } else {
            $isoData = $null
            if ($status -eq 'Modified' -and $isoPath -and (Test-Path $isoPath)) {
                $extInner = [IO.Path]::GetExtension($file).ToLower()
                if ($extInner -eq '.xml') {
                    $isoText = Get-Content -LiteralPath $isoPath | Out-String
                    $isoData = ([xml]$isoText).OuterXml
                } else {
                    $isoData = Extract-PrintableStrings $isoPath
                }
            }

            $resultAnalysis = Analyze-File -FilePath $usbPath -IsoFilePath $null -Context "Root" -Status $status -IsoData $isoData

            switch ($resultAnalysis.Threat) {
                "GREEN"   { $greenRoot++; if ($resultAnalysis.Note -match "Valid") { $validCertRoot++ } }
                "WARNING" { $yellowRoot++; }
                "RED"     { $redRoot++; if ($resultAnalysis.Note -match "Invalid|Not signed") { $noCertRoot++ } }
            }

            if ($resultAnalysis.Threat -ne "GREEN") {
                Write-Log "Root ${file}: $($resultAnalysis.Note)" -Level $resultAnalysis.Threat
            }
        }
    }
    Write-Progress -Activity "Analyzing root differences" -Completed

    # Summary log for valid sig diffs in root
    if ($validSigDiffCountRoot -gt 0) {
        Write-Log "$validSigDiffCountRoot of $($filesToAnalyze.Count) differing root files have valid Microsoft signatures but differ from ISO (likely benign, no concern)." -Level "GREEN"
    }
}


if ($missingFiles.Count -gt 0) {
    $yellowRoot += $missingFiles.Count
}
Write-Log "Root files: $greenRoot GREEN (incl $validCertRoot valid certs, likely benign diffs), $yellowRoot YELLOW (incl $resRoot resources + missing), $redRoot RED (incl $noCertRoot no/invalid certs)" -Context "ROOT"

if (-not $script:ScanSummary) { $script:ScanSummary = @{} }

# Total ISO-side surface files
$totalRootIso   = $filteredIsoHashes.Count

# Files that are NOT identical or missing from the ISO side
$rootDiffCount  = $modifiedFiles.Count + $missingFiles.Count
$matchingRoot   = $totalRootIso - $rootDiffCount
if ($matchingRoot -lt 0) { $matchingRoot = 0 }

# Total green = "matching" + "green diffs"
$greenTotalRoot = $matchingRoot + $greenRoot

$script:ScanSummary['ROOT'] = @{
    Modified = $modifiedFiles.Count
    Extra    = $extraFiles.Count
    Missing  = $missingFiles.Count
    Green    = $greenTotalRoot
    Yellow   = $yellowRoot
    Red      = $redRoot
    Images   = if ($script:RootImageContainerCount) { $script:RootImageContainerCount } else { 0 }
}

$script:SectionDetails['ROOT'] = @{
    Modified = $modifiedFiles.Keys
    Extra    = $extraFiles
    Missing  = $missingFiles
}





$greenFiles += if ($greenRoot -gt 0) { "Root: $greenRoot low threat" } else { $null }
$yellowFiles += if ($yellowRoot -gt 0) { "Root: $yellowRoot medium" } else { $null }
$redFiles += if ($redRoot -gt 0) { "Root: $redRoot high threat" } else { $null }

# Internal image summaries (BOOT / INSTALL) after ROOT analysis
if ($DeepScanWIM) {
    foreach ($phase in 'BOOT','INSTALL') {
        # Pretty per-phase section at the end
        Write-Log "$phase (Internal image) Analysis" -NoTimestamp -Level "IMPORTANT" -Header -Context "OPERATION"

        if ($script:ScanSummary.ContainsKey($phase)) {
            $s = $script:ScanSummary[$phase]

            $threat =
                if ($s.Red -gt 0) { 'RED' }
                elseif ($s.Yellow -gt 0) { 'YELLOW' }
                else { 'GREEN' }

            $logLevel =
                if ($threat -eq 'RED') { 'RED' }
                elseif ($threat -eq 'YELLOW') { 'WARNING' }
                else { 'GREEN' }

            if (($s.Modified + $s.Extra + $s.Missing) -eq 0) {
                Write-Log "Internal ${phase}: No differences between ISO and USB." -Level "GREEN" -Context $phase
            } else {
                Write-Log "Internal ${phase}: Modified $($s.Modified), Extra $($s.Extra), Missing $($s.Missing)." -Level "INFO" -Context $phase
                Write-Log "Internal $phase threat: $threat (Green=$($s.Green), Yellow=$($s.Yellow), Red=$($s.Red))." -Level $logLevel -Context $phase
            }
        } else {
            Write-Log "Internal $phase image not scanned (missing WIM/ESD/SWM or deep scan failed)." -Level "WARNING" -Context $phase
        }
    }
} else {
    Write-Log "Deep internal image scanning (BOOT/INSTALL) was not enabled. Use -DeepScanWIM for full WIM/ESD/SWM comparison." -Level "IMPORTANT" -Context "OPERATION"
}


# Structured summary
Write-FinalSummary -RedItems $redFiles -YellowItems $yellowFiles -GreenItems $greenFiles -MissingRootCount $missingFiles.Count

# Clean up iso mounts
Dismount-ISO -Quiet
# ===== MAIN BODY END =====
}
catch [System.OperationCanceledException] {
    Write-Log "Scan cancelled by user (Ctrl+C). Attempting cleanup..." -Level "WARNING"

    try { Dismount-ISO -Quiet } catch {}
    try { Clean-TempMounts } catch {}

    Write-Log "Cleanup after cancellation complete." -Level "INFO"
}
catch {
    Write-Log "Fatal error: $($_.Exception.Message)" -Level "RED"
    Write-Log $_.Exception.ToString() -Level "RED"

    try { Dismount-ISO -Quiet } catch {}
    try { Clean-TempMounts } catch {}
}
finally {
    [Console]::TreatControlCAsInput = $false
}