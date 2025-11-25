# buildstruc.ps1
# Build MockISO1 / MockISO2 / MockUSB / MockISO2a_IDEN / MockUSB2a_IDEN
# using shrunk_install.wim/esd/swm stored here.

# Base = folder that this script lives in
$base          = $PSScriptRoot
$mockISO1      = Join-Path $base 'MockISO1'
$mockISO2      = Join-Path $base 'MockISO2'
$mockUSB       = Join-Path $base 'MockUSB'
$mockISO2Iden  = Join-Path $base 'MockISO2a_IDEN'
$mockUSBIden   = Join-Path $base 'MockUSB2a_IDEN'

$shrunkWim   = Join-Path $base 'shrunk_install.wim'
$shrunkSwm1  = Join-Path $base 'shrunk_install.swm'
$shrunkSwm2  = Join-Path $base 'shrunk_install2.swm'
$shrunkEsd   = Join-Path $base 'shrunk_install.esd'

function New-Dir {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function New-TextFile {
    param(
        [string]$Path,
        [string]$Content
    )
    $dir = Split-Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) {
        New-Dir $dir
    }
    if (Test-Path $Path -PathType Container) {
        Remove-Item $Path -Recurse -Force
    }
    Set-Content -Path $Path -Value $Content -Encoding ASCII
}

# Sanity checks
foreach ($p in @($shrunkWim, $shrunkSwm1, $shrunkSwm2, $shrunkEsd)) {
    if (-not (Test-Path $p -PathType Leaf)) {
        throw "Required image file not found: $p"
    }
}

$realExe = Join-Path $env:windir 'System32\notepad.exe'
if (-not (Test-Path $realExe -PathType Leaf)) {
    throw "Couldn't find notepad.exe at $realExe"
}

# Optional: clean any old mock trees so we always get a fresh state
foreach ($root in @($mockISO1, $mockISO2, $mockUSB, $mockISO2Iden, $mockUSBIden)) {
    if (Test-Path $root) {
        Remove-Item $root -Recurse -Force
    }
}

# Skeleton dirs
foreach ($root in @($mockISO1, $mockISO2, $mockUSB, $mockISO2Iden, $mockUSBIden)) {
    foreach ($sub in @('', 'boot', 'efi\microsoft\boot', 'sources', 'support\logging')) {
        $path = if ($sub) { Join-Path $root $sub } else { $root }
        New-Dir $path
    }
}

New-Dir (Join-Path $mockISO2 '__chunk_data')
New-Dir (Join-Path $mockUSB  '__chunk_data')
New-Dir (Join-Path $mockISO2Iden '__chunk_data')
New-Dir (Join-Path $mockUSBIden  '__chunk_data')

function Init-CommonBootFiles {
    param(
        [string]$Root,
        [string]$Label
    )
    New-TextFile (Join-Path $Root 'autorun.inf') "[autorun]`nlabel=$Label"
    New-TextFile (Join-Path $Root 'bootmgr')          "MOCK BOOTMGR"
    New-TextFile (Join-Path $Root 'bootmgr.efi')      "MOCK BOOTMGR EFI"
    New-TextFile (Join-Path $Root 'boot\bcd')         "MOCK BCD"
    New-TextFile (Join-Path $Root 'efi\microsoft\boot\bootmgfw.efi') "MOCK EFI BOOT"

    Copy-Item $realExe (Join-Path $Root 'setup.exe')         -Force
    Copy-Item $realExe (Join-Path $Root 'sources\setup.exe') -Force
}

# =========================================================
# MockISO1 : "official" ISO (install.wim)
# =========================================================

Init-CommonBootFiles -Root $mockISO1 -Label 'MockISO1'

Copy-Item $shrunkWim (Join-Path $mockISO1 'sources\boot.wim')    -Force
Copy-Item $shrunkWim (Join-Path $mockISO1 'sources\install.wim') -Force

New-TextFile (Join-Path $mockISO1 'sources\offline.xml') '<root>ISO1</root>'
New-TextFile (Join-Path $mockISO1 'sources\ISO_only.txt') 'Only in ISO1'

# =========================================================
# MockISO2 : "MCT" ISO (install.esd + __chunk_data)
# =========================================================

Init-CommonBootFiles -Root $mockISO2 -Label 'MockISO2'

Copy-Item $shrunkWim (Join-Path $mockISO2 'sources\boot.wim')    -Force
Copy-Item $shrunkEsd (Join-Path $mockISO2 'sources\install.esd') -Force

New-TextFile (Join-Path $mockISO2 'sources\offline.xml') '<root>ISO2</root>'
New-TextFile (Join-Path $mockISO2 '__chunk_data\chunk1.bin') 'MCT ISO chunk'

# =========================================================
# MockUSB : "MCT" USB (split SWM + __chunk_data)
# =========================================================

Init-CommonBootFiles -Root $mockUSB -Label 'MockUSB'

Copy-Item $shrunkWim  (Join-Path $mockUSB 'sources\boot.wim')     -Force
Copy-Item $shrunkSwm1 (Join-Path $mockUSB 'sources\install.swm')  -Force
Copy-Item $shrunkSwm2 (Join-Path $mockUSB 'sources\install2.swm') -Force

New-TextFile (Join-Path $mockUSB 'sources\offline.xml') '<root>USB</root>'
New-TextFile (Join-Path $mockUSB '__chunk_data\chunk1.bin') 'MCT USB chunk'
New-TextFile (Join-Path $mockUSB 'sources\USB_only.txt') 'Only in USB'

# =========================================================
# MockISO2a_IDEN / MockUSB2a_IDEN : fully identical pair
# =========================================================

$idenLabel   = 'MockMCT_IDEN'
$idenOffline = '<root>IDEN</root>'
$idenChunk   = 'IDEN CHUNK PAYLOAD'

# Common boot + setup, identical label on both sides
Init-CommonBootFiles -Root $mockISO2Iden -Label $idenLabel
Init-CommonBootFiles -Root $mockUSBIden  -Label $idenLabel

# Container images
# ISO side: MCT style (boot.wim + install.esd)
Copy-Item $shrunkWim (Join-Path $mockISO2Iden 'sources\boot.wim')    -Force
Copy-Item $shrunkEsd (Join-Path $mockISO2Iden 'sources\install.esd') -Force

# USB side: MCT USB style (boot.wim + split SWM)
Copy-Item $shrunkWim  (Join-Path $mockUSBIden 'sources\boot.wim')     -Force
Copy-Item $shrunkSwm1 (Join-Path $mockUSBIden 'sources\install.swm')  -Force
Copy-Item $shrunkSwm2 (Join-Path $mockUSBIden 'sources\install2.swm') -Force

# Identical metadata / chunks
New-TextFile (Join-Path $mockISO2Iden 'sources\offline.xml') $idenOffline
New-TextFile (Join-Path $mockUSBIden  'sources\offline.xml') $idenOffline

New-TextFile (Join-Path $mockISO2Iden '__chunk_data\chunk1.bin') $idenChunk
New-TextFile (Join-Path $mockUSBIden  '__chunk_data\chunk1.bin') $idenChunk

# IMPORTANT: no ISO_only.txt / USB_only.txt in IDEN pair

Write-Host "MockISO1, MockISO2, MockUSB, MockISO2a_IDEN, MockUSB2a_IDEN built OK under $base." -ForegroundColor Green
