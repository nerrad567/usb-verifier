# buildstruc.ps1
# Build MockISO1 / MockISO2 / MockUSB under this repo folder
# using shrunk_install.wim/esd/swm stored here.

# Base = folder that this script lives in
$base     = $PSScriptRoot
$mockISO1 = Join-Path $base 'MockISO1'
$mockISO2 = Join-Path $base 'MockISO2'
$mockUSB  = Join-Path $base 'MockUSB'

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

# Skeleton dirs
foreach ($root in @($mockISO1, $mockISO2, $mockUSB)) {
    foreach ($sub in @('', 'boot', 'efi\microsoft\boot', 'sources', 'support\logging')) {
        $path = if ($sub) { Join-Path $root $sub } else { $root }
        New-Dir $path
    }
}

New-Dir (Join-Path $mockISO2 '__chunk_data')
New-Dir (Join-Path $mockUSB  '__chunk_data')

# =========================================================
# MockISO1 : "official" ISO (install.wim)
# =========================================================

Copy-Item $shrunkWim (Join-Path $mockISO1 'sources\boot.wim')    -Force
Copy-Item $shrunkWim (Join-Path $mockISO1 'sources\install.wim') -Force

Copy-Item $realExe (Join-Path $mockISO1 'setup.exe')         -Force
Copy-Item $realExe (Join-Path $mockISO1 'sources\setup.exe') -Force

New-TextFile (Join-Path $mockISO1 'autorun.inf')      "[autorun]`nlabel=MockISO1"
New-TextFile (Join-Path $mockISO1 'bootmgr')          "MOCK BOOTMGR"
New-TextFile (Join-Path $mockISO1 'bootmgr.efi')      "MOCK BOOTMGR EFI"
New-TextFile (Join-Path $mockISO1 'boot\bcd')         "MOCK BCD"
New-TextFile (Join-Path $mockISO1 'efi\microsoft\boot\bootmgfw.efi') "MOCK EFI BOOT"

New-TextFile (Join-Path $mockISO1 'sources\offline.xml') '<root>ISO1</root>'
New-TextFile (Join-Path $mockISO1 'sources\ISO_only.txt') 'Only in ISO1'

# =========================================================
# MockISO2 : "MCT" ISO (install.esd + __chunk_data)
# =========================================================

Copy-Item $shrunkWim (Join-Path $mockISO2 'sources\boot.wim')    -Force
Copy-Item $shrunkEsd (Join-Path $mockISO2 'sources\install.esd') -Force

Copy-Item $realExe (Join-Path $mockISO2 'setup.exe')         -Force
Copy-Item $realExe (Join-Path $mockISO2 'sources\setup.exe') -Force

New-TextFile (Join-Path $mockISO2 'autorun.inf')      "[autorun]`nlabel=MockISO2"
New-TextFile (Join-Path $mockISO2 'bootmgr')          "MOCK BOOTMGR"
New-TextFile (Join-Path $mockISO2 'bootmgr.efi')      "MOCK BOOTMGR EFI"
New-TextFile (Join-Path $mockISO2 'boot\bcd')         "MOCK BCD"
New-TextFile (Join-Path $mockISO2 'efi\microsoft\boot\bootmgfw.efi') "MOCK EFI BOOT"

New-TextFile (Join-Path $mockISO2 '__chunk_data\chunk1.bin') 'MCT ISO chunk'
New-TextFile (Join-Path $mockISO2 'sources\offline.xml') '<root>ISO2</root>'

# =========================================================
# MockUSB : "MCT" USB (split SWM + __chunk_data)
# =========================================================

Copy-Item $shrunkWim  (Join-Path $mockUSB 'sources\boot.wim')       -Force
Copy-Item $shrunkSwm1 (Join-Path $mockUSB 'sources\install.swm')    -Force
Copy-Item $shrunkSwm2 (Join-Path $mockUSB 'sources\install2.swm')   -Force

Copy-Item $realExe (Join-Path $mockUSB 'setup.exe')         -Force
Copy-Item $realExe (Join-Path $mockUSB 'sources\setup.exe') -Force

New-TextFile (Join-Path $mockUSB 'autorun.inf')      "[autorun]`nlabel=MockUSB"
New-TextFile (Join-Path $mockUSB 'bootmgr')          "MOCK BOOTMGR"
New-TextFile (Join-Path $mockUSB 'bootmgr.efi')      "MOCK BOOTMGR EFI"
New-TextFile (Join-Path $mockUSB 'boot\bcd')         "MOCK BCD"
New-TextFile (Join-Path $mockUSB 'efi\microsoft\boot\bootmgfw.efi') "MOCK EFI BOOT"

New-TextFile (Join-Path $mockUSB '__chunk_data\chunk1.bin') 'MCT USB chunk'
New-TextFile (Join-Path $mockUSB 'sources\offline.xml') '<root>USB</root>'
New-TextFile (Join-Path $mockUSB 'sources\USB_only.txt') 'Only in USB'

Write-Host "MockISO1, MockISO2, MockUSB structure built OK under $base." -ForegroundColor Green

