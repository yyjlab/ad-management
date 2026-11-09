param([Parameter(Mandatory)][string]$WorkDirectory, [string]$DriverDirectory, [switch]$RegistrationOnly)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run in an elevated Deployment and Imaging Tools Environment.' }
if (-not (Get-Command copype.cmd -ErrorAction SilentlyContinue)) {
    throw 'Install Microsoft ADK Deployment Tools and matching WinPE add-on, then open Deployment and Imaging Tools Environment.'
}
$work = [IO.Path]::GetFullPath($WorkDirectory)
if ([IO.Directory]::Exists($work) -or [IO.File]::Exists($work) -or $work.Length -lt 10) {
    throw 'WorkDirectory must be a new dedicated folder. Existing folders are never overwritten or deleted.'
}
foreach ($name in @('config.json', 'Deploy-Agent.ps1', 'Start.ps1', 'DeviceInfo.ps1', 'HardwareInfo.ps1')) {
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $name))) { throw "Missing bootstrap package file: $name" }
}
$oc = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs'
$packages = @('WinPE-WMI','WinPE-NetFX','WinPE-Scripting','WinPE-PowerShell','WinPE-StorageWMI',
              'WinPE-DismCmdlets','WinPE-SecureStartup','WinPE-SecureBootCmdlets')
foreach ($package in $packages) {
    if (-not (Test-Path -LiteralPath (Join-Path $oc ($package + '.cab')))) { throw "Missing ADK component: $package" }
}
& copype.cmd amd64 $work
if ($LASTEXITCODE -ne 0) { throw 'copype failed.' }
$mount = Join-Path $work 'mount'
$wim = Join-Path $work 'media\sources\boot.wim'
$mounted = $false
try {
    & dism.exe /Mount-Image "/ImageFile:$wim" /Index:1 "/MountDir:$mount"
    if ($LASTEXITCODE -ne 0) { throw 'Mount failed.' }
    $mounted = $true
    foreach ($package in $packages) {
        $cab = Join-Path $oc ($package + '.cab')
        & dism.exe "/Image:$mount" /Add-Package "/PackagePath:$cab"
        if ($LASTEXITCODE -ne 0) { throw "Adding $package failed." }
        $english = Join-Path $oc ('en-us\' + $package + '_en-us.cab')
        if (Test-Path -LiteralPath $english) {
            & dism.exe "/Image:$mount" /Add-Package "/PackagePath:$english"
            if ($LASTEXITCODE -ne 0) { throw 'Adding language resources failed.' }
        }
    }
    if ($DriverDirectory) {
        $drivers = (Resolve-Path -LiteralPath $DriverDirectory).Path
        & dism.exe "/Image:$mount" /Add-Driver "/Driver:$drivers" /Recurse
        if ($LASTEXITCODE -ne 0) { throw 'Adding signed network/storage drivers failed.' }
    }
    $dest = Join-Path $mount 'PCDeploy'
    New-Item -ItemType Directory -Path $dest | Out-Null
    foreach ($name in @('config.json', 'Deploy-Agent.ps1', 'Start.ps1', 'DeviceInfo.ps1', 'HardwareInfo.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $dest $name)
    }
    if ($RegistrationOnly) {
        $configPath = Join-Path $dest 'config.json'
        $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $config | Add-Member -NotePropertyName registration_only -NotePropertyValue $true -Force
        [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 8), [Text.Encoding]::UTF8)
    }
    $startup = "@echo off`r`nwpeinit`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\PCDeploy\Start.ps1`r`npause`r`n"
    [IO.File]::WriteAllText((Join-Path $mount 'Windows\System32\startnet.cmd'), $startup, [Text.Encoding]::ASCII)
    & dism.exe /Unmount-Image "/MountDir:$mount" /Commit
    if ($LASTEXITCODE -ne 0) { throw 'Saving WinPE failed.' }
    $mounted = $false
    & MakeWinPEMedia.cmd /ISO $work (Join-Path $work 'pc-deploy-winpe.iso')
    if ($LASTEXITCODE -ne 0) { throw 'ISO creation failed.' }
    Write-Host ('Created: ' + (Join-Path $work 'pc-deploy-winpe.iso'))
    Write-Host 'Copy the ISO into your existing Ventoy USB, or publish boot.wim through your approved iPXE service.'
    Write-Host 'No USB, physical disk, DHCP server or firmware setting was changed.'
} finally {
    if ($mounted) { & dism.exe /Unmount-Image "/MountDir:$mount" /Discard | Out-Null }
}
