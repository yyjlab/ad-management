param([Parameter(Mandatory)][string]$JobDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Set-BuildStage([string]$Stage) {
    [IO.File]::WriteAllText((Join-Path $JobDirectory 'stage.txt'), $Stage, [Text.Encoding]::UTF8)
}
function Invoke-BuildTool([string]$Tool, [string[]]$ToolArguments) {
    & $Tool @ToolArguments
    if ($LASTEXITCODE -ne 0) { throw "Build tool failed: $([IO.Path]::GetFileName($Tool)) ($LASTEXITCODE)" }
}
$job = [IO.Path]::GetFullPath($JobDirectory)
$settings = Get-Content -LiteralPath (Join-Path $job 'local-build.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$media = Join-Path $job 'Media'
$mount = Join-Path $job 'Mount'
if (Test-Path -LiteralPath $media) { throw 'The job directory already contains Media. It will not be overwritten.' }
New-Item -ItemType Directory -Path $media, $mount | Out-Null
$mounted = $false
try {
    Set-BuildStage '准备 PE 文件'
    # Reject links rather than copying files outside the explicitly selected template.
    if (Get-ChildItem -LiteralPath $settings.template_directory -Recurse -Force |
        Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { throw 'Template must not contain links.' }
    Get-ChildItem -LiteralPath $settings.template_directory -Force | Copy-Item -Destination $media -Recurse
    $wim = Join-Path $media $settings.wim_relative
    Set-BuildStage '注入客户端和驱动'
    Invoke-BuildTool dism.exe @('/Mount-Image', "/ImageFile:$wim", '/Index:1', "/MountDir:$mount")
    $mounted = $true
    if (-not (Test-Path -LiteralPath (Join-Path $mount 'Windows\System32\WindowsPowerShell\v1.0\powershell.exe'))) {
        throw 'Template lacks WinPE PowerShell. Use the previously verified full WinPE template.'
    }
    if ($settings.include_drivers -and $settings.driver_directory) {
        Invoke-BuildTool dism.exe @("/Image:$mount", '/Add-Driver', "/Driver:$($settings.driver_directory)", '/Recurse')
    }
    $dest = Join-Path $mount 'PCDeploy'
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    foreach ($name in @('config.json', 'Deploy-Agent.ps1', 'Start.ps1', 'DeviceInfo.ps1')) {
        Copy-Item -LiteralPath (Join-Path $job $name) -Destination (Join-Path $dest $name) -Force
    }
    $startup = "@echo off" + [Environment]::NewLine + "wpeinit" + [Environment]::NewLine +
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\PCDeploy\Start.ps1" + [Environment]::NewLine +
        "pause" + [Environment]::NewLine
    [IO.File]::WriteAllText((Join-Path $mount 'Windows\System32\startnet.cmd'), $startup, [Text.Encoding]::ASCII)
    Invoke-BuildTool dism.exe @('/Unmount-Image', "/MountDir:$mount", '/Commit')
    $mounted = $false
    Set-BuildStage '生成 ISO'
    $iso = Join-Path $job 'pc-deploy.iso'
    Invoke-BuildTool $settings.oscdimg_path @('-m', '-o', '-n', '-d', '-lPCDEPLOY',
        "-bootdata:2#p0,e,b$($settings.bios_boot_path)#pEF,e,b$($settings.uefi_boot_path)", $media, $iso)
    if (-not (Test-Path -LiteralPath $iso)) { throw 'ISO was not produced.' }
} finally {
    if ($mounted) {
        & dism.exe /Unmount-Image "/MountDir:$mount" /Discard | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Warning "Mount cleanup failed. Check only this mount: $mount" }
    }
}
