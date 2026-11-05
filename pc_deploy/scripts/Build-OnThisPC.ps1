param([switch]$LibraryOnly, [switch]$NonInteractive, [switch]$NoOpen)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Find-LocalMediaAssets {
    param([string]$AssetRoot)
    $result=@{}
    # Inspect only the dedicated PE workspace, never recursively scan local disks.
    $roots=@()
    if (Test-Path -LiteralPath $AssetRoot -PathType Container) {
        $roots=@(Get-Item -LiteralPath $AssetRoot)+@(Get-ChildItem -LiteralPath $AssetRoot -Directory | Sort-Object LastWriteTime -Descending)
    }
    foreach ($root in $roots) {
        if (-not $result.ContainsKey('template_directory')) {
            foreach ($media in @((Join-Path $root.FullName 'Media'),$root.FullName)) {
                foreach ($relative in @('sources\boot.wim','WEPE\WEPE64.WIM')) {
                    if (Test-Path -LiteralPath (Join-Path $media $relative) -PathType Leaf) {
                        $result.template_directory=$media; $result.wim_relative=$relative; break
                    }
                }
                if ($result.ContainsKey('template_directory')) { break }
            }
        }
        foreach ($prefix in @($root.FullName,(Join-Path $root.FullName 'Package'))) {
            $tools=Join-Path $prefix 'Tools\oscdimg.exe'
            $bios=Join-Path $prefix 'Boot\bios.img'
            $uefi=Join-Path $prefix 'Boot\uefi.img'
            if (-not $result.ContainsKey('oscdimg_path') -and (Test-Path -LiteralPath $tools -PathType Leaf)) { $result.oscdimg_path=$tools }
            if (-not $result.ContainsKey('bios_boot_path') -and (Test-Path -LiteralPath $bios -PathType Leaf)) { $result.bios_boot_path=$bios }
            if (-not $result.ContainsKey('uefi_boot_path') -and (Test-Path -LiteralPath $uefi -PathType Leaf)) { $result.uefi_boot_path=$uefi }
        }
        $drivers=Join-Path $root.FullName 'Drivers'
        if (-not $result.ContainsKey('driver_directory') -and (Test-Path -LiteralPath $drivers -PathType Container)) { $result.driver_directory=$drivers }
    }
    $adk=Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Windows Kits\10\Assessment and Deployment Kit'
    foreach ($entry in @{
        oscdimg_path='Deployment Tools\amd64\Oscdimg\oscdimg.exe'
        bios_boot_path='Windows Preinstallation Environment\amd64\Media\Boot\etfsboot.com'
        uefi_boot_path='Windows Preinstallation Environment\amd64\Media\EFI\Microsoft\Boot\efisys.bin'
    }.GetEnumerator()) {
        $candidate=Join-Path $adk $entry.Value
        if (-not $result.ContainsKey($entry.Key) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { $result[$entry.Key]=$candidate }
    }
    return $result
}
function Assert-LocalMediaAssets {
    param([hashtable]$Settings, [string]$WorkRoot)
    foreach ($name in @('template_directory','wim_relative','oscdimg_path','bios_boot_path','uefi_boot_path')) {
        if (-not $Settings.ContainsKey($name) -or -not $Settings[$name]) { throw "Missing local PE component: $name" }
    }
    if ($Settings.wim_relative -notin @('sources\boot.wim','WEPE\WEPE64.WIM')) { throw 'Unsupported WIM location in template.' }
    foreach ($path in @((Join-Path $Settings.template_directory $Settings.wim_relative),$Settings.oscdimg_path,$Settings.bios_boot_path,$Settings.uefi_boot_path)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file missing: $path" }
    }
    $workPrefix=[IO.Path]::GetFullPath($WorkRoot).TrimEnd('\')+'\'
    foreach ($path in @($Settings.template_directory,$Settings.driver_directory)) {
        if (-not $path) { continue }
        $prefix=[IO.Path]::GetFullPath($path).TrimEnd('\')+'\'
        if ($prefix.StartsWith($workPrefix,[StringComparison]::OrdinalIgnoreCase) -or $workPrefix.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'Build output must not overlap the PE template or driver directory.'
        }
    }
    $signature=Get-AuthenticodeSignature -LiteralPath $Settings.oscdimg_path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
        throw 'Please select oscdimg.exe with a valid Microsoft signature.'
    }
}
function Select-LocalMediaPath {
    param([string]$Title,[switch]$Folder,[string]$Filter='All files|*.*',[switch]$Optional)
    Add-Type -AssemblyName System.Windows.Forms
    if ($Folder) {
        $dialog=[Windows.Forms.FolderBrowserDialog]::new()
        $dialog.Description=$Title; $dialog.UseDescriptionForTitle=$true
    } else {
        $dialog=[Windows.Forms.OpenFileDialog]::new()
        $dialog.Title=$Title; $dialog.Filter=$Filter; $dialog.CheckFileExists=$true
    }
    try {
        if ($dialog.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) {
            if ($Folder) { return $dialog.SelectedPath }; return $dialog.FileName
        }
        if ($Optional) { return '' }
        throw 'Cancelled. No ISO was built and no disk was changed.'
    } finally { $dialog.Dispose() }
}
if ($LibraryOnly) { return }
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Install PowerShell 7, then double-click Start-Build.cmd again.' }
$administrator=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $administrator) {
    if ($NonInteractive) { throw 'Building WinPE requires administrator permission.' }
    $entry=$PSCommandPath.Replace("'","''")
    $command="& '$entry'"
    if ($NoOpen) { $command+=' -NoOpen' }
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $process=Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList "-NoProfile -STA -ExecutionPolicy Bypass -EncodedCommand $encoded" -Verb RunAs -Wait -PassThru
    exit $process.ExitCode
}
$exitCode=0
try {
    foreach ($name in @('config.json','Deploy-Agent.ps1','Start.ps1','DeviceInfo.ps1','Build-LocalMedia.ps1')) {
        if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $name) -PathType Leaf)) { throw "Extract the complete downloaded ZIP first. Missing: $name" }
    }
    $config=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $profileDirectory=Join-Path $env:LOCALAPPDATA 'PCDeploy'
    $profilePath=Join-Path $profileDirectory 'local-media-settings.json'
    $settings=Find-LocalMediaAssets (Join-Path $env:SystemDrive 'PEWork')
    foreach ($candidate in @($profilePath,(Join-Path $PSScriptRoot 'local-media-settings.json'))) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $saved=Get-Content -LiteralPath $candidate -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable
            foreach ($name in @('template_directory','wim_relative','oscdimg_path','bios_boot_path','uefi_boot_path','driver_directory')) {
                if ($saved.ContainsKey($name)) { $settings[$name]=$saved[$name] }
            }
        }
    }
    if (-not $settings.ContainsKey('driver_directory')) { $settings.driver_directory='' }
    if (-not $NonInteractive) {
        if (-not $settings.ContainsKey('template_directory') -or -not (Test-Path -LiteralPath (Join-Path $settings.template_directory $settings.wim_relative))) {
            $settings.template_directory=Select-LocalMediaPath '首次选择已有的完整 PE Media 文件夹；以后自动复用' -Folder
            $settings.wim_relative=@('sources\boot.wim','WEPE\WEPE64.WIM') | Where-Object { Test-Path -LiteralPath (Join-Path $settings.template_directory $_) } | Select-Object -First 1
        }
        foreach ($entry in @{
            oscdimg_path=@('选择微软 oscdimg.exe','oscdimg.exe|oscdimg.exe')
            bios_boot_path=@('选择 BIOS 引导文件','BIOS boot|etfsboot.com;*.img')
            uefi_boot_path=@('选择 UEFI 引导文件','UEFI boot|efisys.bin;*.img')
        }.GetEnumerator()) {
            if (-not $settings.ContainsKey($entry.Key) -or -not (Test-Path -LiteralPath $settings[$entry.Key] -PathType Leaf)) {
                $settings[$entry.Key]=Select-LocalMediaPath $entry.Value[0] -Filter $entry.Value[1]
            }
        }
        if ($config.include_drivers -and (-not $settings.driver_directory -or -not (Test-Path -LiteralPath $settings.driver_directory))) {
            $settings.driver_directory=Select-LocalMediaPath '可选：额外的签名网卡驱动目录；取消则保留 PE 原有驱动' -Folder -Optional
        }
    }
    $workRoot=Join-Path $PSScriptRoot 'Builds'
    Assert-LocalMediaAssets $settings $workRoot
    if (-not (Test-Path -LiteralPath $profileDirectory)) { New-Item -ItemType Directory -Path $profileDirectory | Out-Null }
    [IO.File]::WriteAllText($profilePath,($settings | ConvertTo-Json),[Text.Encoding]::UTF8)
    $settings.include_drivers=[bool]$config.include_drivers
    $job=Join-Path $workRoot ((Get-Date -Format 'yyyyMMdd_HHmmss')+'_'+[Guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $job | Out-Null
    foreach ($name in @('config.json','Deploy-Agent.ps1','Start.ps1','DeviceInfo.ps1')) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $job $name) }
    [IO.File]::WriteAllText((Join-Path $job 'local-build.json'),($settings | ConvertTo-Json),[Text.Encoding]::UTF8)
    $log=Join-Path $job 'build.log'
    Write-Host 'Building on this computer. No registration, background service or USB write is required.'
    & (Join-Path $PSScriptRoot 'Build-LocalMedia.ps1') -JobDirectory $job *>&1 | Tee-Object -FilePath $log
    $iso=Join-Path $job 'pc-deploy.iso'
    if (-not (Test-Path -LiteralPath $iso -PathType Leaf)) { throw "ISO missing. Check: $log" }
    Write-Host ('ISO created: '+$iso) -ForegroundColor Green
    if (-not $NoOpen) { Start-Process explorer.exe -ArgumentList ('/select,"'+$iso+'"') | Out-Null }
} catch {
    $exitCode=1
    Write-Host $_.Exception.Message -ForegroundColor Red
} finally {
    if (-not $NonInteractive) { $null=Read-Host 'Press Enter to close' }
}
exit $exitCode
