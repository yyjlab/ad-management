param([string]$InstallationDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Open an administrator PowerShell 7 terminal (pwsh).' }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this installer as administrator.' }
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Security
function Select-BuildFolder([string]$Title, [bool]$Optional=$false) {
    $d = [Windows.Forms.FolderBrowserDialog]::new()
    $d.Description = $Title
    $d.UseDescriptionForTitle = $true
    try {
        if ($d.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) { return $d.SelectedPath }
        if ($Optional) { return '' }
        throw 'Installation cancelled. No scheduled task was installed.'
    } finally { $d.Dispose() }
}
function Select-BuildFile([string]$Title, [string]$Filter) {
    $d = [Windows.Forms.OpenFileDialog]::new()
    $d.Title=$Title; $d.Filter=$Filter; $d.CheckFileExists=$true
    try {
        if ($d.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) { return $d.FileName }
        throw 'Installation cancelled. No scheduled task was installed.'
    } finally { $d.Dispose() }
}
$registration = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'builder-registration.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ([string]$registration.builder_id -notmatch '^[a-f0-9-]{36}$') { throw 'Invalid builder registration.' }
$server = [Uri]$registration.server_url
if ($server.Scheme -notin @('http','https') -or $server.UserInfo -or $server.Query -or $server.Fragment) { throw 'Invalid platform URL.' }
$template = Select-BuildFolder '选择已验证可联网且包含 PowerShell 的 PE Media 文件夹（内有 sources\boot.wim 或 WEPE\WEPE64.WIM）'
$wimRelative = @('sources\boot.wim','WEPE\WEPE64.WIM') | Where-Object { Test-Path -LiteralPath (Join-Path $template $_) } | Select-Object -First 1
if (-not $wimRelative) { throw 'No supported PE WIM in this Media directory.' }
$oscdimg = Select-BuildFile '选择微软 oscdimg.exe（ADK 部署工具或已保存的 Tools 文件夹）' 'oscdimg.exe|oscdimg.exe'
$signature = Get-AuthenticodeSignature -LiteralPath $oscdimg
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft') { throw 'oscdimg must have a valid Microsoft signature.' }
$bios = Select-BuildFile '选择 BIOS 引导文件：etfsboot.com 或 bios.img' 'BIOS 引导文件|etfsboot.com;*.img|所有文件|*.*'
$uefi = Select-BuildFile '选择 UEFI 引导文件：efisys.bin 或 uefi.img' 'UEFI 引导文件|efisys.bin;*.img|所有文件|*.*'
$drivers = Select-BuildFolder '可选：选择签名 INF 驱动文件夹；取消则使用 PE 已有驱动' $true
if ($drivers -and -not (Get-ChildItem -LiteralPath $drivers -Filter '*.inf' -Recurse -File | Select-Object -First 1)) { throw 'Driver directory contains no INF files.' }
if (-not $InstallationDirectory) { $InstallationDirectory = Join-Path $env:LOCALAPPDATA ('PCDeployBuilder\' + $registration.builder_id) }
$destination = [IO.Path]::GetFullPath($InstallationDirectory)
$prefix = $destination.TrimEnd('\') + '\'
foreach ($source in @($template,$oscdimg,$bios,$uefi,$drivers,$PSScriptRoot)) {
    if ($source) {
        $sourcePrefix = [IO.Path]::GetFullPath($source).TrimEnd('\') + '\'
        if ($sourcePrefix.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or
            $prefix.StartsWith($sourcePrefix,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'Installation directory must not overlap a selected source.'
        }
    }
}
if (Test-Path -LiteralPath $destination) { throw 'Choose a new dedicated installation directory; nothing will be overwritten.' }
$taskName = 'PCDeploy-ISO-' + $registration.builder_id.Substring(0,8)
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Builder task already exists.' }
New-Item -ItemType Directory -Path $destination | Out-Null
# This directory contains protected worker credentials and PE enrollment packages.
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
$current = [Security.Principal.WindowsIdentity]::GetCurrent()
foreach ($sid in @($current.User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
Set-Acl -LiteralPath $destination -AclObject $acl
foreach ($name in @('Start-Builder.ps1','Build-LocalMedia.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $destination $name)
}
$protected = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($registration.token),
    $null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
$config = @{
    builder_id=$registration.builder_id; server_url=$registration.server_url
    protected_token=[Convert]::ToBase64String($protected)
    template_directory=$template; wim_relative=$wimRelative; oscdimg_path=$oscdimg
    bios_boot_path=$bios; uefi_boot_path=$uefi; driver_directory=$drivers
    work_root=(Join-Path $destination 'Builds')
}
$configPath = Join-Path $destination 'builder.json'
[IO.File]::WriteAllText($configPath,($config | ConvertTo-Json),[Text.Encoding]::UTF8)
New-Item -ItemType Directory -Path $config.work_root | Out-Null
# EncodedCommand avoids command-line quoting ambiguity with the chosen local path.
$escaped = $configPath.Replace("'","''")
$workerPath = (Join-Path $destination 'Start-Builder.ps1').Replace("'","''")
$command = "& '$workerPath' -ConfigurationPath '$escaped'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
$action = New-ScheduledTaskAction -Execute (Get-Process -Id $PID).Path -Argument "-NoProfile -WindowStyle Hidden -EncodedCommand $encoded"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $current.Name
$principal = New-ScheduledTaskPrincipal -UserId $current.Name -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "Installed: $taskName. Keep this PC on and logged in, then use One-click ISO in the web page."
Write-Host "No USB, physical disk, domain policy, DHCP or existing scheduled task was modified."
