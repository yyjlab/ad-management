param([string]$ConfigPath = "$PSScriptRoot\config.json", [switch]$LibraryOnly, [switch]$RegistrationOnly)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath "$PSScriptRoot\DeviceInfo.ps1") { . "$PSScriptRoot\DeviceInfo.ps1" }

function Assert-WinPE {
    if (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT')) {
        throw 'This agent may run only in Windows PE. No deployment action was performed.'
    }
    if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'Only x64 WinPE is supported.' }
}

function Assert-PlatformUrl {
    param([string]$Url, [bool]$AllowHttp = $false)
    $uri = [uri]$Url
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -notin @('http', 'https') -or
        ($uri.Scheme -eq 'http' -and -not $AllowHttp) -or $uri.UserInfo -or $uri.Query -or
        $uri.Fragment -or $uri.AbsolutePath -cne '/pc-deploy') {
        throw 'Use the approved HTTP/HTTPS deployment URL. HTTPS certificate validation remains enabled.'
    }
}

function Invoke-Platform {
    param([string]$Route, [string]$Token, $Data, [int]$TimeoutSec = 30)
    $json = ConvertTo-Json -InputObject $Data -Depth 16 -Compress
    Invoke-RestMethod -Uri ($script:Server + $Route) -Method Post -Headers @{Authorization="Bearer $Token"} `
        -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec $TimeoutSec
}

function Send-DeploymentProgress {
    param($Job, [string]$Token, [string]$Stage, [Nullable[int]]$Percent)
    # After one-time authorization, reporting must not interrupt local recovery of the target disk.
    $payload=@{stage=$Stage}
    if ($null -ne $Percent) { $payload.percent=[int]$Percent }
    try {
        Invoke-Platform "/api/agent/jobs/$($Job.id)/event" $Token $payload -TimeoutSec 3 | Out-Null
    } catch {
        # Do not expose the HTTP exception, which may contain credentials.
        Write-Host ("Progress report unavailable at {0}. Continuing the authorized local installation." -f $Stage) -ForegroundColor Yellow
    }
}

function Get-DeploymentFailureDetail {
    param([Management.Automation.ErrorRecord]$Failure, $Job, [string]$Token, $Config)
    $detail = 'Error: ' + $Failure.Exception.Message
    if ($Failure.InvocationInfo.MyCommand.Name) {
        $detail += [Environment]::NewLine + 'Command: ' + $Failure.InvocationInfo.MyCommand.Name
    }
    if ($Failure.InvocationInfo.ScriptLineNumber) {
        $detail += [Environment]::NewLine + 'Script line: ' + $Failure.InvocationInfo.ScriptLineNumber
    }
    if ($Failure.FullyQualifiedErrorId) {
        $detail += [Environment]::NewLine + 'Error ID: ' + $Failure.FullyQualifiedErrorId
    }
    if ($Failure.ScriptStackTrace) {
        $detail += [Environment]::NewLine + 'Stack: ' + $Failure.ScriptStackTrace
    }
    if ($Failure.ErrorDetails -and $Failure.ErrorDetails.Message) {
        $detail += [Environment]::NewLine + $Failure.ErrorDetails.Message
    }
    # Never include request bodies, credentials, or the original source-code line.
    foreach ($secret in @($Token, $Job.source_password, $Config.enrollment_token)) {
        if (-not [string]::IsNullOrEmpty([string]$secret)) {
            $detail = $detail.Replace([string]$secret, '[REDACTED]')
        }
    }
    if ($detail.Length -gt 8192) { $detail = $detail.Substring(0, 8160) + [Environment]::NewLine + '[Log truncated.]' }
    $detail
}

function Get-DeploymentUsbLogRoot {
    # Locate the Ventoy data partition by its USB disk and companion EFI volume.
    # Drive letters in PE can differ from those on the preparation computer.
    $roots = @()
    foreach ($disk in @(Get-Disk | Where-Object { [string]$_.BusType -eq 'USB' })) {
        try {
            $parts = @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop)
            $hasVentoy = $false
            $root = $null
            foreach ($part in $parts) {
                $volume = $null
                try { $volume = $part | Get-Volume -ErrorAction Stop } catch { continue }
                if ([string]$volume.FileSystemLabel -eq 'VTOYEFI') { $hasVentoy = $true }
                if ($part.PartitionNumber -eq 1 -and $part.DriveLetter -and
                    [string]$part.DriveLetter -ne 'X' -and [string]$volume.FileSystemLabel -ne 'VTOYEFI') {
                    $root = [string]$part.DriveLetter + ':\'
                }
            }
            if ($hasVentoy -and $root) { $roots += $root }
        } catch { continue }
    }
    $roots = @($roots | Select-Object -Unique)
    if ($roots.Count -eq 1) { $roots[0] }
}

function Save-DeploymentFailureLog {
    param([string]$Detail, [string]$Stage, [string]$LocalDirectory)
    $text = 'Time: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + [Environment]::NewLine +
        'Stage: ' + $Stage + [Environment]::NewLine + $Detail + [Environment]::NewLine + [Environment]::NewLine
    $encoding = New-Object Text.UTF8Encoding($false)
    $localPath = Join-Path $LocalDirectory 'deployment-error.txt'
    try { [IO.File]::WriteAllText($localPath, $text, $encoding) }
    catch { Write-Host 'Could not save the PE error log.' -ForegroundColor Yellow }
    try {
        $usbRoot = Get-DeploymentUsbLogRoot
        if ($usbRoot) {
            $usbPath = Join-Path $usbRoot 'error.log'
            [IO.File]::AppendAllText($usbPath, $text, $encoding)
            Write-Host ('USB error log: ' + $usbPath) -ForegroundColor Yellow
        } else {
            Write-Host 'No unique Ventoy USB data partition found. Error log remains in PE.' -ForegroundColor Yellow
        }
    } catch { Write-Host 'USB error log could not be saved. Error log remains in PE.' -ForegroundColor Yellow }
    Write-Host ('PE error log: ' + $localPath) -ForegroundColor Yellow
}

function Test-TransientPlatformFailure {
    param([Management.Automation.ErrorRecord]$Failure)
    $exception = $Failure.Exception
    $retry = $false
    $httpStatus = $null
    # Windows PE uses Windows PowerShell 5.1; development also tests PowerShell 7.
    for ($depth = 0; $exception -and $depth -lt 16; $depth++) {
        if ($exception -is [Security.Authentication.AuthenticationException]) { return $false }
        if ($exception.Response -and $exception.Response.StatusCode) {
            $httpStatus = [int]$exception.Response.StatusCode
        }
        if ($exception -is [Net.WebException]) {
            if ($exception.Status -in @([Net.WebExceptionStatus]::TrustFailure,
                                      [Net.WebExceptionStatus]::SecureChannelFailure)) { return $false }
            if ($exception.Status -in @([Net.WebExceptionStatus]::Timeout,
                    [Net.WebExceptionStatus]::ConnectFailure, [Net.WebExceptionStatus]::ConnectionClosed,
                    [Net.WebExceptionStatus]::NameResolutionFailure, [Net.WebExceptionStatus]::ProxyNameResolutionFailure,
                    [Net.WebExceptionStatus]::ReceiveFailure, [Net.WebExceptionStatus]::SendFailure,
                    [Net.WebExceptionStatus]::KeepAliveFailure)) { $retry = $true }
        }
        if ($exception.GetType().FullName -eq 'System.Net.Http.HttpRequestException') {
            if ([string]$exception.HttpRequestError -in @('SecureConnectionError','UserAuthenticationError','VersionNegotiationError')) {
                return $false
            }
            $retry = $true
        }
        if ($exception -is [TimeoutException] -or
            $exception -is [Net.Sockets.SocketException] -or
            $exception -is [Threading.Tasks.TaskCanceledException]) { $retry = $true }
        $exception = $exception.InnerException
    }
    if ($null -ne $httpStatus) { return $httpStatus -in @(408, 429, 500, 502, 503, 504) }
    return $retry
}

function Invoke-WaitingPlatform {
    param([string]$Route, [string]$Token, [scriptblock]$DataFactory)
    # Explicitly exclude installation authorization, events, completion, and every disk operation.
    if ($Route -cnotin @('/api/agent/register', '/api/agent/poll')) {
        throw 'Automatic reconnect is allowed only while registering or waiting for a task.'
    }
    $delay = 5
    $reconnecting = $false
    while ($true) {
        # Re-read hardware before each attempt; inventory errors are not network errors.
        $payload = & $DataFactory
        try {
            $response = Invoke-Platform $Route $Token $payload
            if ($reconnecting) { Write-Host 'Connection restored. Continuing to wait for operator approval.' -ForegroundColor Green }
            return $response
        } catch {
            if (-not (Test-TransientPlatformFailure $_)) { throw }
            Write-Host ("Platform temporarily unreachable. Reconnecting in {0}s; no installation is being retried. Ctrl+C to stop." -f $delay) -ForegroundColor Yellow
        }
        # Cancellation interrupts the wait. Keep it outside the request catch.
        Start-Sleep -Seconds $delay
        $reconnecting = $true
        $delay = [int][Math]::Min(30, $delay * 2)
    }
}

function Get-FirmwareDisplayText {
    param($Value)
    $text = ([string]$Value -replace '[\x00-\x1f\x7f]', ' ').Trim()
    if ($text.Length -gt 120) { $text = $text.Substring(0, 120) }
    $text
}

function Get-Inventory {
    param([string]$BootId)
    $computer = Get-CimInstance Win32_ComputerSystem
    $product = Get-CimInstance Win32_ComputerSystemProduct
    $bios = Get-CimInstance Win32_BIOS
    $firmwareValue = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType).PEFirmwareType
    $secureBoot, $tpm2 = $false, $false
    try { $secureBoot = [bool](Confirm-SecureBootUEFI) } catch { }
    try {
        $tpm = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm
        $tpm2 = [bool]($tpm.SpecVersion -match '^2\.0(?:,|$)')
    } catch { }
    $disks = @(Get-Disk | ForEach-Object {
        $physical = $_
        $parts = @()
        if ([string]$physical.PartitionStyle -eq 'GPT') {
            $parts = @(Get-Partition -DiskNumber $physical.Number | ForEach-Object {
                $part = $_
                $volume = $null
                try { $volume = $part | Get-Volume -ErrorAction Stop } catch { }
                $fs = [string]$volume.FileSystemType
                if ($fs -notin @('NTFS', 'FAT32')) { $fs = '' }
                $isWindows = $false
                if ($fs -eq 'NTFS' -and $volume.Path) {
                    $isWindows = Test-Path -LiteralPath (Join-Path $volume.Path 'Windows\System32\config\SYSTEM')
                }
                @{
                    number=[int]$part.PartitionNumber; guid=([string]$part.Guid).Trim('{}').ToLowerInvariant()
                    gpt_type=([string]$part.GptType).Trim('{}').ToLowerInvariant()
                    offset=[long]$part.Offset; size_bytes=[long]$part.Size
                    filesystem=$fs; windows=[bool]$isWindows
                }
            })
        }
        @{
            number = [int]$physical.Number; serial = ([string]$physical.SerialNumber).Trim()
            unique_id = ([string]$physical.UniqueId).Trim(); size_bytes = [long]$physical.Size
            bus = [string]$physical.BusType; model = [string]$physical.FriendlyName
            read_only = [bool]$physical.IsReadOnly; offline = [bool]$physical.IsOffline
            partitions = $parts
        }
    })
    $macs = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
        Where-Object MACAddress | ForEach-Object { [string]$_.MACAddress })
    $serial = ([string]$bios.SerialNumber).Trim()
    if (-not $serial) { $serial = 'Unknown' }
    $details = @{}
    try { if (Get-Command Get-DeploymentDeviceInfo -ErrorAction SilentlyContinue) { $details = Get-DeploymentDeviceInfo -Stage pe } } catch { }
    @{
        hardware_uuid = ([guid]$product.UUID).ToString().ToLowerInvariant(); boot_id = $BootId
        model = [string]$computer.Model; serial = $serial; architecture = 'amd64'
        manufacturer = Get-FirmwareDisplayText $computer.Manufacturer; system_family = Get-FirmwareDisplayText $computer.SystemFamily
        product_name = Get-FirmwareDisplayText $product.Name; product_version = Get-FirmwareDisplayText $product.Version
        firmware = $(if ($firmwareValue -eq 2) { 'UEFI' } else { 'BIOS' })
        secure_boot = $secureBoot; tpm2 = $tpm2
        ram_bytes = [long]$computer.TotalPhysicalMemory; macs = $macs; disks = $disks; wim_apply_v1 = $true
        system_info = $details
    }
}

function Select-VerifiedDisk {
    param($Disks, $Expected)
    $allowed = @('NVMe', 'SATA', 'SAS', 'SCSI', 'ATA', 'RAID')
    $matches = @($Disks | Where-Object {
        ([int]$_.number -eq [int]$Expected.number) -and
        ([string]$_.serial -ceq [string]$Expected.serial) -and
        ([string]$_.unique_id -ceq [string]$Expected.unique_id) -and
        ([long]$_.size_bytes -eq [long]$Expected.size_bytes) -and
        ([string]$_.bus -ceq [string]$Expected.bus)
    })
    if ($matches.Count -ne 1) { throw 'Target disk identity changed or is ambiguous.' }
    $disk = $matches[0]
    if ($allowed -cnotcontains [string]$disk.bus -or $disk.read_only -or $disk.offline -or
        -not ($disk.serial -or $disk.unique_id) -or [long]$disk.size_bytes -lt 64GB) {
        throw 'External, unknown, read-only or unidentified disks cannot be selected.'
    }
    $disk
}

function Select-VerifiedPartition {
    param($Partitions, $Expected)
    $matches = @($Partitions | Where-Object {
        [int]$_.number -eq [int]$Expected.number -and
        [string]$_.guid -ceq [string]$Expected.guid -and
        [string]$_.gpt_type -ceq [string]$Expected.gpt_type -and
        [long]$_.offset -eq [long]$Expected.offset -and
        [long]$_.size_bytes -eq [long]$Expected.size_bytes -and
        [string]$_.filesystem -ceq [string]$Expected.filesystem -and
        [bool]$_.windows -eq [bool]$Expected.windows
    })
    if ($matches.Count -ne 1) { throw 'Selected partition changed or is ambiguous.' }
    $matches[0]
}

function Get-VerifiedPartitionObject {
    param([int]$DiskNumber, $Expected)
    $actual = Get-Partition -DiskNumber $DiskNumber -PartitionNumber $Expected.number
    if ($actual.DiskNumber -ne $DiskNumber -or $actual.PartitionNumber -ne $Expected.number -or
        ([string]$actual.Guid).Trim('{}').ToLowerInvariant() -cne $Expected.guid -or
        ([string]$actual.GptType).Trim('{}').ToLowerInvariant() -cne $Expected.gpt_type -or
        [long]$actual.Offset -ne [long]$Expected.offset -or [long]$actual.Size -ne [long]$Expected.size_bytes -or
        $actual.IsReadOnly -or $actual.IsOffline) { throw 'Actual target partition no longer matches the approved identity.' }
    $actual
}

function Get-FreeDeploymentLetters {
    $used = @(Get-PSDrive -PSProvider FileSystem | ForEach-Object Name)
    $used += @(Get-Partition | Where-Object DriveLetter | ForEach-Object { [string]$_.DriveLetter })
    $free = @('W','S','R','T','U','V','Y','Z','Q','P','O','N','M','L','K','J','I','H','G','F','E','D' |
        Where-Object { $_ -notin $used })
    if ($free.Count -lt 4) { throw 'Not enough unused drive letters. No disk was modified.' }
    $free[0..3]
}

function Assert-PartitionBinding {
    param([string]$Letter, [int]$DiskNumber, $Partition)
    $actual = @(Get-Partition -DriveLetter $Letter)
    if ($actual.Count -ne 1 -or $actual[0].DiskNumber -ne $DiskNumber -or
        $actual[0].PartitionNumber -ne $Partition.PartitionNumber -or
        [long]$actual[0].Offset -ne [long]$Partition.Offset -or
        [long]$actual[0].Size -ne [long]$Partition.Size -or
        ([string]$actual[0].Guid -cne [string]$Partition.Guid)) {
        throw 'Drive letter is not bound to the approved target partition.'
    }
}

function Get-DeploymentNativePercent {
    param([string]$Path)
    $stream=$null
    try {
        $stream=[IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        # DISM redraws with carriage returns. Read only the recent output, including UTF-16 redirects.
        $length=[int][Math]::Min(8192, $stream.Length)
        if ($length -eq 0) { return $null }
        $null=$stream.Seek(-$length, [IO.SeekOrigin]::End)
        $buffer=New-Object byte[] $length
        $read=$stream.Read($buffer, 0, $length)
        $text=[Text.Encoding]::UTF8.GetString($buffer, 0, $read).Replace([string][char]0, '')
        $values=[regex]::Matches($text, '\[[=\s]*(\d{1,3}(?:[.,]\d+)?)%[=\s]*\]')
        for ($index=$values.Count-1; $index -ge 0; $index--) {
            $percent=[double]::Parse($values[$index].Groups[1].Value.Replace(',', '.'), [Globalization.CultureInfo]::InvariantCulture)
            if ($percent -ge 0 -and $percent -le 100) { return [int][Math]::Floor($percent) }
        }
    } catch { return $null }
    finally { if ($stream) { $stream.Dispose() } }
    return $null
}

function Write-DeploymentProgress {
    param([Nullable[int]]$Percent)
    if ($null -eq $Percent) {
        $line='WIM restore [------------------------------] waiting for progress...'
    } else {
        $filled=[int][Math]::Floor([int]$Percent * 30 / 100)
        $line='WIM restore [{0}{1}] {2,3}%' -f ('#' * $filled), ('-' * (30-$filled)), $Percent
    }
    Write-Host ([string][char]13 + $line.PadRight(72)) -NoNewline
}

function Invoke-DeploymentNative {
    param([string]$File, [string[]]$Arguments, [string]$Stage, $Job, [string]$Token)
    $log = Join-Path $PSScriptRoot ($Job.id + '-' + $Stage + '-' + [guid]::NewGuid().ToString('N'))
    $process = Start-Process -FilePath $File -ArgumentList $Arguments -PassThru -NoNewWindow `
        -RedirectStandardOutput ($log + '.log') -RedirectStandardError ($log + '.err')
    # Cache before exit: PowerShell 5.1 otherwise returns a null ExitCode for redirected processes.
    $null=$process.Handle
    $percent=$null
    $lastReported=$null
    $reportClock=[Diagnostics.Stopwatch]::StartNew()
    if ($Stage -eq 'applying') { Write-DeploymentProgress $null }
    while (-not $process.WaitForExit(500)) {
        if ($Stage -eq 'applying') {
            $current=Get-DeploymentNativePercent ($log + '.log')
            if ($null -ne $current -and ($null -eq $percent -or $current -gt $percent)) {
                $percent=$current
                Write-DeploymentProgress $percent
            }
        }
        # Heartbeats remain useful when DISM pauses; only stage changes become operation logs.
        if ($reportClock.ElapsedMilliseconds -ge 10000 -or
            ($percent -ne $lastReported -and $reportClock.ElapsedMilliseconds -ge 5000)) {
            Send-DeploymentProgress $Job $Token $Stage -Percent $percent
            $lastReported=$percent
            $reportClock.Restart()
        }
    }
    $process.WaitForExit()
    if ($Stage -eq 'applying') {
        if ($process.ExitCode -eq 0) {
            Write-DeploymentProgress 100
            Send-DeploymentProgress $Job $Token $Stage -Percent 100
        }
        Write-Host ''
    }
    if ($process.ExitCode -ne 0) {
        $failure = [Management.Automation.ErrorRecord]::new(
            [InvalidOperationException]::new("Deployment tool failed at $Stage (exit code $($process.ExitCode)). No automatic retry."),
            'DeploymentNativeFailed', [Management.Automation.ErrorCategory]::InvalidResult, $null)
        $output = @()
        foreach ($extension in @('.err', '.log')) {
            try {
                $tail = @(Get-Content -LiteralPath ($log + $extension) -Tail 20 -ErrorAction Stop)
                if ($tail.Count) { $output += $extension + ':'; $output += $tail }
            } catch { }
        }
        if ($output.Count) { $failure.ErrorDetails = New-Object Management.Automation.ErrorDetails($output -join [Environment]::NewLine) }
        throw $failure
    }
}

function Merge-CompletionAnswer {
    param([string]$Existing, [string]$Startup)
    $xml = New-Object Xml.XmlDocument
    $xml.XmlResolver = $null
    if ($Existing) {
        if ($Existing.Length -gt 1MB -or $Existing -match '<!DOCTYPE') { throw 'Existing answer file cannot be safely extended.' }
        $xml.LoadXml($Existing)
    } else { $xml.LoadXml('<unattend xmlns="urn:schemas-microsoft-com:unattend" />') }
    $ns = 'urn:schemas-microsoft-com:unattend'
    if ($xml.DocumentElement.LocalName -ne 'unattend' -or $xml.DocumentElement.NamespaceURI -ne $ns) {
        throw 'Existing answer file has an unexpected format.'
    }
    $manager = New-Object Xml.XmlNamespaceManager($xml.NameTable)
    $manager.AddNamespace('u', $ns)
    $settings = $xml.SelectSingleNode('/u:unattend/u:settings[@pass="specialize"]', $manager)
    if (-not $settings) {
        $settings = $xml.CreateElement('settings', $ns)
        $settings.SetAttribute('pass', 'specialize')
        [void]$xml.DocumentElement.AppendChild($settings)
    }
    $component = $settings.SelectSingleNode('u:component[@name="Microsoft-Windows-Deployment" and @processorArchitecture="amd64"]', $manager)
    if (-not $component) {
        $component = $xml.CreateElement('component', $ns)
        foreach ($pair in @(@('name','Microsoft-Windows-Deployment'),@('processorArchitecture','amd64'),
                @('publicKeyToken','31bf3856ad364e35'),@('language','neutral'),@('versionScope','nonSxS'))) {
            $component.SetAttribute($pair[0], $pair[1])
        }
        [void]$settings.AppendChild($component)
    }
    $run = $component.SelectSingleNode('u:RunSynchronous', $manager)
    if (-not $run) { $run = $xml.CreateElement('RunSynchronous', $ns); [void]$component.AppendChild($run) }
    $orders = @($run.SelectNodes('u:RunSynchronousCommand/u:Order', $manager) | ForEach-Object { [int]$_.InnerText })
    $order = 1
    if ($orders.Count) { $order = [int](($orders | Measure-Object -Maximum).Maximum) + 1 }
    $commandNode = $xml.CreateElement('RunSynchronousCommand', $ns)
    [void]$commandNode.SetAttribute('action', 'http://schemas.microsoft.com/WMIConfig/2002/State', 'add')
    foreach ($pair in @(@('Order',[string]$order),@('Path',$startup),@('Description','PC Deploy completion report'))) {
        $element = $xml.CreateElement($pair[0], $ns); $element.InnerText = $pair[1]
        [void]$commandNode.AppendChild($element)
    }
    [void]$run.AppendChild($commandNode)
    return $xml.OuterXml
}

function Add-OfflineCompletion {
    param([string]$WindowsRoot, [string]$JobId, [string]$Command)
    if ($JobId -notmatch '^[a-f0-9-]{36}$' -or
        $Command -notmatch '^powershell\.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ([A-Za-z0-9+/=]+)$') {
        throw 'Invalid completion bootstrap authorization.'
    }
    $bootstrap = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1]))
    $relative = "Setup\Scripts\PCDeploy-$JobId"
    $directory = Join-Path $WindowsRoot $relative
    if (Test-Path -LiteralPath $directory) { throw 'Completion directory already exists; refusing to overwrite.' }
    New-Item -ItemType Directory -Path $directory | Out-Null
    & icacls.exe $directory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot protect offline completion bootstrap.' }
    $bootstrap += "`r`n[IO.File]::WriteAllText(`$PSCommandPath, 'exit 0')`r`n"
    [IO.File]::WriteAllText((Join-Path $directory 'Bootstrap.ps1'), $bootstrap, [Text.Encoding]::Unicode)
    # This short expandable command stays below RunOnce's 260 character limit.
    $startup = 'cmd.exe /d /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\' + $relative + '\Bootstrap.ps1"'
    if ($startup.Length -gt 260) { throw 'Completion startup command is too long.' }
    $hiveName = 'PCDeploy_' + $JobId.Replace('-', '')
    $hivePath = Join-Path $WindowsRoot 'System32\config\SOFTWARE'
    & reg.exe load "HKLM\$hiveName" $hivePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot load the restored Windows SOFTWARE hive.' }
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(
            "$hiveName\Microsoft\Windows\CurrentVersion\RunOnce")
        try { $key.SetValue("!PCDeploy-$JobId", $startup, [Microsoft.Win32.RegistryValueKind]::ExpandString) }
        finally { $key.Dispose() }
    } finally {
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        & reg.exe unload "HKLM\$hiveName" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot unload the restored Windows SOFTWARE hive.' }
    }
    # For generalized/OOBE images, add only our specialize command; preserve existing settings.
    $panther = Join-Path $WindowsRoot 'Panther'
    New-Item -ItemType Directory -Path $panther -Force | Out-Null
    $answerPath = Join-Path $panther 'Unattend.xml'
    $existing = ''
    if (Test-Path -LiteralPath $answerPath) { $existing = [IO.File]::ReadAllText($answerPath) }
    [IO.File]::WriteAllText($answerPath, (Merge-CompletionAnswer $existing $startup), (New-Object Text.UTF8Encoding($false)))
}

function Get-InstallationMarker {
    [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'install-started.txt'))
}

function Invoke-WimDeployment {
    param($Job, $Authorization, [string]$Token, [string]$BootId, [string]$ImagePath)
    if ($RegistrationOnly) { throw 'Installation is blocked in registration-only mode.' }
    Assert-WinPE
    if ($Authorization.kind -cne 'wim' -or $Job.source.kind -cne 'wim' -or
        (Get-InstallationMarker) -cne $Job.id) {
        throw 'Explicit one-time WIM authorization is required.'
    }
    $mode = [string]$Job.profile.disk_mode
    if ($mode -notin @('wipe_disk','system_partition')) { throw 'Unknown WIM disk mode.' }
    $letters = @(Get-FreeDeploymentLetters)
    $before = Get-Inventory $BootId
    $disk = Select-VerifiedDisk $before.disks $Job.target.disk
    $number = [int]$disk.number
    $script:FailureCode = 'DISK_CHANGED'
    if ($mode -eq 'system_partition') {
        $null = Select-VerifiedPartition $disk.partitions $Job.target.partitions.windows
        $null = Select-VerifiedPartition $disk.partitions $Job.target.partitions.efi
        if ($Job.target.partitions.windows.gpt_type -cne 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7' -or
            $Job.target.partitions.windows.filesystem -cne 'NTFS' -or -not $Job.target.partitions.windows.windows -or
            $Job.target.partitions.efi.gpt_type -cne 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b' -or
            $Job.target.partitions.efi.filesystem -cne 'FAT32') { throw 'Unsafe partition selection.' }
        $windows = Get-VerifiedPartitionObject $number $Job.target.partitions.windows
        $efi = Get-VerifiedPartitionObject $number $Job.target.partitions.efi
        # WinPE may already have mounted either approved partition; each supports only one drive letter.
        $partitions = @($windows, $efi)
        for ($index = 0; $index -lt $partitions.Count; $index++) {
            $partition = $partitions[$index]
            $existingLetter = [string]$partition.DriveLetter
            if ($existingLetter -match '^[A-Za-z]$') {
                $letters[$index] = $existingLetter.ToUpperInvariant()
            } else {
                Add-PartitionAccessPath -DiskNumber $number -PartitionNumber $partition.PartitionNumber -AccessPath ($letters[$index] + ':\')
            }
        }
        Assert-PartitionBinding $letters[0] $number $windows
        Assert-PartitionBinding $letters[1] $number $efi
        Get-VerifiedPartitionObject $number $Job.target.partitions.windows | Out-Null
        $script:FailureCode = 'WIM'
        # Preserve the existing EFI filesystem and every other data partition.
        Format-Volume -Partition $windows -FileSystem NTFS -NewFileSystemLabel 'Windows' -Confirm:$false -Force | Out-Null
    } else {
        Select-VerifiedDisk (Get-Inventory $BootId).disks $Job.target.disk | Out-Null
        $actualDisk = Get-Disk -Number $number
        $identity = @{number=[int]$actualDisk.Number; serial=([string]$actualDisk.SerialNumber).Trim()
            unique_id=([string]$actualDisk.UniqueId).Trim(); size_bytes=[long]$actualDisk.Size
            bus=[string]$actualDisk.BusType; read_only=[bool]$actualDisk.IsReadOnly; offline=[bool]$actualDisk.IsOffline}
        Select-VerifiedDisk @($identity) $Job.target.disk | Out-Null
        $script:FailureCode = 'WIM'
        if ([string]$actualDisk.PartitionStyle -ne 'RAW') {
            Clear-Disk -InputObject $actualDisk -RemoveData -RemoveOEM -Confirm:$false
        }
        Initialize-Disk -Number $number -PartitionStyle GPT -Confirm:$false | Out-Null
        $efi = New-Partition -DiskNumber $number -Size 260MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -DriveLetter $letters[1]
        Format-Volume -Partition $efi -FileSystem FAT32 -NewFileSystemLabel 'System' -Confirm:$false -Force | Out-Null
        New-Partition -DiskNumber $number -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' | Out-Null
        $systemMiB = [long]$Job.profile.system_gib * 1024
        if ($systemMiB -eq 0) { $systemMiB = [long][Math]::Floor([long]$disk.size_bytes / 1MB) - 260 - 16 - 1100 - 32 }
        $windows = New-Partition -DiskNumber $number -Size ($systemMiB * 1MB) -DriveLetter $letters[0]
        Format-Volume -Partition $windows -FileSystem NTFS -NewFileSystemLabel 'Windows' -Confirm:$false -Force | Out-Null
        $recovery = New-Partition -DiskNumber $number -Size 1100MB -GptType '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}' -DriveLetter $letters[2]
        Format-Volume -Partition $recovery -FileSystem NTFS -NewFileSystemLabel 'Recovery' -Confirm:$false -Force | Out-Null
        if ([int]$Job.profile.system_gib -gt 0) {
            $dataPart = New-Partition -DiskNumber $number -UseMaximumSize -DriveLetter $letters[3]
            Format-Volume -Partition $dataPart -FileSystem NTFS -NewFileSystemLabel 'Data' -Confirm:$false -Force | Out-Null
        }
    }
    Assert-PartitionBinding $letters[0] $number $windows
    Assert-PartitionBinding $letters[1] $number $efi
    $root = $letters[0] + ':\'
    $script:FailureCode = 'WIM'
    Send-DeploymentProgress $Job $Token 'applying'
    Invoke-DeploymentNative dism.exe @('/Apply-Image', ('/ImageFile:"' + $ImagePath + '"'),
        ('/Index:' + [int]$Job.profile.image_index), ('/ApplyDir:' + $root), '/CheckIntegrity', '/Verify') 'applying' $Job $Token
    if (-not (Test-Path -LiteralPath (Join-Path $root 'Windows\System32\config\SYSTEM'))) {
        throw 'Applied image does not contain a Windows system.'
    }
    Send-DeploymentProgress $Job $Token 'boot_files'
    Add-OfflineCompletion (Join-Path $root 'Windows') $Job.id $Authorization.finalizer_command
    Assert-PartitionBinding $letters[0] $number $windows
    Assert-PartitionBinding $letters[1] $number $efi
    $bcdboot = Join-Path $root 'Windows\System32\bcdboot.exe'
    Invoke-DeploymentNative $bcdboot @(('"' + (Join-Path $root 'Windows') + '"'), '/s', ($letters[1] + ':'), '/f', 'UEFI') 'boot_files' $Job $Token
    # Recovery is configured only when this image actually contains WinRE.
    $winre = Join-Path $root 'Windows\System32\Recovery\Winre.wim'
    if ($mode -eq 'wipe_disk' -and (Test-Path -LiteralPath $winre)) {
        $recoveryPath = $letters[2] + ':\Recovery\WindowsRE'
        New-Item -ItemType Directory -Path $recoveryPath -Force | Out-Null
        Copy-Item -LiteralPath $winre -Destination (Join-Path $recoveryPath 'Winre.wim')
        Invoke-DeploymentNative (Join-Path $root 'Windows\System32\reagentc.exe') @('/Setreimage', '/Path', $recoveryPath, '/Target', (Join-Path $root 'Windows')) 'boot_files' $Job $Token
    }
    $script:FailureCode = 'NETWORK'
    Send-DeploymentProgress $Job $Token 'awaiting_report'
    Write-Host 'WIM applied and UEFI boot configured. Restarting; completion still requires the new Windows report.'
    & wpeutil.exe reboot
    if ($LASTEXITCODE -ne 0) { throw 'Restart failed. Restart the approved machine manually.' }
}

function Invoke-Deployment {
    param($Job, [string]$Token, [string]$BootId)
    if ($RegistrationOnly) { throw 'Installation is blocked in registration-only mode.' }
    Assert-WinPE
    $script:FailureCode = 'PREFLIGHT'
    $before = Get-Inventory $BootId
    Select-VerifiedDisk $before.disks $Job.target.disk | Out-Null
    if ($before.firmware -ne 'UEFI') { throw 'UEFI boot is required.' }
    if ($Job.source.family -eq 'windows11' -and -not ($before.secure_boot -and $before.tpm2)) {
        throw 'Windows 11 requires TPM 2.0 and enabled Secure Boot for this profile.'
    }
    $script:FailureCode = 'SOURCE'
    $secret = ConvertTo-SecureString $Job.source_password -AsPlainText -Force
    $credential = New-Object Management.Automation.PSCredential($Job.source.smb_user, $secret)
    New-PSDrive -Name DeploySource -PSProvider FileSystem -Root $Job.source.path `
        -Credential $credential -Scope Script | Out-Null
    $isWim = $Job.source.kind -ceq 'wim'
    if ($Job.source.kind -and $Job.source.kind -notin @('setup','wim')) { throw 'Unsupported installation kind.' }
    $setupPath = Join-Path $Job.source.path 'setup.exe'
    $imagePath = Join-Path $Job.source.path $Job.source.image_file
    if (-not (Test-Path -LiteralPath $imagePath -PathType Leaf)) { throw 'Installation image file not found.' }
    if (-not $isWim -and -not (Test-Path -LiteralPath $setupPath -PathType Leaf)) { throw 'Windows Setup executable not found.' }
    if ($isWim -and $Job.source.image_file -notmatch '^[A-Za-z0-9_-][A-Za-z0-9_. -]{0,119}\.wim$') { throw 'Unsafe WIM file name.' }
    $sourceLock = $null
    try {
    if ($isWim) {
        foreach ($tool in @('Get-Partition','Get-Volume','Format-Volume','Clear-Disk','Initialize-Disk','New-Partition','Add-PartitionAccessPath','dism.exe','reg.exe','icacls.exe','wpeutil.exe')) {
            if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "Required WinPE tool missing: $tool" }
        }
        $sourceLock = [IO.File]::Open($imagePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    }
    # Read selected image metadata directly without scanning the entire source file.
    $image = Get-WindowsImage -ImagePath $imagePath -Index $Job.profile.image_index
    $expectedImage = @($Job.source.images | Where-Object { $_.index -eq $Job.profile.image_index })
    if ($expectedImage.Count -ne 1 -or [int]$image.Architecture -ne 9 -or
        ([version]$image.Version).Build -ne [int]$expectedImage[0].build -or
        [string]$image.ImageName -cne [string]$expectedImage[0].name) {
        throw 'Actual image metadata does not match the approved source.'
    }
    $systemMiB = [long]$Job.profile.system_gib * 1024
    if ($systemMiB -eq 0) { $systemMiB = [long]($Job.target.disk.size_bytes / 1MB) - 260 - 16 - 1100 - 32 }
    if ($isWim -and $Job.profile.disk_mode -eq 'system_partition') {
        $approvedDisk = Select-VerifiedDisk $before.disks $Job.target.disk
        Select-VerifiedPartition $approvedDisk.partitions $Job.target.partitions.windows | Out-Null
        Select-VerifiedPartition $approvedDisk.partitions $Job.target.partitions.efi | Out-Null
        $systemMiB = [long][Math]::Floor([long]$Job.target.partitions.windows.size_bytes / 1MB)
    }
    if ([long]$image.ImageSize + 10GB -gt $systemMiB * 1MB) {
        throw 'The selected Windows partition is too small for this image and setup workspace.'
    }
    $script:FailureCode = 'DISK_CHANGED'
    $current = Get-Inventory $BootId
    Select-VerifiedDisk $current.disks $Job.target.disk | Out-Null
    $marker = Join-Path $PSScriptRoot 'install-started.txt'
    if (Test-Path -LiteralPath $marker) { throw 'This WinPE boot already started an installation.' }
    $authorization = Invoke-Platform "/api/agent/jobs/$($Job.id)/start" $Token $current
    if ($isWim) {
        if ($authorization.kind -cne 'wim' -or -not $authorization.finalizer_command) { throw 'WIM authorization is missing.' }
        Select-VerifiedDisk (Get-Inventory $BootId).disks $Job.target.disk | Out-Null
        [IO.File]::WriteAllText($marker, $Job.id)
        Invoke-WimDeployment $Job $authorization $Token $BootId $imagePath
        return
    }
    $answer = Join-Path $PSScriptRoot 'approved-answer.xml'
    [IO.File]::WriteAllText($answer, $authorization.answer_xml, (New-Object Text.UTF8Encoding($false)))
    Select-VerifiedDisk (Get-Inventory $BootId).disks $Job.target.disk | Out-Null
    [IO.File]::WriteAllText($marker, $Job.id)
    $script:FailureCode = 'SETUP'
    Write-Host 'Approved. Starting Windows Setup for the selected disk only.' -ForegroundColor Yellow
    # No /Auto, fixed Disk 0 fallback, or disk utilities in the control plane.
    $process = Start-Process -FilePath $setupPath -ArgumentList ('/unattend:"' + $answer + '"') -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) { throw 'Windows Setup failed. Inspect Panther logs locally.' }
    $script:FailureCode = 'NETWORK'
    Invoke-Platform "/api/agent/jobs/$($Job.id)/event" $Token @{stage = 'awaiting_report'} | Out-Null
    Write-Host 'Waiting for Windows Setup and its own restart. Do not start another deployment.'
    } finally {
        if ($sourceLock) { $sourceLock.Dispose() }
        Remove-PSDrive -Name DeploySource -Scope Script -ErrorAction SilentlyContinue
    }
}

if ($LibraryOnly) { return }
Assert-WinPE
$cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-PlatformUrl -Url $cfg.server_url -AllowHttp ($cfg.allow_http -is [bool] -and $cfg.allow_http)
$script:Server = $cfg.server_url.TrimEnd('/')
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'install-started.txt')) {
    throw 'An installation was already authorized in this WinPE boot. Check the platform.'
}
$bootFile = Join-Path $PSScriptRoot 'boot-id.txt'
if (-not (Test-Path -LiteralPath $bootFile)) { [IO.File]::WriteAllText($bootFile, [guid]::NewGuid().ToString()) }
$bootId = [IO.File]::ReadAllText($bootFile).Trim()
$RegistrationOnly = $RegistrationOnly -or ($cfg.registration_only -is [bool] -and $cfg.registration_only)
$registration = Invoke-WaitingPlatform '/api/agent/register' $cfg.enrollment_token { Get-Inventory $bootId }
$token = $registration.token
Write-Host ''
Write-Host 'PC DEPLOY / Waiting for operator approval' -ForegroundColor Cyan
Write-Host ('Device: ' + (Get-Inventory $bootId).serial)
Write-Host ('Screen verification code: ' + $registration.boot_code) -ForegroundColor Yellow
if ($RegistrationOnly) {
    Write-Host 'REGISTRATION ONLY: installation is blocked in this image.' -ForegroundColor Yellow
} else {
    Write-Host 'No disk has been changed. Select this machine and its disk in the platform.'
}
$job = $null
try {
    while ($true) {
        $result = Invoke-WaitingPlatform '/api/agent/poll' $token {
            $status = Get-Inventory $bootId
            if ($RegistrationOnly) { $status.registration_only = $true }
            $status
        }
        if ($RegistrationOnly) {
            if ($result.job) {
                throw 'Server returned an installation task to a registration-only client. Update the server; installation is blocked.'
            }
        } elseif ($result.job) { $job = $result.job; break }
        Start-Sleep -Seconds 8
    }
    Invoke-Deployment $job $token $bootId
} catch {
    $failure = $_
    $detail = Get-DeploymentFailureDetail $failure $job $token $cfg
    if ($job) {
        try {
            Invoke-Platform "/api/agent/jobs/$($job.id)/event" $token @{code=$script:FailureCode;detail=$detail} | Out-Null
        } catch { Write-Host 'Could not report the failure to the platform. Keeping the local error log.' -ForegroundColor Yellow }
    }
    Save-DeploymentFailureLog $detail $script:FailureCode $PSScriptRoot
    Write-Host ('Stopped at stage: ' + $script:FailureCode + '. No automatic retry.') -ForegroundColor Red
    Write-Host $detail -ForegroundColor Red
    throw 'Deployment stopped. See the diagnostic above; secrets have been redacted.'
}
