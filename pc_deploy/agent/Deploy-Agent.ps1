param([string]$ConfigPath = "$PSScriptRoot\config.json", [switch]$LibraryOnly)
$ErrorActionPreference = 'Stop'

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
    param([string]$Route, [string]$Token, $Data)
    $json = ConvertTo-Json -InputObject $Data -Depth 16 -Compress
    Invoke-RestMethod -Uri ($script:Server + $Route) -Method Post -Headers @{Authorization="Bearer $Token"} `
        -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec 30
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
        @{
            number = [int]$_.Number; serial = ([string]$_.SerialNumber).Trim()
            unique_id = ([string]$_.UniqueId).Trim(); size_bytes = [long]$_.Size
            bus = [string]$_.BusType; model = [string]$_.FriendlyName
            read_only = [bool]$_.IsReadOnly; offline = [bool]$_.IsOffline
        }
    })
    $macs = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
        Where-Object MACAddress | ForEach-Object { [string]$_.MACAddress })
    $serial = ([string]$bios.SerialNumber).Trim()
    if (-not $serial) { $serial = 'Unknown' }
    @{
        hardware_uuid = ([guid]$product.UUID).ToString().ToLowerInvariant(); boot_id = $BootId
        model = [string]$computer.Model; serial = $serial; architecture = 'amd64'
        firmware = $(if ($firmwareValue -eq 2) { 'UEFI' } else { 'BIOS' })
        secure_boot = $secureBoot; tpm2 = $tpm2
        ram_bytes = [long]$computer.TotalPhysicalMemory; macs = $macs; disks = $disks
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

function Get-VerifiedHash {
    param([string]$Path, [string]$Expected, [string]$JobId, [string]$Token)
    $stream, $hash = $null, $null
    try {
        $stream = [IO.File]::OpenRead($Path)
        $hash = [Security.Cryptography.SHA256]::Create()
        $buffer = New-Object byte[] (1024 * 1024)
        $lastReport = [DateTime]::UtcNow.AddMinutes(-1)
        while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            [void]$hash.TransformBlock($buffer, 0, $count, $buffer, 0)
            if (([DateTime]::UtcNow - $lastReport).TotalSeconds -ge 10) {
                Invoke-Platform "/api/agent/jobs/$JobId/event" $Token @{stage = 'verifying'} | Out-Null
                $lastReport = [DateTime]::UtcNow
            }
        }
        [void]$hash.TransformFinalBlock($buffer, 0, 0)
        $actual = [BitConverter]::ToString($hash.Hash).Replace('-', '').ToLowerInvariant()
        if ($actual -cne $Expected.ToLowerInvariant()) { throw 'Installation source SHA-256 mismatch.' }
    } finally {
        if ($stream) { $stream.Dispose() }
        if ($hash) { $hash.Dispose() }
    }
}

function Invoke-Deployment {
    param($Job, [string]$Token, [string]$BootId)
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
    $setupPath = Join-Path $Job.source.path 'setup.exe'
    $imagePath = Join-Path $Job.source.path $Job.source.image_file
    Get-VerifiedHash $setupPath $Job.source.setup_sha256 $Job.id $Token
    Get-VerifiedHash $imagePath $Job.source.image_sha256 $Job.id $Token
    $image = Get-WindowsImage -ImagePath $imagePath -Index $Job.profile.image_index
    $expectedImage = @($Job.source.images | Where-Object { $_.index -eq $Job.profile.image_index })
    if ($expectedImage.Count -ne 1 -or [int]$image.Architecture -ne 9 -or
        ([version]$image.Version).Build -ne [int]$expectedImage[0].build -or
        [string]$image.ImageName -cne [string]$expectedImage[0].name) {
        throw 'Actual image metadata does not match the approved source.'
    }
    $systemMiB = [long]$Job.profile.system_gib * 1024
    if ($systemMiB -eq 0) { $systemMiB = [long]($Job.target.disk.size_bytes / 1MB) - 260 - 16 - 1100 - 32 }
    if ([long]$image.ImageSize + 10GB -gt $systemMiB * 1MB) {
        throw 'The selected Windows partition is too small for this image and setup workspace.'
    }
    $script:FailureCode = 'DISK_CHANGED'
    $current = Get-Inventory $BootId
    Select-VerifiedDisk $current.disks $Job.target.disk | Out-Null
    $marker = Join-Path $PSScriptRoot 'install-started.txt'
    if (Test-Path -LiteralPath $marker) { throw 'This WinPE boot already started an installation.' }
    $authorization = Invoke-Platform "/api/agent/jobs/$($Job.id)/start" $Token $current
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
$registration = Invoke-Platform '/api/agent/register' $cfg.enrollment_token (Get-Inventory $bootId)
$token = $registration.token
Write-Host ''
Write-Host 'PC DEPLOY / Waiting for operator approval' -ForegroundColor Cyan
Write-Host ('Device: ' + (Get-Inventory $bootId).serial)
Write-Host ('Screen verification code: ' + $registration.boot_code) -ForegroundColor Yellow
Write-Host 'No disk has been changed. Select this machine and its disk in the platform.'
$job = $null
try {
    while ($true) {
        $result = Invoke-Platform '/api/agent/poll' $token (Get-Inventory $bootId)
        if ($result.job) { $job = $result.job; break }
        Start-Sleep -Seconds 8
    }
    Invoke-Deployment $job $token $bootId
} catch {
    if ($job) {
        try { Invoke-Platform "/api/agent/jobs/$($job.id)/event" $token @{code = $script:FailureCode} | Out-Null } catch { }
    }
    Write-Host 'Stopped. Check platform and local Setup logs. No automatic retry.' -ForegroundColor Red
    throw 'Deployment did not finish normally. Credentials and raw errors are not printed.'
}
