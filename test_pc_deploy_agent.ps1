$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\pc_deploy\agent\Deploy-Agent.ps1" -LibraryOnly
$disk = @{number=3; serial='TEST-SSD'; unique_id='TEST-ID'; size_bytes=512GB;
          bus='NVMe'; read_only=$false; offline=$false}
$expected = $disk.Clone()
Select-VerifiedDisk @($disk) $expected | Out-Null
$count=1
foreach ($change in @(@{bus='USB'}, @{bus='Unknown'}, @{serial='ANOTHER'}, @{number=0},
                      @{size_bytes=256GB}, @{offline=$true}, @{read_only=$true})) {
    $bad=$disk.Clone()
    foreach ($key in $change.Keys) { $bad[$key]=$change[$key] }
    $rejected=$false
    try { Select-VerifiedDisk @($bad) $expected | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw "Disk protection failed for $($change.Keys)" }
    $count++
}
$rejected=$false
try { Select-VerifiedDisk @($disk,$disk) $expected | Out-Null } catch { $rejected=$true }
if (-not $rejected) { throw 'Ambiguous disk selection was not rejected.' }
$count++
$tokens=$null;$errors=$null
foreach ($file in @('agent/Deploy-Agent.ps1','agent/Start.ps1','agent/Finalize.ps1',
                    'scripts/Build-WinPE.ps1','scripts/Inspect-InstallSource.ps1')) {
    [Management.Automation.Language.Parser]::ParseFile((Join-Path "$PSScriptRoot\pc_deploy" $file),[ref]$tokens,[ref]$errors) | Out-Null
    if ($errors.Count) { throw "PowerShell parsing failed: $file" }
    $count++
}
# Validate only URL guards; never execute the WinPE agent or completion task.
Assert-PlatformUrl 'https://deploy.test/pc-deploy'
Assert-PlatformUrl 'http://192.0.2.10/pc-deploy' -AllowHttp $true
$count += 2
foreach ($url in @('http://deploy.test/pc-deploy','ftp://deploy.test/pc-deploy',
                   'https://user:pass@deploy.test/pc-deploy','https://deploy.test/pc-deploy?token=x',
                   'https://deploy.test/pc-deploy#x','https://deploy.test/other','/pc-deploy')) {
    $rejected=$false
    try { Assert-PlatformUrl $url } catch { $rejected=$true }
    if (-not $rejected) { throw "Unexpectedly accepted URL: $url" }
    $count++
}
$finalize = Join-Path "$PSScriptRoot\pc_deploy" 'agent/Finalize.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($finalize,[ref]$tokens,[ref]$errors)
$guard = $ast.Find({param($node) $node -is [Management.Automation.Language.IfStatementAst]}, $false)
$validate = [scriptblock]::Create($guard.Extent.Text)
foreach ($case in @(@{url='https://deploy.test/pc-deploy';allow=$false;valid=$true},
                    @{url='http://deploy.test/pc-deploy';allow=$true;valid=$true},
                    @{url='http://deploy.test/pc-deploy';allow=$false;valid=$false},
                    @{url='http://deploy.test/pc-deploy';allow='true';valid=$false},
                    @{url='https://deploy.test/other';allow=$true;valid=$false})) {
    $server=[uri]$case.url
    $cfg=@{allow_http=$case.allow}
    $valid=$true
    try { & $validate } catch { $valid=$false }
    if ($valid -ne $case.valid) { throw "Completion URL guard failed: $($case.url)" }
    $count++
}
# Installation calls must fail before inventory or disk operations.
$RegistrationOnly = $true
$blocked = $false
try { Invoke-Deployment @{} '' '' } catch {
    $blocked = $_.Exception.Message -eq 'Installation is blocked in registration-only mode.'
}
if (-not $blocked) { throw 'Registration-only mode did not block direct installation.' }
$RegistrationOnly = $false
$count++
# Run only the polling loop with mocked functions, never the WinPE entry point.
$agentPath = Join-Path "$PSScriptRoot\pc_deploy" 'agent/Deploy-Agent.ps1'
$agentAst = [Management.Automation.Language.Parser]::ParseFile($agentPath,[ref]$tokens,[ref]$errors)
$loopAst = $agentAst.Find({param($node) $node -is [Management.Automation.Language.WhileStatementAst] -and $node.Extent.Text.Contains("'/api/agent/poll'")}, $true)
$loop = [scriptblock]::Create($loopAst.Extent.Text)
& {
    $RegistrationOnly = $true
    $bootId = 'simulated-boot'
    $token = 'simulated-token'
    function Get-Inventory { return @{hardware_uuid='simulated'} }
    function Invoke-Platform {
        param($Route, $Token, $Data)
        if ($Data.registration_only -ne $true) { throw 'Missing heartbeat-only flag.' }
        return @{job=@{id='unexpected-task'}}
    }
    function Start-Sleep { throw 'Unexpected loop continuation.' }
    $refused = $false
    try { & $loop } catch { $refused = $_.Exception.Message -like 'Server returned an installation task*' }
    if (-not $refused) { throw 'Registration-only client accepted an unexpected task.' }
}
$count++

# Test XML merging entirely in memory; existing account, name, commands and OOBE settings survive.
$existing = '<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"><settings pass="specialize"><component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"><ComputerName>IMAGE-NAME</ComputerName></component><component name="Microsoft-Windows-Deployment" processorArchitecture="amd64"><RunSynchronous><RunSynchronousCommand wcm:action="add"><Order>7</Order><Path>original-command</Path></RunSynchronousCommand></RunSynchronous></component></settings><settings pass="oobeSystem"><component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"><OOBE><HideEULAPage>true</HideEULAPage></OOBE></component></settings></unattend>'
[xml]$merged = Merge-CompletionAnswer $existing 'cmd.exe /d /c our-report'
$manager = New-Object Xml.XmlNamespaceManager($merged.NameTable)
$manager.AddNamespace('u','urn:schemas-microsoft-com:unattend')
if ($merged.SelectSingleNode('//u:ComputerName',$manager).InnerText -cne 'IMAGE-NAME' -or
    $merged.SelectNodes('//u:RunSynchronousCommand',$manager).Count -ne 2 -or
    $merged.SelectNodes('//u:RunSynchronousCommand/u:Order',$manager)[1].InnerText -ne '8' -or
    $merged.SelectSingleNode('//u:HideEULAPage',$manager).InnerText -ne 'true') {
    throw 'Original image settings were not preserved when adding the completion command.'
}
$count++
foreach ($bad in @('<wrong />','<!DOCTYPE unattend [<!ENTITY x "unsafe">]><unattend />')) {
    $blocked=$false
    try { Merge-CompletionAnswer $bad 'report' | Out-Null } catch { $blocked=$true }
    if (-not $blocked) { throw 'Unsafe existing answer file accepted.' }
    $count++
}
# Simulate the complete WIM executor. Every hardware/native/network function is mocked.
# No native storage command, registry hive, DISM, BCDBoot, or restart may run in this scope.
foreach ($case in @(
    @{mode='wipe_disk';fail='';expected='success'},
    @{mode='system_partition';fail='';expected='success'},
    @{mode='system_partition';fail='partition';expected='failure'},
    @{mode='system_partition';fail='binding';expected='failure'},
    @{mode='wipe_disk';fail='applying';expected='failure'},
    @{mode='system_partition';fail='boot_files';expected='failure'},
    @{mode='wipe_disk';fail='disk';expected='failure'}
)) {
    & {
        param($case)
        $calls = [Collections.Generic.List[string]]::new()
        $bindings = @{}
        $partitionsByNumber = @{}
        $nextPartition = 0
        $target = @{number=7;serial='ONLY-APPROVED';unique_id='DISK-HW-ID';size_bytes=512GB;bus='NVMe';read_only=$false;offline=$false}
        $efiExpected = @{number=1;guid='11111111-1111-1111-1111-111111111111';gpt_type='c12a7328-f81f-11d2-ba4b-00a0c93ec93b';offset=1MB;size_bytes=260MB;filesystem='FAT32';windows=$false}
        $winExpected = @{number=3;guid='33333333-3333-3333-3333-333333333333';gpt_type='ebd0a0a2-b9e5-4433-87c0-68b6b72699c7';offset=1GB;size_bytes=128GB;filesystem='NTFS';windows=$true}
        $target.partitions = @($efiExpected,$winExpected)
        foreach ($entry in $target.partitions) {
            $partitionsByNumber[[int]$entry.number] = [pscustomobject]@{DiskNumber=7;PartitionNumber=$entry.number;
                Guid=$entry.guid;GptType=$entry.gpt_type;Offset=$entry.offset;Size=$entry.size_bytes;IsReadOnly=$false;IsOffline=$false}
        }
        $job = @{id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';source=@{kind='wim'};profile=@{disk_mode=$case.mode;system_gib=128;image_index=1};
                 target=@{disk=$target;partitions=@{windows=$winExpected;efi=$efiExpected}}}
        $auth = @{kind='wim';finalizer_command='mock-authorized-completion'}
        $RegistrationOnly=$false
        function Assert-WinPE { }
        function Get-InstallationMarker { $job.id }
        function Get-FreeDeploymentLetters { 'W','S','R','T' }
        function Get-Inventory {
            $d=$target.Clone()
            if($case.fail -eq 'disk') { $d.serial='CHANGED' }
            @{disks=@($d)}
        }
        function Get-Disk {
            param($Number)
            if($Number -ne 7) { throw 'Unexpected disk access.' }
            [pscustomobject]@{Number=7;SerialNumber='ONLY-APPROVED';UniqueId='DISK-HW-ID';Size=512GB;BusType='NVMe';IsReadOnly=$false;IsOffline=$false;PartitionStyle='GPT'}
        }
        function Clear-Disk {
            param($InputObject,[switch]$RemoveData,[switch]$RemoveOEM,$Confirm)
            if($InputObject.Number -ne 7) { throw 'Wrong disk wipe.' }
            $calls.Add('clear:7')
        }
        function Initialize-Disk {
            param($Number,$PartitionStyle,$Confirm)
            if($Number -ne 7 -or $PartitionStyle -ne 'GPT') { throw 'Wrong disk initialization.' }
            $calls.Add('initialize:7')
        }
        function New-Partition {
            param($DiskNumber,$Size,$GptType,$DriveLetter,[switch]$UseMaximumSize)
            if($DiskNumber -ne 7) { throw 'Wrong disk partition creation.' }
            $script:mockNextPartition++
            $pn=$script:mockNextPartition
            $obj=[pscustomobject]@{DiskNumber=7;PartitionNumber=$pn;Offset=([long]$pn*1GB);Size=$Size;Guid=[guid]::NewGuid().ToString()}
            if($DriveLetter) {$bindings[[string]$DriveLetter]=$obj}
            $calls.Add("create:$pn")
            $obj
        }
        function Get-Partition {
            param($DiskNumber,$PartitionNumber,$DriveLetter)
            if($DriveLetter) { return $bindings[[string]$DriveLetter] }
            if($DiskNumber -ne 7) { throw 'Unexpected partition access.' }
            $obj=$partitionsByNumber[[int]$PartitionNumber]
            if($case.fail -eq 'partition' -and $PartitionNumber -eq 3) {
                return [pscustomobject]@{DiskNumber=7;PartitionNumber=3;Guid='changed';GptType=$winExpected.gpt_type;Offset=1GB;Size=128GB}
            }
            $obj
        }
        function Add-PartitionAccessPath {
            param($DiskNumber,$PartitionNumber,$AccessPath)
            if($DiskNumber -ne 7) { throw 'Wrong disk access path.' }
            $obj=$partitionsByNumber[[int]$PartitionNumber]
            if($case.fail -eq 'binding') {
                $obj=[pscustomobject]@{DiskNumber=0;PartitionNumber=$PartitionNumber;Offset=$obj.Offset;Size=$obj.Size;Guid=$obj.Guid}
            }
            $bindings[$AccessPath.Substring(0,1)]=$obj
        }
        function Format-Volume {
            param($Partition,$FileSystem,$NewFileSystemLabel,$Confirm,[switch]$Force)
            if($Partition.DiskNumber -ne 7) { throw 'Wrong physical disk formatted.' }
            if($case.mode -eq 'system_partition' -and $Partition.PartitionNumber -ne 3) { throw 'Preserve mode formatted another partition.' }
            $calls.Add("format:$($Partition.PartitionNumber):$FileSystem")
        }
        function Invoke-Platform {
            param($Route,$Token,$Data)
            $calls.Add("event:$($Data.stage)")
        }
        function Invoke-DeploymentNative {
            param($File,$Arguments,$Stage,$Job,$Token)
            $calls.Add("native:$Stage")
            if($Stage -eq 'applying' -and ($Arguments -notcontains '/Index:1' -or $Arguments -notcontains '/ApplyDir:W:\')) {
                throw 'Wrong WIM application target.'
            }
            if($Stage -eq 'boot_files' -and $Arguments -notcontains 'S:') {throw 'Wrong EFI target.'}
            if($case.fail -eq $Stage) { throw 'Simulated native tool failure.' }
        }
        function Add-OfflineCompletion {
            param($WindowsRoot,$JobId,$Command)
            if($WindowsRoot -ne 'W:\Windows' -or $JobId -ne $job.id) { throw 'Wrong offline completion target.' }
            $calls.Add('completion')
        }
        function Join-Path {
            param($Path,$ChildPath)
            $Path.TrimEnd('\') + '\' + $ChildPath
        }
        function Test-Path {
            param($LiteralPath)
            $LiteralPath -eq 'W:\Windows\System32\config\SYSTEM'
        }
        function wpeutil.exe {
            param($Action)
            if($Action -ne 'reboot') { throw 'Unexpected action.' }
            $calls.Add('reboot');$global:LASTEXITCODE=0
        }
        $script:mockNextPartition=0
        $failed=$false
        try { Invoke-WimDeployment $job $auth 'mock-token' 'mock-boot' '\\mock-share\images\custom.wim' }
        catch { $failed=$true; if($case.expected -eq 'success') { throw } }
        if($failed -ne ($case.expected -eq 'failure')) { throw "Unexpected result: $($case.mode) / $($case.fail)" }
        if($failed -and $calls.Contains('reboot')) { throw 'Failed deployment rebooted.' }
        if(-not $failed -and -not $calls.Contains('event:awaiting_report')) { throw 'Missing pending completion state.' }
        if($case.mode -eq 'system_partition') {
            if($calls -match '^clear:|^initialize:|^create:' -or $calls.Contains('format:1:FAT32')) { throw 'Preserve mode changed the disk layout or formatted EFI.' }
        }
        if($case.fail -in @('partition','binding','disk') -and ($calls -match '^clear:|^initialize:|^format:|^native:')) {
            throw 'Identity mismatch did not stop before destructive operations.'
        }
    } $case
    $count++
}
$RegistrationOnly=$true
$blocked=$false
try { Invoke-WimDeployment @{} @{} '' '' '' } catch { $blocked=$_.Exception.Message -eq 'Installation is blocked in registration-only mode.' }
if(-not $blocked) {throw 'Registration-only guard missing from WIM executor.'}
$RegistrationOnly=$false
$count++


# Reconnect classification: distinguish transport outages from security/protocol/local failures.
foreach ($case in @(
    @{exception=[Net.WebException]::new('timeout',[Net.WebExceptionStatus]::Timeout);retry=$true},
    @{exception=[Net.WebException]::new('dns',[Net.WebExceptionStatus]::NameResolutionFailure);retry=$true},
    @{exception=[Net.WebException]::new('connect',[Net.WebExceptionStatus]::ConnectFailure);retry=$true},
    @{exception=[Threading.Tasks.TaskCanceledException]::new('timeout');retry=$true},
    @{exception=[Exception]::new('wrapper',[TimeoutException]::new('timeout'));retry=$true},
    @{exception=[Net.WebException]::new('certificate',[Net.WebExceptionStatus]::TrustFailure);retry=$false},
    @{exception=[Net.WebException]::new('tls',[Net.WebExceptionStatus]::SecureChannelFailure);retry=$false},
    @{exception=[Exception]::new('outer',[Security.Authentication.AuthenticationException]::new('tls'));retry=$false},
    @{exception=[IO.FileNotFoundException]::new('local failure');retry=$false},
    @{exception=[FormatException]::new('invalid response');retry=$false}
)) {
    $record=[Management.Automation.ErrorRecord]::new($case.exception,'fixture',[Management.Automation.ErrorCategory]::NotSpecified,$null)
    if((Test-TransientPlatformFailure $record) -ne $case.retry){throw 'Incorrect reconnect exception classification.'}
    $count++
}
if($PSVersionTable.PSVersion.Major -ge 7) {
    foreach($case in @(
        @{exception=[Net.Http.HttpRequestException]::new('response ended');retry=$true},
        @{exception=[Net.Http.HttpRequestException]::new('tls',[Security.Authentication.AuthenticationException]::new('certificate'));retry=$false}
    )) {
        $record=[Management.Automation.ErrorRecord]::new($case.exception,'http-client-fixture',[Management.Automation.ErrorCategory]::NotSpecified,$null)
        if((Test-TransientPlatformFailure $record) -ne $case.retry){throw 'Incorrect PowerShell 7 transport classification.'}
        $count++
    }
}
foreach($status in @(400,401,403,404,408,409,410,422,429,500,502,503,504)) {
    $exception=[Exception]::new('mock HTTP error')
    $exception | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{StatusCode=$status})
    $record=[Management.Automation.ErrorRecord]::new($exception,'http-fixture',[Management.Automation.ErrorCategory]::NotSpecified,$null)
    $expected=$status -in @(408,429,500,502,503,504)
    if((Test-TransientPlatformFailure $record) -ne $expected){throw "Incorrect reconnect HTTP status: $status"}
    $count++
}
foreach($route in @('/api/agent/register','/api/agent/poll')) {
    & {
        param($route)
        $script:retryCalls=0;$script:payloadCalls=0
        $delays=[Collections.Generic.List[int]]::new()
        function Invoke-Platform {
            param($Route,$Token,$Data)
            if($Route -cne $route -or $Token -cne 'same-token' -or $Data.boot_id -cne 'same-boot' -or
                $Data.sequence -ne ($script:retryCalls+1)) { throw 'Reconnect changed credentials or reused stale inventory.' }
            $script:retryCalls++
            if($script:retryCalls -le 5){throw [Net.WebException]::new('offline',[Net.WebExceptionStatus]::ConnectFailure)}
            @{job=@{id='approved-once'}}
        }
        function Start-Sleep {param($Seconds) $delays.Add([int]$Seconds)}
        $result=Invoke-WaitingPlatform $route 'same-token' {
            $script:payloadCalls++
            @{boot_id='same-boot';sequence=$script:payloadCalls}
        }
        if($result.job.id -cne 'approved-once' -or $script:retryCalls -ne 6 -or $script:payloadCalls -ne 6 -or
            ($delays -join ',') -cne '5,10,20,30,30'){throw 'Reconnect/backoff did not recover correctly.'}
        # A later outage starts at 5 seconds again.
        $script:retryCalls=4;$script:payloadCalls=4;$delays.Clear()
        $null=Invoke-WaitingPlatform $route 'same-token' {
            $script:payloadCalls++
            @{boot_id='same-boot';sequence=$script:payloadCalls}
        }
        if(($delays -join ',') -cne '5'){throw 'Reconnect delay did not reset after recovery.'}
    } $route
    $count++
}
# Non-transient authorization errors never sleep, re-register, or retry.
& {
    $script:fatalCalls=0;$script:fatalSleeps=0
    function Invoke-Platform {
        $script:fatalCalls++
        $e=[Exception]::new('session revoked')
        $e | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{StatusCode=403})
        throw $e
    }
    function Start-Sleep {$script:fatalSleeps++;throw 'Security error attempted automatic retry.'}
    $stopped=$false
    try {Invoke-WaitingPlatform '/api/agent/poll' 'token' {@{}} | Out-Null} catch {$stopped=$true}
    if(-not $stopped -or $script:fatalCalls -ne 1 -or $script:fatalSleeps -ne 0){throw 'Authorization failure did not stop immediately.'}
}
$count++
# Unsafe routes are rejected before any request. Inventory failures are not retried.
& {
    function Invoke-Platform {throw 'Unexpected request.'}
    function Start-Sleep {throw 'Unexpected retry.'}
    foreach($route in @('/api/agent/jobs/x/start','/api/agent/jobs/x/event','/api/agent/jobs/x/finish')) {
        $stopped=$false
        try {Invoke-WaitingPlatform $route 'token' {@{}} | Out-Null}
        catch {$stopped=$_.Exception.Message -like 'Automatic reconnect is allowed only*'}
        if(-not $stopped){throw 'An installation endpoint entered automatic retry.'}
    }
    $stopped=$false
    try {Invoke-WaitingPlatform '/api/agent/poll' 'token' {throw [TimeoutException]::new('inventory failure')} | Out-Null}
    catch {$stopped=$_.Exception.Message -eq 'inventory failure'}
    if(-not $stopped){throw 'A local inventory failure was incorrectly retried.'}
}
$count+=4
# Ctrl+C/cancellation during reconnect must remain effective.
& {
    $script:cancelCalls=0
    function Invoke-Platform {$script:cancelCalls++;throw [TimeoutException]::new('offline')}
    function Start-Sleep {throw [OperationCanceledException]::new('cancelled')}
    $stopped=$false
    try {Invoke-WaitingPlatform '/api/agent/poll' 'token' {@{}} | Out-Null}
    catch {$stopped=$_.Exception -is [OperationCanceledException]}
    if(-not $stopped -or $script:cancelCalls -ne 1){throw 'Cancellation was swallowed by the reconnect loop.'}
}
$count++

Write-Output "$count PowerShell protection and parser checks passed. No disk command was executed."
