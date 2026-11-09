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
foreach ($file in @('agent/Deploy-Agent.ps1','agent/Start.ps1','agent/Finalize.ps1','agent/DeviceInfo.ps1',
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
    @{mode='wipe_disk';fail='disk';expected='failure'},
    @{mode='wipe_disk';fail='';reportFailure='applying';expected='success'},
    @{mode='wipe_disk';fail='';reportFailure='boot_files';expected='success'},
    @{mode='wipe_disk';fail='';reportFailure='awaiting_report';expected='success'},
    @{mode='system_partition';fail='';reportFailure='applying';expected='success'},
    @{mode='system_partition';fail='';reportFailure='boot_files';expected='success'},
    @{mode='system_partition';fail='';reportFailure='awaiting_report';expected='success'},
    @{mode='system_partition';fail='';windowsLetter='C';expected='success'},
    @{mode='system_partition';fail='';efiLetter='Z';expected='success'},
    @{mode='system_partition';fail='';windowsLetter='C';efiLetter='Z';expected='success'},
    @{mode='system_partition';fail='existing_binding';windowsLetter='C';efiLetter='Z';expected='failure'}
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
                Guid=$entry.guid;GptType=$entry.gpt_type;Offset=$entry.offset;Size=$entry.size_bytes;IsReadOnly=$false;IsOffline=$false;DriveLetter=[char]0}
        }
        $job = @{id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';source=@{kind='wim'};profile=@{disk_mode=$case.mode;system_gib=128;image_index=1};
                 target=@{disk=$target;partitions=@{windows=$winExpected;efi=$efiExpected}}}
        $auth = @{kind='wim';finalizer_command='mock-authorized-completion'}
        $winLetter='W'; $efiLetter='S'
        foreach ($mount in @(@{number=3;letter=$case.windowsLetter},@{number=1;letter=$case.efiLetter})) {
            if ($mount.letter) {
                $obj=$partitionsByNumber[$mount.number]
                $obj.DriveLetter=$mount.letter
                $bindings[$mount.letter]=$obj
            }
        }
        if ($case.windowsLetter) { $winLetter=$case.windowsLetter }
        if ($case.efiLetter) { $efiLetter=$case.efiLetter }
        if ($case.fail -eq 'existing_binding') {
            $bindings[$winLetter]=[pscustomobject]@{DiskNumber=0;PartitionNumber=3;Guid=$winExpected.guid;Offset=1GB;Size=128GB}
        }
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
            if ([string]$obj.DriveLetter -match '^[A-Za-z]$') { throw 'A partition cannot receive a second drive letter.' }
            $calls.Add("mount:$PartitionNumber")
            $obj.DriveLetter=$AccessPath.Substring(0,1)
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
            if ($case.reportFailure -eq $Data.stage) {
                throw [Net.WebException]::new('Simulated progress outage.',[Net.WebExceptionStatus]::ConnectFailure)
            }
        }
        function Invoke-WimImageApply {
            param($Job,$Token,$ImagePath,$Root,$DiskNumber,$Partition,$ImageBytes,$ExpandedBytes)
            Assert-PartitionBinding $Root.Substring(0,1) $DiskNumber $Partition
            Send-DeploymentProgress $Job $Token 'applying'
            Invoke-DeploymentNative dism.exe @('/Index:1',('/ApplyDir:'+$Root)) 'applying' $Job $Token
        }
        function Invoke-DeploymentNative {
            param($File,$Arguments,$Stage,$Job,$Token)
            $calls.Add("native:$Stage")
            if($Stage -eq 'applying' -and ($Arguments -notcontains '/Index:1' -or $Arguments -notcontains ('/ApplyDir:' + $winLetter + ':\'))) {
                throw 'Wrong WIM application target.'
            }
            if($Stage -eq 'boot_files' -and $Arguments -notcontains ($efiLetter + ':')) {throw 'Wrong EFI target.'}
            if($case.fail -eq $Stage) { throw 'Simulated native tool failure.' }
        }
        function Add-OfflineCompletion {
            param($WindowsRoot,$JobId,$Command)
            if($WindowsRoot -ne ($winLetter + ':\Windows') -or $JobId -ne $job.id) { throw 'Wrong offline completion target.' }
            $calls.Add('completion')
        }
        function Join-Path {
            param($Path,$ChildPath)
            $Path.TrimEnd('\') + '\' + $ChildPath
        }
        function Test-Path {
            param($LiteralPath)
            $LiteralPath -eq ($winLetter + ':\Windows\System32\config\SYSTEM')
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
        if (-not $failed) {
            foreach ($required in @('native:applying','completion','native:boot_files','reboot')) {
                if (@($calls | Where-Object { $_ -eq $required }).Count -ne 1) {
                    throw "The authorized local step was skipped or repeated: $required"
                }
            }
            foreach ($stage in @('applying','boot_files','awaiting_report')) {
                if (@($calls | Where-Object { $_ -eq "event:$stage" }).Count -ne 1) {
                    throw 'Progress reporting was skipped or automatically retried.'
                }
            }
        }
        if ($case.windowsLetter -and $calls.Contains('mount:3')) { throw 'An existing Windows drive letter was reassigned.' }
        if ($case.efiLetter -and $calls.Contains('mount:1')) { throw 'An existing EFI drive letter was reassigned.' }
        if($case.mode -eq 'system_partition') {
            if($calls -match '^clear:|^initialize:|^create:' -or $calls.Contains('format:1:FAT32')) { throw 'Preserve mode changed the disk layout or formatted EFI.' }
        }
        if($case.fail -in @('partition','binding','existing_binding','disk') -and ($calls -match '^clear:|^initialize:|^format:|^native:')) {
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

# Preserve the real failure while redacting secrets, including server error details.
& {
    $failure = $null
    try { throw 'Partition access path failed. password-fixture token-fixture' } catch { $failure = $_ }
    $failure.ErrorDetails = New-Object Management.Automation.ErrorDetails('Server reason: enrollment-fixture')
    $detail = Get-DeploymentFailureDetail $failure @{source_password='password-fixture'} 'token-fixture' @{enrollment_token='enrollment-fixture'}
    if ($detail -notlike '*Partition access path failed*' -or $detail -notlike '*Server reason:*' -or $detail -notlike '*Script line:*') {
        throw 'The original failure diagnostic was lost.'
    }
    foreach ($secret in @('password-fixture','token-fixture','enrollment-fixture')) {
        if ($detail.Contains($secret)) { throw 'A diagnostic exposed a secret.' }
    }
    $detail = Get-DeploymentFailureDetail $failure $null '' $null
    if ($detail -notlike '*Partition access path failed*') { throw 'Failure before a task was assigned lost its diagnostic.' }
}
$count+=2

# USB log selection must ignore internal disks and the EFI partition.
& {
    $script:usbFixture = 'one'
    function Get-Disk {
        [pscustomobject]@{Number=0;BusType='NVMe'}
        if ($script:usbFixture -ne 'absent') { [pscustomobject]@{Number=4;BusType='USB'} }
        if ($script:usbFixture -eq 'multiple') { [pscustomobject]@{Number=5;BusType='USB'} }
    }
    function Get-Partition {
        param($DiskNumber)
        if ($DiskNumber -eq 0) { throw 'Internal disks must never be selected for USB logs.' }
        $letter = if ($DiskNumber -eq 4) { 'F' } else { 'H' }
        [pscustomobject]@{PartitionNumber=1;DriveLetter=$letter;FileSystemLabel='SanDisk'}
        [pscustomobject]@{PartitionNumber=2;DriveLetter='G';FileSystemLabel='VTOYEFI'}
    }
    function Get-Volume {
        param([Parameter(ValueFromPipeline=$true)]$InputObject)
        process { $InputObject }
    }
    if ((Get-DeploymentUsbLogRoot) -cne 'F:\') { throw 'Ventoy data partition was not selected.' }
    $script:usbFixture = 'multiple'
    if (Get-DeploymentUsbLogRoot) { throw 'Ambiguous USB log target was selected.' }
    $script:usbFixture = 'absent'
    if (Get-DeploymentUsbLogRoot) { throw 'Missing USB disk was selected.' }
}
$count+=3

# Exercise log persistence and failure fallback with isolated temporary fixtures.
& {
    $fixture = Join-Path ([IO.Path]::GetTempPath()) ('pcdeploy-log-test-' + [guid]::NewGuid().ToString('N'))
    $local = Join-Path $fixture 'PE'
    $usb = Join-Path $fixture 'USB'
    [IO.Directory]::CreateDirectory($local) | Out-Null
    [IO.Directory]::CreateDirectory($usb) | Out-Null
    try {
        $script:logFixtureRoot = $usb
        function Get-DeploymentUsbLogRoot { $script:logFixtureRoot }
        Save-DeploymentFailureLog 'first sanitized error' 'DISK_CHANGED' $local
        Save-DeploymentFailureLog 'second sanitized error' 'SOURCE' $local
        $history = [IO.File]::ReadAllText((Join-Path $usb 'error.log'))
        if ($history -notlike '*first sanitized error*' -or $history -notlike '*second sanitized error*') {
            throw 'USB error history was overwritten.'
        }
        $script:logFixtureRoot = Join-Path $fixture 'missing'
        Save-DeploymentFailureLog 'USB write failed' 'SOURCE' $local
        if ([IO.File]::ReadAllText((Join-Path $local 'deployment-error.txt')) -notlike '*USB write failed*') {
            throw 'USB failure lost the PE fallback log.'
        }
        $script:logFixtureRoot = $null
        Save-DeploymentFailureLog 'USB removed' 'SOURCE' $local
        if ([IO.File]::ReadAllText((Join-Path $local 'deployment-error.txt')) -notlike '*USB removed*') {
            throw 'Missing USB lost the PE fallback log.'
        }
    } finally { [IO.Directory]::Delete($fixture, $true) }
}
$count+=3

# Error reporting uses the real top-level handler with all I/O mocked.
& {
    $handlerAst = $agentAst.Find({param($node)
        $node -is [Management.Automation.Language.CatchClauseAst] -and
        $node.Extent.Text.Contains('Save-DeploymentFailureLog $detail')
    }, $true)
    if (-not $handlerAst) { throw 'Deployment failure handler not found.' }
    $body = $handlerAst.Body.Extent.Text
    $handler = [scriptblock]::Create($body.Substring(1, $body.Length - 2))
    foreach ($offline in @($false, $true)) {
        $order = [Collections.Generic.List[string]]::new()
        $report = @{}
        $job = @{id='failure-job';source_password='password-fixture'}
        $cfg = @{enrollment_token='enrollment-fixture'}
        $token = 'token-fixture'
        $script:FailureCode = 'DISK_CHANGED'
        function Invoke-Platform {
            param($Route, $Token, $Data)
            $order.Add('report')
            $report.data = $Data
            $report.route = $Route
            if ($Route -ne '/api/agent/jobs/failure-job/event' -or $Data.code -ne 'DISK_CHANGED' -or
                $Data.detail -notlike '*simulated mounting failure*' -or $Data.detail -notlike '*Script line:*') {
                throw 'Failure report omitted the original diagnostic.'
            }
            foreach ($secret in @('password-fixture','token-fixture','enrollment-fixture')) {
                if ($Data.detail.Contains($secret)) { throw 'Failure report exposed a credential.' }
            }
            if ($offline) { throw [TimeoutException]::new('Platform offline.') }
        }
        function Save-DeploymentFailureLog {
            param($Detail,$Stage,$LocalDirectory)
            $order.Add('local')
            if ($Detail -notlike '*simulated mounting failure*') { throw 'Local fallback lost the error.' }
        }
        function Write-Host { }
        try {
            throw 'simulated mounting failure password-fixture token-fixture enrollment-fixture'
        } catch {
            try { & $handler } catch {
                if ($_.Exception.Message -ne 'Deployment stopped. See the diagnostic above; secrets have been redacted.') { throw }
            }
        }
        if (($order -join ',') -ne 'report,local') { throw 'Remote error reporting did not precede the local fallback.' }
        if ($report.route -ne '/api/agent/jobs/failure-job/event' -or $report.data.code -ne 'DISK_CHANGED' -or
            $report.data.detail -notlike '*simulated mounting failure*' -or $report.data.detail -notlike '*Script line:*') {
            throw 'The platform did not receive the actual failure detail.'
        }
        foreach ($secret in @('password-fixture','token-fixture','enrollment-fixture')) {
            if ($report.data.detail.Contains($secret)) { throw 'The platform received an unredacted secret.' }
        }
    }
}
$count += 2

# Native tool failures include bounded output and exit code without running a process or reading a log.
& {
    function Start-Process {
        param($FilePath,$ArgumentList,[switch]$PassThru,[switch]$NoNewWindow,$RedirectStandardOutput,$RedirectStandardError)
        $process = [pscustomobject]@{ExitCode=87}
        $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($Timeout) if ($PSBoundParameters.ContainsKey('Timeout')) { return $true } }
        $process
    }
    function Get-Content { param($LiteralPath,$Tail,$ErrorAction) 'DISM diagnostic fixture password-fixture' }
    function Invoke-Platform { throw 'Unexpected live platform request.' }
    $failure = $null
    try { Invoke-DeploymentNative 'dism.exe' @('/fixture') 'applying' @{id='fixture'} 'token-fixture' } catch { $failure = $_ }
    if (-not $failure) { throw 'Native failure was ignored.' }
    $detail = Get-DeploymentFailureDetail $failure @{source_password='password-fixture'} 'token-fixture' @{}
    if ($detail -notlike '*exit code 87*' -or $detail -notlike '*DISM diagnostic fixture*' -or $detail.Contains('password-fixture')) {
        throw 'Native tool detail or credential protection was lost.'
    }
    $failure.ErrorDetails = New-Object Management.Automation.ErrorDetails(('x' * 20000) + ' password-fixture')
    $bounded = Get-DeploymentFailureDetail $failure @{source_password='password-fixture'} '' @{}
    if ($bounded.Length -gt 8192 -or $bounded.Contains('password-fixture')) { throw 'Remote failure detail is not safely bounded.' }
}
$count += 2

# Parse actual redirected byte encodings and carriage-return redraws in isolated files.
& {
    $fixture=Join-Path ([IO.Path]::GetTempPath()) ('pcdeploy-progress-test-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($fixture) | Out-Null
    try {
        $path=Join-Path $fixture 'native.log'
        foreach ($encoding in @([Text.Encoding]::UTF8,[Text.Encoding]::Unicode,[Text.Encoding]::BigEndianUnicode)) {
            [IO.File]::WriteAllText($path, ("x" * 20000) + [char]13 + '[===== 12.5% =====]' + [char]13 + '[===== 43,9% =====]', $encoding)
            if ((Get-DeploymentNativePercent $path) -ne 43) { throw 'DISM percent parsing failed for a redirected encoding.' }
        }
        [IO.File]::WriteAllText($path, '[==== 100.0% ====]', [Text.Encoding]::UTF8)
        if ((Get-DeploymentNativePercent $path) -ne 100) { throw 'Final DISM percent not recognized.' }
        foreach ($text in @('', 'No progress yet', '[==== 101% ====]', '[==== -1% ====]')) {
            [IO.File]::WriteAllText($path, $text)
            if ($null -ne (Get-DeploymentNativePercent $path)) { throw 'Invalid output was converted to a fake percentage.' }
        }
        if ($null -ne (Get-DeploymentNativePercent (Join-Path $fixture 'missing.log'))) { throw 'Missing log became fake progress.' }
    } finally {
        $root=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
        if (-not ([IO.Path]::GetFullPath($fixture)).StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -or
            -not ([IO.Path]::GetFileName($fixture)).StartsWith('pcdeploy-progress-test-')) { throw 'Unsafe fixture path.' }
        [IO.Directory]::Delete($fixture,$true)
    }
}
$count += 9
& {
    $lines=[Collections.Generic.List[string]]::new()
    function Write-Host { param($Object,[switch]$NoNewline) $lines.Add([string]$Object) }
    Write-DeploymentProgress 37
    Write-DeploymentProgress $null
    if (($lines -join '') -notlike '*###########-------------------*37%*' -or ($lines -join '') -notlike '*waiting for progress*') {
        throw 'Console progress is not a readable hash bar.'
    }
}
$count++
& {
    $sent=[Collections.Generic.List[object]]::new()
    function Invoke-Platform { param($Route,$Token,$Data,$TimeoutSec) $sent.Add(@{data=$Data;timeout=$TimeoutSec}) }
    Send-DeploymentProgress @{id='fixture'} 'fixture-token' 'applying' -Percent 37
    Send-DeploymentProgress @{id='fixture'} 'fixture-token' 'boot_files'
    if ($sent[0].data.percent -ne 37 -or $sent[0].timeout -ne 3 -or $sent[1].data.ContainsKey('percent')) {
        throw 'Progress telemetry omitted the measured percent or imposed a percentage on another phase.'
    }
}
$count++

# The real executor is exercised with a fake process; it cannot run DISM, access storage or retry.
foreach ($case in @(@{exit=0;offline=$false},@{exit=87;offline=$false},@{exit=0;offline=$true})) {
    & {
        param($case)
        $script:nativeTick=0
        $script:nativeStarts=0
        $sent=[Collections.Generic.List[object]]::new()
        $shown=[Collections.Generic.List[object]]::new()
        function Start-Process {
            param($FilePath,$ArgumentList,[switch]$PassThru,[switch]$NoNewWindow,$RedirectStandardOutput,$RedirectStandardError)
            $script:nativeStarts++
            $process=[pscustomobject]@{ExitCode=$case.exit}
            $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {
                param($Timeout)
                if (-not $PSBoundParameters.ContainsKey('Timeout')) { return }
                $script:nativeTick++
                if ($script:nativeTick -eq 1) { return $false }
                if ($script:nativeTick -eq 2) { return $false }
                return $true
            }
            $process
        }
        function Get-DeploymentNativePercent { if ($script:nativeTick -eq 1) { 43 } else { 18 } }
        function Write-DeploymentProgress { param($Percent) $shown.Add($Percent) }
        function Get-DeploymentNetworkSample { @{ticks=([long]$script:nativeTick+1)*[Diagnostics.Stopwatch]::Frequency;adapters=@{fixture=([long]$script:nativeTick+1)*1000000L}} }
        function Invoke-Platform {
            param($Route,$Token,$Data,$TimeoutSec)
            $sent.Add($Data)
            if ($case.offline) { throw [TimeoutException]::new('Telemetry offline.') }
        }
        function Get-Content { param($LiteralPath,$Tail,$ErrorAction) 'Simulated native failure.' }
        function Write-Host { }
        $failed=$false
        try { Invoke-DeploymentNative 'fixture.exe' @('/fixture') 'applying' @{id='progress-fixture'} 'fixture-token' -MeasureNetwork }
        catch { $failed=$true }
        if ($failed -ne ($case.exit -ne 0) -or $script:nativeStarts -ne 1) { throw 'Progress handling retried or masked the native result.' }
        if ($sent[0].percent -ne 43 -or $shown.Contains(18)) { throw 'Live progress was lost or moved backwards.' }
        if(-not $sent[0].metrics.network_speed_available -or $sent[0].metrics.network_bytes_per_second -ne 1000000){throw 'Native progress omitted measured receive rate'}
        if ($case.exit -eq 0 -and $sent[$sent.Count-1].percent -ne 100) { throw 'Successful native completion did not publish 100 percent.' }
        if ($case.exit -ne 0 -and @($sent | Where-Object { $_.percent -eq 100 }).Count) { throw 'Failed native tool falsely reported completion.' }
    } $case
    $count++
}

# Verify real redirected carriage-return output while the child is still running.
# The child only prints fixture percentages; it never runs an imaging or disk tool.
& {
    $fixture=Join-Path ([IO.Path]::GetTempPath()) ('pcdeploy-stdio-test-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($fixture) | Out-Null
    try {
        $library=Join-Path $fixture 'Deploy-Agent.ps1'
        [IO.File]::Copy("$PSScriptRoot\pc_deploy\agent\Deploy-Agent.ps1",$library)
        [IO.File]::Copy("$PSScriptRoot\pc_deploy\agent\DeviceInfo.ps1",(Join-Path $fixture 'DeviceInfo.ps1'))
        . $library -LibraryOnly
        $payloads=[Collections.Generic.List[object]]::new()
        function Invoke-Platform { param($Route,$Token,$Data,$TimeoutSec) $payloads.Add($Data) }
        $child="[Console]::Write('[==== 12.0% ====]' + [char]13); [Console]::Out.Flush(); Start-Sleep -Milliseconds 1500; [Console]::Write('[==== 43.0% ====]' + [char]13); [Console]::Out.Flush(); Start-Sleep -Milliseconds 5000"
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
        Invoke-DeploymentNative (Get-Process -Id $PID).Path @('-NoProfile','-EncodedCommand',$encoded) 'applying' @{id='stdio-fixture'} 'fixture-token'
        if (-not @($payloads | Where-Object { $_.percent -eq 43 }).Count -or $payloads[$payloads.Count-1].percent -ne 100) {
            throw 'Real native stdout was buffered until exit; live percentage updates were lost.'
        }
    } finally {
        $root=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
        if (-not ([IO.Path]::GetFullPath($fixture)).StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -or
            -not ([IO.Path]::GetFileName($fixture)).StartsWith('pcdeploy-stdio-test-')) { throw 'Unsafe fixture path.' }
        [IO.Directory]::Delete($fixture,$true)
    }
}
$count++

# Shared hardware collection is read-only, optional, bounded, and cached in both OS phases.
& {
    . "$PSScriptRoot\pc_deploy\agent\DeviceInfo.ps1"
    $script:DeploymentInfoCache=$null
    $script:deviceQueries=0
    function Get-CimInstance {
        param($ClassName,$Property,$OperationTimeoutSec,$ErrorAction,$Filter)
        $script:deviceQueries++
        if($OperationTimeoutSec -ne 3){throw 'Inventory query must be bounded'}
        switch($ClassName){
            'Win32_ComputerSystem' { [pscustomobject]@{Domain='corp.test';PartOfDomain=$true;TotalPhysicalMemory=16GB} }
            'Win32_Processor' { [pscustomobject]@{Name='Test CPU';NumberOfCores=8;NumberOfLogicalProcessors=16;MaxClockSpeed=4200} }
            'Win32_PhysicalMemory' { [pscustomobject]@{DeviceLocator='DIMM0';Capacity=16GB;Speed=3200;Manufacturer='Fixture';PartNumber='TEST'} }
            'Win32_OperatingSystem' { [pscustomobject]@{Caption='Windows 11 Pro';Version='10.0.26100';BuildNumber='26100';OSArchitecture='64-bit'} }
            default { throw 'Optional class unavailable' }
        }
    }
    $pe=Get-DeploymentDeviceInfo -Stage pe
    if($pe.cpus[0].cores -ne 8 -or $pe.memory_modules[0].capacity_bytes -ne 16GB){throw 'Hardware collection failed'}
    if($pe.ContainsKey('os_name')){throw 'PE must not claim the installed Windows version'}
    $before=$script:deviceQueries
    $again=Get-DeploymentDeviceInfo -Stage pe
    if($script:deviceQueries -ne $before){throw 'Repeated PE polling must reuse the short-lived inventory cache'}
    $windows=Get-DeploymentDeviceInfo -Stage windows
    if($windows.os_name -ne 'Windows 11 Pro' -or $windows.os_build -ne '26100'){throw 'Installed-system details not reported'}
    $script:DeploymentInfoCache=$null
    function Get-CimInstance { throw 'All optional WMI classes unavailable' }
    $minimal=Get-DeploymentDeviceInfo -Stage windows
    if(-not $minimal.ContainsKey('computer_name') -or $minimal.cpus.Count -ne 0){throw 'Missing optional hardware must not stop the callback'}
}
$count+=5



# Network statistics use generated counter snapshots; no benchmark traffic is sent.
& {
    $hz=[Diagnostics.Stopwatch]::Frequency
    $previous=@{ticks=0L;adapters=@{a=100L;b=500L}}
    $current=@{ticks=2L*$hz;adapters=@{a=2000100L;b=4000500L;new=999999999L}}
    $delta=Get-DeploymentNetworkDelta $previous $current
    if($delta.rate -ne 3000000 -or $delta.bytes -ne 6000000){throw 'Network rate was not measured from matching adapter byte counters'}
    $reset=@{ticks=3L*$hz;adapters=@{a=0L}}
    if($null -ne (Get-DeploymentNetworkDelta $current $reset)){throw 'Counter reset became a negative or fabricated rate'}
    $same=@{ticks=4L*$hz;adapters=@{a=0L}}
    if((Get-DeploymentNetworkDelta $reset $same).rate -ne 0){throw 'Measured zero traffic was treated as missing'}
    if($null -ne (Get-DeploymentNetworkDelta $same $same)){throw 'Zero sample duration yielded a rate'}
    $tracker=@{previous=$previous;bytes=0L;seconds=0.0}
    function Get-DeploymentNetworkSample {return $current}
    $metrics=Get-DeploymentNetworkMetrics $tracker -Finished
    if(-not $metrics.network_speed_available -or $metrics.network_average_bytes_per_second -ne 3000000){throw 'Network phase average was not based on sampled bytes and time'}
    function Get-DeploymentNetworkSample {throw 'fixture counter unavailable'}
    if((Get-DeploymentNetworkMetrics $tracker).network_speed_available){throw 'Unavailable counter became a false speed'}
}
$count+=6

# SetupComplete is modified only inside a generated private fixture, never on this Windows installation.
& {
    $fixture=Join-Path ([IO.Path]::GetTempPath()) ('pcdeploy-setuphook-test-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($fixture)
    try {
        $id=[guid]::NewGuid().ToString()
        $startup='cmd.exe /d /c powershell.exe -NoProfile -File "%SystemRoot%\Setup\Scripts\PCDeploy-'+$id+'\Bootstrap.ps1"'
        foreach($case in @('new','existing','bom','utf16')){
            $root=Join-Path $fixture $case
            $scripts=Join-Path $root 'Setup\Scripts'
            $null=[IO.Directory]::CreateDirectory($scripts)
            $path=Join-Path $scripts 'SetupComplete.cmd'
            $original=[Text.Encoding]::ASCII.GetBytes((@('@echo off','rem Existing OEM commands','exit /b 0') -join [Environment]::NewLine))
            if($case -eq 'existing'){[IO.File]::WriteAllBytes($path,$original)}
            if($case -eq 'bom'){[IO.File]::WriteAllBytes($path,[byte[]]@(239,187,191))}
            if($case -eq 'utf16'){[IO.File]::WriteAllText($path,'existing UTF16',[Text.Encoding]::Unicode);$original=[IO.File]::ReadAllBytes($path)}
            Add-CompletionSetupHook $root $id $startup
            $actual=[IO.File]::ReadAllBytes($path)
            if($case -eq 'utf16'){
                if([Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($original)){throw 'Unsupported existing script encoding was overwritten'}
            }else{
                $text=[Text.Encoding]::ASCII.GetString($actual)
                if(-not $text.Contains($startup)){throw 'SYSTEM completion bootstrap hook missing'}
                if($case -eq 'existing' -and -not $text.EndsWith([Text.Encoding]::ASCII.GetString($original))){throw 'Existing SetupComplete commands changed'}
            }
        }
    } finally {
        $safe=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
        if(-not [IO.Path]::GetFullPath($fixture).StartsWith($safe,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture cleanup path'}
        [IO.Directory]::Delete($fixture,$true)
    }
}
$count+=4

# Real background copy and measured metrics, using only generated local fixture files.
& {
    $fixture=Join-Path ([IO.Path]::GetTempPath()) ('pcdeploy-cache-test-'+[guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($fixture)|Out-Null
    try {
        $source=Join-Path $fixture 'source.wim'
        $buffer=New-Object byte[] (8MB)
        (New-Object Random 91).NextBytes($buffer)
        [IO.File]::WriteAllBytes($source,$buffer)
        $expected=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        $reports=[Collections.Generic.List[object]]::new()
        function Invoke-Platform {param($Route,$Token,$Data,$TimeoutSec) $reports.Add($Data); if($script:copyReportOutage){throw 'fixture offline'} }
        $job=@{id='copy-fixture';source=@{image_sha256=$expected};profile=@{image_index=1}}
        $destination=Join-Path $fixture 'copied.wim'
        $script:copyReportOutage=$true
        Copy-DeploymentImage $source $destination $buffer.Length $expected $job 'fixture-token'
        $script:copyReportOutage=$false
        if((Get-FileHash -LiteralPath $destination).Hash -cne $expected){throw 'Background cache corrupted fixture'}
        $final=$reports[$reports.Count-1]
        if($final.percent -ne 100 -or $final.metrics.bytes_copied -ne $buffer.Length -or $final.metrics.bytes_per_second -le 0){throw 'Measured transfer metrics missing'}
        foreach($scenario in @('size','hash','exists')){
            $path=Join-Path $fixture ($scenario+'.wim')
            $length=$buffer.Length;$hash=$expected
            if($scenario -eq 'size'){$length++}
            if($scenario -eq 'hash'){$hash='0'*64}
            if($scenario -eq 'exists'){[IO.File]::WriteAllText($path,'keep')}
            $reports.Clear();$failed=$false
            try{Copy-DeploymentImage $source $path $length $hash $job 'fixture-token'}catch{$failed=$true}
            if(-not $failed -or @($reports|Where-Object {$_.percent -eq 100}).Count){throw 'Unsafe copy was marked complete'}
            if($scenario -eq 'exists' -and [IO.File]::ReadAllText($path) -cne 'keep'){throw 'Copy overwrote existing file'}
        }
        $native=[Collections.Generic.List[object]]::new()
        $script:cacheSpace=100GB;$script:copyReportOutage=$false;$script:applyShouldFail=$false
        function Assert-PartitionBinding {}
        function Get-Volume {param($DriveLetter) @{SizeRemaining=$script:cacheSpace}}
        function Invoke-DeploymentNative {
            param($File,$Arguments,$Stage,$Job,$Token)
            $native.Add($Arguments)
            $image=($Arguments|Where-Object {$_ -like '/ImageFile:*'}).Substring(11).Trim('"')
            if($script:cacheSpace -gt 1GB -and $Job.profile.wim_cache_mode -ne 'network_direct'){
                if($image -eq $source -or -not [IO.File]::Exists($image)){throw 'Apply did not use completed local cache'}
                if((Get-FileHash -LiteralPath $image).Hash -cne $expected){throw 'Wrong cached bytes applied'}
            }elseif($image -ne $source){throw 'Low space did not keep the network source'}
            if(-not @($Arguments|Where-Object {$_ -like '/ScratchDir:*'}).Count -or
               $Arguments -notcontains '/CheckIntegrity' -or $Arguments -notcontains '/Verify'){throw 'Scratch directory or integrity checks missing'}
            if($script:applyShouldFail){throw 'fixture apply failed'}
        }
        Invoke-WimImageApply $job 'fixture-token' $source ($fixture+'\') 7 @{} $buffer.Length 1GB
        if($native.Count -ne 1 -or @(Get-ChildItem -LiteralPath $fixture -Directory -Filter 'PCDeployCache-*').Count){throw 'Cache was repeated or not removed'}
        $script:cacheSpace=1GB
        Invoke-WimImageApply $job 'fixture-token' $source ($fixture+'\') 7 @{} $buffer.Length 1GB
        if($native.Count -ne 2 -or $reports[$reports.Count-1].metrics.mode -ne 'network_direct'){throw 'Low-space fallback failed'}
        $script:cacheSpace=100GB;$script:applyShouldFail=$true;$failed=$false
        try{Invoke-WimImageApply $job 'fixture-token' $source ($fixture+'\') 7 @{} $buffer.Length 1GB}catch{$failed=$true}
        if(-not $failed -or $native.Count -ne 3 -or @(Get-ChildItem -LiteralPath $fixture -Directory -Filter 'PCDeployCache-*').Count){throw 'Failed application retried or retained cache'}
        $job.profile.wim_cache_mode='network_direct';$script:applyShouldFail=$false;$reports.Clear()
        Invoke-WimImageApply $job 'fixture-token' $source ($fixture+'\') 7 @{} $buffer.Length 1GB
        if($native.Count -ne 4 -or @($reports|Where-Object {$_.stage -eq 'caching'}).Count -or
           $reports[$reports.Count-1].metrics.mode -ne 'network_direct' -or
           @(Get-ChildItem -LiteralPath $fixture -Directory -Filter 'PCDeployCache-*').Count){throw 'Explicit direct mode cached or retained a working directory'}
        $script:applyShouldFail=$true;$failed=$false
        try{Invoke-WimImageApply $job 'fixture-token' $source ($fixture+'\') 7 @{} $buffer.Length 1GB}catch{$failed=$true}
        if(-not $failed -or $native.Count -ne 5){throw 'Direct failure retried or fell back to cache'}
        $job.profile.wim_cache_mode='unsupported';$failed=$false
        try{Invoke-WimImageApply $job 'fixture-token' $source ($fixture+'\') 7 @{} $buffer.Length 1GB}catch{$failed=$true}
        if(-not $failed -or $native.Count -ne 5){throw 'Unknown cache mode reached image application'}
        # Direct mode validates an explicitly configured hash before metadata, authorization or disk writes.
        $RegistrationOnly=$false
        function Assert-WinPE {}
        function Get-Inventory {param($BootId) @{firmware='UEFI';disks=@()}}
        function Select-VerifiedDisk {}
        function New-PSDrive {}
        function Remove-PSDrive {}
        function Get-Command {param($Name,$ErrorAction) $true}
        function Get-WindowsImage {throw 'fixture metadata reached'}
        function Invoke-Platform {throw 'Preflight reached authorization unexpectedly'}
        $hashReads=0
        function Get-FileHash {param($LiteralPath,$Algorithm) $script:hashReads++;@{Hash=$expected}}
        $preflight=@{id='preflight';source_password='fixture-only';target=@{disk=@{}};
            source=@{kind='wim';family='windows10';path=$fixture;image_file='source.wim';smb_user='FIXTURE\read';image_sha256=$expected};
            profile=@{image_index=1;wim_cache_mode='network_direct'}}
        $script:hashReads=0
        foreach($scenario in @('mismatch','match','absent','cached')){
            $preflight.profile.wim_cache_mode='network_direct';$preflight.source.image_sha256=$expected
            if($scenario -eq 'mismatch'){$preflight.source.image_sha256='0'*64}
            if($scenario -eq 'absent'){$preflight.source.image_sha256=''}
            if($scenario -eq 'cached'){$preflight.profile.wim_cache_mode='local_cache'}
            $detail=''
            try{Invoke-Deployment $preflight 'fixture-token' 'fixture-boot'}catch{$detail=$_.Exception.Message}
            if($scenario -eq 'mismatch'){
                if($detail -ne 'Network WIM SHA-256 does not match the approved source.'){throw 'Direct mode ignored a mismatched source hash'}
            }elseif($detail -ne 'fixture metadata reached'){throw "Unexpected preflight result: $scenario / $detail"}
        }
        if($script:hashReads -ne 2){throw 'Hash scans must be restricted to explicit direct mode with a configured checksum'}
        Write-Host 'Background copy, byte/hash validation, report outage, low-space fallback, explicit direct mode, preflight hash gating and cleanup checks passed.'
    } finally {
        # Every path below is a generated fixture under our verified private test directory.
        if([IO.Path]::GetFullPath($fixture).StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase)){
            Remove-Item -LiteralPath $fixture -Recurse -Force
        }
    }
}

Write-Output "$count PowerShell protection and parser checks passed. No disk command was executed."

# Metadata-only quick inspection. All I/O is mocked.
& {
    function Test-Path { param($LiteralPath,$PathType) return $true }
    function Get-WindowsImage {
        param($ImagePath,$Index)
        if ($PSBoundParameters.ContainsKey('Index')) {
            return [pscustomobject]@{Architecture=9;DefaultLanguage='zh-CN';ImageName='Test WIM';Version='10.0.26100.1'}
        }
        [pscustomobject]@{ImageIndex=1}
    }
    function Get-FileHash { throw 'Quick inspection must never read full-file hashes.' }
    $raw = & "$PSScriptRoot\pc_deploy\scripts\Inspect-InstallSource.ps1" -SourcePath '\\fixture\reminst\win11.wim' -SmbUser 'FIXTURE\read'
    $source=$raw | ConvertFrom-Json
    if ($source.images.Count -ne 1 -or $source.images[0].build -ne 26100) { throw 'Quick image metadata inspection failed.' }
    if ($source.PSObject.Properties['image_sha256'] -or $source.PSObject.Properties['setup_sha256']) { throw 'Quick manifest still contains hash requirements.' }
}
$agentAst=[Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot\pc_deploy\agent\Deploy-Agent.ps1",[ref]$tokens,[ref]$errors)
$hashCalls=$agentAst.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -in @('Get-VerifiedHash','Get-FileHash')},$true)
if ($hashCalls.Count -ne 1) { throw 'Unexpected source hash scan outside the optional direct-mode preflight.' }
Write-Host 'Quick-source inspection and optional direct-mode hash checks passed. No real image or disk was accessed.'
