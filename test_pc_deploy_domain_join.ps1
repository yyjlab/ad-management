# Isolated domain-join tests. All machine, directory, network and reboot commands are mocked.
$ErrorActionPreference='Stop'
$taskRoot=Join-Path ([IO.Path]::GetTempPath()) ('pcdeploy-domain-test-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($taskRoot) | Out-Null
$taskSource=Join-Path $PSScriptRoot 'pc_deploy\agent\DomainJoin.ps1'
$count=0
function Assert-Join($Condition,[string]$Message) { if(-not $Condition){throw $Message}; $script:count++ }
function New-JoinCase {
    $directory=Join-Path $taskRoot ([guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    [IO.File]::Copy($taskSource,(Join-Path $directory 'DomainJoin.ps1'))
    $directory
}
function Invoke-JoinFixture {
    param([string]$Directory,[hashtable]$Scenario=@{})
    $calls=[Collections.Generic.List[object]]::new()
    $native=[Collections.Generic.List[object]]::new()
    $renames=[Collections.Generic.List[object]]::new()
    $pendingName=$null
    $reboots=[Collections.Generic.List[object]]::new()
    . (Join-Path $Directory 'DomainJoin.ps1')
    function Get-CimInstance {
        param([string]$ClassName)
        if($ClassName -eq 'Win32_OperatingSystem'){
            $boot=if($Scenario.NewBoot){[DateTime]'2026-11-04T11:00:00Z'}else{[DateTime]'2026-11-04T10:00:00Z'}
            return [pscustomobject]@{LastBootUpTime=$boot;ProductType=$(if($Scenario.Server){3}else{1})}
        }
        if($ClassName -eq 'Win32_ComputerSystem'){
            return [pscustomobject]@{PartOfDomain=[bool]$Scenario.Member;
                Domain=$(if($Scenario.OtherDomain){'other.test'}else{'corp.test'});
                Name=$(if($Scenario.ComputerName){$Scenario.ComputerName}elseif($Scenario.ExpectedName){'WFQ101755'}else{'OLD-IMAGE'})}
        }
        throw 'Unexpected CIM query'
    }
    function Get-ItemProperty { param($Path) [pscustomobject]@{EditionID=$(if($Scenario.Home){'Core'}else{'Professional'});CurrentBuildNumber=26100;ImageState='IMAGE_STATE_COMPLETE';SystemSetupInProgress=0;OOBEInProgress=0} }
    function Resolve-DnsName {
        param($Name,$Type,[switch]$DnsOnly,$ErrorAction)
        if($Scenario.DnsFailure){throw 'fixture DNS unavailable'}
        [pscustomobject]@{NameTarget='dc1.corp.test.'}
    }
    function Test-ComputerSecureChannel { param($ErrorAction) return -not $Scenario.BadTrust }
    function Test-JoinNameExists {
        param($Controller,$Domain,$Name,$Credential,$OUPath)
        if ($OUPath -ne 'OU=Workstations,DC=corp,DC=test') { throw 'Name lookup omitted the target OU' }
        if($Scenario.UserCN){return $Name -eq $Scenario.UserCN}
        if($Scenario.Occupied){return $Name -in $Scenario.Occupied}
        return [bool]$Scenario.Collision
    }
    function Invoke-JoinService {
        param($Config,$Action,$Payload)
        $calls.Add(@{action=$Action;payload=$Payload})
        if($Action -eq 'config'){
            if($Scenario.ConfigFailure){throw 'fixture config unavailable'}
            if($Scenario.ManualWaiting){return [pscustomobject]@{waiting_for_release=$true}}
            return [pscustomobject]@{domain=$(if($Scenario.WrongConfig){'other.test'}else{'corp.test'});
                computer_name=$(if($Scenario.ServerName){$Scenario.ServerName}else{$Config.domain_join.computer_name});employee_id=$Config.domain_join.employee_id;username='join-service@corp.test';
                password='Test-only-sensitive-value';ou_path='OU=Workstations,DC=corp,DC=test';join_state=$(if($Scenario.JoiningState){'joining'}else{'checking'})}
        }
        if($Action -eq 'name'){
            if($Scenario.NameTimeout){throw 'fixture response lost after name assignment'}
            $base=[string]$Config.domain_join.employee_id
            $suffix=if($Payload.unavailable_name -eq $base){'A'}elseif($Payload.unavailable_name.EndsWith('Z')){'Z'}else{[char]([int][char]$Payload.unavailable_name[-1]+1)}
            return [pscustomobject]@{computer_name=($base+$suffix)}
        }
        if($Scenario.FailStatus -and $Payload.stage -eq $Scenario.FailStatus){throw 'fixture post timeout'}
        return @{ok=$true}
    }
    function Rename-Computer {
        param($NewName,[switch]$Force,[switch]$PassThru,$ErrorAction)
        $renames.Add($NewName)
        if($Scenario.RenameFailure){throw 'fixture local rename denied'}
        Set-Variable -Name pendingName -Value $NewName -Scope 1
        [pscustomobject]@{HasSucceeded=(-not $Scenario.RenameUnsuccessful)}
    }
    function Add-Computer {
        param($DomainName,$Credential,$Server,[switch]$Force,[switch]$PassThru,$ErrorAction,$NewName,$Options,$OUPath)
        if($NewName){throw 'Add-Computer must not rename after domain join'}
        $native.Add(@{domain=$DomainName;name=$pendingName;options=$Options;ou=$OUPath})
        if($Scenario.NativeFailure){throw 'fixture denied Test-only-sensitive-value'}
        [pscustomobject]@{HasSucceeded=$true}
    }
    function Restart-Computer {
        param([switch]$Force,$ErrorAction)
        $reboots.Add($true)
        if($Scenario.RestartFailure){throw 'fixture restart denied'}
    }
    $employee=if($Scenario.Employee){$Scenario.Employee}else{'WFQ101755'}
    $initialName=if($employee -match '^\d+$'){$employee+'A'}else{$employee}
    $cfg=[pscustomobject]@{server_url=$(if($Scenario.Http){'http://deploy.test/pc-deploy'}else{'https://deploy.test/pc-deploy'});
        job_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';token='fixture-only-completion-token';
        allow_http=$Scenario.GlobalHttp;
        domain_join=@{domain='corp.test';computer_name=$initialName;employee_id=$employee;allow_http=$Scenario.TaskHttp;mode=$(if($Scenario.Manual){'manual'}else{'automatic'})}}
    $savedConfig=Join-Path $Directory 'config.json'
    if(Test-Path -LiteralPath $savedConfig){$cfg=[IO.File]::ReadAllText($savedConfig)|ConvertFrom-Json}
    $result=$null;$failure=$null
    try{$result=Invoke-DeploymentDomainJoin $cfg 'fixture-hardware'}catch{$failure=$_.Exception.Message}
    $journalPath=Join-Path $Directory 'domain-join-state.json'
    $journal=if(Test-Path -LiteralPath $journalPath){[IO.File]::ReadAllText($journalPath)|ConvertFrom-Json}else{$null}
    [pscustomobject]@{result=$result;failure=$failure;native=$native;renames=$renames;reboots=$reboots;calls=$calls;journal=$journal}
}
try {
    $tokens=$null;$errors=$null
    [Management.Automation.Language.Parser]::ParseFile($taskSource,[ref]$tokens,[ref]$errors)|Out-Null
    Assert-Join ($errors.Count -eq 0) 'DomainJoin parser failure'
    $directory=New-JoinCase
    $first=Invoke-JoinFixture $directory
    Assert-Join ($first.result -eq 'wait' -and -not $first.failure) 'Initial join did not wait for reboot'
    Assert-Join ($first.native.Count -eq 1 -and $first.reboots.Count -eq 0) 'Expected one join without automatic reboot'
    Assert-Join ($first.native[0].name -eq 'WFQ101755' -and $first.native[0].ou -like 'OU=Workstations,*') 'Employee name or OU was not passed'
    Assert-Join ($first.native[0].options -match 'AccountCreate' -and $first.native[0].options -match 'JoinWithNewName') 'Rename join omitted account creation'
    Assert-Join ($first.renames.Count -eq 1 -and $first.renames[0] -eq 'WFQ101755') 'Local rename must precede the domain join'
    $sameName=Invoke-JoinFixture (New-JoinCase) @{ExpectedName=$true}
    Assert-Join ($sameName.native.Count -eq 1 -and $sameName.renames.Count -eq 0 -and $sameName.reboots.Count -eq 0) 'Matching local name was renamed or rebooted unnecessarily'
    foreach($scenario in @(@{RenameFailure=$true},@{RenameUnsuccessful=$true})){
        $renameDirectory=New-JoinCase
        $renameFailed=Invoke-JoinFixture $renameDirectory $scenario
        Assert-Join ($renameFailed.result -eq 'failed' -and $renameFailed.native.Count -eq 0 -and $renameFailed.reboots.Count -eq 0) 'Failed local rename proceeded to domain join or reboot'
        Assert-Join ($renameFailed.journal.detail.Contains('Stage: native_computer_rename')) 'Local rename failure lost its stage'
        $renameAgain=Invoke-JoinFixture $renameDirectory
        Assert-Join ($renameAgain.renames.Count -eq 0 -and $renameAgain.native.Count -eq 0) 'Failed local rename was retried automatically'
    }
    Assert-Join ($first.journal.phase -eq 'restart_requested') 'Reboot journal missing'
    Assert-Join (-not ([IO.File]::ReadAllText((Join-Path $directory 'domain-join-state.json')).Contains('Test-only-sensitive-value'))) 'Password persisted in journal'
    $same=Invoke-JoinFixture $directory
    Assert-Join ($same.result -eq 'wait' -and $same.native.Count -eq 0 -and $same.reboots.Count -eq 0) 'Same boot repeated a join or reboot'
    $after=Invoke-JoinFixture $directory @{NewBoot=$true;Member=$true;ExpectedName=$true}
    Assert-Join ($after.result -eq 'ready' -and $after.native.Count -eq 0) 'Post-reboot verification failed'
    Assert-Join ($after.journal.phase -eq 'verified') 'Verified result was not persisted'
    $again=Invoke-JoinFixture $directory @{NewBoot=$true;Member=$true;ExpectedName=$true}
    Assert-Join ($again.result -eq 'ready' -and $again.calls.Count -eq 0) 'Verified journal repeated network mutation'

    foreach($scenario in @(@{Member=$true;OtherDomain=$true},@{Member=$true},
                           @{Home=$true},@{Server=$true},@{WrongConfig=$true})){
        $case=Invoke-JoinFixture (New-JoinCase) $scenario
        Assert-Join ($case.result -eq 'failed' -and $case.native.Count -eq 0 -and $case.reboots.Count -eq 0) 'A protected case performed a domain join'
    }
    $collisionDirectory=New-JoinCase
    $userCollision=Invoke-JoinFixture (New-JoinCase) @{UserCN='WFQ101755'}
    Assert-Join ($userCollision.result -eq 'wait' -and $userCollision.native[0].name -eq 'WFQ101755A' -and $userCollision.reboots.Count -eq 0) 'User CN collision did not select a safe suffix without reboot'
    $collision=Invoke-JoinFixture $collisionDirectory @{Occupied=@('WFQ101755','WFQ101755A')}
    Assert-Join ($collision.result -eq 'wait' -and $collision.native.Count -eq 1) 'Collision prevented a safe suffixed join'
    Assert-Join ($collision.native[0].name -eq 'WFQ101755B') 'Existing base and A did not select B'
    $saved=[IO.File]::ReadAllText((Join-Path $collisionDirectory 'config.json'))|ConvertFrom-Json
    Assert-Join ($saved.domain_join.employee_id -eq 'WFQ101755' -and $saved.domain_join.computer_name -eq 'WFQ101755B') 'Resolved name was not persisted with original employee'
    $collisionReboot=Invoke-JoinFixture $collisionDirectory @{NewBoot=$true;Member=$true;ComputerName='WFQ101755B'}
    Assert-Join ($collisionReboot.result -eq 'ready' -and $collisionReboot.native.Count -eq 0) 'Suffixed name was lost after reboot'
    $numeric=Invoke-JoinFixture (New-JoinCase) @{Employee='101755'}
    Assert-Join ($numeric.result -eq 'wait' -and $numeric.native[0].name -eq '101755A') 'Numeric employee ID failed to use its valid Windows name'
    $exhausted=Invoke-JoinFixture (New-JoinCase) @{Collision=$true}
    Assert-Join ($exhausted.result -eq 'failed' -and $exhausted.native.Count -eq 0) 'Exhausted suffixes performed a native join'
    $lostNameDirectory=New-JoinCase
    $lostName=Invoke-JoinFixture $lostNameDirectory @{Occupied=@('WFQ101755');NameTimeout=$true}
    Assert-Join ($lostName.result -eq 'wait' -and $lostName.native.Count -eq 0) 'Lost naming response should wait before joining'
    $recoveredName=Invoke-JoinFixture $lostNameDirectory @{ServerName='WFQ101755A'}
    Assert-Join ($recoveredName.result -eq 'wait' -and $recoveredName.native[0].name -eq 'WFQ101755A') 'Lost naming response did not resume server assignment'
    $invalidName=Invoke-JoinFixture (New-JoinCase) @{ServerName='UNRELATED'}
    Assert-Join ($invalidName.result -eq 'failed' -and $invalidName.native.Count -eq 0) 'Unrelated computer name was accepted'
    $dns=Invoke-JoinFixture (New-JoinCase) @{DnsFailure=$true}
    Assert-Join ($dns.result -eq 'wait' -and $dns.native.Count -eq 0) 'DNS outage should wait without joining'
    $trust=Invoke-JoinFixture (New-JoinCase) @{Member=$true;ExpectedName=$true;BadTrust=$true}
    Assert-Join ($trust.result -eq 'wait' -and $trust.native.Count -eq 0) 'Bad trust should never overwrite the account'
    $denied=Invoke-JoinFixture (New-JoinCase) @{NativeFailure=$true}
    Assert-Join ($denied.result -eq 'failed' -and $denied.native.Count -eq 1 -and $denied.reboots.Count -eq 0) 'Failed native join handling incorrect'
    Assert-Join (-not $denied.journal.detail.Contains('Test-only-sensitive-value')) 'Native failure leaked password'
    $unknownDirectory=New-JoinCase
    [IO.File]::WriteAllText((Join-Path $unknownDirectory 'domain-join-state.json'),'{"phase":"attempted","boot":"old","detail":""}')
    $unknown=Invoke-JoinFixture $unknownDirectory
    Assert-Join ($unknown.result -eq 'failed' -and $unknown.native.Count -eq 0) 'Unknown prior outcome retried join'

    $lostDirectory=New-JoinCase
    $lost=Invoke-JoinFixture $lostDirectory @{FailStatus='restarting'}
    Assert-Join ($lost.failure -and $lost.native.Count -eq 1 -and $lost.journal.phase -eq 'joined') 'Lost response did not preserve successful join'
    $resumed=Invoke-JoinFixture $lostDirectory
    Assert-Join ($resumed.result -eq 'wait' -and $resumed.native.Count -eq 0 -and $resumed.reboots.Count -eq 0) 'Resume repeated join or reboot'
    $http=Invoke-JoinFixture (New-JoinCase) @{Http=$true}
    Assert-Join ($http.failure -and $http.calls.Count -eq 0 -and $http.native.Count -eq 0) 'HTTP leaked join credentials'
    foreach($case in @(@{Http=$true;GlobalHttp=$true},@{Http=$true;TaskHttp=$true},
                       @{Http=$true;GlobalHttp='true';TaskHttp=$true},@{Http=$true;GlobalHttp=$true;TaskHttp='true'})){
        $blocked=Invoke-JoinFixture (New-JoinCase) $case
        Assert-Join ($blocked.failure -and $blocked.calls.Count -eq 0 -and $blocked.native.Count -eq 0) 'Incomplete or string HTTP opt-in reached credentials'
    }
    $httpDirectory=New-JoinCase
    $approvedHttp=Invoke-JoinFixture $httpDirectory @{Http=$true;GlobalHttp=$true;TaskHttp=$true}
    Assert-Join ($approvedHttp.result -eq 'wait' -and $approvedHttp.native.Count -eq 1 -and $approvedHttp.reboots.Count -eq 0) 'Explicit HTTP opt-in did not complete native join without reboot'
    $httpVerified=Invoke-JoinFixture $httpDirectory @{Http=$true;GlobalHttp=$true;TaskHttp=$true;NewBoot=$true;Member=$true;ExpectedName=$true}
    Assert-Join ($httpVerified.result -eq 'ready' -and $httpVerified.native.Count -eq 0) 'HTTP opt-in lost post-reboot trust verification'
    $manualDirectory=New-JoinCase
    $waiting=Invoke-JoinFixture $manualDirectory @{Manual=$true;ManualWaiting=$true}
    Assert-Join ($waiting.result -eq 'wait' -and $waiting.native.Count -eq 0 -and $waiting.reboots.Count -eq 0) 'Manual waiting performed a join or reboot'
    Assert-Join ($waiting.calls.Count -eq 1 -and $waiting.calls[0].action -eq 'config') 'Manual waiting entered domain work before release'
    Assert-Join ($waiting.calls[0].payload.os_build -eq 26100 -and $waiting.calls[0].payload.oobe_done) 'Manual readiness omitted the installed OS proof'
    Assert-Join ($null -eq $waiting.journal) 'Waiting was incorrectly recorded as a native join attempt'
    $unavailable=Invoke-JoinFixture $manualDirectory @{Manual=$true;ConfigFailure=$true}
    Assert-Join ($unavailable.result -eq 'wait' -and $unavailable.native.Count -eq 0 -and $unavailable.reboots.Count -eq 0) 'Unavailable release service caused a join or restart'
    $released=Invoke-JoinFixture $manualDirectory @{Manual=$true}
    Assert-Join ($released.native.Count -eq 1 -and $released.reboots.Count -eq 0) 'Admin release did not perform exactly one join without reboot'
    $manualReboot=Invoke-JoinFixture $manualDirectory @{Manual=$true;NewBoot=$true;Member=$true;ExpectedName=$true}
    Assert-Join ($manualReboot.result -eq 'ready' -and $manualReboot.native.Count -eq 0) 'Manual mode attempted to fetch recycled credentials after reboot'

    $checkingDirectory=New-JoinCase
    $checkingOffline=Invoke-JoinFixture $checkingDirectory @{FailStatus='checking'}
    Assert-Join ($checkingOffline.result -eq 'wait' -and $checkingOffline.native.Count -eq 0 -and $checkingOffline.reboots.Count -eq 0) 'Platform checking failure became a terminal domain failure'
    Assert-Join ($checkingOffline.journal.phase -eq 'waiting_network') 'Platform outage did not preserve a resumable diagnostic'
    Assert-Join ($checkingOffline.journal.detail.Contains('Stage: platform_status_checking') -and $checkingOffline.journal.detail.Contains('Target AD domain: corp.test')) 'Diagnostic confused the platform endpoint with the AD domain'
    $checkingRecovered=Invoke-JoinFixture $checkingDirectory
    Assert-Join ($checkingRecovered.native.Count -eq 1 -and $checkingRecovered.reboots.Count -eq 0) 'Recovered checking connection did not perform the first join without reboot'
    $joiningDirectory=New-JoinCase
    $joiningOffline=Invoke-JoinFixture $joiningDirectory @{FailStatus='joining'}
    Assert-Join ($joiningOffline.result -eq 'wait' -and $joiningOffline.native.Count -eq 0) 'Lost pre-join acknowledgement performed a native join'
    $joiningRecovered=Invoke-JoinFixture $joiningDirectory @{JoiningState=$true}
    Assert-Join ($joiningRecovered.native.Count -eq 1 -and $joiningRecovered.reboots.Count -eq 0) 'Lost joining acknowledgement did not resume without reboot'
    Assert-Join (@($joiningRecovered.calls | Where-Object {$_.payload.stage -eq 'checking'}).Count -eq 0) 'Resume tried to regress a server joining state'
    $repeatDirectory=New-JoinCase
    $repeatFirst=Invoke-JoinFixture $repeatDirectory @{FailStatus='restarting'}
    $repeatOffline=Invoke-JoinFixture $repeatDirectory @{FailStatus='restarting'}
    Assert-Join ($repeatOffline.result -eq 'wait' -and $repeatOffline.journal.phase -eq 'joined' -and $repeatOffline.native.Count -eq 0) 'Repeated callback outage discarded a successful native join'
    $repeatRecovered=Invoke-JoinFixture $repeatDirectory
    Assert-Join ($repeatRecovered.native.Count -eq 0 -and $repeatRecovered.reboots.Count -eq 0) 'Successful join or reboot was repeated after reconnect'
    $verifyDirectory=New-JoinCase
    $verifyFirst=Invoke-JoinFixture $verifyDirectory
    $verifyOffline=Invoke-JoinFixture $verifyDirectory @{NewBoot=$true;Member=$true;ExpectedName=$true;FailStatus='verified'}
    Assert-Join ($verifyOffline.result -eq 'wait' -and $verifyOffline.journal.phase -eq 'restart_requested') 'Lost verification callback became a false native failure'
    $verifyRecovered=Invoke-JoinFixture $verifyDirectory @{NewBoot=$true;Member=$true;ExpectedName=$true}
    Assert-Join ($verifyRecovered.result -eq 'ready' -and $verifyRecovered.native.Count -eq 0) 'Verification reconnect repeated the domain join'

    $failedReportDirectory=New-JoinCase
    $failedReport=Invoke-JoinFixture $failedReportDirectory @{NativeFailure=$true;FailStatus='failed'}
    Assert-Join ($failedReport.result -eq 'wait' -and -not $failedReport.failure) 'Failure reporting outage escaped instead of waiting safely'
    $firstFailure=[IO.File]::ReadAllText((Join-Path $failedReportDirectory 'domain-join-state.json'))
    Assert-Join ($failedReport.journal.detail.Contains('Stage: native_domain_join')) 'Original native failure was not saved'
    $repeatedReport=Invoke-JoinFixture $failedReportDirectory @{FailStatus='failed'}
    Assert-Join ($repeatedReport.result -eq 'wait' -and -not $repeatedReport.failure) 'Repeated failure reporting outage escaped'
    Assert-Join (([IO.File]::ReadAllText((Join-Path $failedReportDirectory 'domain-join-state.json'))) -ceq $firstFailure) 'Callback rejection overwrote the first domain failure'
    Assert-Join ($repeatedReport.native.Count -eq 0 -and $repeatedReport.reboots.Count -eq 0) 'Reporting a failed task retried a join or reboot'
    $failureDelivered=Invoke-JoinFixture $failedReportDirectory
    Assert-Join ($failureDelivered.result -eq 'failed' -and $failureDelivered.calls[0].payload.detail -ceq $failedReport.journal.detail) 'Recovered callback lost the original diagnosis'
    Assert-Join ($failureDelivered.native.Count -eq 0 -and $failureDelivered.reboots.Count -eq 0) 'Recovered failure callback changed machine state'

    $timeoutDirectory=New-JoinCase
    foreach($name in @('Finalize.ps1','DeviceInfo.ps1')){
        [IO.File]::Copy((Join-Path $PSScriptRoot ('pc_deploy\agent\'+$name)),(Join-Path $timeoutDirectory $name))
    }
    [IO.File]::WriteAllText((Join-Path $timeoutDirectory 'domain-join-state.json'),$firstFailure)
    $timeoutConfig=@{server_url='https://deploy.test/pc-deploy';job_id='fixture';hardware_uuid='fixture-hardware';
        token='fixture-only-token';expires_at=0;domain_join=@{domain='corp.test';mode='manual'}}
    [IO.File]::WriteAllText((Join-Path $timeoutDirectory 'config.json'),($timeoutConfig|ConvertTo-Json -Depth 4))
    $timeoutRunner=@'
function Invoke-RestMethod {
    param($Method,$Uri,$Headers,$ContentType,$Body,$TimeoutSec,[switch]$UseBasicParsing)
    [IO.File]::WriteAllBytes((Join-Path $PSScriptRoot 'sent.json'),$Body)
}
& (Join-Path $PSScriptRoot 'Finalize.ps1')
exit $LASTEXITCODE
'@
    [IO.File]::WriteAllText((Join-Path $timeoutDirectory 'Timeout.ps1'),$timeoutRunner)
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -File (Join-Path $timeoutDirectory 'Timeout.ps1')
    Assert-Join ($LASTEXITCODE -eq 1) 'Timed-out finalizer did not exit as failed'
    Assert-Join (([IO.File]::ReadAllText((Join-Path $timeoutDirectory 'domain-join-state.json'))) -ceq $firstFailure) 'Finalizer timeout replaced the original failure journal'
    $timeoutSent=[IO.File]::ReadAllText((Join-Path $timeoutDirectory 'sent.json'))|ConvertFrom-Json
    Assert-Join ($timeoutSent.detail -ceq $failedReport.journal.detail) 'Finalizer timeout reported a generic error instead of the first diagnosis'


    # Exercise finalizer startup before Windows is ready, with all OS/network calls intercepted.
    foreach($diagnosticCase in @('waiting','error','identity')){
        $directory=New-JoinCase
        foreach($name in @('Finalize.ps1','DeviceInfo.ps1')){
            [IO.File]::Copy((Join-Path $PSScriptRoot ('pc_deploy\agent\'+$name)),(Join-Path $directory $name))
        }
        $fixtureConfig=@{server_url='https://deploy.test/pc-deploy';job_id='diagnostic-fixture';
            hardware_uuid=[guid]::NewGuid().ToString();token='fixture-only-token';diagnostic_case=$diagnosticCase}
        [IO.File]::WriteAllText((Join-Path $directory 'config.json'),($fixtureConfig|ConvertTo-Json))
        $runner=@'
$ErrorActionPreference='Stop'
$fixtureConfig=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'config.json'))|ConvertFrom-Json
function Get-CimInstance {
    param($ClassName)
    if($ClassName -ne 'Win32_ComputerSystemProduct'){throw 'Unexpected hardware query'}
    $identity=if($fixtureConfig.diagnostic_case -eq 'identity'){[guid]::NewGuid().ToString()}else{$fixtureConfig.hardware_uuid}
    return @{UUID=$identity}
}
function Get-ItemProperty {
    param($Path,$ErrorAction)
    if($fixtureConfig.diagnostic_case -eq 'error'){throw 'Fixture setup query failed fixture-only-token'}
    return @{ImageState='IMAGE_STATE_UNDEPLOYABLE';SystemSetupInProgress=1;OOBEInProgress=1}
}
function Invoke-RestMethod {
    param($Method,$Uri,$Headers,$ContentType,$Body,$TimeoutSec,[switch]$UseBasicParsing)
    [IO.File]::WriteAllBytes((Join-Path $PSScriptRoot 'status.json'),$Body)
}
function Start-Sleep {param($Seconds) exit 42}
function Unregister-ScheduledTask {throw 'Pending startup must not remove its scheduled task'}
& (Join-Path $PSScriptRoot 'Finalize.ps1')
exit $LASTEXITCODE
'@
        [IO.File]::WriteAllText((Join-Path $directory 'Startup.ps1'),$runner)
        & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -File (Join-Path $directory 'Startup.ps1')
        Assert-Join ($LASTEXITCODE -eq 42) 'Finalizer did not wait for a safe ready state'
        $journal=[IO.File]::ReadAllText((Join-Path $directory 'finalize-state.json'))|ConvertFrom-Json
        $expectedPhase=if($diagnosticCase -eq 'waiting'){'waiting_setup'}else{'waiting_retry'}
        Assert-Join ($journal.phase -eq $expectedPhase) 'Startup diagnosis did not identify the blocked phase'
        Assert-Join (-not $journal.detail.Contains('fixture-only-token')) 'Startup diagnosis leaked the completion token'
        Assert-Join (-not (Test-Path -LiteralPath (Join-Path $directory 'domain-join-state.json'))) 'Finalizer joined a domain before a validated Windows ready state'
        $status=Join-Path $directory 'status.json'
        if($diagnosticCase -eq 'identity'){
            Assert-Join (-not (Test-Path -LiteralPath $status)) 'Foreign hardware sent an authorized task diagnosis'
        }else{
            $sent=[IO.File]::ReadAllText($status)|ConvertFrom-Json
            Assert-Join ($sent.phase -eq $expectedPhase -and $sent.hardware_uuid -ceq $fixtureConfig.hardware_uuid) 'Platform did not receive the same safe startup diagnosis'
        }
    }

    function Test-JoinHttpDetail {
        . $taskSource
        $config=[pscustomobject]@{server_url='http://deploy.test/pc-deploy';token='fixture-only-completion-token';domain_join=@{domain='corp.test'}}
        $record=[Management.Automation.ErrorRecord]::new([Exception]::new('HTTP 400 Bad Request'),'WebCmdletWebResponseException',[Management.Automation.ErrorCategory]::InvalidOperation,$null)
        $record.ErrorDetails=[Management.Automation.ErrorDetails]::new('{"error":"Task credentials expired. fixture-only-completion-token Test-only-sensitive-value"}')
        $detail=Get-JoinFailureDetail $record $config 'platform_config' 'Test-only-sensitive-value'
        Assert-Join ($detail.Contains('Service response: ') -and $detail.Contains('Task credentials expired.')) 'HTTP response reason was discarded'
        Assert-Join (-not $detail.Contains('fixture-only-completion-token') -and -not $detail.Contains('Test-only-sensitive-value')) 'HTTP response diagnostics leaked credentials'
        $record.ErrorDetails=[Management.Automation.ErrorDetails]::new(('x'*5000)+'fixture-only-completion-token')
        Assert-Join ((Get-JoinFailureDetail $record $config 'platform_config').Length -le 4000) 'HTTP response diagnosis exceeded the platform limit'
    }
    Test-JoinHttpDetail

    function Test-JoinWire {
        . $taskSource
        $capture=@{}
        function Invoke-RestMethod {
            param($Method,$Uri,$Headers,$ContentType,$Body,$TimeoutSec,[switch]$UseBasicParsing)
            $capture.type=$ContentType;$capture.body=$Body
            return @{ok=$true}
        }
        $text=-join ([char[]]@(0x57df,0x540d,0x89e3,0x6790,0x5931,0x8d25))
        $config=[pscustomobject]@{server_url='https://deploy.test/pc-deploy';job_id='fixture';token='fixture-only-token'}
        Invoke-JoinService $config 'status' @{detail=$text} | Out-Null
        Assert-Join ($capture.body -is [byte[]] -and $capture.type -match 'charset=utf-8') 'Unicode diagnostics were sent with a default string encoding'
        $parsed=[Text.Encoding]::UTF8.GetString($capture.body)|ConvertFrom-Json
        Assert-Join ($parsed.detail -ceq $text) 'Chinese diagnostics did not survive the outgoing JSON bytes'
    }
    Test-JoinWire
    Write-Output "$count isolated domain join checks passed. No real directory, machine name, membership or reboot was changed."
} finally {
    $resolved=[IO.Path]::GetFullPath($taskRoot)
    $temporary=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if(-not $resolved.StartsWith($temporary,[StringComparison]::OrdinalIgnoreCase) -or
       -not ([IO.Path]::GetFileName($resolved)).StartsWith('pcdeploy-domain-test-')){throw 'Unsafe test cleanup path'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
