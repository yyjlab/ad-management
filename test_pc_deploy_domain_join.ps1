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
        param($Controller,$Domain,$Name,$Credential)
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
    function Add-Computer {
        param($DomainName,$Credential,$Server,[switch]$Force,[switch]$PassThru,$ErrorAction,$NewName,$Options,$OUPath)
        $native.Add(@{domain=$DomainName;name=$NewName;options=$Options;ou=$OUPath})
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
    [pscustomobject]@{result=$result;failure=$failure;native=$native;reboots=$reboots;calls=$calls;journal=$journal}
}
try {
    $tokens=$null;$errors=$null
    [Management.Automation.Language.Parser]::ParseFile($taskSource,[ref]$tokens,[ref]$errors)|Out-Null
    Assert-Join ($errors.Count -eq 0) 'DomainJoin parser failure'
    $directory=New-JoinCase
    $first=Invoke-JoinFixture $directory
    Assert-Join ($first.result -eq 'wait' -and -not $first.failure) 'Initial join did not wait for reboot'
    Assert-Join ($first.native.Count -eq 1 -and $first.reboots.Count -eq 1) 'Expected one join and one reboot'
    Assert-Join ($first.native[0].name -eq 'WFQ101755' -and $first.native[0].ou -like 'OU=Workstations,*') 'Employee name or OU was not passed'
    Assert-Join ($first.native[0].options -match 'AccountCreate' -and $first.native[0].options -match 'JoinWithNewName') 'Rename join omitted account creation'
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
    Assert-Join ($resumed.result -eq 'wait' -and $resumed.native.Count -eq 0 -and $resumed.reboots.Count -eq 1) 'Resume repeated join'
    $http=Invoke-JoinFixture (New-JoinCase) @{Http=$true}
    Assert-Join ($http.failure -and $http.calls.Count -eq 0 -and $http.native.Count -eq 0) 'HTTP leaked join credentials'
    foreach($case in @(@{Http=$true;GlobalHttp=$true},@{Http=$true;TaskHttp=$true},
                       @{Http=$true;GlobalHttp='true';TaskHttp=$true},@{Http=$true;GlobalHttp=$true;TaskHttp='true'})){
        $blocked=Invoke-JoinFixture (New-JoinCase) $case
        Assert-Join ($blocked.failure -and $blocked.calls.Count -eq 0 -and $blocked.native.Count -eq 0) 'Incomplete or string HTTP opt-in reached credentials'
    }
    $httpDirectory=New-JoinCase
    $approvedHttp=Invoke-JoinFixture $httpDirectory @{Http=$true;GlobalHttp=$true;TaskHttp=$true}
    Assert-Join ($approvedHttp.result -eq 'wait' -and $approvedHttp.native.Count -eq 1 -and $approvedHttp.reboots.Count -eq 1) 'Explicit HTTP opt-in did not complete native join once'
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
    Assert-Join ($released.native.Count -eq 1 -and $released.reboots.Count -eq 1) 'Admin release did not perform exactly one join and reboot'
    $manualReboot=Invoke-JoinFixture $manualDirectory @{Manual=$true;NewBoot=$true;Member=$true;ExpectedName=$true}
    Assert-Join ($manualReboot.result -eq 'ready' -and $manualReboot.native.Count -eq 0) 'Manual mode attempted to fetch recycled credentials after reboot'

    $checkingDirectory=New-JoinCase
    $checkingOffline=Invoke-JoinFixture $checkingDirectory @{FailStatus='checking'}
    Assert-Join ($checkingOffline.result -eq 'wait' -and $checkingOffline.native.Count -eq 0 -and $checkingOffline.reboots.Count -eq 0) 'Platform checking failure became a terminal domain failure'
    Assert-Join ($checkingOffline.journal.phase -eq 'waiting_network') 'Platform outage did not preserve a resumable diagnostic'
    Assert-Join ($checkingOffline.journal.detail.Contains('Stage: platform_status_checking') -and $checkingOffline.journal.detail.Contains('Target AD domain: corp.test')) 'Diagnostic confused the platform endpoint with the AD domain'
    $checkingRecovered=Invoke-JoinFixture $checkingDirectory
    Assert-Join ($checkingRecovered.native.Count -eq 1 -and $checkingRecovered.reboots.Count -eq 1) 'Recovered checking connection did not perform the first join once'
    $joiningDirectory=New-JoinCase
    $joiningOffline=Invoke-JoinFixture $joiningDirectory @{FailStatus='joining'}
    Assert-Join ($joiningOffline.result -eq 'wait' -and $joiningOffline.native.Count -eq 0) 'Lost pre-join acknowledgement performed a native join'
    $joiningRecovered=Invoke-JoinFixture $joiningDirectory @{JoiningState=$true}
    Assert-Join ($joiningRecovered.native.Count -eq 1 -and $joiningRecovered.reboots.Count -eq 1) 'Lost joining acknowledgement did not resume safely'
    Assert-Join (@($joiningRecovered.calls | Where-Object {$_.payload.stage -eq 'checking'}).Count -eq 0) 'Resume tried to regress a server joining state'
    $repeatDirectory=New-JoinCase
    $repeatFirst=Invoke-JoinFixture $repeatDirectory @{FailStatus='restarting'}
    $repeatOffline=Invoke-JoinFixture $repeatDirectory @{FailStatus='restarting'}
    Assert-Join ($repeatOffline.result -eq 'wait' -and $repeatOffline.journal.phase -eq 'joined' -and $repeatOffline.native.Count -eq 0) 'Repeated callback outage discarded a successful native join'
    $repeatRecovered=Invoke-JoinFixture $repeatDirectory
    Assert-Join ($repeatRecovered.native.Count -eq 0 -and $repeatRecovered.reboots.Count -eq 1) 'Successful join was repeated after reconnect'
    $verifyDirectory=New-JoinCase
    $verifyFirst=Invoke-JoinFixture $verifyDirectory
    $verifyOffline=Invoke-JoinFixture $verifyDirectory @{NewBoot=$true;Member=$true;ExpectedName=$true;FailStatus='verified'}
    Assert-Join ($verifyOffline.result -eq 'wait' -and $verifyOffline.journal.phase -eq 'restart_requested') 'Lost verification callback became a false native failure'
    $verifyRecovered=Invoke-JoinFixture $verifyDirectory @{NewBoot=$true;Member=$true;ExpectedName=$true}
    Assert-Join ($verifyRecovered.result -eq 'ready' -and $verifyRecovered.native.Count -eq 0) 'Verification reconnect repeated the domain join'

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
