# Loaded only by the protected post-install finalizer, never by WinPE.
function Assert-JoinTransport {
    param($Config)
    $scheme = ([uri]$Config.server_url).Scheme
    if ($scheme -eq 'https') { return }
    if ($scheme -eq 'http' -and $Config.allow_http -is [bool] -and $Config.allow_http -and
        $Config.domain_join.allow_http -is [bool] -and $Config.domain_join.allow_http) { return }
    throw 'Domain join requires HTTPS unless HTTP is explicitly approved for this task.'
}
function Invoke-JoinService {
    param($Config, [string]$Action, $Payload)
    Assert-JoinTransport $Config
    $json = $Payload | ConvertTo-Json -Depth 8 -Compress
    Invoke-RestMethod -UseBasicParsing -Method Post -Uri ($Config.server_url + '/api/agent/jobs/' + $Config.job_id + '/domain-join/' + $Action) `
        -Headers @{Authorization=('Bearer ' + $Config.token)} -ContentType 'application/json; charset=utf-8' `
        -Body ([Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec 30
}
function Get-JoinFailureDetail {
    param([Management.Automation.ErrorRecord]$Failure, $Config, [string]$Stage,
          [string]$Password = '', [string]$Controller = '')
    $lines = @(('Stage: ' + $Stage), ('Platform: ' + $Config.server_url),
        ('Target AD domain: ' + $Config.domain_join.domain),
        ('Domain controller: ' + $(if ($Controller) { $Controller } else { '(not resolved)' })),
        ('Error: ' + $Failure.Exception.Message),
        ('Error ID: ' + $Failure.FullyQualifiedErrorId),
        ('Script line: ' + $Failure.InvocationInfo.ScriptLineNumber))
    if ($Failure.ErrorDetails.Message) {
        $lines += ('Service response: ' + $Failure.ErrorDetails.Message)
    }
    $detail = $lines -join [Environment]::NewLine
    foreach ($secret in @($Password, $Config.token)) {
        if ($secret) { $detail = $detail.Replace([string]$secret, '[redacted]') }
    }
    if ($detail.Length -gt 4000) { $detail = $detail.Substring(0,4000) }
    return $detail
}
function Save-JoinJournal {
    param([string]$Phase, [string]$Boot, [string]$Detail = '')
    $value = @{phase=$Phase; boot=$Boot; detail=$Detail} | ConvertTo-Json -Compress
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'domain-join-state.json'), $value, (New-Object Text.UTF8Encoding($false)))
}
function Send-JoinState {
    param($Config, [string]$Hardware, [string]$Stage, [string]$Detail = '')
    $payload = @{hardware_uuid=$Hardware; stage=$Stage; detail=$Detail}
    if ($Config.device_info) { $payload.device_info = $Config.device_info }
    if ($Stage -eq 'verified') {
        $payload.domain = $Config.domain_join.domain
        $payload.computer_name = $Config.domain_join.computer_name
        $payload.secure_channel = $true
    }
    Invoke-JoinService $Config 'status' $payload | Out-Null
}
function Test-JoinNameExists {
    param([string]$Controller, [string]$Domain, [string]$Name, $Credential, [string]$OUPath)
    Add-Type -AssemblyName System.DirectoryServices
    $base = ($Domain.Split('.') | ForEach-Object { 'DC=' + $_ }) -join ','
    $entry = $null; $searcher = $null; $matches = $null
    try {
        $flags = [DirectoryServices.AuthenticationTypes]::Secure -bor
            [DirectoryServices.AuthenticationTypes]::Signing -bor [DirectoryServices.AuthenticationTypes]::Sealing
        $entry = [DirectoryServices.DirectoryEntry]::new(
            ('LDAP://' + $Controller + '/' + $base), $Credential.UserName,
            $Credential.GetNetworkCredential().Password, $flags)
        $searcher = [DirectoryServices.DirectorySearcher]::new($entry)
        $searcher.Filter = '(|(sAMAccountName=' + $Name + '$)(cn=' + $Name + '))'
        $searcher.ClientTimeout = [TimeSpan]::FromSeconds(15)
        $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds(15)
        $matches = $searcher.FindAll()
        foreach ($match in $matches) {
            if ([string]$match.Properties.samaccountname[0] -ieq ($Name + '$') -or
                ($OUPath -and [string]$match.Properties.distinguishedname[0] -ieq ('CN=' + $Name + ',' + $OUPath))) { return $true }
        }
        return $false
    } finally {
        if ($matches) { $matches.Dispose() }
        if ($searcher) { $searcher.Dispose() }
        if ($entry) { $entry.Dispose() }
    }
}
function Set-JoinComputerName {
    param($Config, [string]$Name)
    $base = [string]$Config.domain_join.employee_id
    if ($base -cnotmatch '^[A-Z0-9](?:[A-Z0-9-]{0,12}[A-Z0-9])?$' -or
        ($Name -cne $base -and $Name -cnotmatch ('^' + [regex]::Escape($base) + '[A-Z]$')) -or
        $Name -match '^\d+$') { throw 'The assigned computer name is outside this employee ID and its A-Z suffixes.' }
    if ([string]$Config.domain_join.computer_name -cne $Name) {
        $Config.domain_join.computer_name = $Name
        [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'config.json'),
            ($Config | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
    }
}
function Invoke-DeploymentDomainJoin {
    param($Config, [string]$Hardware)
    Assert-JoinTransport $Config
    $journalPath = Join-Path $PSScriptRoot 'domain-join-state.json'
    $journal = if (Test-Path -LiteralPath $journalPath) {
        [IO.File]::ReadAllText($journalPath) | ConvertFrom-Json
    } else { $null }
    $os = Get-CimInstance Win32_OperatingSystem
    $boot = ([DateTime]$os.LastBootUpTime).ToUniversalTime().ToString('o')
    $configuration = $null; $credential = $null; $controller = ''; $operation = 'initial_checks'
    try {
        if ($journal.phase -eq 'failed') {
            try { Send-JoinState $Config $Hardware 'failed' $journal.detail }
            catch { return 'wait' }
            return 'failed'
        }
        if ($os.ProductType -ne 1) { throw 'Automatic domain join is restricted to newly installed workstations.' }
        $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
        if ($edition -match '^(Core|Home)') { throw 'This Windows edition cannot join an AD domain. Use Pro, Enterprise or Education.' }
        if ($journal.phase -in @('joined', 'restart_requested') -and
            ([DateTime]$journal.boot).ToUniversalTime().ToString('o') -ceq $boot) {
            if ($journal.phase -eq 'joined') {
                try { Send-JoinState $Config $Hardware 'restarting' }
                catch {
                    Save-JoinJournal 'joined' $boot (Get-JoinFailureDetail $_ $Config 'platform_status_restarting')
                    return 'wait'
                }
                Save-JoinJournal 'restart_requested' $boot
            }
            return 'wait'
        }
        if ($Config.domain_join.mode -eq 'manual' -and
            $journal.phase -notin @('attempted', 'joined', 'restart_requested', 'verified')) {
            $setup = Get-ItemProperty 'HKLM:\SYSTEM\Setup'
            $state = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State').ImageState
            try {
                $configuration = Invoke-JoinService $Config 'config' @{
                    hardware_uuid=$Hardware; computer_name=$env:COMPUTERNAME;
                    os_build=[int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber;
                    image_state=$state; oobe_done=($setup.SystemSetupInProgress -eq 0 -and $setup.OOBEInProgress -eq 0);
                    device_info=$Config.device_info
                }
            } catch {
                Save-JoinJournal 'waiting_network' $boot (Get-JoinFailureDetail $_ $Config 'platform_config')
                return 'wait'
            }
            if ($configuration.waiting_for_release -is [bool] -and $configuration.waiting_for_release) { return 'wait' }
        }
        $system = Get-CimInstance Win32_ComputerSystem
        $domain = [string]$Config.domain_join.domain
        $name = [string]$Config.domain_join.computer_name
        if ($system.PartOfDomain) {
            if ([string]$system.Domain -ine $domain -or [string]$system.Name -ine $name) {
                throw 'The restored system already belongs to a domain or computer name different from this task. Automatic unjoin or overwrite is blocked.'
            }
            $trusted = $false
            try { $trusted = [bool](Test-ComputerSecureChannel -ErrorAction Stop) } catch { }
            if (-not $trusted) {
                $stage = if ($journal.phase -in @('joined', 'restart_requested', 'verified')) { 'restarting' } else { 'checking' }
                try { Send-JoinState $Config $Hardware $stage 'Waiting for the domain controller and a valid machine secure channel.' }
                catch { return 'wait' }
                return 'wait'
            }
            if ($journal.phase -ne 'verified') {
                try { Send-JoinState $Config $Hardware 'verified' }
                catch { return 'wait' }
                Save-JoinJournal 'verified' $boot
            }
            return 'ready'
        }
        if ($journal.phase -in @('attempted', 'joined', 'restart_requested', 'verified')) {
            throw 'A domain join was already attempted but domain membership could not be verified. No automatic retry will be made.'
        }
        try {
            $records = @(Resolve-DnsName -Name ('_ldap._tcp.dc._msdcs.' + $domain) -Type SRV -DnsOnly -ErrorAction Stop)
            $record = $records | Where-Object NameTarget | Select-Object -First 1
            if (-not $record) { throw 'No domain controller SRV record was returned.' }
            $controller = ([string]$record.NameTarget).TrimEnd('.')
        } catch {
            $detail = Get-JoinFailureDetail $_ $Config 'domain_dns_lookup'
            Save-JoinJournal 'waiting_network' $boot $detail
            try { Send-JoinState $Config $Hardware 'checking' $detail } catch { }
            return 'wait'
        }
        if (-not $configuration) {
            try { $configuration = Invoke-JoinService $Config 'config' @{hardware_uuid=$Hardware;device_info=$Config.device_info} }
            catch {
                Save-JoinJournal 'waiting_network' $boot (Get-JoinFailureDetail $_ $Config 'platform_config' '' $controller)
                return 'wait'
            }
        }
        if ([string]$configuration.domain -cne $domain -or
            [string]$configuration.employee_id -cne [string]$Config.domain_join.employee_id) {
            throw 'Domain join configuration does not match this installation task.'
        }
        if ($configuration.join_state -ne 'joining') {
            $previous = if ($journal.phase -eq 'waiting_network') { $journal.detail } else { '' }
            try { Send-JoinState $Config $Hardware 'checking' $previous }
            catch {
                Save-JoinJournal 'waiting_network' $boot (Get-JoinFailureDetail $_ $Config 'platform_status_checking' $configuration.password $controller)
                return 'wait'
            }
            if ($journal.phase -eq 'waiting_network') { Save-JoinJournal 'checking' $boot }
        }
        Set-JoinComputerName $Config ([string]$configuration.computer_name)
        $name = [string]$Config.domain_join.computer_name
        $secret = ConvertTo-SecureString $configuration.password -AsPlainText -Force
        $credential = New-Object Management.Automation.PSCredential($configuration.username, $secret)
        $operation = 'ad_computer_name_lookup'
        $available = $false
        for ($attempt = 0; $attempt -lt 27; $attempt++) {
            if (-not (Test-JoinNameExists $controller $domain $name $credential ([string]$configuration.ou_path))) { $available = $true; break }
            try {
                $assigned = Invoke-JoinService $Config 'name' @{hardware_uuid=$Hardware; unavailable_name=$name}
            } catch {
                if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -lt 500) {
                    throw 'No available employee computer name remains, or this task no longer permits naming. No existing AD account was replaced.'
                }
                return 'wait'
            }
            Set-JoinComputerName $Config ([string]$assigned.computer_name)
            $name = [string]$Config.domain_join.computer_name
        }
        if (-not $available) { throw 'The employee computer name and A-Z suffixes are occupied. No existing AD account was replaced.' }
        try { Send-JoinState $Config $Hardware 'joining' }
        catch {
            Save-JoinJournal 'waiting_network' $boot (Get-JoinFailureDetail $_ $Config 'platform_status_joining' $configuration.password $controller)
            return 'wait'
        }
        # Never repeat a native rename/join after a crash.
        Save-JoinJournal 'attempted' $boot
        $parameters = @{DomainName=$domain; Credential=$credential; Server=$controller;
            Force=$true; PassThru=$true; ErrorAction='Stop'}
        if ([string]$system.Name -ine $name) {
            $operation = 'native_computer_rename'
            $renamed = Rename-Computer -NewName $name -Force -PassThru -ErrorAction Stop
            if (-not $renamed.HasSucceeded) { throw 'Local computer rename failed.' }
            $parameters.Options='AccountCreate,JoinWithNewName'
        }
        if ($configuration.ou_path) { $parameters.OUPath=[string]$configuration.ou_path }
        $operation = 'native_domain_join'
        $joined = Add-Computer @parameters
        if (-not $joined.HasSucceeded) { throw 'Add-Computer did not report success.' }
        Save-JoinJournal 'joined' $boot
    } catch {
        $detail = Get-JoinFailureDetail $_ $Config $operation $configuration.password $controller
        Save-JoinJournal 'failed' $boot $detail
        try { Send-JoinState $Config $Hardware 'failed' $detail }
        catch { return 'wait' }
        return 'failed'
    } finally {
        $credential=$null; $configuration=$null
    }
    # Resume reporting without another join.
    Send-JoinState $Config $Hardware 'restarting'
    Save-JoinJournal 'restart_requested' $boot
    return 'wait'
}
