$ErrorActionPreference = 'Stop'
$hardware=''
function Save-FinalizerState {
    param([string]$Phase,[string]$Detail='')
    try {
        if($cfg.token){$Detail=$Detail.Replace([string]$cfg.token,'[REDACTED]')}
        if($Detail.Length -gt 1600){$Detail=$Detail.Substring(0,1600)}
        $body=@{phase=$Phase;hardware_uuid=$hardware;detail=$Detail;updated=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress
        [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'finalize-state.json'),$body,[Text.UTF8Encoding]::new($false))
        if($hardware -and $hardware -ceq $cfg.hardware_uuid){
            Invoke-RestMethod -UseBasicParsing -Method Post -Uri ($cfg.server_url+'/api/agent/jobs/'+$cfg.job_id+'/post-install/status') -Headers @{Authorization=('Bearer '+$cfg.token)} -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 3|Out-Null
        }
    } catch { }
}
Save-FinalizerState 'starting'
try {
$cfg = Get-Content -LiteralPath "$PSScriptRoot\config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
$server = [uri]$cfg.server_url
if (-not $server.IsAbsoluteUri -or $server.Scheme -notin @('http', 'https') -or
    ($server.Scheme -eq 'http' -and -not ($cfg.allow_http -is [bool] -and $cfg.allow_http)) -or $server.UserInfo -or
    $server.Query -or $server.Fragment -or $server.AbsolutePath -cne '/pc-deploy') {
    throw 'An approved HTTP/HTTPS deployment URL is required.'
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($server.Scheme -eq 'https' -and $cfg.ca_pem) {
    $encoded = $cfg.ca_pem -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s',''
    $bytes = [Convert]::FromBase64String($encoded)
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$bytes)
    $store = New-Object Security.Cryptography.X509Certificates.X509Store -ArgumentList @('Root','LocalMachine')
    try { $store.Open('ReadWrite'); $store.Add($cert) } finally { $store.Close(); $cert.Dispose() }
}
if ($cfg.domain_join) {
    . "$PSScriptRoot\DomainJoin.ps1"
    Assert-JoinTransport $cfg
}
. "$PSScriptRoot\DeviceInfo.ps1"
} catch { Save-FinalizerState 'initialization_failed' $_.Exception.Message; throw }
$deadline = [DateTime]::UtcNow.AddHours(2)
if ($cfg.domain_join.mode -eq 'manual') {
    $deadline = ([DateTime]'1970-01-01T00:00:00Z').ToUniversalTime().AddSeconds([double]$cfg.expires_at)
}
Save-FinalizerState 'started'
$reportedStartup=$false
$workingStarted=$false
$hardware=''
while ([DateTime]::UtcNow -lt $deadline) {
    try {
        $product = Get-CimInstance Win32_ComputerSystemProduct
        $hardware = ([guid]$product.UUID).ToString().ToLowerInvariant()
        if ($hardware -cne $cfg.hardware_uuid) { throw 'Machine identity mismatch.' }
        if(-not $reportedStartup){Save-FinalizerState 'started';$reportedStartup=$true}
        $setup = Get-ItemProperty 'HKLM:\SYSTEM\Setup'
        $state = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State').ImageState
        if ($state -eq 'IMAGE_STATE_COMPLETE' -and $setup.SystemSetupInProgress -eq 0 -and $setup.OOBEInProgress -eq 0) {
            if(-not $workingStarted){Save-FinalizerState 'working';$workingStarted=$true}
            $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
            $display = @{}
            try {
                $computer = Get-CimInstance Win32_ComputerSystem
                $display = @{model=[string]$computer.Model;manufacturer=[string]$computer.Manufacturer;
                    system_family=[string]$computer.SystemFamily;product_name=[string]$product.Name;
                    product_version=[string]$product.Version}
                $oem = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation' -ErrorAction SilentlyContinue
                if ($oem.Model) { $display.oem_model=[string]$oem.Model }
            } catch { }
            try { $display.system_info = Get-DeploymentDeviceInfo -Stage windows } catch { }
            $cfg | Add-Member -NotePropertyName device_info -NotePropertyValue $display -Force
            $body = @{hardware_uuid=$hardware; computer_name=$env:COMPUTERNAME; os_build=$build;
                image_state=$state; oobe_done=$true; device_info=$display}
            if ($cfg.domain_join) {
                $join = Invoke-DeploymentDomainJoin $cfg $hardware
                if ($join -eq 'wait') { Start-Sleep -Seconds 20; continue }
                if ($join -eq 'failed') {
                    Unregister-ScheduledTask -TaskName ('PCDeploy-' + $cfg.job_id) -Confirm:$false
                    Remove-Item -LiteralPath "$PSScriptRoot\config.json"
                    exit 1
                }
                $body.domain_name = $cfg.domain_join.domain
                $body.domain_join_verified = $true
            }
            $body = [Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Depth 8 -Compress))
            Invoke-RestMethod -UseBasicParsing -Method Post -Uri ($cfg.server_url + '/api/agent/jobs/' + $cfg.job_id + '/finish') `
                -Headers @{Authorization=('Bearer ' + $cfg.token)} -ContentType 'application/json; charset=utf-8' -Body $body -TimeoutSec 30 | Out-Null
            Unregister-ScheduledTask -TaskName ('PCDeploy-' + $cfg.job_id) -Confirm:$false
            # Remove only this task's one-time token, not its diagnostic script or logs.
            Remove-Item -LiteralPath "$PSScriptRoot\config.json"
            exit 0
        } else {
            Save-FinalizerState 'waiting_setup' ('ImageState='+$state+'; SystemSetupInProgress='+$setup.SystemSetupInProgress+'; OOBEInProgress='+$setup.OOBEInProgress)
        }
    } catch {
        $detail=$_.Exception.Message
        Save-FinalizerState 'waiting_retry' $detail
    }
    Start-Sleep -Seconds 20
}
Save-FinalizerState 'timed_out' 'Post-install checks timed out; see finalize-state.json and domain-join-state.json.'
if ($cfg.domain_join) {
    try {
        $last = try {
            [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'domain-join-state.json')) | ConvertFrom-Json
        } catch { $null }
        if ($last.phase -eq 'failed') {
            $detail = [string]$last.detail
        } else {
            $detail = 'Post-install domain DNS or trust verification timed out; no automatic reinstall or second domain join.'
            Save-JoinJournal 'failed' '' $detail
        }
        Send-JoinState $cfg $cfg.hardware_uuid 'failed' $detail
    } catch { }
}
exit 1
