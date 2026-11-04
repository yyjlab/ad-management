$ErrorActionPreference = 'Stop'
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
$deadline = [DateTime]::UtcNow.AddHours(2)
while ([DateTime]::UtcNow -lt $deadline) {
    try {
        $setup = Get-ItemProperty 'HKLM:\SYSTEM\Setup'
        $state = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State').ImageState
        if ($state -eq 'IMAGE_STATE_COMPLETE' -and $setup.SystemSetupInProgress -eq 0 -and $setup.OOBEInProgress -eq 0) {
            $hardware = ([guid](Get-CimInstance Win32_ComputerSystemProduct).UUID).ToString().ToLowerInvariant()
            if ($hardware -cne $cfg.hardware_uuid) { throw 'Machine identity mismatch.' }
            $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
            $body = @{hardware_uuid=$hardware; computer_name=$env:COMPUTERNAME; os_build=$build;
                image_state=$state; oobe_done=$true}
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
            $body = $body | ConvertTo-Json -Compress
            Invoke-RestMethod -Method Post -Uri ($cfg.server_url + '/api/agent/jobs/' + $cfg.job_id + '/finish') `
                -Headers @{Authorization=('Bearer ' + $cfg.token)} -ContentType 'application/json' -Body $body -TimeoutSec 30 | Out-Null
            Unregister-ScheduledTask -TaskName ('PCDeploy-' + $cfg.job_id) -Confirm:$false
            # Remove only this task's one-time token, not its diagnostic script or logs.
            Remove-Item -LiteralPath "$PSScriptRoot\config.json"
            exit 0
        }
    } catch { }
    Start-Sleep -Seconds 20
}
if ($cfg.domain_join) {
    try {
        Save-JoinJournal 'failed' '' 'Post-install domain DNS or trust verification timed out; no automatic reinstall or second domain join.'
        Send-JoinState $cfg $cfg.hardware_uuid 'failed' 'Post-install domain DNS or trust verification timed out; no automatic reinstall or second domain join.'
    } catch { }
}
exit 1
