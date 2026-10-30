$ErrorActionPreference = 'Stop'
$cfg = Get-Content -LiteralPath "$PSScriptRoot\config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT')) { throw 'Windows PE is required.' }
if (([uri]$cfg.server_url).Scheme -eq 'https' -and $cfg.ca_pem) {
    $encoded = $cfg.ca_pem -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s',''
    $bytes = [Convert]::FromBase64String($encoded)
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$bytes)
    $store = New-Object Security.Cryptography.X509Certificates.X509Store -ArgumentList @('Root','LocalMachine')
    try { $store.Open('ReadWrite'); $store.Add($cert) } finally { $store.Close(); $cert.Dispose() }
}
& wpeutil.exe UpdateBootInfo
if ($LASTEXITCODE -ne 0) { throw 'Could not detect firmware mode.' }
& "$PSScriptRoot\Deploy-Agent.ps1" -ConfigPath "$PSScriptRoot\config.json"
