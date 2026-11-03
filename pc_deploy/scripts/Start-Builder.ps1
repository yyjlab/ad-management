param([Parameter(Mandatory)][string]$ConfigurationPath, [switch]$Once)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Windows PowerShell cannot provide the process ArgumentList and upload APIs used here.
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Use PowerShell 7 (pwsh).' }
Add-Type -AssemblyName System.Security
$cfg = Get-Content -LiteralPath $ConfigurationPath -Raw -Encoding UTF8 | ConvertFrom-Json
$bytes = [Convert]::FromBase64String($cfg.protected_token)
$token = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect(
    $bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser))
$base = $cfg.server_url.TrimEnd('/')
$uri = [Uri]$base
if ($uri.Scheme -notin @('http','https') -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) { throw 'Invalid platform URL.' }
$mutex = [Threading.Mutex]::new($false, ('Local\PCDeployBuilder-' + $cfg.builder_id))
if (-not $mutex.WaitOne(0)) { throw 'This builder is already running.' }
$handler = [Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$http = [Net.Http.HttpClient]::new($handler)
$http.Timeout = [TimeSpan]::FromSeconds(60)
$http.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
$instance = [Guid]::NewGuid().ToString()
function Invoke-BuilderRequest([string]$Route, [object]$Value, [string]$OutputFile) {
    # Only retry requests made idempotent by the fixed-purpose queue protocol.
    for ($attempt=0; $attempt -lt 5; $attempt++) {
        $response = $null
        try {
            if ($OutputFile) { $response = $http.GetAsync($base+$Route).GetAwaiter().GetResult() }
            else {
                $content = [Net.Http.StringContent]::new(($Value | ConvertTo-Json -Depth 10 -Compress), [Text.Encoding]::UTF8, 'application/json')
                try { $response = $http.PostAsync($base+$Route,$content).GetAwaiter().GetResult() }
                finally { $content.Dispose() }
            }
            if (-not $response.IsSuccessStatusCode) {
                $status = [int]$response.StatusCode
                if ($status -in @(408,429,500,502,503,504) -and $attempt -lt 4) { Start-Sleep -Seconds ([Math]::Min(30,5*($attempt+1))); continue }
                throw [InvalidOperationException]::new("Platform rejected builder request ($status).")
            }
            if ($OutputFile) {
                $stream = [IO.File]::Create($OutputFile)
                try { $response.Content.CopyToAsync($stream).GetAwaiter().GetResult() } finally { $stream.Dispose() }
                return
            }
            return ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json)
        } catch [Net.Http.HttpRequestException] {
            if ($attempt -ge 4) { throw }; Start-Sleep -Seconds 5
        } catch [Threading.Tasks.TaskCanceledException] {
            if ($attempt -ge 4) { throw }; Start-Sleep -Seconds 5
        } finally { if ($response) { $response.Dispose() } }
    }
}
function Send-Iso([string]$Identity, [string]$Path) {
    $size = (Get-Item -LiteralPath $Path).Length
    $sha = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $null = Invoke-BuilderRequest "/api/media-worker/jobs/$Identity/update" @{stage='上传 ISO';size=$size;sha256=$sha}
    $file = [IO.File]::OpenRead($Path)
    try {
        $buffer = [byte[]]::new(262144)
        [long]$offset = 0
        while (($count=$file.Read($buffer,0,$buffer.Length)) -gt 0) {
            $sent = $false
            for ($attempt=0; $attempt -lt 5; $attempt++) {
                $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, "$base/api/media-worker/jobs/$Identity/chunk")
                $request.Content = [Net.Http.ByteArrayContent]::new($buffer,0,$count)
                $request.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('application/octet-stream')
                $null = $request.Headers.TryAddWithoutValidation('X-Upload-Offset',[string]$offset)
                $response = $null
                try {
                    $response = $http.SendAsync($request).GetAwaiter().GetResult()
                    if ($response.IsSuccessStatusCode) { $sent=$true; break }
                    if ([int]$response.StatusCode -notin @(408,429,500,502,503,504)) { throw [InvalidOperationException]::new('ISO upload rejected.') }
                } catch [Net.Http.HttpRequestException] {
                    if ($attempt -ge 4) { throw }
                } catch [Threading.Tasks.TaskCanceledException] {
                    if ($attempt -ge 4) { throw }
                } finally { if ($response) { $response.Dispose() }; $request.Dispose() }
                Start-Sleep -Seconds 5
            }
            if (-not $sent) { throw 'ISO upload interrupted; create a new build after checking connectivity.' }
            $offset += $count
        }
    } finally { $file.Dispose() }
    $null = Invoke-BuilderRequest "/api/media-worker/jobs/$Identity/finish" @{}
}
try {
    do {
        $id = $null
        try {
            $reply = Invoke-BuilderRequest '/api/media-worker/poll' @{
                instance=$instance; template_name=(Split-Path -Leaf $cfg.template_directory)
                driver_name=$(if ($cfg.driver_directory) { Split-Path -Leaf $cfg.driver_directory } else { '无额外驱动' })
            }
            if ($reply.job) {
                $id = [string]$reply.job.id
                if ($id -notmatch '^[a-f0-9-]{36}$') { throw 'Invalid job ID.' }
                $job = Join-Path $cfg.work_root $id
                if (Test-Path -LiteralPath $job) { throw 'Job directory exists; refusing a second build.' }
                New-Item -ItemType Directory -Path $job | Out-Null
                $zip = Join-Path $job 'client.zip'
                Invoke-BuilderRequest "/api/media-worker/jobs/$id/package" $null $zip
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $archive = [IO.Compression.ZipFile]::OpenRead($zip)
                try {
                    foreach ($name in @('config.json','Deploy-Agent.ps1','Start.ps1')) {
                        $entry = $archive.GetEntry($name)
                        if (-not $entry -or $entry.Length -gt 1048576) { throw 'Invalid client package.' }
                        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,(Join-Path $job $name),$false)
                    }
                } finally { $archive.Dispose() }
                $clientConfig = Get-Content -LiteralPath (Join-Path $job 'config.json') -Raw | ConvertFrom-Json
                # A separate fixed local configuration, without the builder credential, goes to the build process.
                $buildCfg = @{
                    template_directory=$cfg.template_directory; wim_relative=$cfg.wim_relative
                    oscdimg_path=$cfg.oscdimg_path; bios_boot_path=$cfg.bios_boot_path; uefi_boot_path=$cfg.uefi_boot_path
                    driver_directory=$cfg.driver_directory; include_drivers=[bool]$clientConfig.include_drivers
                }
                [IO.File]::WriteAllText((Join-Path $job 'local-build.json'),($buildCfg | ConvertTo-Json),[Text.Encoding]::UTF8)
                $psi = [Diagnostics.ProcessStartInfo]::new()
                $psi.FileName = (Get-Process -Id $PID).Path
                $psi.UseShellExecute = $false
                $psi.CreateNoWindow = $true
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true
                foreach ($arg in @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'Build-LocalMedia.ps1'),'-JobDirectory',$job)) {
                    $psi.ArgumentList.Add($arg)
                }
                $process = [Diagnostics.Process]::Start($psi)
                $stdout = $process.StandardOutput.ReadToEndAsync()
                $stderr = $process.StandardError.ReadToEndAsync()
                $reportFailed = $false
                try {
                    do {
                        $stagePath = Join-Path $job 'stage.txt'
                        $stage = if (Test-Path -LiteralPath $stagePath) { (Get-Content -LiteralPath $stagePath -Raw -Encoding UTF8).Trim() } else { '准备 PE 文件' }
                        if ($stage -notin @('准备 PE 文件','注入客户端和驱动','生成 ISO')) { $stage='准备 PE 文件' }
                        if (-not $reportFailed) {
                            try { $null = Invoke-BuilderRequest "/api/media-worker/jobs/$id/update" @{stage=$stage} }
                            catch { $reportFailed = $true }
                        }
                        $null = $process.WaitForExit(5000)
                    } while (-not $process.HasExited)
                    [IO.File]::WriteAllText((Join-Path $job 'build.log'),
                        $stdout.GetAwaiter().GetResult()+[Environment]::NewLine+$stderr.GetAwaiter().GetResult(),[Text.Encoding]::UTF8)
                    if ($reportFailed) { throw 'Platform connection was lost during build; local output retained, not published.' }
                    if ($process.ExitCode -ne 0) { throw 'Local ISO build failed. Inspect this job directory and DISM logs.' }
                } finally { $process.Dispose() }
                Send-Iso $id (Join-Path $job 'pc-deploy.iso')
                Write-Host ('ISO ready: ' + $id)
            }
        } catch {
            # Do not log server response bodies, bearer tokens, or package configurations.
            Write-Warning ('Builder waiting or failed: ' + $_.Exception.GetType().Name)
            if ($id) { try { $null=Invoke-BuilderRequest "/api/media-worker/jobs/$id/update" @{stage='制作失败'} } catch {} }
        }
        if (-not $Once) { Start-Sleep -Seconds 8 }
    } while (-not $Once)
} finally {
    $http.Dispose()
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
