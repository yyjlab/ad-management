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
Write-Output "$count PowerShell protection and parser checks passed. No disk command was executed."
