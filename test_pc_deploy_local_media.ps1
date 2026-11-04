$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
[Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot\pc_deploy\scripts\Build-OnThisPC.ps1",[ref]$tokens,[ref]$errors) | Out-Null
if($errors.Count){throw ($errors | Out-String)}
. "$PSScriptRoot\pc_deploy\scripts\Build-OnThisPC.ps1" -LibraryOnly
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('pcdeploy-local-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $media=Join-Path $testRoot 'template\Media\WEPE'
    $tools=Join-Path $testRoot 'runtime\Package\Tools'
    $boot=Join-Path $testRoot 'runtime\Package\Boot'
    $drivers=Join-Path $testRoot 'driver\Drivers'
    New-Item -ItemType Directory -Path $media,$tools,$boot,$drivers | Out-Null
    foreach($file in @((Join-Path $media 'WEPE64.WIM'),(Join-Path $tools 'oscdimg.exe'),(Join-Path $boot 'bios.img'),(Join-Path $boot 'uefi.img'))){
        [IO.File]::WriteAllText($file,'fixture-only')
    }
    $assets=Find-LocalMediaAssets $testRoot
    if($assets.template_directory -ne (Split-Path -Parent $media)){throw 'Existing Media was not found'}
    if($assets.wim_relative -ne 'WEPE\WEPE64.WIM'){throw 'Wrong WIM selected'}
    if($assets.oscdimg_path -ne (Join-Path $tools 'oscdimg.exe')){throw 'Local oscdimg was not reused'}
    if($assets.driver_directory -ne $drivers){throw 'Local driver directory was not reused'}
    & {
        function Get-AuthenticodeSignature { param($LiteralPath) return @{Status='Valid';SignerCertificate=@{Subject='CN=Microsoft Corporation'}} }
        Assert-LocalMediaAssets $assets (Join-Path $testRoot 'separate\Builds')
        $blocked=$false
        try{Assert-LocalMediaAssets $assets (Join-Path $assets.template_directory 'Builds')}catch{$blocked=$true}
        if(-not $blocked){throw 'Nested template/output paths were accepted'}
        $blocked=$false
        try{Assert-LocalMediaAssets $assets $testRoot}catch{$blocked=$true}
        if(-not $blocked){throw 'Ancestor template/output paths were accepted'}
        $invalid=$assets.Clone();$invalid.wim_relative='..\outside.wim'
        $blocked=$false
        try{Assert-LocalMediaAssets $invalid (Join-Path $testRoot 'separate\Builds')}catch{$blocked=$true}
        if(-not $blocked){throw 'Unsafe WIM path accepted'}
    }
    & {
        function Get-AuthenticodeSignature { param($LiteralPath) return @{Status='NotSigned';SignerCertificate=$null} }
        $blocked=$false
        try{Assert-LocalMediaAssets $assets (Join-Path $testRoot 'separate\Builds')}catch{$blocked=$true}
        if(-not $blocked){throw 'Unsigned ISO tool accepted'}
    }
    $ast=[Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot\pc_deploy\scripts\Build-OnThisPC.ps1",[ref]$tokens,[ref]$errors)
    $provisioning=$ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and
        $n.GetCommandName() -in @('Register-ScheduledTask','New-ScheduledTaskAction','Invoke-WebRequest','Invoke-RestMethod','Clear-Disk','Format-Volume')},$true)
    if($provisioning.Count){throw 'Local runner unexpectedly provisions an agent or touches a disk'}
    Write-Host '10 local-media detection, path protection, signature and no-agent checks passed. No real build or disk operation was executed.'
} finally {
    # Only this test's random temporary fixture tree is removed.
    $resolved=[IO.Path]::GetFullPath($testRoot)
    $tempPrefix=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if(-not $resolved.StartsWith($tempPrefix,[StringComparison]::OrdinalIgnoreCase)){throw 'Invalid test cleanup target'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
