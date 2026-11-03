param([Parameter(Mandatory)][string]$SourcePath,
      [ValidateSet('windows11','windows10')][string]$Family = 'windows11',
      [string]$Name = 'Windows installation source',
      [string]$SmbUser = 'FILESERVER\deploy-read')
$ErrorActionPreference = 'Stop'
if ($SourcePath -notmatch '^\\\\[^\\]+\\[^\\]+') { throw 'Use an existing read-only UNC installation source.' }
$base = $SourcePath.TrimEnd('\')
$kind = 'setup'
$file = 'sources\install.wim'
if ([IO.Path]::GetExtension($base) -ieq '.wim') {
    $kind = 'wim'
    $file = Split-Path -Path $base -Leaf
    $base = Split-Path -Path $base -Parent
    if ($file -notmatch '^[A-Za-z0-9_-][A-Za-z0-9_. -]{0,119}\.wim$') { throw 'Use a safe WIM filename.' }
} elseif (-not (Test-Path -LiteralPath (Join-Path $base $file))) { $file = 'sources\install.esd' }
$imagePath = Join-Path $base $file
$setupPath = Join-Path $base 'setup.exe'
if (-not (Test-Path -LiteralPath $imagePath) -or ($kind -eq 'setup' -and -not (Test-Path -LiteralPath $setupPath))) {
    throw 'Use an extracted Windows ISO folder, or pass the full UNC path of a custom .wim file. No file was modified.'
}
Write-Host 'Read-only scan: computing hashes and inspecting image indexes. This may take several minutes.'
$images = @(Get-WindowsImage -ImagePath $imagePath | ForEach-Object {
    $item = Get-WindowsImage -ImagePath $imagePath -Index $_.ImageIndex
    if ([int]$item.Architecture -ne 9) { throw 'Only x64 media is supported.' }
    $language = [string]$item.DefaultLanguage
    if (-not $language) { $language = [string](@($item.Languages)[0]) }
    if ($language -notin @('zh-CN','en-US')) { throw 'Only zh-CN and en-US media are supported in this release.' }
    @{index=[int]$item.ImageIndex; name=[string]$item.ImageName; build=([version]$item.Version).Build;
      architecture='amd64'; language=$language}
})
@{
    name=$Name; path=$base; family=$Family; image_file=$file; smb_user=$SmbUser; kind=$kind
    image_sha256=(Get-FileHash -LiteralPath $imagePath -Algorithm SHA256).Hash.ToLowerInvariant()
    setup_sha256=$(if ($kind -eq 'setup') { (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { '' })
    images=$images
} | ConvertTo-Json -Depth 8
