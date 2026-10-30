param([Parameter(Mandatory)][string]$SourcePath,
      [ValidateSet('windows11','windows10')][string]$Family = 'windows11',
      [string]$Name = 'Windows installation source',
      [string]$SmbUser = 'FILESERVER\deploy-read')
$ErrorActionPreference = 'Stop'
if ($SourcePath -notmatch '^\\\\[^\\]+\\[^\\]+') { throw 'Use an existing read-only UNC installation source.' }
$base = $SourcePath.TrimEnd('\')
$file = 'sources\install.wim'
if (-not (Test-Path -LiteralPath (Join-Path $base $file))) { $file = 'sources\install.esd' }
$imagePath = Join-Path $base $file
$setupPath = Join-Path $base 'setup.exe'
if (-not (Test-Path -LiteralPath $imagePath) -or -not (Test-Path -LiteralPath $setupPath)) {
    throw 'Extract a legitimate Windows ISO into this share first. No file was modified.'
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
    name=$Name; path=$base; family=$Family; image_file=$file; smb_user=$SmbUser
    image_sha256=(Get-FileHash -LiteralPath $imagePath -Algorithm SHA256).Hash.ToLowerInvariant()
    setup_sha256=(Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant()
    images=$images
} | ConvertTo-Json -Depth 8
