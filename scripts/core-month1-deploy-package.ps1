param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath,

    [Parameter(Mandatory = $true)]
    [string]$ChecksumPath,

    [Parameter(Mandatory = $true)]
    [string]$RunbookPath,

    [Parameter(Mandatory = $true)]
    [string]$Version,

    [string]$Commit = "",

    [string]$OutDir = "C:\Users\BlakeSaunders\OneDrive - Core Advisors\Core AI\Buzz - Deploy",

    [switch]$AllowUnsigned
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RequiredFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $Resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $Item = Get-Item -LiteralPath $Resolved.Path
    if (!$Item.PSIsContainer) {
        return $Item
    }
    throw "$Label must be a file: $Path"
}

function Get-FileSha256Lower {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Assert-ChecksumMentionsInstaller {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ChecksumFile,

        [Parameter(Mandatory = $true)]
        [string]$InstallerName,

        [Parameter(Mandatory = $true)]
        [string]$InstallerSha256
    )

    $Lines = Get-Content -LiteralPath $ChecksumFile
    foreach ($Line in $Lines) {
        $Trimmed = $Line.Trim()
        if ($Trimmed.Length -eq 0) {
            continue
        }
        $Parts = $Trimmed -split "\s+", 2
        if ($Parts.Count -eq 2 -and
            $Parts[0].ToLowerInvariant() -eq $InstallerSha256 -and
            ($Parts[1].TrimStart("*") -eq $InstallerName)) {
            return
        }
    }
    throw "checksum file does not contain the installer SHA-256 for $InstallerName"
}

$Installer = Resolve-RequiredFile -Path $InstallerPath -Label "Installer"
$Checksum = Resolve-RequiredFile -Path $ChecksumPath -Label "Checksum"
$Runbook = Resolve-RequiredFile -Path $RunbookPath -Label "Runbook"

if ($Installer.Extension.ToLowerInvariant() -ne ".exe") {
    throw "installer must be a Windows .exe file: $($Installer.FullName)"
}

$InstallerSha256 = Get-FileSha256Lower -Path $Installer.FullName
Assert-ChecksumMentionsInstaller `
    -ChecksumFile $Checksum.FullName `
    -InstallerName $Installer.Name `
    -InstallerSha256 $InstallerSha256

$Signature = Get-AuthenticodeSignature -LiteralPath $Installer.FullName
if (!$AllowUnsigned -and $Signature.Status -ne "Valid") {
    throw "installer is not signed or signature is not valid: $($Signature.Status)"
}

if ([string]::IsNullOrWhiteSpace($Commit)) {
    $GitCommit = ""
    try {
        $GitCommit = (git -C (Split-Path -Parent $PSScriptRoot) rev-parse HEAD 2>$null).Trim()
    } catch {
        $GitCommit = ""
    }
    $Commit = $GitCommit
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$OutItem = Get-Item -LiteralPath $OutDir
if (!$OutItem.PSIsContainer) {
    throw "OutDir must be a directory: $OutDir"
}

$CopiedPaths = @()
foreach ($Source in @($Installer, $Checksum, $Runbook)) {
    $Destination = Join-Path $OutItem.FullName $Source.Name
    Copy-Item -LiteralPath $Source.FullName -Destination $Destination -Force
    $CopiedPaths += $Destination
}

$Files = foreach ($Path in $CopiedPaths) {
    $Item = Get-Item -LiteralPath $Path
    [pscustomobject]@{
        name   = $Item.Name
        bytes  = $Item.Length
        sha256 = Get-FileSha256Lower -Path $Item.FullName
    }
}

$Manifest = [pscustomobject]@{
    schema_version   = 1
    package          = "core-buzz-month1-windows-desktop"
    version          = $Version
    commit           = $Commit
    created_at       = (Get-Date).ToUniversalTime().ToString("o")
    installer_signed = ($Signature.Status -eq "Valid")
    files            = $Files
}

$ManifestPath = Join-Path $OutItem.FullName "core-buzz-month1-version-manifest.json"
$Manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8

[pscustomobject]@{
    out_dir  = $OutItem.FullName
    manifest = $ManifestPath
}
