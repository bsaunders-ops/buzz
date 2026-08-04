Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("core-month1-package-test-" + [guid]::NewGuid().ToString("N"))
$Artifacts = Join-Path $TempRoot "artifacts"
$OutDir = Join-Path $TempRoot "out"

try {
    New-Item -ItemType Directory -Path $Artifacts, $OutDir | Out-Null
    $Installer = Join-Path $Artifacts "Buzz_0.5.3_x64-setup.exe"
    $Checksum = Join-Path $Artifacts "SHA256SUMS"
    $Runbook = Join-Path $Artifacts "month1-runbook.md"
    Set-Content -LiteralPath $Installer -Value "fake installer bytes" -NoNewline
    $InstallerHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Installer).Hash.ToLowerInvariant()
    Set-Content -LiteralPath $Checksum -Value "$InstallerHash  Buzz_0.5.3_x64-setup.exe"
    Set-Content -LiteralPath $Runbook -Value "# Runbook"

    & (Join-Path $RepoRoot "scripts/core-month1-deploy-package.ps1") `
        -InstallerPath $Installer `
        -ChecksumPath $Checksum `
        -RunbookPath $Runbook `
        -OutDir $OutDir `
        -Version "0.5.3-core-month1" `
        -Commit "abc123" `
        -AllowUnsigned | Out-Null

    $ManifestPath = Join-Path $OutDir "core-buzz-month1-version-manifest.json"
    if (!(Test-Path -LiteralPath $ManifestPath)) {
        throw "manifest was not created"
    }
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    if ($Manifest.version -ne "0.5.3-core-month1") {
        throw "unexpected version in manifest: $($Manifest.version)"
    }
    if ($Manifest.commit -ne "abc123") {
        throw "unexpected commit in manifest: $($Manifest.commit)"
    }
    if ($Manifest.files.Count -ne 3) {
        throw "expected exactly 3 copied files, got $($Manifest.files.Count)"
    }
    foreach ($Name in @("Buzz_0.5.3_x64-setup.exe", "SHA256SUMS", "month1-runbook.md")) {
        if (!(Test-Path -LiteralPath (Join-Path $OutDir $Name))) {
            throw "missing copied file: $Name"
        }
    }

    $UnsignedFailure = $false
    try {
        & (Join-Path $RepoRoot "scripts/core-month1-deploy-package.ps1") `
            -InstallerPath $Installer `
            -ChecksumPath $Checksum `
            -RunbookPath $Runbook `
            -OutDir (Join-Path $TempRoot "signed-required") `
            -Version "0.5.3-core-month1" `
            -Commit "abc123" | Out-Null
    } catch {
        $UnsignedFailure = $_.Exception.Message -like "*not signed*"
    }
    if (!$UnsignedFailure) {
        throw "unsigned installer should fail without -AllowUnsigned"
    }
} finally {
    if ($TempRoot.StartsWith([System.IO.Path]::GetTempPath(), [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
