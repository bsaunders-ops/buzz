# Core Buzz Month-1 Windows deploy package

Use `scripts/core-month1-deploy-package.ps1` after CI or the approved Windows
build lane has produced the Month-1 NSIS installer, checksum file, and runbook.

Default output:

```powershell
C:\Users\BlakeSaunders\OneDrive - Core Advisors\Core AI\Buzz - Deploy
```

Example:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\core-month1-deploy-package.ps1 `
  -InstallerPath .\artifacts\Buzz_0.5.3_x64-setup.exe `
  -ChecksumPath .\artifacts\SHA256SUMS `
  -RunbookPath .\docs\azure-foundation-runbook.md `
  -Version 0.5.3-core-month1 `
  -Commit (git rev-parse HEAD)
```

The script verifies that the checksum file contains the installer hash, requires
a valid Authenticode signature by default, copies the three handoff files, and
writes `core-buzz-month1-version-manifest.json` with SHA-256 hashes and byte
counts. Use `-AllowUnsigned` only for local script tests or throwaway unsigned
canary builds; do not use it for the Blake live pilot handoff.
