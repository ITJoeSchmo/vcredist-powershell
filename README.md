# vcredist-powershell

A PowerShell-based toolkit for managing Microsoft Visual C++ Redistributable runtimes across Windows environments at scale. Forked from [abbodi1406/vcredist](https://github.com/abbodi1406/vcredist) (a batch/.NET AIO repack), rewritten in PowerShell to address reliability issues encountered when deploying across ~400 servers.

## Why This Exists

The upstream project provides an all-in-one repack of the latest VC++ redistributables, but its batch-based installer proved too fragile for large managed environments (SCCM/MECM). Common issues included unreliable detection, incomplete uninstalls of WiX-bundled packages, and poor handling of edge cases like Restart Manager interference. This rewrite solves those problems with structured compliance checking, intelligent WiX bundle detection, and robust MSI exit code handling.

## Repository Structure

```
├── Update-VisualCppRedists.ps1          # Main orchestrator — runs compliance checks, uninstalls, and installs
├── Get-VisualCppRedistInstallers.ps1    # Downloads the latest AIO repack from abbodi1406/vcredist via GitHub API and extracts the MSI installers using portable 7-Zip
├── InstallerRegistration.ps1            # Microsoft-derived MSI registration utilities (GUID compression, product enumeration, registry backup/restore, force-uninstall via registry scrub) — dot-sourced by the main script when -AllowForceUninstall is used
├── Update-VCppManifest.ps1              # Updates VisualCppRedistsManifest.json with latest expected versions/product codes
├── VisualCppRedistsManifest.json        # Declarative product catalog — product codes, DLL baselines, installer paths, regex filters, and per-product flags
└── mecm/                               # MECM/SCCM deployment artifacts
```

## Key Capabilities

### Three-Layer Compliance Model

Every product in the manifest is validated against three independent checks before any action is taken. All three must pass for a product to be considered compliant.

**1. DLL Version Check** (`Test-VcRedistDllCompliance`) — Resolves wildcarded DLL paths (including WinSxS for older runtimes), reads `FileVersionRaw` to avoid string-parsing issues with stamps like `11.00.51106.1 built by: Q11REL`, and compares the highest discovered version against the manifest baseline. If no DLL is found on disk, this check passes — MSI presence is validated separately.

**2. WiX/Burn Bundle Detection** (`Test-IsWixBundle`) — Any redistributable installed via a WiX Burn bundle is treated as non-compliant by default (overridable with `-SkipUpToDateWiXBundle`). Detection uses multiple signals: `Bundle*` registry properties, `.exe` uninstallers pointing to Package Cache, `state.rsm` files, and dependency mappings under `HKLM:\SOFTWARE\Classes\Installer\Dependencies`.

**3. Registered Installations** — Compares expected MSI ProductCodes from the manifest against what's actually registered in the x86/x64 uninstall hives. A product is compliant only when there are no missing entries, no unexpected entries, no WiX-installed products, and the expected count matches exactly. Special handling exists for VC++ 2005/2008, which may deploy DLLs into WinSxS without MSI registration — when `doNotReinstallIfOrphanedDll` is set and the DLL version check passes, these are considered compliant.

Each compliance result includes a `Note` field with a plain-English explanation, making output self-explanatory and auditable.

### Architecture Resolution

WiX Burn bundles typically register in the 32-bit uninstall hive regardless of the actual payload architecture. A multi-layer fallback determines the true architecture:

1. **All dependent MSI installs share one architecture** → trust that
2. **32-bit OS** → always x86
3. **Uninstaller path** contains `x64` or `x86` → infer from path
4. **DisplayName** contains architecture hints (`x64`, `64-bit`, etc.) → infer from name

### Debug Runtime Filtering

Debug runtimes are explicitly excluded via `-notmatch '(?i)\b(Debug)\b'` in the `Get-Installs` function. Debug runtimes are developer-only and produce false positives in compliance checks — they should never be remediated in production.

### Execution Model

When a product fails compliance, the script uninstalls and reinstalls in order:

**Uninstall rules:**

| Scenario             | Action                              |
|----------------------|-------------------------------------|
| WiX bundle detected  | Uninstall via bundle EXE (`/uninstall /quiet /norestart`) |
| MSI installed by WiX | Handled by bundle uninstall         |
| Standalone MSI       | Uninstall via `msiexec /X`          |

**Install:** Each MSI from the manifest's `installers` array is installed via `msiexec /i` with `/qn /norestart`.

Key implementation details:

- `.Handle` is cached before reading `.ExitCode` — a PS 5.1 workaround for reliable exit code retrieval
- MSI exit codes handled: `0` (success), `3010` (reboot required), `1605` (already uninstalled), `1612` (triggers force-repair → uninstall → reinstall cycle), `1618`/`0x80070652` (install in progress — retries after 5 minutes)
- When `-AllowForceUninstall` is set, failed uninstalls fall back to `InstallerRegistration.ps1` which scrubs the MSI registration from the registry (with backup to `C:\MATS\`) using methods derived from Microsoft's Install/Uninstall Troubleshooter (`MicrosoftProgram_Install_and_Uninstall.meta.diagcab`)

### Restart Manager Safety

The Windows Restart Manager can kill processes (including `CcmExec`) mid-operation, producing exit codes like `1601` or `0xC000013A` and terminating the script. All MSI operations use `MSIRESTARTMANAGERCONTROL=Disable` and `/norestart` to prevent forced process termination, deferring file-lock resolution to a controlled reboot — critical for managed environments like SCCM/MECM.

## Usage

```powershell
# 1. Download and extract the installer MSIs from the upstream repack
.\Get-VisualCppRedistInstallers.ps1

# 2. Run the update (requires elevation)
.\Update-VisualCppRedists.ps1
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-WhatIf` | Dry-run mode — prints all `Start-Process` commands without executing them |
| `-Verbose` | Outputs all compliance check details, not just failures |
| `-AllowForceUninstall` | On failed uninstall, scrubs MSI registration from registry using Microsoft's troubleshooter methods (backs up to `C:\MATS\`) |
| `-SkipUpToDateWiXBundle` | Treats WiX bundles as compliant if the DLL version check passes, only reinstalling when version check fails |

### MECM/SCCM Deployment

The `mecm/` directory contains artifacts for deploying via Microsoft Endpoint Configuration Manager. When run non-interactively (e.g., deployed via SCCM), the script passes exit codes back to the parent process — returning `3010` if any operation required a reboot.

## Supported Products

The manifest covers VC++ 2005 through 2022 (both x86 and x64), plus Visual Studio 2010 Tools for Office Runtime. Each entry defines product codes, DLL paths (including WinSxS patterns for older runtimes), version baselines, regex filters for DisplayName matching, and installer paths relative to the extracted repack.

## Design Philosophy

- **Compliance-first**: Check before acting; produce auditable, structured output
- **Declarative catalog**: The manifest defines expected state; the script enforces it
- **Flat control flow**: Early `continue` over deep nesting
- **Functions only when justified**: Reuse exists or complexity is meaningfully reduced
- **Safe for managed environments**: No process kills, no surprise reboots, `MSIRESTARTMANAGERCONTROL=Disable` everywhere

## Roadmap

- [ ] Source installers directly from Microsoft rather than relying on the upstream AIO repack (the repacks are more space-efficient, but direct sourcing removes a dependency)

## Upstream

Forked from [abbodi1406/vcredist](https://github.com/abbodi1406/vcredist) — an AIO repack of the latest Microsoft Visual C++ Redistributable runtimes.
