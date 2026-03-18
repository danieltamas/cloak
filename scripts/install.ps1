#Requires -Version 5.1
<#
.SYNOPSIS
    Cloak installer for Windows.
.DESCRIPTION
    Downloads the Cloak binary and adds it to the user PATH.
    Usage (manual):    irm https://getcloak.dev/install.ps1 | iex
    Usage (extension): $env:CLOAK_ACCEPT='1'; irm https://getcloak.dev/install.ps1 | iex
    Usage (versioned): .\install.ps1 -Version v1.2.3
#>
param(
    [string]$Version = "latest",
    [switch]$Yes
)

$ErrorActionPreference = "Stop"

$InstallerVersion = "2026.03.18-1"
$Repo = "danieltamas/cloak"
$InstallDir = Join-Path $env:LOCALAPPDATA "cloak\bin"

# ── Colours ──────────────────────────────────────────────────────────────────

function Write-Ok($msg)   { Write-Host "  ✓  $msg" -ForegroundColor Green }
function Write-Info($msg)  { Write-Host "  →  $msg" -ForegroundColor Cyan }
function Write-Warn($msg)  { Write-Host "  !  $msg" -ForegroundColor Yellow }
function Write-Fail($msg)  { Write-Host "  ✗  $msg" -ForegroundColor Red; exit 1 }

function Write-Banner {
    Write-Host ""
    $art = @(
        "   ██████╗██╗      ██████╗  █████╗ ██╗  ██╗"
        "  ██╔════╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝"
        "  ██║     ██║     ██║   ██║███████║█████╔╝ "
        "  ██║     ██║     ██║   ██║██╔══██║██╔═██╗ "
        "  ╚██████╗███████╗╚██████╔╝██║  ██║██║  ██╗"
        "   ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"
    )
    foreach ($line in $art) {
        Write-Host $line -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "  Protect .env secrets from AI coding agents" -ForegroundColor DarkGray
    Write-Host ""
}

# ── Rollback ─────────────────────────────────────────────────────────────────

$InstalledBinary = $false

function Invoke-Rollback {
    if ($InstalledBinary) {
        $binPath = Join-Path $InstallDir "cloak.exe"
        if (Test-Path $binPath) {
            Remove-Item $binPath -Force -ErrorAction SilentlyContinue
            Write-Ok "Rolled back cloak binary"
        }
    }
    Write-Host ""
    Write-Host "  Your system is unchanged." -ForegroundColor DarkGray
    Write-Host ""
}

# ── Platform detection ───────────────────────────────────────────────────────

function Get-Platform {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        "X64"   { return "x86_64" }
        "Arm64" { return "aarch64" }
        default { Write-Fail "Unsupported architecture: $arch" }
    }
}

# ── Download ─────────────────────────────────────────────────────────────────

function Install-CloakBinary {
    $arch = Get-Platform
    $bin = "cloak-windows-${arch}.exe"

    if ($Version -eq "latest") {
        $url = "https://github.com/$Repo/releases/latest/download/$bin"
    } else {
        $url = "https://github.com/$Repo/releases/download/$Version/$bin"
    }

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $tmpPath = Join-Path $env:TEMP "cloak-download.exe"
    $binPath = Join-Path $InstallDir "cloak.exe"

    Write-Info "Downloading Cloak $Version..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $tmpPath -UseBasicParsing
    } catch {
        if (Test-Path $tmpPath) { Remove-Item $tmpPath -Force -ErrorAction SilentlyContinue }
        Write-Fail "Download failed. Check your network or visit https://github.com/$Repo/releases"
    }

    Move-Item -Path $tmpPath -Destination $binPath -Force
    $script:InstalledBinary = $true
    Write-Ok "Cloak binary → $binPath"
}

# ── PATH ─────────────────────────────────────────────────────────────────────

function Add-ToPath {
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($currentPath -like "*$InstallDir*") {
        Write-Ok "$InstallDir already in PATH"
        return
    }

    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-Ok "Added $InstallDir to user PATH"
    Write-Info "Open a new terminal for the PATH change to take effect."
}

# ── Main ─────────────────────────────────────────────────────────────────────

Write-Banner
Write-Host "  installer v$InstallerVersion" -ForegroundColor DarkGray
Write-Host ""

$arch = Get-Platform
Write-Ok "Platform: windows / $arch"

# ── Disclosure ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  This installer will make the following changes:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Installs" -NoNewline
Write-Host ""
Write-Host "    • cloak.exe → $InstallDir\cloak.exe" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  System changes" -NoNewline
Write-Host ""
Write-Host "    • Adds $InstallDir to your user PATH (if not already present)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  At runtime" -NoNewline
Write-Host ""
Write-Host "    • Vault + auth files → $env:APPDATA\cloak\" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  No admin required. No system files modified." -ForegroundColor DarkGray
Write-Host "  Uninstall: Remove-Item $InstallDir\cloak.exe; Remove-Item -Recurse $env:APPDATA\cloak" -ForegroundColor DarkGray
Write-Host ""

# ── Consent ──────────────────────────────────────────────────────────────────

$autoAccept = ($env:CLOAK_ACCEPT -eq "1") -or $Yes

if ($autoAccept) {
    Write-Info "Non-interactive install (CLOAK_ACCEPT=1 or -Yes)"
} else {
    $reply = Read-Host "  Proceed with installation? [Y/n]"
    if ($reply -match '^[nN]') {
        Write-Host ""
        Write-Info "Installation cancelled."
        exit 0
    }
}

Write-Host ""

try {
    Install-CloakBinary
    Add-ToPath

    Write-Host ""
    Write-Host "  Cloak is installed." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Run " -NoNewline
    Write-Host "cloak --help" -ForegroundColor White -NoNewline
    Write-Host " to get started."
    Write-Host "  Docs: https://getcloak.dev" -ForegroundColor DarkGray
    Write-Host ""
} catch {
    Invoke-Rollback
    throw
}
