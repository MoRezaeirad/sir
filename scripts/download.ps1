# Download and install sir pre-built binaries from GitHub Releases.
#
# Usage (run from an elevated or standard PowerShell prompt):
#   irm https://raw.githubusercontent.com/somoore/sir/main/scripts/download.ps1 | iex
#   # or pin a specific version:
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/somoore/sir/main/scripts/download.ps1))) v0.1.3
#
# Supported platforms:
#   Windows x64  (amd64)
#   Windows ARM  (arm64)
#
# Installs sir.exe and mister-core.exe to %LOCALAPPDATA%\sir\bin and
# adds that directory to the user-level PATH. No administrator rights
# required. Pass a version tag as the first argument to pin a specific
# release; defaults to latest.
#
# Security: the downloaded archive is verified against the SHA-256
# checksum published in the release's checksums.txt before installation.

param(
    [string]$Version = "latest"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Repo    = "somoore/sir"
$ApiBase = "https://api.github.com/repos/$Repo"
$GhBase  = "https://github.com/$Repo/releases/download"

function Write-Info  { Write-Host "[+] $args" -ForegroundColor Green  }
function Write-Warn  { Write-Host "[!] $args" -ForegroundColor Yellow }
function Write-Fatal { Write-Host "[x] $args" -ForegroundColor Red; exit 1 }

# --- Version resolution ---
if ($Version -eq "latest") {
    Write-Info "Resolving latest release..."
    $releases = Invoke-RestMethod -Uri "$ApiBase/releases?per_page=1"
    $Version  = $releases[0].tag_name
    if (-not $Version) { Write-Fatal "Could not determine latest release." }
}
Write-Info "Version: $Version"

# --- Platform detection ---
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
$Platform = switch ($arch) {
    "X64"   { "windows_amd64" }
    "Arm64" { "windows_arm64" }
    default { Write-Fatal "Unsupported architecture: $arch. sir supports Windows x64 and ARM64." }
}
Write-Info "Platform: $Platform"

# --- Install directory ---
$InstallDir = Join-Path $env:LOCALAPPDATA "sir\bin"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$TmpDir = Join-Path $env:TEMP ("sir-install-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null

try {
    # --- Download archive ---
    $Archive    = "sir_${Version}_${Platform}.zip"
    $ArchiveUrl = "$GhBase/$Version/$Archive"
    $ArchivePath = Join-Path $TmpDir $Archive

    Write-Info "Downloading $Archive..."
    Invoke-WebRequest -Uri $ArchiveUrl -OutFile $ArchivePath -UseBasicParsing

    # --- Download and verify checksums ---
    $ChecksumsUrl  = "$GhBase/$Version/checksums.txt"
    $ChecksumsPath = Join-Path $TmpDir "checksums.txt"
    Write-Info "Downloading checksums.txt..."
    Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $ChecksumsPath -UseBasicParsing

    Write-Info "Verifying SHA-256 checksum..."
    $ActualHash   = (Get-FileHash -Algorithm SHA256 -Path $ArchivePath).Hash.ToLower()
    $ChecksumLine = Get-Content $ChecksumsPath | Where-Object { $_ -match [regex]::Escape($Archive) }
    if (-not $ChecksumLine) {
        Write-Fatal "Archive $Archive not found in checksums.txt — cannot verify integrity."
    }
    $ExpectedHash = ($ChecksumLine -split '\s+')[0].ToLower()
    if ($ActualHash -ne $ExpectedHash) {
        Write-Fatal @"
Checksum mismatch!
  Expected: $ExpectedHash
  Actual:   $ActualHash
The downloaded archive may have been tampered with. Do not install.
"@
    }
    Write-Info "Checksum verified: $ActualHash"

    # --- Extract ---
    Write-Info "Extracting..."
    $ExtractDir = Join-Path $TmpDir "extracted"
    Expand-Archive -Path $ArchivePath -DestinationPath $ExtractDir -Force

    # --- Install binaries ---
    $SirBin  = Join-Path $ExtractDir "sir.exe"
    $McBin   = Join-Path $ExtractDir "mister-core.exe"
    if (-not (Test-Path $SirBin))  { Write-Fatal "Archive missing sir.exe."        }
    if (-not (Test-Path $McBin))   {
        Write-Warn "mister-core.exe not found in archive — sir will use the built-in fallback evaluator."
        Write-Warn "This is expected for Windows ARM64 builds. Policy enforcement is still active."
    }

    Copy-Item -Force -Path $SirBin -Destination $InstallDir
    if (Test-Path $McBin) {
        Copy-Item -Force -Path $McBin -Destination $InstallDir
    }

    # --- Write binary manifest ---
    $ManifestDir = Join-Path $env:USERPROFILE ".sir"
    New-Item -ItemType Directory -Force -Path $ManifestDir | Out-Null
    $SirHash = (Get-FileHash -Algorithm SHA256 (Join-Path $InstallDir "sir.exe")).Hash.ToLower()
    $Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    $Manifest = @{
        version             = $Version
        installed_at        = $Timestamp
        install_method      = "download"
        sir_sha256          = $SirHash
        sir_path            = Join-Path $InstallDir "sir.exe"
        platform            = $Platform
    }
    if (Test-Path (Join-Path $InstallDir "mister-core.exe")) {
        $McHash = (Get-FileHash -Algorithm SHA256 (Join-Path $InstallDir "mister-core.exe")).Hash.ToLower()
        $Manifest.mister_core_sha256 = $McHash
        $Manifest.mister_core_path   = Join-Path $InstallDir "mister-core.exe"
    }
    $Manifest | ConvertTo-Json | Set-Content -Path (Join-Path $ManifestDir "binary-manifest.json")
    New-Item -ItemType File -Force -Path (Join-Path $ManifestDir ".manifest-expected") | Out-Null
    Write-Info "Binary manifest written to $ManifestDir\binary-manifest.json"

    Write-Info "Installed to $InstallDir"

    # --- PATH setup (user-level, no elevation required) ---
    $UserPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        [System.Environment]::SetEnvironmentVariable("PATH", "$InstallDir;$UserPath", "User")
        $env:PATH = "$InstallDir;$env:PATH"
        Write-Info "Added $InstallDir to user PATH."
        Write-Warn "Restart your terminal (or run: `$env:PATH = '$InstallDir;' + `$env:PATH) to use sir."
    }

} finally {
    Remove-Item -Recurse -Force -Path $TmpDir -ErrorAction SilentlyContinue
}

Write-Info "Installation complete."
Write-Host ""
Write-Host "Next: cd into a project and run 'sir install' to set up agent hooks."
Write-Host ""
Write-Host "Note: On Windows, sir operates in hook_gate mode only."
Write-Host "OS-level containment (sir run) requires macOS or Linux."
Write-Host "Run 'sir status' to see what is enforced on this platform."
Write-Host ""
Write-Host "For full cryptographic verification (cosign):"
Write-Host "  https://github.com/$Repo/blob/main/scripts/verify-release.sh"
