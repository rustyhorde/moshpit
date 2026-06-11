#!/usr/bin/env pwsh

$unstable = $false

foreach ($arg in $args) {
    switch ($arg) {
        '--unstable' { $unstable = $true }
        { $_ -in @('--help', '-h') } {
            Write-Host "Usage: run_musl.ps1 [OPTIONS]"
            Write-Host ""
            Write-Host "Builds Linux MUSL binaries via Docker and installs them to ~."
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  --unstable     Build with --features unstable instead of the stable build"
            Write-Host "  --help, -h     Show this help message"
            exit 0
        }
        default {
            Write-Host "Unknown argument: $arg"
            Write-Host "Run 'run_musl.ps1 --help' for usage."
            exit 1
        }
    }
}

$releaseDir = 'target/x86_64-unknown-linux-musl/release'
$bins = @('mp', 'mps', 'mp-keygen', 'mpa')

function Invoke-Step([string]$Command) {
    Write-Host ""
    Write-Host "==> $Command"
    Invoke-Expression $Command
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $Command"
        exit 1
    }
}

$currentDir = (Get-Location).Path
$gitConfig = Join-Path $HOME '.gitconfig'
$buildArgs = if ($unstable) { 'cargo build --release --features unstable' } else { 'cargo build --release' }

Invoke-Step "docker run -v cargo-cache:/root/.cargo/registry -v `"${currentDir}:/home/rust/src`" -v `"${gitConfig}:/root/.gitconfig:ro`" --rm -t blackdex/rust-musl:x86_64-musl-stable $buildArgs"

# Docker Desktop on Windows manages target/ ownership via the Windows filesystem;
# the Linux-side 'sudo chown' from run_musl.fish is not needed here.

Write-Host ""
Write-Host "==> Copying binaries to ~"
foreach ($bin in $bins) {
    $src = "$releaseDir/$bin"
    Write-Host ""
    Write-Host "==> Copy-Item $src ~"
    try {
        Copy-Item $src ~ -ErrorAction Stop
    } catch {
        Write-Host "FAILED: Copy-Item $src ~"
        Write-Host $_.Exception.Message
        exit 1
    }
}

Write-Host ""
Write-Host "All MUSL build steps completed successfully."
