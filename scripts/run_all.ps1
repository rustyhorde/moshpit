#!/usr/bin/env pwsh

$runTests    = $true
$runCoverage = $true
$runFuzz     = $true
$runDocs     = $true
$runInstall  = $true
$runMusl     = $true
$muslUnstable = $false
$runClean    = $false

foreach ($arg in $args) {
    switch ($arg) {
        { $_ -in @('--help', '-h') } {
            Write-Host "Usage: run_all.ps1 [OPTIONS]"
            Write-Host ""
            Write-Host "Runs the full moshpit CI pipeline locally."
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  --no-test      Skip nextest and all coverage steps"
            Write-Host "  --no-coverage  Skip coverage steps only (lcov + html reports)"
            Write-Host "  --no-fuzz      Skip the cargo fuzz steps"
            Write-Host "  --no-docs      Skip the documentation step"
            Write-Host "  --no-install   Skip the cargo install step"
            Write-Host "  --no-musl      Skip the MUSL Docker build step"
            Write-Host "  --unstable     Pass --unstable to run_musl.ps1 (builds unstable instead of stable)"
            Write-Host "  --clean        Run cargo clean after all steps complete"
            Write-Host "  --help, -h     Show this help message"
            Write-Host ""
            Write-Host "Steps (in order):"
            Write-Host "  1.  cargo fmt"
            Write-Host "  2.  cargo fmt --all -- --check"
            Write-Host "  3.  cargo matrix clippy --all-targets -- -D warnings"
            Write-Host "  4.  cargo matrix build"
            Write-Host "  5.  cargo nextest run ...              (skipped with --no-test)"
            Write-Host "  6.  cargo test (libmoshpit-fuzz)       (skipped with --no-test)"
            Write-Host "  7.  cargo doc -p libmoshpit            (skipped with --no-docs)"
            Write-Host "  8.  cargo llvm-cov nextest ...         (skipped with --no-test or --no-coverage)"
            Write-Host "  9.  cargo llvm-cov report --lcov ...   (skipped with --no-test or --no-coverage)"
            Write-Host "  10. cargo llvm-cov report --html       (skipped with --no-test or --no-coverage)"
            Write-Host "  11. cargo fuzz run (30s each target)   (skipped with --no-fuzz)"
            Write-Host "  12. run_install.ps1                    (skipped with --no-install)"
            Write-Host "  13. run_musl.ps1                       (skipped with --no-musl; --unstable passed through)"
            Write-Host "  14. cargo clean                        (only with --clean)"
            exit 0
        }
        '--no-test' {
            $runTests    = $false
            $runCoverage = $false
        }
        '--no-coverage' { $runCoverage  = $false }
        '--no-fuzz'     { $runFuzz      = $false }
        '--no-docs'     { $runDocs      = $false }
        '--no-install'  { $runInstall   = $false }
        '--no-musl'     { $runMusl      = $false }
        '--unstable'    { $muslUnstable = $true  }
        '--clean'       { $runClean     = $true  }
        default {
            Write-Host "Unknown argument: $arg"
            Write-Host "Run 'run_all.ps1 --help' for usage."
            exit 1
        }
    }
}

function Invoke-Step([string]$Command) {
    Write-Host ""
    Write-Host "==> $Command"
    Invoke-Expression $Command
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $Command"
        exit 1
    }
}

function Invoke-Script {
    param([string]$Path, [string[]]$ScriptArgs = @())
    $display = if ($ScriptArgs.Count -gt 0) { "$Path $($ScriptArgs -join ' ')" } else { $Path }
    Write-Host ""
    Write-Host "==> $display"
    & $Path @ScriptArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $display"
        exit 1
    }
}

Invoke-Step 'cargo fmt'
Invoke-Step 'cargo fmt --all -- --check'
Invoke-Step 'cargo matrix clippy --all-targets -- -D warnings'
Invoke-Step 'cargo matrix build'

if ($runTests) {
    Invoke-Step 'cargo matrix nextest run'
    Invoke-Step 'cargo matrix test --doc -p libmoshpit'
    if ($muslUnstable) {
        Invoke-Step 'cargo test --manifest-path libmoshpit/fuzz/Cargo.toml --features unstable'
    } else {
        Invoke-Step 'cargo test --manifest-path libmoshpit/fuzz/Cargo.toml'
    }
}

if ($runDocs) {
    Invoke-Step 'cargo doc -p libmoshpit'
}

if ($runCoverage) {
    Invoke-Step 'cargo matrix -F unstable llvm-cov nextest --no-report'
    Invoke-Step 'cargo llvm-cov report --lcov --output-path lcov.info'
    Invoke-Step 'cargo llvm-cov report --html'
}

if ($runFuzz) {
    Invoke-Step 'cargo fuzz run --fuzz-dir libmoshpit/fuzz fuzz_frame -- -max_total_time=30'
    Invoke-Step 'cargo fuzz run --fuzz-dir libmoshpit/fuzz fuzz_encframe -- -max_total_time=30'
    Invoke-Step 'cargo fuzz run --fuzz-dir libmoshpit/fuzz fuzz_encframe_decrypt -- -max_total_time=30'
    Invoke-Step 'cargo fuzz run --fuzz-dir libmoshpit/fuzz fuzz_escape_intercept -- -max_total_time=30'
    Invoke-Step 'cargo fuzz run --fuzz-dir libmoshpit/fuzz fuzz_keyfile -- -max_total_time=30'
    Invoke-Step 'cargo fuzz run --fuzz-dir libmoshpit/fuzz fuzz_emulator -- -max_total_time=30'
    if ($muslUnstable) {
        Invoke-Step 'cargo fuzz run --fuzz-dir libmoshpit/fuzz --features unstable fuzz_pubkey_parse -- -max_total_time=30'
    }
}

if ($runInstall) {
    Invoke-Script "$PSScriptRoot\run_install.ps1"
}

if ($runMusl) {
    $muslArgs = if ($muslUnstable) { @('--unstable') } else { @() }
    Invoke-Script "$PSScriptRoot\run_musl.ps1" $muslArgs
}

if ($runClean) {
    Invoke-Step 'cargo clean'
}

Write-Host ""
Write-Host "All steps completed successfully."
