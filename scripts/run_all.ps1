#!/usr/bin/env pwsh

$runTests    = $true
$runCoverage = $true
$runFuzz     = $false
$runDocs     = $true
$runInstall  = $false
$runMusl     = $false
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
            Write-Host "  --no-docs      Skip the documentation step"
            Write-Host "  --fuzz         Run the cargo fuzz steps"
            Write-Host "  --install      Run the cargo install step"
            Write-Host "  --musl         Run the MUSL Docker build step (stable)"
            Write-Host "  --unstable     Run the MUSL Docker build step with the unstable feature"
            Write-Host "  --clean        Run cargo clean after all steps complete"
            Write-Host "  --help, -h     Show this help message"
            Write-Host ""
            Write-Host "Steps (in order):"
            Write-Host "  1.  cargo fmt"
            Write-Host "  2.  cargo fmt --all -- --check"
            Write-Host "  3.  cargo matrix clippy --all-targets -- -D warnings"
            Write-Host "  4.  cargo matrix build"
            Write-Host "  5.  cargo matrix nextest run ...       (skipped with --no-test)"
            Write-Host "  6.  cargo matrix nextest run (libmoshpit-fuzz: stable + unstable) (skipped with --no-test)"
            Write-Host "  7.  cargo doc -p libmoshpit            (skipped with --no-docs)"
            Write-Host "  8.  cargo llvm-cov nextest ...         (skipped with --no-test or --no-coverage)"
            Write-Host "  9.  cargo llvm-cov report --lcov ...   (skipped with --no-test or --no-coverage)"
            Write-Host "  10. cargo llvm-cov report --html       (skipped with --no-test or --no-coverage)"
            Write-Host "  11. cargo fuzz run (30s each target)   (only with --fuzz)"
            Write-Host "  12. run_install.ps1                    (only with --install)"
            Write-Host "  13. run_musl.ps1                       (only with --musl or --unstable; --unstable builds unstable)"
            Write-Host "  14. cargo clean                        (only with --clean)"
            exit 0
        }
        '--no-test' {
            $runTests    = $false
            $runCoverage = $false
        }
        '--no-coverage' { $runCoverage  = $false }
        '--no-docs'     { $runDocs      = $false }
        '--fuzz'        { $runFuzz      = $true  }
        '--install'     { $runInstall   = $true  }
        '--musl'        { $runMusl      = $true  }
        '--unstable'    { $runMusl = $true; $muslUnstable = $true }
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
    Push-Location libmoshpit/fuzz
    Invoke-Step 'cargo matrix nextest run'
    Pop-Location
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
    Invoke-Step 'cargo fuzz run --fuzz-dir libmoshpit/fuzz --features unstable fuzz_pubkey_parse -- -max_total_time=30'
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
