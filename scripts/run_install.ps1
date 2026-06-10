#!/usr/bin/env pwsh

function Invoke-Step([string]$Command) {
    Write-Host ""
    Write-Host "==> $Command"
    Invoke-Expression $Command
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $Command"
        exit 1
    }
}

Invoke-Step 'cargo install --path moshpits --force --locked'
Invoke-Step 'cargo install --path moshpit --force --locked'
Invoke-Step 'cargo install --path keygen --force --locked'
Invoke-Step 'cargo install --path agent --force --locked'

Write-Host ""
Write-Host "All packages installed successfully."
