# Builds the project for msvc-x64 and msvc-x86 in parallel.
#
# Requirements:
#   - PowerShell 7+ (uses ForEach-Object -Parallel)
#   - rustup/cargo (https://rustup.rs)
#   - Visual Studio Build Tools with the C++ workload for x86 and x64
#   - Network access the first time a rustup target is added
#
# Artifacts follow the default cargo layout (target/<triple>/release) and are
# copied to dist/ as version_renamer-msvc-<name>.exe. The exit code is
# non-zero if any target fails; the remaining targets still build.
$ErrorActionPreference = 'Stop'
[System.Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$projectRoot = $PSScriptRoot
$dist = Join-Path $projectRoot 'dist'
$targets = [ordered]@{
    'msvc-x64'   = 'x86_64-pc-windows-msvc'
    'msvc-x86'   = 'i686-pc-windows-msvc'
}

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'This script requires PowerShell 7+ (ForEach-Object -Parallel).'
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw 'cargo was not found. Install Rust first: https://rustup.rs'
}
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
    throw 'rustup was not found. Install Rust first: https://rustup.rs'
}

Write-Host 'Checking rustup targets...'
$installed = (rustup target list --installed) -join "`n"
foreach ($triple in $targets.Values) {
    if ($installed -notmatch [regex]::Escape($triple)) {
        Write-Host "  Adding missing target: $triple"
        rustup target add $triple
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "  Failed to add target $triple; its build will fail."
        }
    }
}

Write-Host ''
Write-Host 'Building in parallel...'
$results = $targets.GetEnumerator() | ForEach-Object -Parallel {
    $name = $_.Key
    $triple = $_.Value
    $logPrefix = "[$name] "
    Push-Location $using:projectRoot
    try {
        cargo build --release --target $triple 2>&1 |
            ForEach-Object { Write-Host ($logPrefix + $_) }
        if ($LASTEXITCODE -ne 0) {
            throw "cargo exited with code $LASTEXITCODE"
        }
        [pscustomobject]@{
            Name   = $name
            Triple = $triple
            Ok     = $true
            Exe    = Join-Path $using:projectRoot "target\$triple\release\version_renamer.exe"
        }
    } catch {
        [pscustomobject]@{
            Name   = $name
            Triple = $triple
            Ok     = $false
            Exe    = ''
        }
    } finally {
        Pop-Location
    }
} -ThrottleLimit 3

$ok = @($results | Where-Object { $_.Ok })
$failed = @($results | Where-Object { -not $_.Ok })

if ($ok.Count -gt 0) {
    New-Item -ItemType Directory -Path $dist -Force | Out-Null
    foreach ($r in $ok) {
        if (-not (Test-Path -LiteralPath $r.Exe)) {
            Write-Warning "$($r.Name): artifact not found at '$($r.Exe)'"
            continue
        }
        $dest = Join-Path $dist "version_renamer-$($r.Name).exe"
        Copy-Item -LiteralPath $r.Exe -Destination $dest -Force
        Write-Host "Copied $($r.Exe) -> $dest"
    }
}

Write-Host ''
Write-Host '=== Build summary ==='
foreach ($r in $results) {
    $status = if ($r.Ok) { 'OK' } else { 'FAILED' }
    Write-Host ("{0,-7} {1,-10} {2}" -f $status, $r.Name, $r.Triple)
}
if ($failed.Count -gt 0) {
    $names = ($failed | ForEach-Object { $_.Name }) -join ', '
    Write-Warning "$($failed.Count) target(s) failed: $names"
    exit 1
}
Write-Host "All $($results.Count) targets built successfully."
exit 0
