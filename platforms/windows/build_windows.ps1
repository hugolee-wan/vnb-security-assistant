$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Resolve-Path (Join-Path $ScriptDir "..\..")
$WinDir = Join-Path $RootDir "platforms\windows"
$WinLibDir = Join-Path $WinDir "lib"

Push-Location $RootDir
try {
    Write-Host "[1/3] Compiling VNB Security Assistant for Windows (x86_64-pc-windows-msvc)..." -ForegroundColor Cyan
    $env:RUSTFLAGS = "--remap-path-prefix=$RootDir=."
    cargo build --release

    New-Item -ItemType Directory -Force -Path $WinLibDir | Out-Null

    Write-Host "[2/3] Staging Windows executable and shared DLL into platforms/windows/..." -ForegroundColor Cyan
    Copy-Item -Force "target\release\vnb-security-assistant.exe" (Join-Path $WinDir "vnb-security-assistant.exe")
    if (Test-Path "target\release\vnb_edr_gpui.dll") {
        Copy-Item -Force "target\release\vnb_edr_gpui.dll" (Join-Path $WinLibDir "vnb_edr_gpui.dll")
    }

    Write-Host "[3/3] Verifying headless check..." -ForegroundColor Cyan
    & (Join-Path $WinDir "vnb-security-assistant.exe") --abi-info
    Write-Host "Build complete: $WinDir" -ForegroundColor Green
} finally {
    Pop-Location
}
