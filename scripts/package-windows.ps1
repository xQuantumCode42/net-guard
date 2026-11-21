param([string]$PrebuiltDirectory)

$ErrorActionPreference = 'Stop'

function Confirm-ExitCode {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed (exit $LASTEXITCODE)"
    }
}

$project = Split-Path -Parent $PSScriptRoot
$desktop = Join-Path $project 'apps/desktop'
$buildDir = Join-Path $project 'target'
$target = 'x86_64-pc-windows-msvc'
if ($PrebuiltDirectory) {
    $PrebuiltDirectory = (Resolve-Path -LiteralPath $PrebuiltDirectory).Path
}

Push-Location $project
try {
    node scripts/check-version.mjs
    Confirm-ExitCode 'Version check'
    $metadataJson = cargo metadata --no-deps --format-version 1 --locked
    Confirm-ExitCode 'Cargo metadata'
    $metadata = $metadataJson | ConvertFrom-Json
    $version = ($metadata.packages | Where-Object name -eq 'netguard-desktop').version
    $release = Join-Path $project "release/$version"
    $destination = Join-Path $release 'windows-x64'
    if (Test-Path -LiteralPath $destination) {
        throw "An artifact already exists at $destination. Move it to a backup before rebuilding this version."
    }

    if ($PrebuiltDirectory) {
        $binaries = $PrebuiltDirectory
    } else {
        Push-Location $desktop
        try {
            npm.cmd ci --no-audit --no-fund
            Confirm-ExitCode 'Frontend install'
            npm.cmd run build
            Confirm-ExitCode 'Frontend build'
        } finally {
            Pop-Location
        }
        cargo build --locked --release --target $target --target-dir $buildDir -p netguard-desktop -p netguard-agent --features tauri/custom-protocol
        Confirm-ExitCode 'Windows build'
        $binaries = Join-Path $buildDir "$target/release"
    }

    $gui = Join-Path $binaries 'netguard-desktop.exe'
    $bytes = [IO.File]::ReadAllBytes($gui)
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    $architecture = [BitConverter]::ToUInt16($bytes, ($pe + 4))
    $subsystem = [BitConverter]::ToUInt16($bytes, ($pe + 24 + 68))
    if ($architecture -ne 0x8664 -or $subsystem -ne 2) {
        throw 'Expected a Windows x64 GUI executable that starts without a console.'
    }
    $agentVersion = & (Join-Path $binaries 'netguard-agent.exe') --version
    Confirm-ExitCode 'Agent version check'
    if ($agentVersion -ne "NetGuard $version") {
        throw "Unexpected agent version: $agentVersion"
    }

    $staging = Join-Path $release ('.staging-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    $names = @('netguard-desktop.exe', 'netguard-agent.exe')
    foreach ($name in $names) {
        Copy-Item -LiteralPath (Join-Path $binaries $name) -Destination (Join-Path $staging $name)
    }
    $hashes = foreach ($name in $names) {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $staging $name)).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    Set-Content -LiteralPath (Join-Path $staging 'SHA256SUMS') -Value $hashes -Encoding ascii
    Rename-Item -LiteralPath $staging -NewName 'windows-x64'
    Write-Output $destination
} finally {
    Pop-Location
}
