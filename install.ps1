$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'Only 64-bit Windows is supported by the prebuilt installer. Install from source with: cargo install --git https://github.com/DailenG/entangle entangle'
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Avoid script-module cmdlets that may not load when PSModulePath is polluted.
function Get-Sha256Hex([string]$Path) {
    $stream = $null
    $hasher = $null
    try {
        $stream = [IO.File]::OpenRead($Path)
        $hasher = [Security.Cryptography.SHA256]::Create()
        $bytes = $hasher.ComputeHash($stream)
        return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
    } finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        if ($null -ne $hasher) {
            $hasher.Dispose()
        }
    }
}

function Expand-ZipArchive([string]$Path, [string]$Destination) {
    $null = Add-Type -AssemblyName System.IO.Compression.FileSystem
    $null = [IO.Directory]::CreateDirectory($Destination)
    [IO.Compression.ZipFile]::ExtractToDirectory($Path, $Destination)
}

function Assert-Checksum {
    $filePath = [string]$args[0]
    $sumsPath = [string]$args[1]
    $fileName = [string]$args[2]
    $expected = $null

    foreach ($line in [IO.File]::ReadAllLines($sumsPath)) {
        if ($line -match '^([0-9a-fA-F]{64})\s+(.+)$' -and $matches[2] -eq $fileName) {
            $expected = $matches[1].ToLowerInvariant()
            break
        }
    }

    if (-not $expected) {
        throw "No checksum found for $fileName in $sumsPath"
    }
    $actual = Get-Sha256Hex -Path $filePath
    if ($actual -ne $expected) {
        throw "SHA-256 mismatch for $fileName"
    }
}

function Test-PathListContainsInstallDir {
    $pathList = [string]$args[0]
    $installPath = [string]$args[1]
    $normalizedInstallPath = $installPath.TrimEnd([char]'\')

    foreach ($entry in ($pathList -split ';')) {
        if (-not [string]::IsNullOrWhiteSpace($entry)) {
            $expandedEntry = [Environment]::ExpandEnvironmentVariables($entry.Trim())
            if ($expandedEntry.TrimEnd([char]'\') -ieq $normalizedInstallPath) {
                return $true
            }
        }
    }
    return $false
}

$target = 'x86_64-pc-windows-msvc'
if ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64' -or $env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
    Write-Output 'Windows ARM64 detected; installing the x64 build, which runs under emulation.'
}

$version = if ([string]::IsNullOrWhiteSpace($env:ENTANGLE_VERSION)) { 'latest' } else { $env:ENTANGLE_VERSION }
$installDir = if ([string]::IsNullOrWhiteSpace($env:ENTANGLE_INSTALL_DIR)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw 'LOCALAPPDATA is unavailable; set ENTANGLE_INSTALL_DIR to a user-writable directory.'
    }
    Join-Path $env:LOCALAPPDATA 'Programs\entangle\bin'
} else {
    $env:ENTANGLE_INSTALL_DIR
}
$installDir = [IO.Path]::GetFullPath($installDir)

if ($env:ENTANGLE_DOWNLOAD_BASE) {
    $downloadBase = $env:ENTANGLE_DOWNLOAD_BASE.TrimEnd('/')
} elseif ($version -eq 'latest') {
    $downloadBase = 'https://github.com/DailenG/entangle/releases/latest/download'
} else {
    $downloadBase = "https://github.com/DailenG/entangle/releases/download/$version"
}

$tempDir = Join-Path ([IO.Path]::GetTempPath()) ("entangle-install-" + [guid]::NewGuid().ToString('N'))
$null = New-Item -Path $tempDir -ItemType Directory -Force

try {
    $archiveName = "entangle-$target.zip"
    $archivePath = Join-Path $tempDir $archiveName
    $sumsPath = Join-Path $tempDir 'SHA256SUMS'
    $extractDir = Join-Path $tempDir 'entangle'
    $null = Invoke-WebRequest -Uri "$downloadBase/$archiveName" -OutFile $archivePath -UseBasicParsing
    $null = Invoke-WebRequest -Uri "$downloadBase/SHA256SUMS" -OutFile $sumsPath -UseBasicParsing
    Assert-Checksum $archivePath $sumsPath $archiveName

    Expand-ZipArchive -Path $archivePath -Destination $extractDir
    $entangleBinary = Get-ChildItem -Path $extractDir -Filter 'entangle.exe' -Recurse -File | Select-Object -First 1
    if (-not $entangleBinary) {
        throw 'The Entangle archive does not contain an entangle.exe binary.'
    }
    $null = New-Item -Path $installDir -ItemType Directory -Force
    $binaryPath = Join-Path $installDir 'entangle.exe'
    $oldBinaryPath = "$binaryPath.old"
    if (Test-Path -LiteralPath $binaryPath) {
        Remove-Item -LiteralPath $oldBinaryPath -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $binaryPath -Destination $oldBinaryPath -Force
    }
    Copy-Item -LiteralPath $entangleBinary.FullName -Destination $binaryPath -Force

    $pathChanged = $false
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (Test-PathListContainsInstallDir $userPath $installDir)) {
        $pathChanged = $true
        if ([string]::IsNullOrWhiteSpace($userPath)) {
            $newUserPath = $installDir
        } else {
            $newUserPath = "$userPath;$installDir"
        }
        [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
    }

    if (-not (Test-PathListContainsInstallDir $env:Path $installDir)) {
        if ([string]::IsNullOrEmpty($env:Path)) {
            $env:Path = $installDir
        } else {
            $env:Path = "$installDir;$env:Path"
        }
    }

    Write-Output "`nEntangle version:"
    & $binaryPath --version
    Write-Output "Entangle executable: $binaryPath"
    $jsonEscapedPath = $binaryPath.Replace('\', '\\')
    Write-Output "MCP config command (JSON-escaped): `"$jsonEscapedPath`""
    if ($pathChanged) {
        Write-Output 'Added the install directory to your user PATH; restart your terminal to pick it up.'
    }
    Write-Output 'Reload or restart your MCP client so it runs this version.'
    Write-Output 'Pairing-key changes take effect without a client reload; binary upgrades require one.'
    Write-Output 'Pair this machine: run `entangle pair init` on your first machine, then `entangle pair join <code>` here.'
} finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
