$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Assert-Checksum {
    $filePath = [string]$args[0]
    $sumsPath = [string]$args[1]
    $fileName = [string]$args[2]
    $expected = $null

    foreach ($line in Get-Content -LiteralPath $sumsPath) {
        if ($line -match '^([0-9a-fA-F]{64})\s+(.+)$' -and $matches[2] -eq $fileName) {
            $expected = $matches[1].ToLowerInvariant()
            break
        }
    }

    if (-not $expected) {
        throw "No checksum found for $fileName in $sumsPath"
    }
    $actual = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
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

    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDir -Force
    $entangleBinary = Get-ChildItem -Path $extractDir -Filter 'entangle.exe' -Recurse -File | Select-Object -First 1
    if (-not $entangleBinary) {
        throw 'The Entangle archive does not contain an entangle.exe binary.'
    }
    $null = New-Item -Path $installDir -ItemType Directory -Force
    $binaryPath = Join-Path $installDir 'entangle.exe'
    Copy-Item -LiteralPath $entangleBinary.FullName -Destination $binaryPath -Force

    if (Get-Command croc -ErrorAction SilentlyContinue) {
        Write-Output "Using existing croc: $((Get-Command croc).Source)"
    } elseif ($env:ENTANGLE_SKIP_CROC -eq '1') {
        Write-Output 'Skipping croc installation because ENTANGLE_SKIP_CROC=1'
    } else {
        $crocVersion = if ([string]::IsNullOrWhiteSpace($env:CROC_VERSION)) { 'v11.5.4' } else { $env:CROC_VERSION }
        if (-not $crocVersion.StartsWith('v')) {
            $crocVersion = "v$crocVersion"
        }
        $crocAsset = 'Windows-64bit.zip'
        $crocArchiveName = "croc_${crocVersion}_$crocAsset"
        $crocSumsName = "croc_${crocVersion}_checksums.txt"
        if ($env:CROC_DOWNLOAD_BASE) {
            $crocDownloadBase = $env:CROC_DOWNLOAD_BASE.TrimEnd('/')
        } else {
            $crocDownloadBase = "https://github.com/schollz/croc/releases/download/$crocVersion"
        }
        $crocArchivePath = Join-Path $tempDir $crocArchiveName
        $crocSumsPath = Join-Path $tempDir $crocSumsName
        $crocExtractDir = Join-Path $tempDir 'croc'
        $null = Invoke-WebRequest -Uri "$crocDownloadBase/$crocArchiveName" -OutFile $crocArchivePath -UseBasicParsing
        $null = Invoke-WebRequest -Uri "$crocDownloadBase/$crocSumsName" -OutFile $crocSumsPath -UseBasicParsing
        Assert-Checksum $crocArchivePath $crocSumsPath $crocArchiveName

        Expand-Archive -LiteralPath $crocArchivePath -DestinationPath $crocExtractDir -Force
        $crocBinary = Get-ChildItem -Path $crocExtractDir -Filter 'croc.exe' -Recurse -File | Select-Object -First 1
        if (-not $crocBinary) {
            throw 'The croc archive does not contain a croc.exe binary.'
        }
        Copy-Item -LiteralPath $crocBinary.FullName -Destination (Join-Path $installDir 'croc.exe') -Force
    }

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (Test-PathListContainsInstallDir $userPath $installDir)) {
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
    if (Test-Path (Join-Path $installDir 'croc.exe')) {
        Write-Output 'croc version:'
        & (Join-Path $installDir 'croc.exe') --version
    }
    Write-Output 'Restart your terminal and reload or restart your MCP client to pick up the PATH change.'
} finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
