& {
    $ErrorActionPreference = 'Stop'
    $appArgs = @($args)
    $release = if ($env:NETWATCH_RELEASE) { $env:NETWATCH_RELEASE } else { 'v4.0.0' }
    if ($release -notmatch '^[A-Za-z0-9._-]+$') { throw 'Invalid release tag' }
    $architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    if ($architecture -ne 'X64') { throw 'This release provides Windows x64. ARM64 may use x64 emulation.' }
    $base = if ($env:NETWATCH_INSTALL_DIR) { $env:NETWATCH_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'NetWatch' }
    $root = Join-Path $base 'native'
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $current = Join-Path $root 'current'
    $previous = Join-Path $root 'previous'
    if ($env:NETWATCH_ROLLBACK -eq '1') {
        $digest = (Get-Content -LiteralPath $previous -Raw).Trim()
        if ($digest -notmatch '^[a-f0-9]{64}$') { throw 'Invalid previous version' }
    } else {
        $artifact = 'netwatch-Windows-x86_64.exe'
        $temporary = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $temporary | Out-Null
        try {
            $app = Join-Path $temporary $artifact
            Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/iproby/networktestby_mac/releases/download/$release/$artifact" -OutFile $app
            $sumFile = Join-Path $temporary 'checksum'
            Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/iproby/networktestby_mac/releases/download/$release/$artifact.sha256" -OutFile $sumFile
            $digest = ((Get-Content -LiteralPath $sumFile -Raw) -split '\s+')[0].ToLowerInvariant()
            if ($digest -notmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $app -Algorithm SHA256).Hash.ToLowerInvariant() -ne $digest) { throw 'SHA-256 mismatch. Launch cancelled.' }
            $target = Join-Path $root ($digest + '.exe')
            if (-not (Test-Path -LiteralPath $target)) {
                & $app --version
                if ($LASTEXITCODE -ne 0) { throw 'Release startup check failed' }
                Move-Item -LiteralPath $app -Destination $target
            }
        } finally { Remove-Item -LiteralPath $temporary -Recurse -Force }
    }
    $target = Join-Path $root ($digest + '.exe')
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $digest) { throw 'Damaged application cache' }
    $old = if (Test-Path -LiteralPath $current) { (Get-Content -LiteralPath $current -Raw).Trim() } else { '' }
    if ($old -ne $digest) {
        if ($old -match '^[a-f0-9]{64}$') { Set-Content -LiteralPath $previous -Value $old -Encoding ascii }
        Set-Content -LiteralPath $current -Value $digest -Encoding ascii
    }
    & $target @appArgs
    if ($LASTEXITCODE -ne 0) { throw "NetWatch exited with code $LASTEXITCODE" }
} @args
