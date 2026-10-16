# Remote entry: irm https://raw.githubusercontent.com/iproby/networktestby_mac/main/install.ps1 | iex
& {
    $ErrorActionPreference = 'Stop'
    $AppArgs = @($args)
    $ref = if ($env:NETWATCH_REF) { $env:NETWATCH_REF } else { 'main' }
    if ($ref -notmatch '^[A-Za-z0-9._/-]+$' -or $ref.StartsWith('/') -or $ref.Contains('..')) {
        throw 'Invalid NETWATCH_REF: use a branch, tag or commit SHA.'
    }
    $python = $null
    $prefix = @()
    foreach ($name in @('py', 'python', 'python3')) {
        $candidate = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $candidate) { continue }
        $candidatePrefix = @()
        if ($name -eq 'py') { $candidatePrefix = @('-3') }
        try {
            & $candidate.Source @candidatePrefix -c 'import sys; raise SystemExit(sys.version_info < (3, 9))' 2>$null
            if ($LASTEXITCODE -eq 0) {
                $python = $candidate.Source
                $prefix = @($candidatePrefix)
                break
            }
        } catch { continue }
    }
    if (-not $python) { throw 'Install Python 3.9+ from https://www.python.org/downloads/ and run this command again.' }
    $workDir = Join-Path ([IO.Path]::GetTempPath()) ('netwatch-installer-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $workDir | Out-Null
    try {
        $bootstrap = Join-Path $workDir 'bootstrap.py'
        Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/iproby/networktestby_mac/$ref/bootstrap.py" -OutFile $bootstrap
        & $python @prefix $bootstrap @AppArgs
        if ($LASTEXITCODE -ne 0) { throw "NetWatch exited with code $LASTEXITCODE" }
    } finally {
        Remove-Item -Recurse -Force -LiteralPath $workDir
    }
} @args
