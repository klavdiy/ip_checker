# IP Address Geolocation Checker — Windows launcher
# Requires Python 3 on PATH. Optional: nmap, whois (Sysinternals or third-party), nslookup (built-in).

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PyScript = Join-Path $ScriptDir "ip_checker.py"

if (-not (Test-Path -LiteralPath $PyScript)) {
    Write-Error "ip_checker.py not found: $PyScript"
    exit 1
}

$launcher = $null
foreach ($name in @("python3", "python", "py")) {
    if (Get-Command $name -ErrorAction SilentlyContinue) {
        $launcher = $name
        break
    }
}

if (-not $launcher) {
    Write-Host "Error: Python 3 not found. Install from https://www.python.org/downloads/ and re-open the terminal." -ForegroundColor Red
    exit 1
}

if ($launcher -eq "py") {
    & py -3 $PyScript @args
} else {
    & $launcher $PyScript @args
}
exit $LASTEXITCODE
