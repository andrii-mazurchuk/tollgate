# Tollgate installer for Windows (PowerShell 5.1+). No admin rights needed. Re-run = upgrade.
#
#   irm https://raw.githubusercontent.com/andrii-mazurchuk/tollgate/main/install.ps1 | iex
#   .\install.ps1 [--source PATH|URL] [--ref TAG] [--modify-path] [--install-uv] [--uninstall]
#
#   --source       what to install: a local clone, or a pip/uv spec (default git+https://github.com/andrii-mazurchuk/tollgate)
#   --ref          git tag/branch/commit for a git+ source
#   --modify-path  allow adding the bin dir to the user PATH (otherwise the line is printed)
#   --install-uv   if neither uv nor Python 3.13+ is found, install uv with its official installer
#   --uninstall    remove the program (your data in the Tollgate home is kept; the path is printed)
#
# Order: uv found -> `uv tool install`; else Python 3.13+ -> venv in <home>\venv + a shim in <home>\bin;
# else -> print (or with --install-uv run) the uv installer. Then `tollgate init`.
$ErrorActionPreference = 'Stop'

$Source = 'git+https://github.com/andrii-mazurchuk/tollgate'; $Ref = ''
$ModifyPath = $false; $InstallUv = $false; $Uninstall = $false
for ($i = 0; $i -lt $args.Count; $i++) {
    switch -Regex ($args[$i]) {
        '^--?source$'      { $i++; $Source = $args[$i] }
        '^--?ref$'         { $i++; $Ref = $args[$i] }
        '^--?modify-?path$' { $ModifyPath = $true }
        '^--?install-?uv$' { $InstallUv = $true }
        '^--?uninstall$'   { $Uninstall = $true }
        default { throw "unknown option $($args[$i]) (see the header of install.ps1)" }
    }
}

function Say($m) { Write-Host "[tollgate] $m" }
function Run($exe) {
    $rest = $args
    Say ("run: $exe " + ($rest -join ' '))
    $ErrorActionPreference = 'Continue'  # PS 5.1: native stderr (uv progress) under 2>&1 must not abort; exit code decides
    & $exe @rest
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -ne 0) { throw "$exe exited with $LASTEXITCODE" }
}
function Add-UserPath($dir) {
    $p = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($p -split ';') -contains $dir) { return }
    if ($ModifyPath) {
        [Environment]::SetEnvironmentVariable('Path', ($(if ($p) { "$p;$dir" } else { $dir })), 'User')
        Say "added $dir to the user PATH (new terminals)"
    } else {
        Say "add to PATH yourself (or re-run with --modify-path):"
        Write-Host "  [Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path','User') + ';$dir', 'User')"
    }
}

$TgHome = if ($env:TOLLGATE_HOME) { $env:TOLLGATE_HOME } else { Join-Path $env:LOCALAPPDATA 'Tollgate' }
$uv = (Get-Command uv -ErrorAction SilentlyContinue).Source

if ($Uninstall) {
    if ($uv) { $ErrorActionPreference = 'Continue'; foreach ($t in "agent-tollgate", "tollgate") { & $uv tool uninstall $t 2>$null }; $ErrorActionPreference = 'Stop' }
    foreach ($d in 'venv', 'bin') { $p = Join-Path $TgHome $d; if (Test-Path $p) { Remove-Item -Recurse -Force $p; Say "removed $p" } }
    Say "kept your data: $TgHome (policy, audit log, accounts). Delete it with: Remove-Item -Recurse -Force '$TgHome'"
    Say "if you ran 'tollgate service install --yes', remove the task first: tollgate service uninstall --yes (or schtasks /Delete /TN Tollgate /F)"
    exit 0
}

if (Test-Path $Source) { $Source = (Resolve-Path $Source).Path }  # local clone
$spec = if ($Ref -and $Source -like 'git+*') { "$Source@$Ref" } else { $Source }
Say "installing tollgate from $spec"

if (-not $uv) {
    $py = $null
    $ErrorActionPreference = 'Continue'  # a missing `py -3.13` writes to stderr; that is a "no", not a crash
    foreach ($c in @(@('py', '-3.13'), @('python'), @('python3'))) {
        if (Get-Command $c[0] -ErrorAction SilentlyContinue) {
            $pyArgs = @($c | Select-Object -Skip 1)
            & $c[0] @pyArgs -c 'import sys; sys.exit(0 if sys.version_info >= (3, 13) else 1)' 2>$null
            if ($LASTEXITCODE -eq 0) { $py = $c; break }
        }
    }
    $ErrorActionPreference = 'Stop'
    if (-not $py) {
        $cmd = 'powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"'
        if (-not $InstallUv) {
            Say 'neither uv nor Python 3.13+ found. Install uv (it brings its own Python), then re-run this script:'
            Write-Host "  $cmd"
            Say '(or re-run with --install-uv to do it now)'
            exit 1
        }
        if (-not $ModifyPath) { $env:UV_NO_MODIFY_PATH = '1' }
        Say "run: $cmd"
        Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
        $uvDir = if ($env:UV_INSTALL_DIR) { $env:UV_INSTALL_DIR } else { Join-Path $env:USERPROFILE '.local\bin' }
        $uv = Join-Path $uvDir 'uv.exe'
        if (-not (Test-Path $uv)) { throw "uv not found at $uv after its installer ran" }
    }
}

if ($uv) {
    Run $uv tool install --force --reinstall --python 3.13 $spec
    $bin = (& $uv tool dir --bin).Trim()
    $tollgate = Join-Path $bin 'tollgate.exe'
} else {
    $venv = Join-Path $TgHome 'venv'
    $pyArgs = @($py | Select-Object -Skip 1)
    if (-not (Test-Path (Join-Path $venv 'Scripts\python.exe'))) { Run $py[0] @pyArgs -m venv $venv }
    Run (Join-Path $venv 'Scripts\python.exe') -m pip install --upgrade --quiet $spec
    $bin = Join-Path $TgHome 'bin'
    New-Item -ItemType Directory -Force $bin | Out-Null
    Set-Content -Encoding ascii (Join-Path $bin 'tollgate.cmd') "@`"$venv\Scripts\tollgate.exe`" %*"
    $tollgate = Join-Path $venv 'Scripts\tollgate.exe'
}
if (-not (Test-Path $tollgate)) { throw "installed, but $tollgate is missing" }
Say "installed: $tollgate"
Add-UserPath $bin

Run $tollgate init

Write-Host ""
Say "done. tollgate = $tollgate (the next steps above; 'tollgate doctor' checks the setup)"
Say "upgrade: re-run this script. uninstall: .\install.ps1 --uninstall"
