# =================================================
# =          Ritam's PowerShell Profile           =
# =================================================

if ($Host.Name -ne 'ConsoleHost') { return }


# ---------------- Environment ----------------
$env:LANG = "en_US.UTF-8"
$env:EDITOR = "code"


# ---------------- eza not ls ----------------
if (Get-Command eza -ErrorAction SilentlyContinue) {

    function ls {
        eza --all --group-directories-first --icons --no-user @args
    }

    function ll {
        eza --long --all --group-directories-first --icons --no-user @args
    }

    function tree {
        eza --tree --all --icons @args
    }
}


# ---------------- (lazy) ----------------
function z {
    Remove-Item Function:z -Force
    Invoke-Expression (& zoxide init powershell)
    z @args
}

function fuck {
    Remove-Item Function:fuck -Force
    Invoke-Expression (& thefuck --alias)
    fuck @args
}

# ---------------- Git sugar ----------------
Set-Alias g git

function gcom {
    git add .
    git commit -m ($args -join ' ')
}

function lazyg {
    git add .
    git commit -m ($args -join ' ')
    git push
}

# ---------------- Utility & helpers ----------------

# py venv shortcut
function ipva {
    $activate = ".\.venv\Scripts\Activate.ps1"
    if (Test-Path $activate) {
        Write-Host "Activating .venv"
        . $activate
    }
    else {
        Write-Host "No .venv found"
    }
}

function pubip {
    Invoke-RestMethod "https://ifconfig.me/all"
}

# Unix-ish
function which($name) {
    (Get-Command $name -ErrorAction SilentlyContinue).Source
}

function touch($file) {
    New-Item -ItemType File -Name $file -Force | Out-Null
}

function grep {
    param($pattern, $path = ".")
    Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue |
    Select-String $pattern
}

function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

function pgrep($name) {
    Get-Process $name -ErrorAction SilentlyContinue
}

# ---------------- Fun ----------------
function inspire {
    Invoke-RestMethod "https://www.affirmations.dev/" |
    Select-Object -ExpandProperty affirmation |
    cowsay
}

# ---------------- Prompt ----------------
$profileDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ENV:STARSHIP_CONFIG = Join-Path $profileDir "starship\starship.toml"

Invoke-Expression (&starship init powershell)
