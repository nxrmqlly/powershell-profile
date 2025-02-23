# Load Modules
Import-Module -Name Terminal-Icons
Import-Module -Name z

# Check if running as Administrator
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Change prompt and window title if running as Administrator
$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
if ($isAdmin) { $Host.UI.RawUI.WindowTitle += " [ADMIN]" }

# test command exists (no idea how this works)
function Test-CommandExists {
    Param ($command)
    $ErrorActionPreference = 'SilentlyContinue'
    try { return [bool](Get-Command $command -ErrorAction Stop) }
    catch { return $false }
    finally { $ErrorActionPreference = 'Continue' }
}

function prompt { "[$(Get-Location)] " + ($(if ($isAdmin) { "#" } else { "$" })) + " " }




# ====================================== SHORTCUTS =============================================
# cd shortcuts
function cd... { Set-Location ..\.. }

function cd.... { Set-Location ..\..\.. }

# file hashing
function md5 { Get-FileHash -Algorithm MD5 $args }

function sha1 { Get-FileHash -Algorithm SHA1 $args }

function sha256 { Get-FileHash -Algorithm SHA256 $args }

function sha512 { Get-FileHash -Algorithm SHA512 $args }

# dirs shortcuts
function Env: { Set-Location Env: }

function dirs {
    Get-ChildItem -Recurse -Include "$args" | ForEach-Object FullName
}



# ====================================== ALIASES ============================================

Set-Alias -Name sudo -Value admin
Set-Alias -Name start-docker -Value "C:\Program Files\Docker\Docker\Docker Desktop.exe"
Set-Alias -Name co -Value code
Set-Alias -Name g -Value git

# ====================================== DEFAULT EDITOR ============================================

$editors = @('nvim', 'code', 'notepad++', 'pvim', 'vim', 'vi', 'sublime_text', 'notepad')
foreach ($editor in $editors) {
    if (Test-CommandExists $editor) {
        $EDITOR = $editor
        break
    }
}
Set-Alias -Name vim -Value $EDITOR

# ====================================== EASY GIT ============================================

function gcom { git add .; git commit -m "$args" }

function lazyg { git add .; git commit -m "$args"; git push }

# ====================================== UTILITY ============================================

function ipva {
    $venvScriptPath = Join-Path -Path (Get-Location) -ChildPath ".venv\Scripts\activate.ps1"
    if (Test-Path $venvScriptPath) {
        Write-Host "Activating virtual environment (./.venv/Scripts/activate.ps1)"
        . $venvScriptPath
    }
    else {
        Write-Host "No virtual environment found."
    }
}

function admin {
    Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList ($args -join ' ')
}
function pubip { Invoke-RestMethod -Uri "ifconfig.me/all" }

function uptime {
    # no ideea how this works
    If ($PSVersionTable.PSVersion.Major -eq 5) {
        Get-WmiObject win32_operatingsystem | Select-Object @{EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) } } | Format-Table -HideTableHeaders
    }
    Else {
        net statistics workstation | Select-String "since" | ForEach-Object { $_.ToString().Replace('Statistics since ', '') }
    }
}

function mystbin {
    param (
        [Parameter(Mandatory = $true)] [string]$filePath,
        [switch]$V
    )
    if (-Not (Test-Path $filePath)) { Write-Error "File '$filePath' does not exist."; return }
    $jsonPayload = @{ expires = $null; files = @(@{ content = (Get-Content -Path $filePath -Raw); filename = [System.IO.Path]::GetFileName($filePath) }); password = $null } | ConvertTo-Json -Depth 3
    $response = Invoke-RestMethod -Uri "https://mystb.in/api/paste" -Method POST -ContentType "application/json" -Body $jsonPayload
    if ($response.id) {
        if ($V) { Write-Output $response }
        Write-Output "Paste URL: https://mystb.in/$($response.id)"
    }
    else {
        Write-Error "Failed to create paste."
    }
}

# linux inspired commands

function grep($regex, $dir) { if ($dir) { Get-ChildItem $dir | Select-String $regex } else { $input | Select-String $regex } }

function find-file($name) { Get-ChildItem -Recurse -Filter "*$name*" -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "$(($_.Directory).FullName)\$($_.Name)" } }

function touch($file) { "" | Out-File $file -Encoding ASCII }

function df { Get-Volume }

function sed($file, $find, $replace) { (Get-Content $file).replace("$find", "$replace") | Set-Content $file }

function which($name) { Get-Command $name | Select-Object -ExpandProperty Definition }

function export($name, $value) { Set-Item -Path "env:$Name" -Value $Value -Force }

function pkill($name) { Get-Process $name -ErrorAction SilentlyContinue | Stop-Process }

function pgrep($name) { Get-Process $name }

function inspire { Invoke-RestMethod -Uri "https://www.affirmations.dev/" | ForEach-Object { $_.affirmation } | cowsay }


# ====================================== OH-MY-POSH (PROMPT) ============================================
$profileDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ompCfg = Join-Path $profileDir "themes\ritam.omp.json"

# init oh-my-posh with the config
oh-my-posh init pwsh --config $ompCfg | Invoke-Expression
