Import-Module -Name Terminal-Icons
Import-Module -Name z

# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If so and the current host is a command line, then change to red color 
# as warning to user that they are operating in an elevated context
# Useful shortcuts for traversing directories
function cd... { Set-Location ..\.. }
function cd.... { Set-Location ..\..\.. }

# Compute file hashes - useful for checking successful downloads 
function md5 { Get-FileHash -Algorithm MD5 $args }
function sha1 { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }
function sha512 { Get-FileHash -Algorithm SHA512 $args }

# Quick shortcut to start notepad
function n { notepad $args }

# Drive shortcuts
function Env: { Set-Location Env: }

function ipva {
    $projectDirectory = Get-Item -Path (Get-Location)
    $venvDirectory = Join-Path -Path $projectDirectory -ChildPath ".venv"
    $venvScriptPath = Join-Path -Path $venvDirectory -ChildPath "Scripts\activate.ps1"

    if (Test-Path -Path $venvDirectory) {
        if (Test-Path -Path $venvScriptPath) {
            Write-Host "Running 'activate.ps1' script in .\.venv\Scripts"
            . $venvScriptPath
        }
        else {
            Write-Host "No 'activate.ps1' script found in the .\.venv\Scripts directory."
        }
    }
    else {
        Write-Host "'.venv' directory not found."
    }
}


# Set up command prompt and window title. Use UNIX-style convention for identifying 
# whether user is elevated (root) or not. Window title shows current version of PowerShell
# and appends [ADMIN] if appropriate for easy taskbar identification
function prompt { 
    if ($isAdmin) {
        "[" + (Get-Location) + "] # " 
    }
    else {
        "[" + (Get-Location) + "] $ "
    }
}



$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
if ($isAdmin) {
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}

# Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
function dirs {
    if ($args.Count -gt 0) {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    }
    else {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}

# Simple function to start a new elevated process. If arguments are supplied then 
# a single command is started with admin rights; if not then a new admin instance
# of PowerShell is started.
function admin {
    if ($args.Count -gt 0) {   
        $argList = "& '" + $args + "'"
        Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $argList
    }
    else {
        Start-Process "$psHome\powershell.exe" -Verb runAs
    }
}

# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights. 
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin
Set-Alias docker-start "C:\Program Files\Docker\Docker\Docker Desktop.exe"

# We don't need these any more; they were just temporary variables to get to $isAdmin. 
# Delete them to prevent cluttering up the user profile. 
Remove-Variable identity
Remove-Variable principal

Function Test-CommandExists {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try { if (Get-Command $command) { RETURN $true } }
    Catch { Write-Host "$command does not exist"; RETURN $false }
    Finally { $ErrorActionPreference = $oldPreference }
} 
#
# Aliases
#
# If your favorite editor is not here, add an elseif and ensure that the directory it is installed in exists in your $env:Path
#

if (Test-CommandExists nvim) {
    $EDITOR = 'nvim'
}
elseif (Test-CommandExists code) {
    $EDITOR = 'code'
}
elseif (Test-CommandExists notepad++) {
    $EDITOR = 'notepad++'
}
elseif (Test-CommandExists pvim) {
    $EDITOR = 'pvim'
}
elseif (Test-CommandExists vim) {
    $EDITOR = 'vim'
}
elseif (Test-CommandExists vi) {
    $EDITOR = 'vi'
}
elseif (Test-CommandExists sublime_text) {
    $EDITOR = 'sublime_text'
}
elseif (Test-CommandExists notepad) {
    $EDITOR = 'notepad'
}
Set-Alias -Name vim -Value $EDITOR

Set-Alias -Name co -Value code

Set-Alias -Name g -Value git

function ez { eza --icons=always --color=always -l }

function ll { eza --icons=always --color=always -l }

function gcom {
    git add .
    git commit -m "$args"
}
function lazyg {
    git add .
    git commit -m "$args"
    git push
}
function Get-PubIP {
    curl "ifconfig.me/all"
}
function uptime {
    #Windows Powershell only
    If ($PSVersionTable.PSVersion.Major -eq 5 ) {
        Get-WmiObject win32_operatingsystem |
        Select-Object @{EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) } } | Format-Table -HideTableHeaders
    }
    Else {
        net statistics workstation | Select-String "since" | foreach-object { $_.ToString().Replace('Statistics since ', '') }
    }
}

function Restart-Profile {
    & $profile
}
function find-file($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        $place_path = $_.directory
        Write-Output "${place_path}\${_}"
    }
}

function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}
function touch($file) {
    "" | Out-File $file -Encoding ASCII
}
function df {
    get-volume
}
function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}
function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}
function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}
function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}
function pgrep($name) {
    Get-Process $name
}

function inspire {
    Invoke-RestMethod -Uri "https://www.affirmations.dev/" | ForEach-Object { $_.affirmation } | cowsay
}

function mystbin {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$filePath,
        [switch]$V
    )

    if (-Not (Test-Path $filePath)) {
        Write-Error "File '$filePath' does not exist."
        return
    }

    $fileName = [System.IO.Path]::GetFileName($filePath)
    $fileContent = Get-Content -Path $filePath -Raw

    $jsonPayload = @{
        expires  = $null
        files    = @(@{
                content  = $fileContent
                filename = $fileName
            })
        password = $null
    } | ConvertTo-Json -Depth 3

    $response = Invoke-RestMethod -Uri "https://mystb.in/api/paste" `
                                  -Method POST `
                                  -ContentType "application/json" `
                                  -Body $jsonPayload

    if ($response.id) {
        if ($V) {
            Write-Output $response
        }

        Write-Output "Paste URL: https://mystb.in/$($response.id)"
    }
    else {
        Write-Error "Failed to create paste."
    }
}


oh-my-posh init pwsh --config 'C:\Users\Ritam Das\AppData\Local\Programs\oh-my-posh\themes\space.omp.json' | Invoke-Expression
$env:VIRTUAL_ENV_DISABLE_PROMPT = 1
$env:XDG_CONFIG_HOME = "$HOME\.config"

