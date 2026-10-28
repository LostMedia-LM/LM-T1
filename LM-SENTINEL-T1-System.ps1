$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "`n[WARNING] This script is NOT running with Administrator privileges." -ForegroundColor Red
    Write-Host "[ACTION] Please right-click PowerShell and then select 'Run as Administrator.'" -ForegroundColor Yellow
    Write-Host ""
    Pause
    exit 1
}

function Write-ColoredLine {
    param (
        [string]$Text,
        [ConsoleColor]$Color = 'White'
    )
    $oldColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Text
    $Host.UI.RawUI.ForegroundColor = $oldColor
}

function Wait-ForEnter {
    param(
        [string]$Message = "Press Enter to Continue"
    )
    Start-Sleep -Seconds 1
    Write-ColoredLine $Message Yellow
    while ($true) {
        if ([System.Console]::KeyAvailable) {
            $key = [System.Console]::ReadKey($true)
            if ($key.Key -eq "Enter") { break }
        }
        Start-Sleep -Milliseconds 100
    }
}

Clear-Host
Write-Host ""
Write-Host "  ███╗   ███╗██╗   ██╗███████╗    ██╗      ██████╗ ███████╗████████╗    ███╗   ███╗███████╗██████╗ ██╗ █████╗ " -ForegroundColor Cyan
Write-Host "  ████╗ ████║██║   ██║██╔════╝    ██║     ██╔═══██╗██╔════╝╚══██╔══╝    ████╗ ████║██╔════╝██╔══██╗██║██╔══██╗" -ForegroundColor Cyan
Write-Host "  ██╔████╔██║██║   ██║███████╗    ██║     ██║   ██║███████╗   ██║       ██╔████╔██║█████╗  ██║  ██║██║███████║" -ForegroundColor Cyan
Write-Host "  ██║╚██╔╝██║╚██╗ ██╔╝╚════██║    ██║     ██║   ██║╚════██║   ██║       ██║╚██╔╝██║██╔══╝  ██║  ██║██║██╔══██║" -ForegroundColor Cyan
Write-Host "  ██║ ╚═╝ ██║ ╚████╔╝ ███████║    ███████╗╚██████╔╝███████║   ██║       ██║ ╚═╝ ██║███████╗██████╔╝██║██║  ██║" -ForegroundColor Cyan
Write-Host "  ╚═╝     ╚═╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝     ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═╝" -ForegroundColor Cyan
Write-Host ""
Write-ColoredLine "=== MVS Lost Media Hub ===" Cyan
Write-ColoredLine "Applications will download and extract to C:\ToolsETA." White
Write-ColoredLine "If a prompt shows up, press OK to run the application." White
Write-ColoredLine "Follow the instructions listed below." White
Write-Host ""
$cpu = Get-WmiObject Win32_Processor | Select-Object -First 1

if ($cpu.NumberOfCores -ge 4 -and $cpu.MaxClockSpeed -ge 2500) {
    Write-Host "Detected CPU: $($cpu.Name)" -ForegroundColor Green
    Write-Host "Your CPU looks good." -ForegroundColor Green 
} else {
    Write-Host "Detected CPU: $($cpu.Name)" -ForegroundColor Red
    Write-Host "Your CPU may be a bit weak. This process may take longer for you." -ForegroundColor Yellow
}

Write-Host ""
 
$gpuList = Get-WmiObject Win32_VideoController
$gpuNames = $gpuList | Select-Object -ExpandProperty Name

$activeGPU = $gpuList | Where-Object { $_.Name -match "NVIDIA|RTX" } | Select-Object -First 1

if (-not $activeGPU) {
    $activeGPU = $gpuList | Sort-Object AdapterRAM -Descending | Select-Object -First 1
}

$activeGPUName = $activeGPU.Name

Write-Host "Detected GPUs:" -ForegroundColor White
$gpuNames | ForEach-Object { Write-Host " - $_" -ForegroundColor White }

Write-Host ""
Write-Host "Active GPU: $activeGPUName" -ForegroundColor Cyan

$goodGPUs = @("RTX 30", "RTX 40", "RTX 50", "RX 6000", "RX 7000")

$gpuIsGood = $false
foreach ($keyword in $goodGPUs) {
    if ($activeGPUName -like "*$keyword*") {
        $gpuIsGood = $true
        break
    }
}

if ($gpuIsGood) {
    Write-Host "Your GPU looks good." -ForegroundColor Green
} else {
    Write-Host "Your GPU may be a bit weak. Some processes may be slower." -ForegroundColor Yellow
}

Write-ColoredLine ""
Write-ColoredLine "=== Credits ===" Yellow
Write-ColoredLine "Mangaka | Discord: https://discord.gg/2gP6MaKURK" White
Write-Host ""
Wait-ForEnter -Message "Press Enter to Continue"
Clear-Host

# ====== STEP 2: PROCESS EXPLORER ======

function Write-ColoredLine {
    param (
        [string]$Text,
        [ConsoleColor]$Color = 'White'
    )
    $oldColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Text
    $Host.UI.RawUI.ForegroundColor = $oldColor
}

function Wait-ForEnter {
    Start-Sleep -Seconds 1
    Write-ColoredLine "Press Enter to exit." Yellow
    while ($true) {
        if ([System.Console]::KeyAvailable) {
            $key = [System.Console]::ReadKey($true)
            if ($key.Key -eq "Enter") { break }
        }
        Start-Sleep -Milliseconds 100
    }
}

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    $scriptPath = try {
        (Resolve-Path -Path $MyInvocation.MyCommand.Definition).Path
    } catch {
        Write-Host "[ERROR] Could not resolve script path. Are you running this from a file?" -ForegroundColor Red
        pause
        exit 1
    }

    Write-Host "[INFO] Relaunching with admin rights..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
    exit
}

Clear-Host
Write-ColoredLine "Step 1 of 1: Process Explorer" White
Write-ColoredLine "INSTRUCTION: Wait for Process Explorer to open. Scroll to the bottom, then close the window." Yellow
Write-Host ""

function Show-LoadingBar {
    for ($i = 0; $i -le 10; $i++) {
        $percent = $i * 10
        $bar = "#" * $i + "-" * (10 - $i)
        Write-Host -NoNewline "`rProgress: [ $bar ] $percent% " -ForegroundColor White
        Start-Sleep -Milliseconds 200
    }
    Write-Host ""
    Write-Host ""
}

Show-LoadingBar

# Close existing Process Explorer processes
$processNames = @("procexp", "procexp32", "procexp64", "procexp64a")
$runningPE = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $processNames -contains $_.ProcessName.ToLower()
}

if ($runningPE) {
    foreach ($proc in $runningPE) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            Write-ColoredLine "[SUCCESS] Terminated Process Explorer PID $($proc.Id)." Green
        } catch {
            Write-ColoredLine "[FAILED] Failed to terminate PID $($proc.Id): $($_.Exception.Message)" Red
        }
    }
    Start-Sleep -Seconds 1
} else {
    Write-ColoredLine "[SUCCESS] No running Process Explorer processes were found." Green
}

# Paths
$baseFolder = "C:\ToolsETA"
$extractFolder = Join-Path $baseFolder "ProcessExplorer"
$zipUrl = "https://download.sysinternals.com/files/ProcessExplorer.zip"
$zipPath = Join-Path $baseFolder "ProcessExplorer.zip"

$regFileUrl = "https://pastebin.com/raw/gse8NxwU"
$regFilePath = Join-Path $baseFolder "procexp_config.reg"

# Prepare working folder
try {
    if (Test-Path $baseFolder) {
        Remove-Item -Path $baseFolder -Recurse -Force -ErrorAction Stop
        Write-ColoredLine "[SUCCESS] Cleaned up existing C:\ToolsETA folder." Green
    }

    New-Item -ItemType Directory -Path $baseFolder -Force -ErrorAction Stop | Out-Null
    Write-ColoredLine "[SUCCESS] Prepared C:\ToolsETA." Green
} catch {
    Write-ColoredLine "[FAILED] Could not prepare C:\ToolsETA: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

# Use Windows curl.exe
$curl = "$env:SystemRoot\System32\curl.exe"

if (-not (Test-Path $curl)) {
    Write-ColoredLine "[FAILED] curl.exe was not found at $curl." Red
    Wait-ForEnter
    exit 1
}

# Download Process Explorer
try {
    Write-ColoredLine "[INFO] Downloading Process Explorer..." Yellow

    & $curl "-L" "--fail" "--silent" "--show-error" "--output" $zipPath $zipUrl

    if ($LASTEXITCODE -ne 0) {
        throw "curl.exe returned exit code $LASTEXITCODE."
    }

    if (-not (Test-Path $zipPath)) {
        throw "Process Explorer ZIP was not created."
    }

    if ((Get-Item $zipPath).Length -lt 10000) {
        throw "Downloaded Process Explorer ZIP is unexpectedly small."
    }

    Write-ColoredLine "[SUCCESS] Downloaded Process Explorer." Green
} catch {
    Write-ColoredLine "[FAILED] Failed to download Process Explorer: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

# Extract Process Explorer
try {
    if (Test-Path $extractFolder) {
        Remove-Item $extractFolder -Recurse -Force -ErrorAction SilentlyContinue
    }

    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractFolder -Force -ErrorAction Stop
    Write-ColoredLine "[SUCCESS] Extracted Process Explorer zip." Green
} catch {
    Write-ColoredLine "[FAILED] Failed to extract Process Explorer: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

# Download registry configuration
try {
    Write-ColoredLine "[INFO] Downloading Process Explorer registry configuration..." Yellow

    & $curl "-L" "--fail" "--silent" "--show-error" "--output" $regFilePath $regFileUrl

    if ($LASTEXITCODE -ne 0) {
        throw "curl.exe returned exit code $LASTEXITCODE."
    }

    if (-not (Test-Path $regFilePath)) {
        throw "Registry configuration file was not created."
    }

    if ((Get-Item $regFilePath).Length -eq 0) {
        throw "Registry configuration file is empty."
    }

    Write-ColoredLine "[SUCCESS] Downloaded Process Explorer registry configuration." Green
} catch {
    Write-ColoredLine "[FAILED] Failed to download registry config: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

# Import registry configuration
try {
    $regExe = "$env:SystemRoot\System32\reg.exe"

    if (-not (Test-Path $regExe)) {
        throw "reg.exe not found at expected location: $regExe"
    }

    & $regExe import $regFilePath

    if ($LASTEXITCODE -eq 0) {
        Write-ColoredLine "[SUCCESS] Imported registry configuration successfully." Green
    } else {
        throw "reg import returned exit code $LASTEXITCODE."
    }
} catch {
    Write-ColoredLine "[FAILED] Registry importing failed: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

# Find Process Explorer executable
$actualExe = Get-ChildItem -Path $extractFolder -Filter "procexp64.exe" -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1

if (-not $actualExe) {
    Write-ColoredLine "[FAILED] procexp64.exe was not found after extraction." Red
    Write-ColoredLine "[FAILED] Success Rate: 0% (0 / 1)." Red
    Wait-ForEnter
    exit 1
}

# Launch Process Explorer
try {
    Write-ColoredLine "[SUCCESS] Found procexp64.exe." Green

    $process = Start-Process -FilePath $actualExe.FullName -PassThru -ErrorAction Stop
    Start-Sleep -Seconds 1

    try {
        $wshell = New-Object -ComObject WScript.Shell
        Start-Sleep -Milliseconds 500

        if ($wshell.AppActivate($process.Id)) {
            Start-Sleep -Milliseconds 500
            $wshell.SendKeys('% ')
            Start-Sleep -Milliseconds 200
            $wshell.SendKeys('x')
            Start-Sleep -Milliseconds 500
            Write-ColoredLine "[SUCCESS] Process Explorer window maximized." Green
        }
    } catch {
        # Maximizing/focusing the window is optional.
    }

    Write-ColoredLine "[SUCCESS] Process Explorer launched successfully." Green
    Write-Host ""

    $process.WaitForExit()

    Write-ColoredLine "[SUCCESS] Success Rate: 100% (1 / 1)." Green
} catch {
    Write-ColoredLine "[FAILED] Could not launch Process Explorer: $($_.Exception.Message)" Red
    Write-ColoredLine "[FAILED] Success Rate: 0% (0 / 1)." Red
}

Wait-ForEnter
exit
