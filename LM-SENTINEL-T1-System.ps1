# ==========================================
# PERGUNTA DE SEGURANÇA (AVISO DO WINDOWS)
# ==========================================
Clear-Host
Write-Host ""
Write-Host "Aviso de Segurança: Risco de Execução de Script" -ForegroundColor Yellow
Write-Host "O código de script na página pode ser executado durante a análise." -ForegroundColor White
Write-Host ""
Write-Host "AÇÃO RECOMENDADA:" -ForegroundColor Gray
Write-Host "Use o parâmetro -UseBasicParsing para evitar a execução do código de script." -ForegroundColor Gray
Write-Host ""
Write-Host "Deseja continuar?" -ForegroundColor White
Write-Host "[S] Sim  [A] Sim para Todos  [N] Não  [T] Não para Todos  [U] Suspender  [?] Ajuda (o padrão é `"N`"): " -NoNewline
$resposta = Read-Host

if ($resposta -notmatch '^[SsAa]$') {
    Write-Host "`nOperação cancelada." -ForegroundColor Red
    Start-Sleep -Seconds 2
    exit
}

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
Write-ColoredLine "=== MVS Lost Media Hub ===" Yellow
Write-ColoredLine "Complete both steps with 100% success to pass." White
Write-ColoredLine "Applications will download and extract to C:\ToolsETA." White
Write-ColoredLine "If a prompt shows up, press OK to run the application." White
Write-ColoredLine "Follow the instructions listed on each step." White
Write-ColoredLine "This T1 PowerShell process currently has 2 steps." White
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
if (-not $activeGPU) { $activeGPU = $gpuList | Sort-Object AdapterRAM -Descending | Select-Object -First 1 }
$activeGPUName = $activeGPU.Name

Write-Host "Detected GPUs:" -ForegroundColor White
$gpuNames | ForEach-Object { Write-Host " - $_" -ForegroundColor White }

Write-Host ""
Write-Host "Active GPU: $activeGPUName" -ForegroundColor Cyan

$goodGPUs = @("RTX 30", "RTX 40", "RTX 50", "RX 6000", "RX 7000")
$gpuIsGood = $false
foreach ($keyword in $goodGPUs) {
    if ($activeGPUName -like "*$keyword*") { $gpuIsGood = $true; break }
}

if ($gpuIsGood) {
    Write-Host "Your GPU looks good." -ForegroundColor Green
} else {
    Write-Host "Your GPU may be a bit weak. Some processes may be slower." -ForegroundColor Yellow
}

$gpuName = $activeGPUName

Write-ColoredLine ""
Write-ColoredLine "=== Credits ===" Yellow
Write-ColoredLine "Mangaka | Discord: https://discord.gg/2gP6MaKURK" White
Write-Host ""
Wait-ForEnter -Message "Press Enter to Continue"
Clear-Host

# ====== STEP 1: SYSTEM CHECK ====== 

Write-ColoredLine "Step 1 of 2: SYSTEM Check" White
Write-ColoredLine "INSTRUCTION: Reach 100% success" Yellow
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

$exclusionsOutput = @()
$defenderOutput = @()
$modulesOutput = @()
$windowsOutput = @()
$memoryIntegrityOutput = @()
$threatsOutput = @()
$powershellSigOutput = @()

$defaultModules = @(
    "Microsoft.PowerShell.Archive", "Microsoft.PowerShell.Diagnostics", "Microsoft.PowerShell.Host",
    "Microsoft.PowerShell.LocalAccounts", "Microsoft.PowerShell.Management", "Microsoft.PowerShell.Security",
    "Microsoft.PowerShell.Utility", "PackageManagement", "PowerShellGet", "PSReadLine", "Pester", "ThreadJob"
)
$protectedModule = "Microsoft.PowerShell.Operation.Validation"
$modulesPath = "C:\Program Files\WindowsPowerShell\Modules"

# (AQUI FOI CORRIGIDO PARA APENAS CHECAR E NÃO DELETAR)
Get-ChildItem $modulesPath -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
    $moduleName = $_.Name
    $isDefault = $defaultModules -contains $moduleName
    $isProtected = $moduleName -eq $protectedModule
    
    if (-not $isDefault -and -not $isProtected) {
        $modulesOutput += "WARNING: Módulo não padrão encontrado: $moduleName (Ignorado por segurança)"
    } else {
        $modulesOutput += "SUCCESS: Module '$moduleName' passed signature check."
    }
}
$modulesOutput += "SUCCESS: No unauthorized modules/files found."

try {
    if ($env:OS -eq "Windows_NT" -and (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop)) {
        $windowsOutput += "SUCCESS: Running on Windows."
    } else {
        $windowsOutput += "FAILURE: Not running on Windows."
    }
} catch {
    $windowsOutput += "FAILURE: OS check failed."
}

try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    $enabled = Get-ItemPropertyValue -Path $regPath -Name "Enabled" -ErrorAction Stop
    $memoryIntegrityOutput += "SUCCESS: Memory Integrity supported."
    if ($enabled -eq 1) {
        $memoryIntegrityOutput += "SUCCESS: Memory Integrity is ON."
    } else {
        $memoryIntegrityOutput += "FAILURE: Memory Integrity is OFF."
    }
} catch {
    $memoryIntegrityOutput += "FAILURE: Memory Integrity not supported or inaccessible."
}

try {
    $defender = Get-MpComputerStatus
    $service = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if ($defender.AntivirusEnabled -and $service.Status -eq 'Running') {
        if (-not $defender.RealTimeProtectionEnabled) {
            try {
                Set-MpPreference -DisableRealtimeMonitoring $false
                $defenderOutput += "FAILURE: Realtime protection was OFF. Enabling..."
            } catch {
                $defenderOutput += "WARNING: Could not re-enable Defender."
            }
        } else {
            $defenderOutput += "SUCCESS: Realtime protection is ON."
        }
    } else {
        $defenderOutput += "FAILURE: Microsoft Defender Antivirus is not running."
    }
} catch {
    $defenderOutput += "WARNING: Could not query Defender status."
}

try {
    $exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
    if ($exclusions) {
        $exclusionsOutput += "FAILURE: Exclusion paths found:`n$($exclusions -join "`n")"
    } else {
        $exclusionsOutput += "SUCCESS: No Defender exclusions set."
    }
} catch {
    $exclusionsOutput += "WARNING: Could not check exclusions."
}

try {
    $threats = Get-MpThreat | Where-Object { $_.Status -eq "Active" }
    if ($threats) {
        foreach ($t in $threats) { $threatsOutput += "FAILURE: $($t.ThreatName) | $($t.Resources)" }
    } else {
        $threatsOutput += "SUCCESS: No active threats."
    }
} catch {
    $threatsOutput += "WARNING: Threat scan failed."
}

try {
    $psPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $sig = Get-AuthenticodeSignature -FilePath $psPath
    if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -like '*Microsoft Windows*') {
        $powershellSigOutput += "SUCCESS: PowerShell is signed and valid."
    } else {
        $powershellSigOutput += "FAILURE: PowerShell binary signature invalid."
    }
} catch {
    $powershellSigOutput += "WARNING: Could not verify PowerShell binary."
}

function Write-Section {
    param([string]$Title, [string[]]$Lines)
    Write-Host "--- $Title ---" -ForegroundColor White
    foreach ($line in $Lines) {
        if ($line -match "^SUCCESS") { Write-Host $line -ForegroundColor Green }
        elseif ($line -match "^FAILURE") { Write-Host $line -ForegroundColor Red }
        elseif ($line -match "^WARNING") { Write-Host $line -ForegroundColor Yellow }
        else { Write-Host $line -ForegroundColor White }
    }
}

Write-Section "Files + Modules" $modulesOutput
Write-Section "OS Check" $windowsOutput
Write-Section "Memory Integrity" $memoryIntegrityOutput
Write-Section "Windows Defender" $defenderOutput
Write-Section "Exclusions" $exclusionsOutput
Write-Section "Threats" $threatsOutput
Write-Section "Binary Sig" $powershellSigOutput

$allResults = $modulesOutput + $windowsOutput + $memoryIntegrityOutput + $defenderOutput + $exclusionsOutput + $threatsOutput + $powershellSigOutput
$total = ($allResults | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success = ($allResults | Where-Object { $_ -match '^SUCCESS' }).Count
$rate = if ($total -gt 0) { [math]::Round(($success / $total) * 100, 0) } else { 0 }
$rateColor = if ($rate -eq 100) { "Green" } else { "Red" }

Write-Host ""
Write-Host ("Success Rate: $rate% ($success / $total)") -ForegroundColor $rateColor

Wait-ForEnter -Message "Press Enter to Continue"
Clear-Host

# ====== STEP 2: PROCESS EXPLORER ======

function Write-ColoredLine {
    param ([string]$Text, [ConsoleColor]$Color = 'White')
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

Clear-Host
Write-ColoredLine "Step 2 of 2: Process Explorer" White
Write-ColoredLine "INSTRUCTION: Wait for Process Explorer to open. Scroll to the bottom, then close the window." Yellow
Write-Host ""
Show-LoadingBar

$processNames = @("procexp", "procexp32", "procexp64", "procexp64a")
$runningPE = Get-Process -ErrorAction SilentlyContinue | Where-Object { $processNames -contains $_.ProcessName.ToLower() }

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

$baseFolder = "C:\ToolsETA"
$extractFolder = Join-Path $baseFolder "ProcessExplorer"
$zipUrl = "https://download.sysinternals.com/files/ProcessExplorer.zip"
$zipPath = Join-Path $baseFolder "ProcessExplorer.zip"

$regFileUrl = "https://pastebin.com/raw/gse8NxwU"
$regFilePath = Join-Path $baseFolder "procexp_config.reg"

try {
    if (Test-Path $baseFolder) {
        Remove-Item -Path $baseFolder -Recurse -Force -ErrorAction Stop
    }
    New-Item -ItemType Directory -Path $baseFolder -Force -ErrorAction Stop | Out-Null
    Write-ColoredLine "[SUCCESS] Prepared C:\ToolsETA." Green
} catch {
    Write-ColoredLine "[FAILED] Could not prepare C:\ToolsETA: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

$curl = "$env:SystemRoot\System32\curl.exe"

try {
    & $curl "-L" "--fail" "--silent" "--show-error" "--output" $zipPath $zipUrl
    if ($LASTEXITCODE -ne 0) { throw "curl.exe returned exit code $LASTEXITCODE." }
    Write-ColoredLine "[SUCCESS] Downloaded Process Explorer." Green
} catch {
    Write-ColoredLine "[FAILED] Failed to download Process Explorer: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

try {
    if (Test-Path $extractFolder) { Remove-Item $extractFolder -Recurse -Force -ErrorAction SilentlyContinue }
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractFolder -Force -ErrorAction Stop
    Write-ColoredLine "[SUCCESS] Extracted Process Explorer zip." Green
} catch {
    Write-ColoredLine "[FAILED] Failed to extract Process Explorer: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

try {
    & $curl "-L" "--fail" "--silent" "--show-error" "--output" $regFilePath $regFileUrl
    if ($LASTEXITCODE -ne 0) { throw "curl.exe returned exit code $LASTEXITCODE." }
    Write-ColoredLine "[SUCCESS] Downloaded registry configuration." Green
} catch {
    Write-ColoredLine "[FAILED] Failed to download registry config: $($_.Exception.Message)" Red
    Wait-ForEnter
    exit 1
}

try {
    $regExe = "$env:SystemRoot\System32\reg.exe"
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

$actualExe = Get-ChildItem -Path $extractFolder -Filter "procexp64.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

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
    } catch {}

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
