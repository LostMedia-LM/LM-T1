[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$global:PSDefaultParameterValues = @{}
foreach ($__n in @(
    'Invoke-WebRequest','Invoke-RestMethod','Invoke-Expression','Test-Path','Get-Item',
    'Get-ChildItem','Get-ItemProperty','Get-ItemPropertyValue','Get-CimInstance','Get-WmiObject',
    'Get-Process','Start-Process','Get-Service','Get-WinEvent','Get-AuthenticodeSignature',
    'Get-MpComputerStatus','Get-MpPreference','Get-Module','New-Item','Remove-Item','Add-Content'
)) {
    Microsoft.PowerShell.Management\Remove-Item -Path "Alias:\$__n"    -Force -ErrorAction SilentlyContinue
    Microsoft.PowerShell.Management\Remove-Item -Path "Function:\$__n" -Force -ErrorAction SilentlyContinue
}

Clear-Host

$script:MvsLmVersion = '1.0.0'

function Disable-ConsoleQuickEdit {
    try {
        if (-not ('LocConsoleApi' -as [type])) {
            Add-Type -Namespace Loc -Name LocConsoleApi -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
'@ -ErrorAction Stop
        }

        $stdin = [Loc.LocConsoleApi]::GetStdHandle(-10)
        [uint32]$mode = 0
        if (-not [Loc.LocConsoleApi]::GetConsoleMode($stdin, [ref]$mode)) { return }

        $mode = ($mode -bor 0x0080) -band (-bnot 0x0040) -band (-bnot 0x0020)
        [void][Loc.LocConsoleApi]::SetConsoleMode($stdin, $mode)
    } catch {}
}

function Invoke-ConsoleRefresh {
    try { [Console]::Out.Flush() } catch {}
    try { [Console]::Error.Flush() } catch {}
}

Disable-ConsoleQuickEdit
Invoke-ConsoleRefresh

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Open-LocalMachineRegistryKey {
    param([string]$SubKeyPath)

    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )
        if ([string]::IsNullOrWhiteSpace($SubKeyPath)) { return $base }
        return $base.OpenSubKey($SubKeyPath)
    } catch {
        return $null
    }
}

function Add-RegistryKeyFingerprint {
    param(
        [Microsoft.Win32.RegistryKey]$Key,
        [string]$Prefix,
        [System.Collections.Generic.List[string]]$Parts
    )

    foreach ($name in $Key.GetValueNames()) {
        $raw = $Key.GetValue($name)
        if ($null -eq $raw) {
            $Parts.Add("$Prefix|$name=")
        } elseif ($raw -is [byte[]]) {
            $Parts.Add("$Prefix|$name=0x$([BitConverter]::ToString($raw).Replace('-', ''))")
        } else {
            $Parts.Add("$Prefix|$name=$raw")
        }
    }

    foreach ($subName in $Key.GetSubKeyNames()) {
        $subKey = $Key.OpenSubKey($subName)
        if ($subKey) {
            Add-RegistryKeyFingerprint -Key $subKey -Prefix "$Prefix\$subName" -Parts $Parts
            $subKey.Close()
        } else {
            $Parts.Add("$Prefix\$subName=<missing>")
        }
    }
}

# ===================== BANNER MVS LOST MEDIA =====================
Write-Host ""
Write-Host "  ███╗   ███╗██╗   ██╗███████╗    ██╗      ██████╗ ███████╗████████╗" -ForegroundColor Cyan
Write-Host "  ████╗ ████║██║   ██║██╔════╝    ██║     ██╔═══██╗██╔════╝╚══██╔══╝" -ForegroundColor Cyan
Write-Host "  ██╔████╔██║██║   ██║███████╗    ██║     ██║   ██║███████╗   ██║   " -ForegroundColor Cyan
Write-Host "  ██║╚██╔╝██║╚██╗ ██╔╝╚════██║    ██║     ██║   ██║╚════██║   ██║   " -ForegroundColor Cyan
Write-Host "  ██║ ╚═╝ ██║ ╚████╔╝ ███████║    ███████╗╚██████╔╝███████║   ██║   " -ForegroundColor Cyan
Write-Host "  ╚═╝     ╚═╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝   ╚═╝   " -ForegroundColor Cyan
Write-Host ""
Write-Host "  ███╗   ███╗███████╗██████╗ ██╗ █████╗ " -ForegroundColor Cyan
Write-Host "  ████╗ ████║██╔════╝██╔══██╗██║██╔══██╗" -ForegroundColor Cyan
Write-Host "  ██╔████╔██║█████╗  ██║  ██║██║███████║" -ForegroundColor Cyan
Write-Host "  ██║╚██╔╝██║██╔══╝  ██║  ██║██║██╔══██║" -ForegroundColor Cyan
Write-Host "  ██║ ╚═╝ ██║███████╗██████╔╝██║██║  ██║" -ForegroundColor Cyan
Write-Host "  ╚═╝     ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  MVS LOST MEDIA v$($script:MvsLmVersion)" -ForegroundColor White
Write-Host "  Credits: Mangaka | Discord: https://discord.gg/2gP6MaKURK" -ForegroundColor White
Write-Host ""
# ==================================================================

if (-not (Test-Admin)) {
    Write-Host "WARNING: Run as Administrator for full results." -ForegroundColor Yellow
}

function Write-Section {
    param($Title, $Lines)
    Write-Host "--- $Title ---" -ForegroundColor Cyan
    foreach ($line in $Lines) {
        if ($line -like "SUCCESS*") { Write-Host $line -ForegroundColor Green }
        elseif ($line -like "FAILURE*") { Write-Host $line -ForegroundColor Red }
        elseif ($line -like "WARNING*") { Write-Host $line -ForegroundColor Yellow }
    }
    Write-Host ""
}

function Invoke-ToolDownload {
    param(
        [string]$Url,
        [string]$ZipPath,
        [string]$DestDir
    )

    if (-not $Url -or -not $ZipPath -or -not $DestDir) { return $false }

    try {
        $zipParent = Split-Path $ZipPath -Parent
        if ($zipParent -and -not (Test-Path $zipParent)) {
            New-Item -ItemType Directory -Path $zipParent -Force | Out-Null
        }
        if (-not (Test-Path $DestDir)) {
            New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
        }

        if (Test-Path -LiteralPath $ZipPath) {
            Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
        }

        $previousProtocol = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $downloaded = $false
        foreach ($attempt in 1..2) {
            try {
                Microsoft.PowerShell.Utility\Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing -TimeoutSec 120 `
                    -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' | Out-Null
                if ((Test-Path -LiteralPath $ZipPath) -and ((Get-Item -LiteralPath $ZipPath).Length -gt 1024)) {
                    $downloaded = $true
                    break
                }
            } catch {
                if ($attempt -eq 2) { throw }
                Start-Sleep -Seconds 2
            }
        }

        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol
        if (-not $downloaded) { return $false }

        Expand-Archive -Path $ZipPath -DestinationPath $DestDir -Force
        return $true
    } catch {
        Write-Warning "Download failed: $($_.Exception.Message)"
        return $false
    }
}

function Resolve-ToolExecutable {
    param(
        [string]$DestDir,
        [string]$ExeName,
        [string[]]$FallbackNames = @()
    )

    foreach ($name in @($ExeName) + @($FallbackNames)) {
        $direct = Join-Path $DestDir $name
        if (Test-Path -LiteralPath $direct) { return $direct }
    }

    foreach ($name in @($ExeName) + @($FallbackNames)) {
        $found = Get-ChildItem -Path $DestDir -Filter $name -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { return $found.FullName }
    }

    return $null
}

function Start-LocExternalTool {
    param(
        [string]$Name,
        [string]$Url,
        [string]$ZipPath,
        [string]$DestDir,
        [string]$ExeName,
        [string[]]$FallbackExeNames = @(),
        [string[]]$StartArguments = @(),
        [switch]$Wait,
        [ValidateSet('Normal', 'Maximized')]
        [string]$WindowStyle = 'Normal'
    )

    $exe = Resolve-ToolExecutable -DestDir $DestDir -ExeName $ExeName -FallbackNames $FallbackExeNames
    if (-not $exe) {
        if (Invoke-ToolDownload -Url $Url -ZipPath $ZipPath -DestDir $DestDir) {
            $exe = Resolve-ToolExecutable -DestDir $DestDir -ExeName $ExeName -FallbackNames $FallbackExeNames
        }
    }

    if (-not $exe) {
        Write-Host "WARNING: $Name unavailable (download or extract failed)." -ForegroundColor Yellow
        return $false
    }

    try { Unblock-File -LiteralPath $exe -ErrorAction SilentlyContinue } catch {}

    try {
        $startParams = @{
            FilePath    = $exe
            WindowStyle = $WindowStyle
            PassThru    = $true
            ErrorAction = 'Stop'
        }
        if ($StartArguments.Count -gt 0) { $startParams['ArgumentList'] = $StartArguments }

        $proc = Start-Process @startParams
        if ($Wait) { $proc.WaitForExit() }
        return $true
    } catch {
        Write-Host "WARNING: $Name failed to start: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

function Get-Exclusions {
    $list = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    try {
        $prefs = Get-MpPreference -ErrorAction Stop
        foreach ($item in @($prefs.ExclusionPath) + @($prefs.ExclusionProcess) + @($prefs.ExclusionExtension)) {
            if ($item) { [void]$list.Add([string]$item) }
        }
    } catch {}

    $regRoots = @(
        'SOFTWARE\Microsoft\Windows Defender\Exclusions',
        'SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
    )
    $regTypes = @('Paths', 'Processes', 'Extensions')

    foreach ($root in $regRoots) {
        foreach ($type in $regTypes) {
            try {
                $key = Open-LocalMachineRegistryKey -SubKeyPath "$root\$type"
                if (-not $key) { continue }
                foreach ($name in $key.GetValueNames()) {
                    if ($name) { [void]$list.Add($name) }
                }
                $key.Close()
            } catch {}
        }
    }

    return @($list)
}

$script:DefenderExclusionsRegRoots = @(
    'SOFTWARE\Microsoft\Windows Defender\Exclusions',
    'SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
)
$script:DefenderThreatsRegRoots = @(
    'SOFTWARE\Microsoft\Windows Defender\Threats',
    'SOFTWARE\Policies\Microsoft\Windows Defender\Threats'
)
$script:DefenderThreatsSystemSubkeys = @(
    'ThreatSeverityDefaultAction',
    'ThreatIDDefaultAction',
    'ThreatTypeDefaultAction'
)

function Get-RegistrySubtreeFingerprint {
    param([string]$RelativePath)

    $parts = New-Object 'System.Collections.Generic.List[string]'

    try {
        $root = Open-LocalMachineRegistryKey -SubKeyPath $RelativePath
        if (-not $root) { return 'MISSING' }
        Add-RegistryKeyFingerprint -Key $root -Prefix $RelativePath -Parts $parts
        $root.Close()
    } catch {
        return 'ERROR'
    }

    if ($parts.Count -eq 0) { return 'EMPTY' }
    return ($parts | Sort-Object) -join '|'
}

function Get-DefenderRegistryMonitorLabels {
    $labels = @{}
    foreach ($root in $script:DefenderExclusionsRegRoots) {
        $labels[$root] = "Defender Exclusions registry ($root)"
    }
    foreach ($root in $script:DefenderThreatsRegRoots) {
        $labels[$root] = "Defender Threats registry ($root)"
    }
    return $labels
}

function Get-DefenderRegistryFingerprints {
    $fps = @{}
    foreach ($root in ($script:DefenderExclusionsRegRoots + $script:DefenderThreatsRegRoots)) {
        $fps[$root] = Get-RegistrySubtreeFingerprint -RelativePath $root
    }
    return $fps
}

function Get-AllowedDefenderThreats {
    $list = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($relPath in @(
        'SOFTWARE\Microsoft\Windows Defender\Exclusions\Threats',
        'SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Threats'
    )) {
        try {
            $key = Open-LocalMachineRegistryKey -SubKeyPath $relPath
            if (-not $key) { continue }
            foreach ($name in $key.GetValueNames()) {
                if ($name) { [void]$list.Add("$relPath -> $name") }
            }
            foreach ($subName in $key.GetSubKeyNames()) {
                [void]$list.Add("$relPath\$subName")
            }
            $key.Close()
        } catch {}
    }

    foreach ($root in $script:DefenderThreatsRegRoots) {
        try {
            $key = Open-LocalMachineRegistryKey -SubKeyPath $root
            if (-not $key) { continue }
            foreach ($subName in $key.GetSubKeyNames()) {
                if ($script:DefenderThreatsSystemSubkeys -contains $subName) { continue }
                if ($subName -match '(?i)^\{?[0-9A-F-]{36}\}?$|^\d+$') {
                    [void]$list.Add("$root\$subName")
                }
            }
            $key.Close()
        } catch {}
    }

    return @($list)
}

function Get-DefenderStatusAlerts {
    $alerts = @()

    try {
        $def = Get-MpComputerStatus -ErrorAction Stop
        if (-not $def.RealTimeProtectionEnabled) {
            $alerts += 'FAILURE: Real-time protection disabled'
        }
        if (-not $def.IsTamperProtected) {
            $alerts += 'WARNING: Tamper protection disabled'
        }
    } catch {
        $alerts += 'WARNING: Defender status unavailable'
    }

    foreach ($disableKey in @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
        'HKLM:\SOFTWARE\Microsoft\Windows Defender'
    )) {
        try {
            $disabled = Get-ItemPropertyValue -Path $disableKey -Name 'DisableAntiSpyware' -ErrorAction Stop
