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

$script:MvsLmVersion = '1.0.1'

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
Write-Host "  ███╗   ███╗██╗   ██╗███████╗    ██╗      ██████╗ ███████╗████████╗    ███╗   ███╗███████╗██████╗ ██╗ █████╗ " -ForegroundColor Cyan
Write-Host "  ████╗ ████║██║   ██║██╔════╝    ██║     ██╔═══██╗██╔════╝╚══██╔══╝    ████╗ ████║██╔════╝██╔══██╗██║██╔══██╗" -ForegroundColor Cyan
Write-Host "  ██╔████╔██║██║   ██║███████╗    ██║     ██║   ██║███████╗   ██║       ██╔████╔██║█████╗  ██║  ██║██║███████║" -ForegroundColor Cyan
Write-Host "  ██║╚██╔╝██║╚██╗ ██╔╝╚════██║    ██║     ██║   ██║╚════██║   ██║       ██║╚██╔╝██║██╔══╝  ██║  ██║██║██╔══██║" -ForegroundColor Cyan
Write-Host "  ██║ ╚═╝ ██║ ╚████╔╝ ███████║    ███████╗╚██████╔╝███████║   ██║       ██║ ╚═╝ ██║███████╗██████╔╝██║██║  ██║" -ForegroundColor Cyan
Write-Host "  ╚═╝     ╚═╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝     ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═╝" -ForegroundColor Cyan
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
            if ($disabled -eq 1) { $alerts += 'FAILURE: DisableAntiSpyware active' }
        } catch {}
    }

    return $alerts
}

function Get-RegistryToolProcessHits {
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    $messages = @()

    foreach ($procName in @('regedit.exe', 'reg.exe')) {
        try {
            Get-CimInstance Win32_Process -Filter "Name='$procName'" -ErrorAction Stop | ForEach-Object {
                $procId = [int]$_.ProcessId
                if (-not $seen.Add($procId)) { return }
                $path = [string]$_.ExecutablePath
                $cmd = [string]$_.CommandLine
                $label = "$procName (PID $procId)"
                if ($path) { $label += " -> $path" }
                if ($cmd) { $label += " [$cmd]" }
                $messages += $label
            }
        } catch {}
    }

    return $messages
}

$script:WindhawkProcessName = 'windhawk.exe'
$script:WindhawkWatchPaths = @(
    (Join-Path $env:USERPROFILE 'Downloads\windhawk.exe'),
    (Join-Path ${env:ProgramFiles} 'Windhawk\windhawk.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Windhawk\windhawk.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Windhawk\windhawk.exe')
)

function Get-WindhawkProcessHits {
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    $messages = @()

    try {
        Get-CimInstance Win32_Process -Filter "Name='$($script:WindhawkProcessName)'" -ErrorAction Stop | ForEach-Object {
            $procId = [int]$_.ProcessId
            if (-not $seen.Add($procId)) { return }
            $path = [string]$_.ExecutablePath
            $label = "$($script:WindhawkProcessName) (PID $procId)"
            if ($path) { $label += " -> $path" }
            $messages += $label
        }
    } catch {}

    return $messages
}

function Get-WindhawkStep1Alerts {
    $alerts = @()
    $hits = @(Get-WindhawkProcessHits)

    if ($hits.Count -gt 0) {
        foreach ($hit in $hits) {
            $alerts += "FAILURE: Windhawk running $hit"
        }
        return $alerts
    }

    $foundPaths = @()
    foreach ($p in ($script:WindhawkWatchPaths | Select-Object -Unique)) {
        if ($p -and (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) {
            $foundPaths += $p
        }
    }
    if ($foundPaths.Count -gt 0) {
        foreach ($p in $foundPaths) {
            $alerts += "WARNING: Windhawk found $p"
        }
        return $alerts
    }

    $alerts += 'SUCCESS: Windhawk not detected'
    return $alerts
}

function Get-CheatFolderHits {
    $hits = New-Object 'System.Collections.Generic.HashSet[string]'
    $scanPaths = @(
        (Join-Path $env:USERPROFILE "Downloads"),
        (Join-Path $env:USERPROFILE "Desktop"),
        $env:LOCALAPPDATA,
        $env:APPDATA,
        $env:ProgramData,
        $env:TEMP,
        "$env:SystemDrive\"
    )

    foreach ($scanPath in $scanPaths) {
        if (-not (Test-Path $scanPath)) { continue }

        $maxDepth = 2
        if ($scanPath -eq "$env:SystemDrive\") { $maxDepth = 1 }

        Get-ChildItem -Path $scanPath -Directory -Recurse -Depth $maxDepth -ErrorAction SilentlyContinue | ForEach-Object {
            $nameLower = $_.Name.ToLower()
            $matched = Get-MatchedCheatKeyword -Text $nameLower -FolderName
            if ($matched) { [void]$hits.Add($_.FullName) }
        }
    }

    return @($hits)
}

function Get-BamRegistryFingerprints {
    $fps = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $roots = @(
        'SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
        'SYSTEM\CurrentControlSet\Services\dam\State\UserSettings'
    )

    foreach ($root in $roots) {
        try {
            $rootKey = Open-LocalMachineRegistryKey -SubKeyPath $root
            if (-not $rootKey) { continue }

            foreach ($sidName in $rootKey.GetSubKeyNames()) {
                if ($sidName -eq 'S-1-5-18') { continue }
                $sidKey = $rootKey.OpenSubKey($sidName)
                if (-not $sidKey) { continue }

                foreach ($valueName in $sidKey.GetValueNames()) {
                    if ($valueName) { [void]$fps.Add("$root|$sidName|$valueName") }
                }
                $sidKey.Close()
            }
            $rootKey.Close()
        } catch {}
    }

    return @($fps)
}

function Get-PrefetchFileNames {
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $prefetchPath = "$env:WINDIR\Prefetch"
    if (-not (Test-Path $prefetchPath)) { return @($names) }

    try {
        Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction Stop | ForEach-Object {
            [void]$names.Add($_.Name)
        }
    } catch {}

    return @($names)
}

function Get-TamperLogEvents {
    param([datetime]$Since)

    $events = @()
    $filters = @(
        @{ LogName = 'Security'; Id = 1102 },
        @{ LogName = 'System'; Id = 104 },
        @{ LogName = 'Microsoft-Windows-Eventlog/Operational'; Id = 104 }
    )

    foreach ($filter in $filters) {
        try {
            $filter.StartTime = $Since
            Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | ForEach-Object { $events += $_ }
        } catch {}
    }

    try {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            Id        = 23
            StartTime = $Since
        } -ErrorAction Stop | Where-Object {
            $_.Message -match '(?i)\\Prefetch\\|\\bam\\|\\dam\\|UserSettings'
        } | ForEach-Object { $events += $_ }
    } catch {}

    return $events
}

function Write-MonitorAlert {
    param(
        [string]$Message,
        [string]$LogFile,
        [string]$Color = 'Yellow'
    )

    if ($Color -eq 'Red') { $Color = 'Yellow' }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
    Invoke-ConsoleRefresh
    try {
        Add-Content -LiteralPath $LogFile -Value "[$timestamp] $Message" -ErrorAction Stop
    } catch {
        $fallback = Join-Path $env:TEMP 'mvs_lost_media_security_events.log'
        try { Add-Content -LiteralPath $fallback -Value "[$timestamp] $Message" -ErrorAction SilentlyContinue } catch {}
    }
}

$script:CursorSchemeValueNames = @(
    '(Default)', 'Arrow', 'Help', 'AppStarting', 'Wait', 'Crosshair', 'IBeam',
    'NWPen', 'No', 'SizeNS', 'SizeWE', 'SizeNWSE', 'SizeNESW', 'SizeAll',
    'UpArrow', 'Hand', 'CursorBaseSize'
)

function Expand-CursorPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    return [Environment]::ExpandEnvironmentVariables($Path)
}

function Get-CursorSchemeState {
    $state = @{}
    $keyPath = 'HKCU:\Control Panel\Cursors'
    if (-not (Test-Path $keyPath)) { return $state }

    foreach ($name in $script:CursorSchemeValueNames) {
        try {
            $state[$name] = [string](Get-ItemPropertyValue -Path $keyPath -Name $name -ErrorAction Stop)
        } catch {
            $state[$name] = ''
        }
    }
    return $state
}

function Get-CursorSchemeChanges {
    param(
        [hashtable]$Baseline,
        [hashtable]$Current
    )

    $changes = @()
    foreach ($name in $script:CursorSchemeValueNames) {
        $old = if ($Baseline.ContainsKey($name)) { [string]$Baseline[$name] } else { '' }
        $new = if ($Current.ContainsKey($name)) { [string]$Current[$name] } else { '' }
        if ($old -eq $new) { continue }

        $displayOld = Expand-CursorPath $old
        $displayNew = Expand-CursorPath $new
        $msg = "$name changed: '$displayOld' -> '$displayNew'"

        if ($displayNew -match '(?i)\.(cur|ani)$' -and $displayNew -notmatch '(?i)\\windows\\cursors\\') {
            $msg += ' [non-standard cursor path]'
        }

        $kw = Get-MatchedCheatKeyword -Text $displayNew
        if ($kw) { $msg += " [keyword: $kw]" }

        $changes += $msg
    }
    return $changes
}

$script:NvidiaShadowPlayFtsRegPath = 'SOFTWARE\NVIDIA Corporation\Global\NvApp\ShadowPlay\FTS'

function Test-NvidiaGpuPresent {
    try {
        $gpus = Get-CimInstance Win32_VideoController -ErrorAction Stop | Select-Object -ExpandProperty Name
        foreach ($gpu in $gpus) {
            if ($gpu -match '(?i)nvidia') { return $true }
        }
    } catch {}
    return $false
}

function Get-NvidiaShadowPlayFtsState {
    $state = @{
        Exists = $false
        Values = @{}
    }

    try {
        $key = Open-LocalMachineRegistryKey -SubKeyPath $script:NvidiaShadowPlayFtsRegPath
        if (-not $key) { return $state }

        $state.Exists = $true
        foreach ($name in $key.GetValueNames()) {
            $raw = $key.GetValue($name)
            if ($raw -is [int]) {
                $state.Values[$name] = [int]$raw
            } elseif ($raw -is [byte[]] -and $raw.Length -ge 4) {
                $state.Values[$name] = [BitConverter]::ToInt32($raw, 0)
            } else {
                $state.Values[$name] = [string]$raw
            }
        }
        $key.Close()
    } catch {}

    return $state
}

function Get-NvidiaShadowPlayFtsAlerts {
    $alerts = @()
    $state = Get-NvidiaShadowPlayFtsState
    $nvidiaGpu = Test-NvidiaGpuPresent

    if (-not $nvidiaGpu) {
        $alerts += 'SUCCESS: NVIDIA ShadowPlay N/A'
        return $alerts
    }

    if (-not $state.Exists -or $state.Values.Count -eq 0) {
        $alerts += 'SUCCESS: ShadowPlay FTS not present'
        return $alerts
    }

    foreach ($name in ($state.Values.Keys | Sort-Object)) {
        $alerts += "SUCCESS: ShadowPlay FTS $name = $($state.Values[$name])"
    }

    return $alerts
}

function Get-MainCplProcessHits {
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    $messages = @()

    foreach ($procName in @('rundll32.exe', 'control.exe')) {
        try {
            Get-CimInstance Win32_Process -Filter "Name='$procName'" -ErrorAction Stop | ForEach-Object {
                $cmd = [string]$_.CommandLine
                if ($cmd -notmatch '(?i)main\.cpl') { return }
                if (-not $seen.Add([int]$_.ProcessId)) { return }
                $messages += "main.cpl opened PID $($_.ProcessId)"
            }
        } catch {}
    }

    return $messages
}

$script:CheatKeywords = @(
    'matcha', 'isabelle', 'severe', 'matrix', 'clarity', 'loader', 'photon', 'valex', 'aimmy',
    'keyauth', 'melatonin', 'evolve', 'serotonin', 'dx9ware', 'unicore', 'monolith', 'skript',
    'ntfsdump', 'atlanta', 'eulen', 'hammafia', 'redengine', 'susano', 'bypass'
)

$script:FolderOnlyKeywords = @('map')

function Test-KeywordTokenMatch {
    param(
        [string]$Text,
        [string]$Keyword
    )

    if ([string]::IsNullOrWhiteSpace($Text) -or [string]::IsNullOrWhiteSpace($Keyword)) { return $false }
    $escaped = [regex]::Escape($Keyword)
    return [regex]::IsMatch($Text, "(?i)(^|[\\_\s\-\.])(($escaped))($|[\\_\s\-\.])")
}

function Test-TrustedProcessPath {
   
