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

$script:LostTier1Version = '1.8.0'

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

# -----------------------------------------------------------
# LOSTMEDIA T1 RECORDING | MVS LostMedia
# Creditos: Mangak 
# -----------------------------------------------------------
Write-Host '  #      ###   #### ##### #   # ##### ####  #####  ###' -ForegroundColor Cyan
Write-Host '  #     #   # #       #   ## ## #     #   #   #   #   #' -ForegroundColor Cyan
Write-Host '  #     #   # #       #   # # # #     #   #   #   #   #' -ForegroundColor Cyan
Write-Host '  #     #   #  ###    #   #   # ####  #   #   #   #####' -ForegroundColor Cyan
Write-Host '  #     #   #     #   #   #   # #     #   #   #   #   #' -ForegroundColor Cyan
Write-Host '  #     #   #     #   #   #   # #     #   #   #   #   #' -ForegroundColor Cyan
Write-Host '  #####  ###  ####    #   #   # ##### ####  ##### #   #' -ForegroundColor Cyan
Write-Host ''
Write-Host '  #####   #         ####  #####  ####  ###  ####  ####  ##### #   #  ####' -ForegroundColor DarkCyan
Write-Host '    #    ##         #   # #     #     #   # #   # #   #   #   ##  # #' -ForegroundColor DarkCyan
Write-Host '    #     #         #   # #     #     #   # #   # #   #   #   # # # #' -ForegroundColor DarkCyan
Write-Host '    #     #         ####  ####  #     #   # ####  #   #   #   #  ## #  ##' -ForegroundColor DarkCyan
Write-Host '    #     #         # #   #     #     #   # # #   #   #   #   #   # #   #' -ForegroundColor DarkCyan
Write-Host '    #     #         #  #  #     #     #   # #  #  #   #   #   #   # #   #' -ForegroundColor DarkCyan
Write-Host '    #   #####       #   # #####  ####  ###  #   # ####  ##### #   #  ####' -ForegroundColor DarkCyan
Write-Host ''
Write-Host '  === LOSTMEDIA T1 RECORDING ===' -ForegroundColor White
Write-Host '  System Check / Process Explorer / Live Monitor' -ForegroundColor Gray
Write-Host ''
Write-Host '  === DISCORD SERVERS ===' -ForegroundColor Cyan
Write-Host '  Justice Department: https://discord.gg/gsdQbYFP79' -ForegroundColor White
Write-Host '  LM oficial:         https://discord.gg/2gP6MaKURK' -ForegroundColor White
Write-Host ''
Write-Host '  === CREDITS ===' -ForegroundColor Cyan
Write-Host '  Mangak             - Personalizacao Lost Media' -ForegroundColor Gray
Write-Host ''

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
    'C:\Users\Stef\Downloads\windhawk.exe',
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
        $fallback = Join-Path $env:TEMP 'lostmedia_t1_security_events.log'
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
    param([string]$ExecutablePath)

    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) { return $true }
    $path = $ExecutablePath.ToLower().Replace('/', '\')
    $prefixes = @(
        "$($env:SystemRoot.ToLower())\",
        "$($env:ProgramFiles.ToLower())\"
    )
    $pf86 = ${env:ProgramFiles(x86)}
    if ($pf86) { $prefixes += "$($pf86.ToLower())\" }
    foreach ($prefix in $prefixes) {
        if ($path.StartsWith($prefix)) { return $true }
    }
    return $false
}

$script:MasqueradeProcessPaths = @{
    'svchost.exe'       = @('\windows\system32\svchost.exe', '\windows\syswow64\svchost.exe')
    'explorer.exe'      = @('\windows\explorer.exe')
    'csrss.exe'         = @('\windows\system32\csrss.exe')
    'lsass.exe'         = @('\windows\system32\lsass.exe')
    'services.exe'      = @('\windows\system32\services.exe')
    'smss.exe'          = @('\windows\system32\smss.exe')
    'winlogon.exe'      = @('\windows\system32\winlogon.exe')
    'dwm.exe'           = @('\windows\system32\dwm.exe')
    'taskhostw.exe'     = @('\windows\system32\taskhostw.exe')
    'runtimebroker.exe' = @('\windows\system32\runtimebroker.exe')
    'conhost.exe'       = @('\windows\system32\conhost.exe', '\windows\syswow64\conhost.exe')
    'dllhost.exe'       = @('\windows\system32\dllhost.exe', '\windows\syswow64\dllhost.exe')
    'spoolsv.exe'       = @('\windows\system32\spoolsv.exe')
    'wininit.exe'       = @('\windows\system32\wininit.exe')
    'sihost.exe'        = @('\windows\system32\sihost.exe')
    'fontdrvhost.exe'   = @('\windows\system32\fontdrvhost.exe')
}

function Get-MatchedCheatKeyword {
    param(
        [string]$Text,
        [switch]$FolderName
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $lower = $Text.ToLower()

    if ($FolderName) {
        foreach ($kw in ($script:CheatKeywords + $script:FolderOnlyKeywords)) {
            if ($lower -like "*$kw*") { return $kw }
        }
        return $null
    }

    foreach ($kw in $script:CheatKeywords) {
        if ($kw.Length -le 4) {
            if (Test-KeywordTokenMatch -Text $lower -Keyword $kw) { return $kw }
        } elseif ($lower -like "*$kw*") {
            return $kw
        }
    }
    return $null
}

function Test-MasqueradeProcessPath {
    param(
        [string]$ProcessName,
        [string]$ExecutablePath
    )

    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) { return $null }
    $nameLower = $ProcessName.ToLower()
    if (-not $script:MasqueradeProcessPaths.ContainsKey($nameLower)) { return $null }

    $pathLower = $ExecutablePath.ToLower().Replace('/', '\')
    foreach ($legitSuffix in $script:MasqueradeProcessPaths[$nameLower]) {
        if ($pathLower.EndsWith($legitSuffix)) { return $null }
    }

    return "Windows process '$ProcessName' running from non-standard path: $ExecutablePath"
}

function Get-SuspiciousProcessHits {
    $hits = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $messages = @()

    try {
        Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
            $procName = $_.Name
            $procPath = $_.ExecutablePath
            $procId = $_.ProcessId

            $masquerade = Test-MasqueradeProcessPath -ProcessName $procName -ExecutablePath $procPath
            if ($masquerade) {
                $key = "masquerade|$procName|$procPath"
                if ($hits.Add($key)) { $messages += "FAILURE: Masquerade $procName (PID $procId)" }
            }

            $nameKw = Get-MatchedCheatKeyword -Text $procName
            if ($nameKw) {
                $key = "name|$procName|$nameKw"
                if ($hits.Add($key)) { $messages += "FAILURE: $procName (PID $procId) [$nameKw]" }
            }

            if ($procPath -and -not (Test-TrustedProcessPath -ExecutablePath $procPath)) {
                $pathKw = Get-MatchedCheatKeyword -Text $procPath
                if ($pathKw) {
                    $key = "path|$procPath|$pathKw|$procId"
                    if ($hits.Add($key)) { $messages += "FAILURE: $procPath (PID $procId) [$pathKw]" }
                }
            }
        }
    } catch {
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $nameKw = Get-MatchedCheatKeyword -Text $_.Name
            if ($nameKw) {
                $key = "name|$($_.Name)|$nameKw"
                if ($hits.Add($key)) { $messages += "FAILURE: $($_.Name) (PID $($_.Id)) [$nameKw]" }
            }
        }
    }

    return $messages
}

$script:MonitorProcessAllowlist = @(
    'robloxplayerbeta.exe',
    'fishstrap.exe',
    'robloxcrashhandler.exe',
    'bloxstrap.exe'
)

function Test-NoImagePathIgnoredProcess {
    param([string]$ProcessName)

    if ([string]::IsNullOrWhiteSpace($ProcessName)) { return $true }
    return $ProcessName -match '(?i)^(svchost|conhost|dllhost|RuntimeBroker|WmiPrvSE|SearchHost|ShellHost|ctfmon|sihost|taskhostw|spoolsv|lsass|services|smss|csrss|wininit|winlogon|fontdrvhost|dwm|explorer|msedgewebview2|SecurityHealthService|audiodg|smartscreen|SearchIndexer|Registry|NisSrv|MpDefenderCoreService|MsMpEng)\.exe$'
}

function Test-ShouldLogProcessMonitorEvent {
    param($Proc)

    $seriousReasons = @($Proc.Reasons | Where-Object { $_ -ne 'no image path' })
    $nameLower = [string]$Proc.Name
    if ($nameLower) { $nameLower = $nameLower.ToLower() }

    if ($nameLower -and $script:MonitorProcessAllowlist -contains $nameLower) {
        if ($seriousReasons.Count -eq 0) { return $false }
    }

    if ($seriousReasons.Count -gt 0) { return $true }
    if ($Proc.UserLand) { return $true }
    return $false
}

function Get-ProcessSuspiciousReasons {
    param(
        [string]$ProcessName,
        [string]$ExecutablePath
    )

    $reasons = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
        if ($ProcessName -notmatch '(?i)^(System|Registry|Secure System|Memory Compression|Idle)$') {
            if (-not (Test-NoImagePathIgnoredProcess -ProcessName $ProcessName)) {
                [void]$reasons.Add('no image path')
            }
        }
    } else {
        $leaf = Split-Path $ExecutablePath -Leaf
        if ($ProcessName -and $leaf -and ($ProcessName.ToLower() -ne $leaf.ToLower())) {
            [void]$reasons.Add('name/path mismatch')
        }
    }

    if (Test-MasqueradeProcessPath -ProcessName $ProcessName -ExecutablePath $ExecutablePath) {
        [void]$reasons.Add('masquerade')
    }

    $nameKw = Get-MatchedCheatKeyword -Text $ProcessName
    if ($nameKw) { [void]$reasons.Add($nameKw) }

    if ($ExecutablePath -and -not (Test-TrustedProcessPath -ExecutablePath $ExecutablePath)) {
        $pathKw = Get-MatchedCheatKeyword -Text $ExecutablePath
        if ($pathKw) { [void]$reasons.Add($pathKw) }
    }

    return @($reasons)
}

function Test-UserLandProcessPath {
    param([string]$ExecutablePath)

    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) { return $false }
    $path = $ExecutablePath.ToLower().Replace('/', '\')
    foreach ($marker in @('\downloads\', '\desktop\', '\temp\')) {
        if ($path -like "*$marker*") { return $true }
    }
    return $false
}

function Get-ProcessSnapshot {
    $snap = @{}
    try {
        Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
            $procId = [int]$_.ProcessId
            $path = [string]$_.ExecutablePath
            $name = [string]$_.Name
            $reasons = @(Get-ProcessSuspiciousReasons -ProcessName $name -ExecutablePath $path)
            $snap[$procId] = @{
                Name       = $name
                Path       = $path
                Reasons    = $reasons
                UserLand   = Test-UserLandProcessPath -ExecutablePath $path
                Suspicious = ($reasons.Count -gt 0)
            }
        }
    } catch {}
    return $snap
}

function Update-ProcessChangeMonitor {
    param(
        [hashtable]$Previous,
        [hashtable]$Current,
        [hashtable]$Watched,
        [string]$LogFile
    )

    foreach ($procId in $Current.Keys) {
        if ($Previous.ContainsKey($procId)) { continue }

        $proc = $Current[$procId]
        if (-not (Test-ShouldLogProcessMonitorEvent -Proc $proc)) { continue }

        $label = "$($proc.Name) (PID $procId)"
        if ($proc.Path) { $label += " -> $($proc.Path)" }

        $tags = @($proc.Reasons | Where-Object { $_ -ne 'no image path' })
        if ($tags.Count -gt 0) {
            Write-MonitorAlert -Message "Started [$($tags -join ', ')]: $label" -LogFile $LogFile -Color Yellow
        } else {
            Write-MonitorAlert -Message "Started [userland]: $label" -LogFile $LogFile -Color Yellow
        }
        $Watched[$procId] = $proc
    }

    foreach ($procId in $Previous.Keys) {
        if ($Current.ContainsKey($procId)) { continue }
        if (-not $Watched.ContainsKey($procId)) { continue }

        $proc = $Previous[$procId]
        $label = "$($proc.Name) (PID $procId)"
        if ($proc.Path) { $label += " -> $($proc.Path)" }

        $tags = @($proc.Reasons | Where-Object { $_ -ne 'no image path' })
        if ($tags.Count -gt 0) {
            Write-MonitorAlert -Message "Exited [$($tags -join ', ')]: $label" -LogFile $LogFile -Color Yellow
        } else {
            Write-MonitorAlert -Message "Exited [userland]: $label" -LogFile $LogFile -Color Yellow
        }
        $Watched.Remove($procId) | Out-Null
    }
}

$script:ExternalReaderAllowlist = @(
    'robloxplayerbeta', 'robloxcrashhandler', 'robloxplayerlauncher',
    'bloxstrap', 'fishstrap', 'lunarstrap',
    'msmpeng', 'nissrv', 'securityhealthservice', 'mpdefendercoreservice',
    'csrss', 'lsass', 'wininit', 'services', 'searchindexer', 'wmiprvse',
    'powershell', 'pwsh', 'explorer'
)

$script:CaptureWindowAllowlist = @(
    'logonui', 'consent', 'dwm', 'textinputhost', 'screenclippinghost',
    'snippingtool', 'searchhost', 'startmenuexperiencehost',
    'applicationframehost', 'systemsettings', 'shellexperiencehost'
)

function Initialize-ExternalScanApi {
    if ('Loc.ExternalScan' -as [type]) { return $true }
    try {
        Add-Type -Namespace Loc -Name ExternalScan -UsingNamespace System.Text, System.Collections.Generic -MemberDefinition @'
[DllImport("user32.dll")]
private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
[DllImport("user32.dll")]
private static extern bool IsWindowVisible(IntPtr hWnd);
[DllImport("user32.dll", SetLastError = true)]
private static extern bool GetWindowDisplayAffinity(IntPtr hWnd, out uint dwAffinity);
[DllImport("user32.dll", SetLastError = true)]
private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
[DllImport("user32.dll", CharSet = CharSet.Unicode)]
private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
[DllImport("user32.dll", CharSet = CharSet.Unicode)]
private static extern int GetClassNameW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
[DllImport("ntdll.dll")]
private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);
[DllImport("kernel32.dll", SetLastError = true)]
private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
[DllImport("kernel32.dll", SetLastError = true)]
private static extern bool DuplicateHandle(IntPtr srcProc, IntPtr srcHandle, IntPtr tgtProc, out IntPtr tgtHandle, uint access, bool inherit, uint options);
[DllImport("kernel32.dll", SetLastError = true)]
private static extern bool CloseHandle(IntPtr h);
[DllImport("kernel32.dll", SetLastError = true)]
private static extern int GetProcessId(IntPtr h);
[DllImport("kernel32.dll")]
private static extern IntPtr GetCurrentProcess();

private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

private const int SystemExtendedHandleInformation = 0x40;
private const uint PROCESS_DUP_HANDLE = 0x0040;
private const uint PROCESS_VM_READ = 0x0010;
private const uint DUPLICATE_SAME_ACCESS = 0x0002;

private static List<string> _winHits;
private static EnumWindowsProc _winCb;

private static bool WindowCallback(IntPtr hWnd, IntPtr lParam) {
    try {
        if (!IsWindowVisible(hWnd)) { return true; }
        uint affinity;
        if (!GetWindowDisplayAffinity(hWnd, out affinity)) { return true; }
        if (affinity == 0) { return true; }
        uint pid = 0;
        GetWindowThreadProcessId(hWnd, out pid);
        StringBuilder title = new StringBuilder(256);
        GetWindowTextW(hWnd, title, title.Capacity);
        StringBuilder cls = new StringBuilder(256);
        GetClassNameW(hWnd, cls, cls.Capacity);
        _winHits.Add(pid.ToString() + "|" + affinity.ToString() + "|" + title.ToString() + "|" + cls.ToString());
    } catch { }
    return true;
}

public static string[] FindCaptureProtectedWindows() {
    _winHits = new List<string>();
    _winCb = new EnumWindowsProc(WindowCallback);
    try { EnumWindows(_winCb, IntPtr.Zero); } catch { }
    return _winHits.ToArray();
}

public static int[] FindRobloxMemoryReaders(int[] targetPids) {
    List<int> readers = new List<int>();
    if (targetPids == null || targetPids.Length == 0) { return readers.ToArray(); }
    HashSet<int> targets = new HashSet<int>(targetPids);

    int length = 0x20000;
    IntPtr buffer = Marshal.AllocHGlobal(length);
    try {
        int needed = 0;
        int status = 0;
        for (int tries = 0; tries < 16; tries++) {
            status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, length, out needed);
            if (status == unchecked((int)0xC0000004)) {
                Marshal.FreeHGlobal(buffer);
                length = (needed > length ? needed : length * 2) + 0x10000;
                buffer = Marshal.AllocHGlobal(length);
                continue;
            }
            break;
        }
        if (status != 0) { return readers.ToArray(); }

        int ptr = IntPtr.Size;
        long handleCount = Marshal.ReadIntPtr(buffer).ToInt64();
        int headerSize = ptr * 2;
        int entrySize = ptr * 3 + 16;

        IntPtr self = GetCurrentProcess();
        Dictionary<int, IntPtr> opened = new Dictionary<int, IntPtr>();
        HashSet<int> done = new HashSet<int>();

        for (long i = 0; i < handleCount; i++) {
            int offset = (int)(headerSize + i * entrySize);
            int ownerPid = (int)Marshal.ReadIntPtr(buffer, offset + ptr).ToInt64();
            if (ownerPid <= 4) { continue; }
            if (done.Contains(ownerPid)) { continue; }
            if (targets.Contains(ownerPid)) { continue; }
            uint access = (uint)Marshal.ReadInt32(buffer, offset + ptr * 3);
            if ((access & PROCESS_VM_READ) == 0) { continue; }
            IntPtr handleValue = Marshal.ReadIntPtr(buffer, offset + ptr * 2);

            IntPtr owner;
            if (!opened.TryGetValue(ownerPid, out owner)) {
                owner = OpenProcess(PROCESS_DUP_HANDLE, false, ownerPid);
                opened[ownerPid] = owner;
            }
            if (owner == IntPtr.Zero) { continue; }

            IntPtr dup;
            if (!DuplicateHandle(owner, handleValue, self, out dup, 0, false, DUPLICATE_SAME_ACCESS)) { continue; }
            try {
                int objPid = GetProcessId(dup);
                if (objPid != 0 && targets.Contains(objPid)) {
                    readers.Add(ownerPid);
                    done.Add(ownerPid);
                }
            } catch { } finally {
                CloseHandle(dup);
            }
        }

        foreach (KeyValuePair<int, IntPtr> kv in opened) {
            if (kv.Value != IntPtr.Zero) { CloseHandle(kv.Value); }
        }
    } catch {
    } finally {
        Marshal.FreeHGlobal(buffer);
    }
    return readers.ToArray();
}
'@ -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Get-RobloxTargetIds {
    $ids = New-Object 'System.Collections.Generic.List[int]'
    try {
        Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.ProcessName -match '(?i)^RobloxPlayerBeta$' } |
            ForEach-Object { $ids.Add([int]$_.Id) }
    } catch {}
    return @($ids)
}

function Resolve-ProcessIdentity {
    param([int]$TargetPid)

    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid" -ErrorAction Stop | Select-Object -First 1
        if ($p) { return @{ Name = [string]$p.Name; Path = [string]$p.ExecutablePath } }
    } catch {}
    try {
        $p = Get-Process -Id $TargetPid -ErrorAction Stop
        return @{ Name = "$($p.ProcessName).exe"; Path = [string]$p.Path }
    } catch {}
    return @{ Name = "PID $TargetPid"; Path = '' }
}

function Get-ExternalCheatHits {
    if (-not (Initialize-ExternalScanApi)) {
        return , @('WARNING: External scan unavailable')
    }

    $messages = @()

    $targets = @(Get-RobloxTargetIds)
    if ($targets.Count -gt 0) {
        $readers = @()
        try { $readers = @([Loc.ExternalScan]::FindRobloxMemoryReaders([int[]]$targets)) } catch {}
        foreach ($ownerId in ($readers | Select-Object -Unique)) {
            $info = Resolve-ProcessIdentity -TargetPid $ownerId
            $nameLower = ($info.Name -replace '\.exe$', '').ToLower()
            if ($script:ExternalReaderAllowlist -contains $nameLower) { continue }
            $label = "$($info.Name) (PID $ownerId)"
            if ($info.Path) { $label += " -> $($info.Path)" }
            $messages += "FAILURE: Reading Roblox memory $label"
        }
    }

    $windows = @()
    try { $windows = @([Loc.ExternalScan]::FindCaptureProtectedWindows()) } catch {}
    foreach ($w in $windows) {
        $parts = $w -split '\|', 4
        if ($parts.Count -lt 2) { continue }
        $winPid = 0
        [void][int]::TryParse($parts[0], [ref]$winPid)
        if ($winPid -eq $PID -or $winPid -le 0) { continue }

        $info = Resolve-ProcessIdentity -TargetPid $winPid
        $nameLower = ($info.Name -replace '\.exe$', '').ToLower()
        if ($script:CaptureWindowAllowlist -contains $nameLower) { continue }

        $affLabel = switch ($parts[1]) {
            '1'  { 'WDA_MONITOR' }
            '17' { 'WDA_EXCLUDEFROMCAPTURE' }
            default { "affinity=$($parts[1])" }
        }
        $title = if ($parts.Count -ge 3 -and $parts[2]) { " '$($parts[2])'" } else { '' }
        $label = "$($info.Name) (PID $winPid)$title [$affLabel]"

        if ($info.Path -and -not (Test-TrustedProcessPath -ExecutablePath $info.Path)) {
            $messages += "FAILURE: Window hidden from capture $label -> $($info.Path)"
        } else {
            $messages += "WARNING: Window hidden from capture $label"
        }
    }

    if ($messages.Count -eq 0) {
        return , @('SUCCESS: No external/overlay cheat detected')
    }
    return $messages
}

$script:BaselineBamKeys = @{}
$script:BaselinePrefetchFiles = @{}

Write-Host "[ LOSTMEDIA T1 | ETAPA 1/3 - SYSTEM CHECK ]" -ForegroundColor Cyan
Write-Host ""

for ($i = 0; $i -le 20; $i++) {
    $percent = $i * 5
    $bar = ("#" * $i) + ("-" * (20 - $i))
    Write-Host "`r[ $bar ] $percent%" -NoNewline
    Start-Sleep -Milliseconds 120
}
Write-Host "`n"

$passedChecks = 0
$totalChecks  = 0

$moduleOutput          = @()
$cpuGpuOutput          = @()
$processOutput         = @()
$keyAuthOutput         = @()
$powershellSigOutput   = @()
$osOutput              = @()
$vmOutput              = @()
$defenderOutput        = @()
$exclusionsOutput      = @()
$allowedThreatsOutput  = @()
$memoryIntegrityOutput = @()
$nvidiaOutput          = @()
$windhawkOutput        = @()
$externalOutput        = @()
$registryOutput        = @()

$totalChecks++
$modules = @(
    "Microsoft.PowerShell.Operation.Validation",
    "PackageManagement",
    "Pester",
    "PowerShellGet",
    "PSReadline"
)
$moduleFails = @()
foreach ($mod in $modules) {
    if (-not (Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue)) {
        $moduleFails += $mod
    }
}
if ($moduleFails.Count -eq 0) {
    $moduleOutput += "SUCCESS: Modules OK"
    $passedChecks++
} else {
    foreach ($fail in $moduleFails) { $moduleOutput += "FAILURE: Missing module $fail" }
}

try {
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name
    if ($cpu) { $cpuGpuOutput += "SUCCESS: CPU detected -> $cpu" }

    $gpus = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name
    foreach ($gpu in $gpus) {
        $cpuGpuOutput += "SUCCESS: GPU detected -> $gpu"
    }
} catch {
    $cpuGpuOutput += "WARNING: Unable to query CPU/GPU information."
}

$totalChecks++
try {
    $def = Get-MpComputerStatus
    if ($def.RealTimeProtectionEnabled) {
        $defenderOutput += "SUCCESS: Windows Defender real-time protection enabled."
        $passedChecks++
    } else {
        $defenderOutput += "FAILURE: Windows Defender real-time protection disabled."
    }

    if (-not $def.IsTamperProtected) {
        $defenderOutput += "WARNING: Tamper protection disabled."
    }
} catch {
    $defenderOutput += "WARNING: Unable to query Defender."
}

foreach ($disableKey in @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
    'HKLM:\SOFTWARE\Microsoft\Windows Defender'
)) {
    try {
        $disabled = Get-ItemPropertyValue -Path $disableKey -Name 'DisableAntiSpyware' -ErrorAction Stop
        if ($disabled -eq 1) { $defenderOutput += "FAILURE: DisableAntiSpyware active." }
    } catch {}
}

$totalChecks++
try {
    $allExclusions = @(Get-Exclusions)

    if ($allExclusions.Count -eq 0) {
        $exclusionsOutput += "SUCCESS: No Defender exclusions."
        $passedChecks++
    } else {
        foreach ($excl in $allExclusions) {
            $exclKw = Get-MatchedCheatKeyword -Text $excl
            if ($exclKw) {
                $exclusionsOutput += "FAILURE: Defender exclusion [$exclKw] -> $excl"
            } else {
                $exclusionsOutput += "FAILURE: Defender exclusion -> $excl"
            }
        }
    }
} catch {
    $exclusionsOutput += "WARNING: Exclusions check failed."
}

$totalChecks++
try {
    $allowedThreats = @(Get-AllowedDefenderThreats)
    if ($allowedThreats.Count -eq 0) {
        $allowedThreatsOutput += "SUCCESS: No allowed threats."
        $passedChecks++
    } else {
        foreach ($threat in $allowedThreats) {
            $allowedThreatsOutput += "FAILURE: Allowed threat -> $threat"
        }
    }
} catch {
    $allowedThreatsOutput += "WARNING: Allowed threats check failed."
}

$totalChecks++
try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    $enabled = Get-ItemPropertyValue -Path $regPath -Name Enabled
    if ($enabled -eq 1) {
        $memoryIntegrityOutput += "SUCCESS: Memory Integrity enabled."
        $passedChecks++
    } else {
        $memoryIntegrityOutput += "FAILURE: Memory Integrity disabled."
    }
} catch {
    $memoryIntegrityOutput += "WARNING: Memory Integrity status unavailable."
}

$totalChecks++
$nvidiaOutput += @(Get-NvidiaShadowPlayFtsAlerts)
$passedChecks++

$totalChecks++
$procHits = @(Get-SuspiciousProcessHits)
if ($procHits.Count -eq 0) {
    $processOutput += "SUCCESS: Processes clean"
    $passedChecks++
} else {
    $processOutput += $procHits
}

$totalChecks++
try {
    $keyAuthHits = @()
    $keyAuthRoots = @(
        'C:\ProgramData\KeyAuth',
        (Join-Path $env:ProgramData 'KeyAuth')
    )
    foreach ($keyRoot in ($keyAuthRoots | Select-Object -Unique)) {
        if (-not (Test-Path $keyRoot)) { continue }
        Get-ChildItem $keyRoot -Recurse -Directory -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object {
            $keyAuthHits += $_.FullName
        }
    }
    if ($keyAuthHits.Count -eq 0) {
        $keyAuthOutput += "SUCCESS: KeyAuth clean"
        $passedChecks++
    } else {
        foreach ($hit in ($keyAuthHits | Select-Object -Unique)) {
            $keyAuthOutput += "FAILURE: KeyAuth $hit"
        }
    }
} catch {
    $keyAuthOutput += "WARNING: KeyAuth check failed"
}

$totalChecks++
foreach ($line in (Get-WindhawkStep1Alerts)) {
    $windhawkOutput += $line
    if ($line -like 'SUCCESS*') { $passedChecks++ }
}

$totalChecks++
$externalOutput += @(Get-ExternalCheatHits)
if (-not ($externalOutput | Where-Object { $_ -like 'FAILURE*' })) { $passedChecks++ }

$totalChecks++
$registryHit = $false
try {
    if (Test-Path -LiteralPath 'HKCU:\Antenna') {
        $registryOutput += "FAILURE: Cheat found"
        $registryHit = $true
    }
} catch {}

if (-not $registryHit) {
    $registryOutput += "SUCCESS: Registry clean"
    $passedChecks++
}

Write-Section "Modules" $moduleOutput
Write-Section "CPU & GPU Detections" $cpuGpuOutput
Write-Section "Windows Defender" $defenderOutput
Write-Section "Defender Exclusions" $exclusionsOutput
Write-Section "Allowed Threats" $allowedThreatsOutput
Write-Section "Memory Integrity" $memoryIntegrityOutput
Write-Section "NVIDIA ShadowPlay" $nvidiaOutput
Write-Section "Process Scan" $processOutput
Write-Section "KeyAuth Check" $keyAuthOutput
Write-Section "Windhawk" $windhawkOutput
Write-Section "External / Overlay" $externalOutput
Write-Section "Registry" $registryOutput

if ($totalChecks -ne 0) { $successRate = [math]::Round(($passedChecks / $totalChecks) * 100) } else { $successRate = 0 }
Write-Host "Overall Success Rate: $successRate%" -ForegroundColor Cyan
Write-Host ""

Write-Host "Press Enter to continue..." -ForegroundColor Yellow
Read-Host "Press Enter to continue" | Out-Null

Clear-Host
Write-Host "[ LOSTMEDIA T1 | ETAPA 2/3 - PROCESS EXPLORER ]" -ForegroundColor Cyan
Write-Host ""

Write-Host "Launching Process Explorer..." -ForegroundColor Green
Write-Host ""
if (Start-LocExternalTool -Name 'Process Explorer' `
        -Url 'https://download.sysinternals.com/files/ProcessExplorer.zip' `
        -ZipPath "$env:TEMP\procexp.zip" `
        -DestDir "$env:TEMP\ProcessExplorer" `
        -ExeName 'procexp64.exe' `
        -FallbackExeNames @('procexp.exe') `
        -StartArguments @('/accepteula') `
        -Wait) {
    Write-Host ""
    Write-Host "Process Explorer closed." -ForegroundColor Cyan
}

Write-Host "Press Enter to continue..." -ForegroundColor Yellow
Read-Host "Press Enter to continue" | Out-Null

Clear-Host
Write-Host "[ LOSTMEDIA T1 | ETAPA 3/3 - LIVE MONITOR ]" -ForegroundColor Cyan
Write-Host ""
Write-Host "Keep this window open during the match. Must show again after match." -ForegroundColor Yellow
Write-Host ""

$logFile = Join-Path $env:ProgramData 'lostmedia_t1_security_events.log'
try {
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }
    Write-MonitorAlert -Message "LostMedia T1 Recording (LOC base v$($script:LocTier1Version)) monitor started" -LogFile $logFile
} catch {
    $logFile = Join-Path $env:TEMP 'lostmedia_t1_security_events.log'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }
    Write-Host "WARNING: Logging to $logFile" -ForegroundColor Yellow
    Write-MonitorAlert -Message "LostMedia T1 Recording (LOC base v$($script:LocTier1Version)) monitor started" -LogFile $logFile
}

Register-WmiEvent -Class Win32_VolumeChangeEvent -SourceIdentifier USBChange | Out-Null
trap {
    Get-EventSubscriber -SourceIdentifier USBChange -ErrorAction SilentlyContinue |
        Unregister-Event -Force -ErrorAction SilentlyContinue
    break
}

foreach ($fp in (Get-BamRegistryFingerprints)) { $script:BaselineBamKeys[$fp] = $true }
foreach ($pf in (Get-PrefetchFileNames)) { $script:BaselinePrefetchFiles[$pf] = $true }

$previousExclusions = @{}
foreach ($ex in (Get-Exclusions)) { $previousExclusions[$ex] = $true }
$knownCheatFolders = @{}
foreach ($folder in (Get-CheatFolderHits)) {
    $knownCheatFolders[$folder] = $true
}
$reportedBamDeletions = @{}
$reportedPrefetchDeletions = @{}
$reportedTamperEvents = @{}
$reportedPrefetchHits = @{}
$reportedCursorChanges = @{}
$reportedMainCplHits = @{}
$baselineCursorScheme = Get-CursorSchemeState
$reportedDefenderStatus = @{}
$reportedRegistryTools = @{}
$reportedWindhawkHits = @{}
$reportedDefenderRegChanges = @{}
$reportedExternalHits = @{}
$baselineDefenderReg = Get-DefenderRegistryFingerprints
$defenderRegLabels = Get-DefenderRegistryMonitorLabels
$lastProcessSnapshot = Get-ProcessSnapshot
$watchedProcesses = @{}
$monitoringStart = Get-Date
$folderScanCounter = 0
$deletionScanCounter = 0
$processChangeCounter = 0
$mainCplScanCounter = 0
$defenderScanCounter = 0
$externalScanCounter = 0

foreach ($line in (Get-DefenderStatusAlerts)) {
    if ($line -like 'FAILURE*' -or $line -like 'WARNING*') {
        $reportedDefenderStatus[$line] = $true
        $color = 'Yellow'
        Write-MonitorAlert -Message $line -LogFile $logFile -Color $color
    }
}

foreach ($hit in (Get-WindhawkProcessHits)) {
    $reportedWindhawkHits[$hit] = $true
    Write-MonitorAlert -Message "Windhawk: $hit" -LogFile $logFile -Color Yellow
}

foreach ($line in (Get-ExternalCheatHits)) {
    if ($line -like 'SUCCESS*') { continue }
    if (-not $reportedExternalHits.ContainsKey($line)) {
        $reportedExternalHits[$line] = $true
        Write-MonitorAlert -Message $line -LogFile $logFile -Color Yellow
    }
}

while ($true) {
    $usbEvent = Wait-Event -SourceIdentifier USBChange -Timeout 1
    if ($usbEvent) {
        $eventType = $usbEvent.SourceEventArgs.NewEvent.EventType
        $driveLetter = $usbEvent.SourceEventArgs.NewEvent.DriveName

        if ($eventType -eq 2) {
            Write-MonitorAlert -Message "USB in $driveLetter" -LogFile $logFile
        } elseif ($eventType -eq 3) {
            Write-MonitorAlert -Message "USB out $driveLetter" -LogFile $logFile
        }

        Remove-Event -EventIdentifier $usbEvent.EventIdentifier -ErrorAction SilentlyContinue
    }

    try {
        $currentExclusions = @{}
        foreach ($ex in (Get-Exclusions)) { $currentExclusions[$ex] = $true }

        foreach ($ex in $currentExclusions.Keys) {
            if (-not $previousExclusions.ContainsKey($ex)) {
                $exclKw = Get-MatchedCheatKeyword -Text $ex
                if ($exclKw) {
                    Write-MonitorAlert -Message "Exclusion added [$exclKw]: $ex" -LogFile $logFile -Color Yellow
                } else {
                    Write-MonitorAlert -Message "Exclusion added: $ex" -LogFile $logFile -Color Yellow
                }
            }
        }

        foreach ($ex in $previousExclusions.Keys) {
            if (-not $currentExclusions.ContainsKey($ex)) {
                Write-MonitorAlert -Message "Exclusion removed: $ex" -LogFile $logFile -Color Yellow
            }
        }

        $previousExclusions = $currentExclusions
    } catch {}

    foreach ($change in (Get-CursorSchemeChanges -Baseline $baselineCursorScheme -Current (Get-CursorSchemeState))) {
        if (-not $reportedCursorChanges.ContainsKey($change)) {
            $reportedCursorChanges[$change] = $true
            Write-MonitorAlert -Message "Cursor changed: $change" -LogFile $logFile -Color Yellow
        }
    }

    $mainCplScanCounter++
    if ($mainCplScanCounter -ge 5) {
        $mainCplScanCounter = 0
        foreach ($hit in (Get-MainCplProcessHits)) {
            if (-not $reportedMainCplHits.ContainsKey($hit)) {
                $reportedMainCplHits[$hit] = $true
                Write-MonitorAlert -Message $hit -LogFile $logFile -Color Yellow
            }
        }

        foreach ($hit in (Get-RegistryToolProcessHits)) {
            if (-not $reportedRegistryTools.ContainsKey($hit)) {
                $reportedRegistryTools[$hit] = $true
                Write-MonitorAlert -Message "Registry tool: $hit" -LogFile $logFile -Color Yellow
            }
        }

        foreach ($hit in (Get-WindhawkProcessHits)) {
            if (-not $reportedWindhawkHits.ContainsKey($hit)) {
                $reportedWindhawkHits[$hit] = $true
                Write-MonitorAlert -Message "Windhawk: $hit" -LogFile $logFile -Color Yellow
            }
        }
    }

    $defenderScanCounter++
    if ($defenderScanCounter -ge 5) {
        $defenderScanCounter = 0

        try {
            foreach ($line in (Get-DefenderStatusAlerts)) {
                if (-not $reportedDefenderStatus.ContainsKey($line)) {
                    $reportedDefenderStatus[$line] = $true
                    $color = 'Yellow'
                    Write-MonitorAlert -Message $line -LogFile $logFile -Color $color
                }
            }

            foreach ($entry in (Get-DefenderRegistryFingerprints).GetEnumerator()) {
                $root = $entry.Key
                $currentFp = $entry.Value
                $baselineFp = $baselineDefenderReg[$root]
                if ($currentFp -eq $baselineFp) { continue }

                $changeKey = "$root|$currentFp"
                if ($reportedDefenderRegChanges.ContainsKey($changeKey)) { continue }
                $reportedDefenderRegChanges[$changeKey] = $true

                $label = if ($defenderRegLabels.ContainsKey($root)) { $defenderRegLabels[$root] } else { $root }
                Write-MonitorAlert -Message "$label changed: $currentFp" -LogFile $logFile -Color Yellow
            }
        } catch {}
    }

    $externalScanCounter++
    if ($externalScanCounter -ge 5) {
        $externalScanCounter = 0
        foreach ($line in (Get-ExternalCheatHits)) {
            if ($line -like 'SUCCESS*') { continue }
            if (-not $reportedExternalHits.ContainsKey($line)) {
                $reportedExternalHits[$line] = $true
                Write-MonitorAlert -Message $line -LogFile $logFile -Color Yellow
            }
        }
    }

    $folderScanCounter++
    if ($folderScanCounter -ge 30) {
        $folderScanCounter = 0
        foreach ($folder in (Get-CheatFolderHits)) {
            if (-not $knownCheatFolders.ContainsKey($folder)) {
                $knownCheatFolders[$folder] = $true
                Write-MonitorAlert -Message "Cheat folder: $folder" -LogFile $logFile -Color Yellow
            }
        }
    }

    $processChangeCounter++
    if ($processChangeCounter -ge 3) {
        $processChangeCounter = 0
        $currentProcessSnapshot = Get-ProcessSnapshot
        Update-ProcessChangeMonitor -Previous $lastProcessSnapshot -Current $currentProcessSnapshot -Watched $watchedProcesses -LogFile $logFile
        $lastProcessSnapshot = $currentProcessSnapshot
    }

    $deletionScanCounter++
    if ($deletionScanCounter -ge 10) {
        $deletionScanCounter = 0

        $currentBam = @{}
        foreach ($fp in (Get-BamRegistryFingerprints)) { $currentBam[$fp] = $true }
        foreach ($fp in $script:BaselineBamKeys.Keys) {
            if (-not $currentBam.ContainsKey($fp) -and -not $reportedBamDeletions.ContainsKey($fp)) {
                $reportedBamDeletions[$fp] = $true
                $display = ($fp -split '\|')[-1]
                Write-MonitorAlert -Message "BAM removed: $display" -LogFile $logFile -Color Yellow
            }
        }

        $currentPrefetch = @{}
        foreach ($pf in (Get-PrefetchFileNames)) {
            $currentPrefetch[$pf] = $true
            if (-not $script:BaselinePrefetchFiles.ContainsKey($pf) -and -not $reportedPrefetchHits.ContainsKey($pf)) {
                $pfKw = Get-MatchedCheatKeyword -Text $pf
                if ($pfKw) {
                    $reportedPrefetchHits[$pf] = $true
                    Write-MonitorAlert -Message "Prefetch added [$pfKw]: $pf" -LogFile $logFile -Color Yellow
                }
            }
        }
        foreach ($pf in $script:BaselinePrefetchFiles.Keys) {
            if (-not $currentPrefetch.ContainsKey($pf) -and -not $reportedPrefetchDeletions.ContainsKey($pf)) {
                $reportedPrefetchDeletions[$pf] = $true
                Write-MonitorAlert -Message "Prefetch deleted: $pf" -LogFile $logFile -Color Yellow
            }
        }

        foreach ($ev in (Get-TamperLogEvents -Since $monitoringStart)) {
            $eventKey = "$($ev.LogName)|$($ev.RecordId)"
            if ($reportedTamperEvents.ContainsKey($eventKey)) { continue }
            $reportedTamperEvents[$eventKey] = $true
            Write-MonitorAlert -Message "Log cleared ($($ev.Id))" -LogFile $logFile -Color Yellow
        }
    }
}
