#requires -Version 5.1
<#
MVS LOST MEDIA / LM-REGTRACE T1:02 / BUILD 3.8.0
Registry + Roblox logs + Windows event evidence.
Read-only. Does not transmit, delete, modify or upload player data.
Roblox logs are sampled locally, by metadata and limited keyword categories;
raw contents, usernames, IP addresses and command lines are not reported.
Usage: powershell.exe -File .\LM-REGTRACE-T1-Registry.ps1
Parameters: -Hours 72 -NoPause -SkipLogContent
#>
[CmdletBinding()]
param(
    [ValidateRange(1,168)][int]$Hours = 72,
    [switch]$NoPause,
    [switch]$SkipLogContent
)

$ErrorActionPreference = 'Continue'
$script:Rows = New-Object 'System.Collections.Generic.List[object]'
$script:Session = ([guid]::NewGuid().ToString('N').Substring(0,8)).ToUpperInvariant()
$script:When = Get-Date
$script:Since = $script:When.AddHours(-$Hours)
$script:Docs = [Environment]::GetFolderPath('MyDocuments')
if ([string]::IsNullOrWhiteSpace($script:Docs)) { $script:Docs = Join-Path $env:USERPROFILE 'Documents' }
$script:ReportDir = Join-Path $script:Docs 'MVS-Lost-Media-T1'
$script:EventDetails = New-Object 'System.Collections.Generic.List[string]'
$script:RobloxFileCount = 0
$script:RobloxReadCount = 0
$script:LogAvailable = $false

function LM-Write([string]$Text = '', [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    Write-Host $Text -ForegroundColor $Color
}
function LM-Section([string]$Text, [int]$Number) {
    LM-Write ''
    LM-Write ('  << {0:00} / {1}' -f $Number, $Text.ToUpperInvariant()) Magenta
    LM-Write ('  ' + ('-' * 69)) DarkCyan
}
function LM-Add([string]$Section, [string]$Name, [string]$Status, [string]$Message) {
    $colors = @{ OK='Green'; REVIEW='Red'; ATENCAO='Yellow'; INFO='Gray'; UNVERIFIED='DarkYellow' }
    $color = 'White'
    if ($colors.ContainsKey($Status)) { $color = $colors[$Status] }
    $display = $Message
    if ($Status -eq 'REVIEW') {
        $prefix = if ($Name -match '(?i)\.exe') { 'ARQUIVO SUSPEITO' } else { 'EVENTO SUSPEITO' }
        $display = $prefix + ' | ' + $Message
    }
    LM-Write ('  [{0,-10}] {1,-28} | {2}' -f $Status,$Name,$display) $color
    [void]$script:Rows.Add([pscustomobject]@{
        Section=$Section; Name=$Name; Status=$Status; Message=$Message
    })
}
function LM-Value([string]$Path, [string]$Name) {
    try {
        if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) {
            return [pscustomobject]@{ State='ABSENT'; Value=$null }
        }
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($key.GetValueNames() -notcontains $Name) {
            return [pscustomobject]@{ State='ABSENT'; Value=$null }
        }
        return [pscustomobject]@{ State='FOUND'; Value=$key.GetValue($Name) }
    } catch {
        return [pscustomobject]@{ State='ERROR'; Value=$null }
    }
}
function LM-DisabledSetting([string]$Label, [string]$Path, [string]$Name) {
    $v = LM-Value $Path $Name
    if ($v.State -eq 'ERROR') { LM-Add 'REGISTRY' $Label 'UNVERIFIED' 'Registro inacessivel.' }
    elseif ($v.State -eq 'ABSENT') { LM-Add 'REGISTRY' $Label 'INFO' 'Politica nao definida.' }
    elseif ([string]$v.Value -eq '1') {
        LM-Add 'REGISTRY' $Label 'ATENCAO' 'Configuracao de desativacao encontrada; verificar contexto.'
    } else { LM-Add 'REGISTRY' $Label 'INFO' ('Valor configurado: '+[string]$v.Value) }
}
function LM-EnabledSetting([string]$Label, [string]$Path, [string]$Name) {
    $v = LM-Value $Path $Name
    if ($v.State -eq 'ERROR') { LM-Add 'REGISTRY' $Label 'UNVERIFIED' 'Registro inacessivel.' }
    elseif ($v.State -eq 'ABSENT') { LM-Add 'REGISTRY' $Label 'INFO' 'Configuracao nao definida.' }
    elseif ([string]$v.Value -eq '1') { LM-Add 'REGISTRY' $Label 'OK' 'Habilitado no registro.' }
    else { LM-Add 'REGISTRY' $Label 'ATENCAO' ('Valor atual: '+[string]$v.Value) }
}
function LM-CheckRegistry {
    LM-Section 'REGISTRO E POLITICAS DE PROTECAO' 1
    $root = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    LM-DisabledSetting 'Defender - DisableAntiSpyware' $root 'DisableAntiSpyware'
    $rt = Join-Path $root 'Real-Time Protection'
    foreach ($setting in @('DisableRealtimeMonitoring','DisableBehaviorMonitoring',
            'DisableOnAccessProtection','DisableIOAVProtection')) {
        LM-DisabledSetting ('Defender - '+$setting) $rt $setting
    }
    LM-EnabledSetting 'UAC' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
    LM-EnabledSetting 'Integridade de memoria' 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled'
    LM-EnabledSetting 'Bloqueio drivers vulneraveis' 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable'
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        foreach($entry in @(
            @{Field='ExclusionPath'; Label='Exclusoes de pastas'},
            @{Field='ExclusionProcess'; Label='Exclusoes de processos'},
            @{Field='ExclusionExtension'; Label='Exclusoes de extensoes'},
            @{Field='ExclusionIpAddress'; Label='Exclusoes de IPs'}
        )) {
            $n = @($pref.($entry.Field) | Where-Object { $null -ne $_ -and ([string]$_).Length -gt 0 }).Count
            if ($n -gt 0) {
                LM-Add 'REGISTRY' $entry.Label 'ATENCAO' ("$n exclusao(oes) configurada(s); revisar intencao.")
            } else { LM-Add 'REGISTRY' $entry.Label 'OK' 'Nenhuma exclusao retornada.' }
        }
    } catch { LM-Add 'REGISTRY' 'Exclusoes Defender' 'UNVERIFIED' 'Consulta indisponivel.' }
    try {
        $runEntries=0
        foreach($regPath in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')) {
            if (Test-Path -LiteralPath $regPath) {
                $key = Get-Item -LiteralPath $regPath -ErrorAction Stop
                $runEntries += @($key.GetValueNames()).Count
            }
        }
        LM-Add 'REGISTRY' 'Inicializacao automatica' 'INFO' ("$runEntries valor(es) Run encontrados; apenas contagem.")
    } catch { LM-Add 'REGISTRY' 'Inicializacao automatica' 'UNVERIFIED' 'Consulta incompleta.' }
}

# Search selected known Roblox/client launcher log directories only; no full disk scan.
function LM-LogRoots {
    $roots = New-Object 'System.Collections.Generic.List[string]'
    foreach ($pair in @(
        @{Base=$env:LOCALAPPDATA; Child='Roblox\logs'},
        @{Base=$env:LOCALAPPDATA; Child='Roblox\Logs'},
        @{Base=$env:LOCALAPPDATA; Child='Bloxstrap\Logs'},
        @{Base=$env:LOCALAPPDATA; Child='Fishstrap\Logs'},
        @{Base=$env:APPDATA; Child='Bloxstrap\Logs'},
        @{Base=$env:APPDATA; Child='Fishstrap\Logs'}
    )) {
        if ([string]::IsNullOrWhiteSpace($pair.Base)) { continue }
        $p = Join-Path $pair.Base $pair.Child
        if ((Test-Path -LiteralPath $p -PathType Container) -and (-not $roots.Contains($p))) {
            [void]$roots.Add($p)
        }
    }
    return $roots.ToArray()
}
function LM-CheckRobloxLogs {
    LM-Section 'ROBLOX - LOGS DO CLIENTE E LAUNCHERS' 2
    $roots = @(LM-LogRoots)
    if ($roots.Count -eq 0) {
        LM-Add 'ROBLOX LOGS' 'Pastas de logs' 'UNVERIFIED' 'Nenhuma pasta conhecida acessivel neste perfil.'
        return
    }
    $uniqueFiles = @{}
    $allFiles = New-Object 'System.Collections.Generic.List[object]'
    foreach($root in $roots) {
        try {
            $found = @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction Stop |
                Where-Object { $_.Extension -in @('.log','.txt') })
            LM-Add 'ROBLOX LOGS' (Split-Path (Split-Path $root -Parent) -Leaf) 'INFO' ("$($found.Count) arquivo(s) de log encontrado(s).")
            foreach($item in $found) {
                if (-not $uniqueFiles.ContainsKey($item.FullName)) {
                    $uniqueFiles[$item.FullName] = $true
                    [void]$allFiles.Add($item)
                }
            }
        } catch {
            LM-Add 'ROBLOX LOGS' 'Leitura de pastas' 'UNVERIFIED' 'Sem acesso a uma pasta de logs.'
        }
    }
    $script:RobloxFileCount = $allFiles.Count
    $script:LogAvailable = $allFiles.Count -gt 0
    if ($allFiles.Count -eq 0) {
        LM-Add 'ROBLOX LOGS' 'Arquivos disponiveis' 'UNVERIFIED' 'Pasta encontrada, mas sem arquivos .log/.txt acessiveis.'
        return
    }
    $latest = @($allFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 500)
    $recent = @($allFiles | Where-Object { $_.LastWriteTime -ge $script:Since })
    $bytes = [long]0
    foreach($file in $allFiles) { $bytes += [long]$file.Length }
    LM-Add 'ROBLOX LOGS' 'Inventario total' 'INFO' ("$($allFiles.Count) arquivo(s), $($recent.Count) atualizado(s) em ${Hours}h; ~"+[math]::Round($bytes/1MB,1)+' MB.')
    if ($allFiles.Count -gt 500) {
        LM-Add 'ROBLOX LOGS' 'Limite de leitura' 'INFO' 'Os 500 logs mais recentes foram priorizados; demais contabilizados.'
    }
    if ($SkipLogContent) {
        LM-Add 'ROBLOX LOGS' 'Conteudo dos logs' 'INFO' 'Leitura opcional ignorada; somente metadados.'
        return
    }
    # Category counts only: never save raw log lines or personal identifiers.
    $categories = @{
        'Integridade / antitamper' = '(?i)\b(tamper(?:ing|ed)?|integrity\s+(?:check|violation|failure)|unauthorized\s+(?:modification|access))\b'
        'Injecao / hook' = '(?i)\b(inject(?:ion|ed|or)?|hook(?:ing|ed)?|remote\s+thread)\b'
        'Executor / exploit' = '(?i)\b(executor|exploit|exploit(?:ing|ed)|cheat(?:ing|er)?)\b'
        'Falhas cliente' = '(?i)\b(crash|unhandled\s+exception|access\s+violation|fatal\s+error)\b'
    }
    $totals=@{}
    foreach($key in $categories.Keys) { $totals[$key]=0 }
    $read = 0; $failed = 0; $truncated = 0
    foreach($file in $latest) {
        try {
            # Read only up to last 512 KiB per file; avoid loading multi-GB logs.
            $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            try {
                $length = [long]$stream.Length
                if($length -gt 524288) {
                    [void]$stream.Seek(-524288,[IO.SeekOrigin]::End)
                    $truncated++
                }
                $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true, 8192, $true)
                try {
                    if ($length -gt 524288) { [void]$reader.ReadLine() }
                    $localHits=@{}
                    foreach($key in $categories.Keys){$localHits[$key]=0}
                    while (-not $reader.EndOfStream) {
                        $line = $reader.ReadLine()
                        if ($null -eq $line) { break }
                        foreach($cat in $categories.Keys) {
                            if ($line -match $categories[$cat]) { $localHits[$cat]++ }
                        }
                    }
                    foreach($cat in $categories.Keys) { $totals[$cat] += $localHits[$cat] }
                    $read++
                } finally { $reader.Dispose() }
            } finally { $stream.Dispose() }
        } catch { $failed++ }
    }
    $script:RobloxReadCount = $read
    LM-Add 'ROBLOX LOGS' 'Arquivos lidos' 'INFO' ("$read lidos, $failed indisponiveis, $truncated amostrados pelo final (512 KiB).")
    foreach ($cat in @('Integridade / antitamper','Injecao / hook','Executor / exploit','Falhas cliente')) {
        $n = [int]$totals[$cat]
        $status = if ($n -gt 0 -and $cat -ne 'Falhas cliente') {'ATENCAO'} else {'INFO'}
        LM-Add 'ROBLOX LOGS' $cat $status ("$n linha(s) com termos relacionados; conferir contexto no log original.")
    }
    if ($failed -gt 0) { LM-Add 'ROBLOX LOGS' 'Falhas de leitura' 'UNVERIFIED' ("$failed arquivo(s) nao puderam ser lidos.") }
}

# Windows event logs: event IDs only, no raw messages or commands.
function LM-ReadEvents([string]$LogName, [int[]]$Ids, [int]$Max = 250) {
    try {
        $meta = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        if (-not $meta.IsEnabled) { return [pscustomobject]@{Status='DISABLED'; Events=@()} }
    } catch { return [pscustomobject]@{Status='UNAVAILABLE'; Events=@()} }
    try {
        $evts = @(Get-WinEvent -FilterHashtable @{
            LogName=$LogName; ID=$Ids; StartTime=$script:Since
        } -MaxEvents $Max -ErrorAction Stop)
        return [pscustomobject]@{Status='OK'; Events=$evts}
    } catch {
        # NoMatchingEventsFound differs from denied access or channel failure.
        $errId = [string]$_.FullyQualifiedErrorId
        if($errId -match 'NoMatchingEventsFound|NoEventsFound') {
            return [pscustomobject]@{Status='OK'; Events=@()}
        }
        return [pscustomobject]@{Status='UNAVAILABLE'; Events=@()}
    }
}
function LM-EventGroup([string]$Label, [string]$LogName, [int[]]$Ids, [int]$Max = 250) {
    $response = LM-ReadEvents $LogName $Ids $Max
    if ($response.Status -ne 'OK') {
        LM-Add 'EVENTOS' $Label 'UNVERIFIED' ('Canal '+$LogName+' indisponivel/desabilitado.')
        return
    }
    $arr=@($response.Events)
    LM-Add 'EVENTOS' $Label 'INFO' ("$($arr.Count) evento(s) em ${Hours}h; IDs: $($Ids -join ','); maximo $Max.")
    foreach($id in $Ids) {
        $count=@($arr | Where-Object {$_.Id -eq $id}).Count
        if($count -gt 0) { [void]$script:EventDetails.Add(('{0}: ID {1} = {2}' -f $Label,$id,$count)) }
    }
}
function LM-XmlFields($Event) {
    $fields = @{}
    try {
        [xml]$xml=$Event.ToXml()
        foreach($n in @($xml.Event.EventData.Data)) {
            if ($null -ne $n.Name) { $fields[[string]$n.Name]=[string]$n.'#text' }
        }
    } catch { }
    return $fields
}
function LM-CheckWindowsEvents {
    LM-Section 'EVENTOS DE SEGURANCA DO WINDOWS' 3
    LM-EventGroup 'Microsoft Defender' 'Microsoft-Windows-Windows Defender/Operational' @(1006,1007,1116,1117,1118,5001,5007) 350
    LM-EventGroup 'Security: processos' 'Security' @(4688,4689) 400
    LM-EventGroup 'Security: log limpo' 'Security' @(1102) 20
    LM-EventGroup 'System: servicos/log' 'System' @(104,7045) 100
    LM-EventGroup 'Code Integrity' 'Microsoft-Windows-CodeIntegrity/Operational' @(3033,3063,3076,3077) 180
    LM-EventGroup 'AppLocker EXE/DLL' 'Microsoft-Windows-AppLocker/EXE and DLL' @(8002,8003,8004) 180
    LM-EventGroup 'PowerShell Operational' 'Microsoft-Windows-PowerShell/Operational' @(4103,4104) 200
    LM-EventGroup 'PowerShell classico' 'Windows PowerShell' @(400,403,600) 120
    LM-EventGroup 'Task Scheduler' 'Microsoft-Windows-TaskScheduler/Operational' @(106,140,200,201) 150
    LM-EventGroup 'Application: erros' 'Application' @(1000,1001,1002) 200
    # Only flag clear-log events as attention, do not assume the reason.
    foreach($spec in @(
        @{Label='Security'; Log='Security'; Ids=@(1102)},
        @{Label='System'; Log='System'; Ids=@(104)}
    )) {
        $r = LM-ReadEvents $spec.Log $spec.Ids 15
        if ($r.Status -eq 'OK' -and @($r.Events).Count -gt 0) {
            LM-Add 'AUDITORIA' ('Log '+$spec.Label+' limpo') 'ATENCAO' ("$(@($r.Events).Count) evento(s) registrado(s) em ${Hours}h.")
        }
    }
}
function LM-CheckSysmon {
    LM-Section 'SYSMON - EVENTOS LIGADOS AO ROBLOX' 4
    # Prioritize direct process-interaction events; high-volume image-load events can
    # otherwise fill the sample before more relevant Roblox evidence is examined.
    $response = LM-ReadEvents 'Microsoft-Windows-Sysmon/Operational' @(8,10,25) 500
    if ($response.Status -ne 'OK') {
        LM-Add 'SYSMON' 'Telemetria' 'UNVERIFIED' 'Sysmon nao disponivel ou log inacessivel.'
        return
    }
    LM-EventGroup 'Sysmon: outros eventos' 'Microsoft-Windows-Sysmon/Operational' @(1,5,7,11,12,13,14,22) 200
    $events=@($response.Events)
    LM-Add 'SYSMON' 'Eventos consultados' 'INFO' ("$($events.Count) evento(s) coletado(s) em ${Hours}h; limite 500.")
    $linked=0; $shown=0
    foreach($ev in $events) {
        $f=LM-XmlFields $ev
        $image=([string]$f['Image'])
        $target=([string]$f['TargetImage'])
        $source=([string]$f['SourceImage'])
        $isRoblox = $image -match '(?i)robloxplayerbeta\.exe$' -or
                    $target -match '(?i)robloxplayerbeta\.exe$' -or
                    $source -match '(?i)robloxplayerbeta\.exe$'
        if (-not $isRoblox) { continue }
        $linked++
        if ($shown -ge 25) { continue }
        $shown++
        $sourceName = [IO.Path]::GetFileName($source)
        if ([string]::IsNullOrWhiteSpace($sourceName)) { $sourceName = '(origem nao informada)' }
        $stamp=$ev.TimeCreated.ToString('MM-dd HH:mm:ss')
        $status='INFO'
        $detail='evento vinculado ao Roblox'
        if ($ev.Id -eq 8) {
            $status='REVIEW'; $detail='criacao de thread remota registrada'
        } elseif ($ev.Id -eq 25) {
            $status='REVIEW'; $detail='evento de alteracao de processo'
        } elseif ($ev.Id -eq 10) {
            $rights=[string]$f['GrantedAccess']; $mask=[long]0; $parsed=$false
            try {
                if ($rights -match '^0x[0-9a-fA-F]+$') {
                    $mask=[Convert]::ToInt64($rights.Substring(2),16); $parsed=$true
                }
            } catch { }
            if ($parsed -and ((($mask -band 0x20) -ne 0) -and (($mask -band 0x8) -ne 0))) {
                $status='REVIEW'; $detail='permissoes VM_WRITE + VM_OPERATION concedidas'
            } elseif ($parsed -and ((($mask -band 0x20) -ne 0) -or (($mask -band 0x10) -ne 0))) {
                $status='ATENCAO'; $detail='acesso a memoria com permissoes relevantes'
            } else { $detail='acesso ao processo registrado' }
        }
        LM-Add 'SYSMON' ('ID '+$ev.Id+' | '+$sourceName) $status ($stamp+' | '+$detail)
    }
    if($linked -eq 0) { LM-Add 'SYSMON' 'Eventos Roblox' 'INFO' 'Nenhum evento relacionado encontrado na amostra.' }
    else { LM-Add 'SYSMON' 'Cobertura Roblox' 'INFO' ("$linked evento(s) relacionados; exibidos $shown.") }
}
function LM-Export {
    LM-Section 'RESULTADO E RELATORIOS' 5
    $ok = @($script:Rows | Where-Object {$_.Status -eq 'OK'}).Count
    $red = @($script:Rows | Where-Object {$_.Status -eq 'REVIEW'}).Count
    $yellow = @($script:Rows | Where-Object {$_.Status -eq 'ATENCAO'}).Count
    $unknown = @($script:Rows | Where-Object {$_.Status -eq 'UNVERIFIED'}).Count
    LM-Write ("  [RESULTADO] OK: $ok | REVIEW: $red | ATENCAO: $yellow | NAO VERIFICADO: $unknown") Cyan
    try {
        if (-not (Test-Path -LiteralPath $script:ReportDir)) {
            [void](New-Item -ItemType Directory -Path $script:ReportDir -Force -ErrorAction Stop)
        }
        $prefix='LM-T1-'+$script:Session+'-REGTRACE'
        $full=Join-Path $script:ReportDir ($prefix+'.txt')
        $discord=Join-Path $script:ReportDir ($prefix+'-DISCORD.txt')
        $lines = New-Object 'System.Collections.Generic.List[string]'
        [void]$lines.Add('MVS LOST MEDIA | REGTRACE T1:02 | BUILD 3.8.0')
        [void]$lines.Add('Sessao: '+$script:Session)
        [void]$lines.Add('Data: '+$script:When.ToString('yyyy-MM-dd HH:mm:ss'))
        [void]$lines.Add("Janela de eventos: $Hours hora(s)")
        [void]$lines.Add('Somente leitura; relatorio salvo localmente.')
        [void]$lines.Add('Roblox: '+$script:RobloxFileCount+' logs encontrados; '+$script:RobloxReadCount+' amostrados.')
        [void]$lines.Add('')
        foreach($row in $script:Rows) {
            [void]$lines.Add(('[{0}] {1} / {2}: {3}' -f $row.Status,$row.Section,$row.Name,$row.Message))
        }
        [void]$lines.Add('')
        [void]$lines.Add("RESUMO: OK=$ok REVIEW=$red ATENCAO=$yellow NAO_VERIFICADO=$unknown")
        $lines.ToArray() | Set-Content -LiteralPath $full -Encoding UTF8 -ErrorAction Stop
        $msg = New-Object 'System.Collections.Generic.List[string]'
        [void]$msg.Add('**MVS LOST MEDIA | T1:02 REGTRACE 3.8**')
        [void]$msg.Add('Sessao: `'+$script:Session+'`')
        [void]$msg.Add("Periodo: ${Hours}h | Roblox logs: $($script:RobloxFileCount) | Amostrados: $($script:RobloxReadCount)")
        [void]$msg.Add("REVIEW: **$red** | ATENCAO: **$yellow** | NAO VERIFICADO: **$unknown**")
        $priority=@($script:Rows | Where-Object {$_.Status -eq 'REVIEW'} | Select-Object -First 5)
        foreach($row in $priority) {
            $item='- SUSPEITO: '+$row.Name+' ('+$row.Section+') - '+$row.Message
            if($item.Length -gt 180) { $item=$item.Substring(0,177)+'...' }
            [void]$msg.Add($item)
        }
        if($priority.Count -eq 0) { [void]$msg.Add('Nenhum alerta prioritario observado.') }
        if($unknown -gt 0) { [void]$msg.Add('Algumas fontes estavam indisponiveis.') }
        [void]$msg.Add('Relatorio completo: salvo localmente para revisao.')
        $msg.ToArray() | Set-Content -LiteralPath $discord -Encoding UTF8 -ErrorAction Stop
        LM-Write ('  [RELATORIO] '+$full) Green
        LM-Write ('  [DISCORD] '+$discord) Green
    } catch { LM-Write ('  [ERRO] Falha ao gravar relatorio: '+$_.Exception.Message) Yellow }
}
function LM-End {
    LM-Write ''
    LM-Write ('  +' + ('-' * 69) + '+') DarkCyan
    LM-Write ('  | ' + 'REGTRACE CONCLUIDO / MVS LOST MEDIA'.PadRight(67) + ' |') Cyan
    LM-Write ('  +' + ('-' * 69) + '+') DarkCyan
    if($NoPause) { return }
    try {
        Start-Sleep -Milliseconds 300
        if ([Console]::IsInputRedirected) { [void](Read-Host '  Pressione ENTER para fechar') }
        else {
            while([Console]::KeyAvailable) { [void][Console]::ReadKey($true) }
            LM-Write '  >> Pressione QUALQUER TECLA para fechar...' Magenta
            [void][Console]::ReadKey($true)
        }
    } catch { [void](Read-Host '  Pressione ENTER para fechar') }
}

Clear-Host
LM-Write ('  +' + ('-' * 69) + '+') DarkCyan
LM-Write ('  | ' + 'LM // TIER ONE'.PadRight(67) + ' |') Cyan
LM-Write ('  | ' + 'REGTRACE / ROBLOX LOGS / WINDOWS EVENTS'.PadRight(67) + ' |') White
LM-Write ('  | ' + ('BUILD 3.8.0   SESSION '+$script:Session).PadRight(67) + ' |') Magenta
LM-Write ('  +' + ('-' * 69) + '+') DarkCyan
LM-Write ('  [LOCAL] Somente leitura, sem envio de dados. Janela: '+$Hours+'h.') DarkGray
LM-CheckRegistry
LM-CheckRobloxLogs
LM-CheckWindowsEvents
LM-CheckSysmon
LM-Export
LM-End
