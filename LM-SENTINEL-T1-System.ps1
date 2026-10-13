#requires -Version 5.1
<#
MVS Lost Media | T1 SYSTEM CHECK | Build 2.11.0
Public, read-only Windows security and process audit.
Investigation tab shows only initial executable sample and Roblox, not injected code.
Defender history counts are limited and cannot establish a clean/compromised machine.
No external connections made by the script, no automatic elevation or system changes.
Only creates local reports and an optional aggregate-only comparison snapshot.
Unsigned files or other observations are NOT proof of cheating.

Options:
  -ShowDetails             Displays names of unsigned/unverifiable executables locally.
                           Names/paths are NEVER saved to reports.
  -MaxSignatureChecks 100  Maximum distinct readable executables checked (20..200).
  -NoHistory               Does not read or write the previous-run aggregate snapshot.
  -NoViewer                Skips the read-only visual inspection window.
  -NoPause                 Skips the ENTER prompt before the visual panel.
#>
[CmdletBinding()]
param(
    [switch]$ShowDetails,
    [ValidateRange(20,200)][int]$MaxSignatureChecks = 100,
    [switch]$NoHistory,
    [switch]$NoViewer,
    [switch]$NoPause
)

$ErrorActionPreference = 'Continue'
$script:Session = ([guid]::NewGuid().ToString('N').Substring(0,8)).ToUpperInvariant()
$script:StartedAt = Get-Date
$script:Started = $script:StartedAt.ToString('yyyy-MM-dd HH:mm:ss')
$script:Checks = New-Object 'System.Collections.Generic.List[object]'
$script:CheckIndex = 0
$script:GuiProcesses = @()
$script:GuiSignatureMap = @{}
$script:GuiReady = $false
$script:QuietAudit = $true
$script:LastProgressLength = 0
$script:GuiReviewItems = @()
# Baseline kept only in memory: used to compare the first process snapshot with
# subsequent manual refreshes in the Roblox inspection tab. Never persisted.
$script:BaselineProcessKeys = @{}
$script:GuiRobloxCount = 0
$script:GuiNewCount = 0
# Local-only data: never written to TXT, JSON or Discord reports.
$script:InvestigationPaths = @{}
$script:DefenderRecentCount = -1
$script:DefenderEntriesChecked = 0
$script:DefenderSummary = 'Consulta ainda nao executada.'
# Telemetria do Windows ja existente. Nunca ativa auditoria nem instala Sysmon.
# Linhas de comando, contas, enderecos e caminhos completos nao sao mostrados ou salvos.
$script:TimelineRows = @()
$script:AccessRows = @()
$script:ParentRows = @()
$script:TimelineSource = 'Nenhuma fonte de eventos disponivel.'
$script:AccessSource = 'Sysmon indisponivel ou sem eventos de interesse.'
$script:EventWindowMinutes = 45
$script:EventReadLimit = 250
$script:SysmonProcessEventsRead = 0
$script:SysmonInteractionEventsRead = 0
$script:SysmonRobloxEvents = 0
# Dados resumidos em memoria, sem enderecos de rede ou linhas de comando.
$script:RecentRows = @()
$script:NetworkRows = @()
$script:CoverageRows = @()
$script:NetworkSource = 'Consulta ainda nao executada.'
$script:ActivitySource = 'Consulta ainda nao executada.'
# Etapas opcionais, somente leitura. Informacoes detalhadas ficam na janela.
$script:CaptureRows = @()
$script:TaskRows = @()
$script:CodeIntegrityRows = @()
$script:CaptureSource = 'Consulta ainda nao executada.'
$script:TaskSource = 'Consulta ainda nao executada.'
$script:CodeIntegritySource = 'Consulta ainda nao executada.'


$script:Stats = [ordered]@{
    ProcessCount = -1
    RobloxRunning = $false
    UniqueReadable = 0
    Inspected = 0
    SignedValid = 0
    Unsigned = 0
    OtherSignature = 0
    PathUnavailable = 0
}

function Say([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    Write-Host $Message -ForegroundColor $Color
}
function Write-LMIntro {
    Clear-Host
    Say ''
    Say '  +------------------------------------------------------------------+' DarkCyan
    Say '  |                                                                  |' DarkCyan
    Say '  |             MVS LOST MEDIA  |  T1 RECORDING POLICY               |' Cyan
    Say '  |                                                                  |' DarkCyan
    Say '  |                       _       __  __                             |' Cyan
    Say '  |                      | |     |  \/  |                            |' Cyan
    Say '  |                      | |     | |\/| |                            |' Cyan
    Say '  |                      | |___  | |  | |                            |' Cyan
    Say '  |                      |_____| |_|  |_|                            |' Cyan
    Say '  |                                                                  |' DarkCyan
    Say '  |     SYSTEM CHECK  /  BUILD 2.11.0  /  SOMENTE LEITURA               |' White
    Say '  |                                                                  |' DarkCyan
    Say '  +------------------------------------------------------------------+' DarkCyan
    Say '  Servidor: MVS Lost Media | Dono: Mangaka' Gray
    Say ('  Sessao: ' + $script:Session + ' | ' + $script:Started) DarkGray
    Say '  Nenhum arquivo pessoal e enviado. Nenhum alerta prova cheats.' DarkGray
    Say ''
    Say '  VERIFICANDO SEU PC' Cyan
}
function Write-LMProgress([int]$Percent,[string]$Step) {
    $count = [int][Math]::Floor(([Math]::Max(0,[Math]::Min(100,$Percent)) * 26) / 100)
    $bar = ('#' * $count) + ('.' * (26-$count))
    $line = ('  Verification [{0}] {1,3}%  {2}' -f $bar,$Percent,$Step)
    $padded = $line.PadRight([Math]::Max($script:LastProgressLength,$line.Length))
    $script:LastProgressLength = $padded.Length
    Write-Host ("`r" + $padded) -NoNewline -ForegroundColor Cyan
    if ($Percent -ge 100) { Write-Host '' }
}
function Write-LMSection([string]$Id,[string]$Heading) {
    if ($script:QuietAudit) { return }
    Write-Host ''
    Say ('  [' + $Id + ']  ' + $Heading.ToUpperInvariant()) Cyan
    Say '  --------------------------------------------------------------' DarkGray
}
function Check([string]$Label,[string]$State,[string]$Explanation) {
    $script:CheckIndex++
    $color = switch ($State) {
        'OK'     { [ConsoleColor]::Green }
        'REVIEW' { [ConsoleColor]::Yellow }
        default  { [ConsoleColor]::DarkGray }
    }
    if (-not $script:QuietAudit) {
        Write-Host ('  {0:00}  ' -f $script:CheckIndex) -NoNewline -ForegroundColor DarkGray
        Write-Host ('[{0,-6}] ' -f $State) -NoNewline -ForegroundColor $color
        Write-Host ($Label + ' | ' + $Explanation)
    }
    [void]$script:Checks.Add([pscustomobject]@{
        Label=$Label; State=$State; Explanation=$Explanation
    })
}
function SignatureStatus([string]$Location) {
    try {
        $r = Get-AuthenticodeSignature -LiteralPath $Location -ErrorAction Stop
        return [string]$r.Status
    } catch { return 'Unavailable' }
}
function WinStatus([string]$Name, $Value) {
    if ($null -eq $Value) { Check $Name 'INFO' 'Estado nao informado pelo Windows.' }
    elseif ($Value -eq $true) { Check $Name 'OK' 'Habilitado.' }
    else { Check $Name 'REVIEW' 'Estado desabilitado; exige verificacao de contexto.' }
}

function Get-LMEventFields($EventRecord) {
    # Os eventos XML contêm campos sensiveis que NAO sao exibidos ou gravados.
    # Somente os campos explicitamente selecionados sao usados, e caminhos
    # completos sao reduzidos aos nomes dos executaveis.
    $fields = @{}
    try {
        [xml]$doc = $EventRecord.ToXml()
        $nodes = $doc.GetElementsByTagName('Data')
        foreach ($node in $nodes) {
            $name = [string]$node.GetAttribute('Name')
            if ($name -and $name -in @('Image','ParentImage','SourceImage','TargetImage','NewProcessName','ParentProcessName','GrantedAccess','Type','NewProcessId','ProcessId')) {
                $fields[$name] = [string]$node.InnerText
            }
        }
    } catch { }
    return $fields
}
function Get-LMAccessRights([string]$GrantedAccess) {
    # Sysmon ID 10: bits representam PERMISSOES concedidas na abertura
    # do processo. Nao comprovam leitura, escrita nem injeção efetivas.
    $result = [pscustomobject]@{ Mask='Indisponivel'; Rights='Nao informado' }
    try {
        $valueText = $GrantedAccess.Trim()
        if ($valueText -notmatch '(?i)^0x[0-9a-f]{1,8}$') { return $result }
        $value = [Convert]::ToUInt32($valueText.Substring(2),16)
        $names = New-Object 'System.Collections.Generic.List[string]'
        if (($value -band [uint32]0x10) -ne 0) { [void]$names.Add('VM_READ') }
        if (($value -band [uint32]0x20) -ne 0) { [void]$names.Add('VM_WRITE') }
        if (($value -band [uint32]0x08) -ne 0) { [void]$names.Add('VM_OPERATION') }
        if (($value -band [uint32]0x02) -ne 0) { [void]$names.Add('CREATE_THREAD') }
        if ($names.Count -eq 0) { [void]$names.Add('Outras permissoes') }
        $result.Mask = ('0x{0:X}' -f $value)
        $result.Rights = ($names.ToArray() -join ', ')
    } catch { }
    return $result
}

function Get-LMFileLabel([string]$FullPath) {
    if ([string]::IsNullOrWhiteSpace($FullPath)) { return '-' }
    try { return [IO.Path]::GetFileName($FullPath.Trim('"')) } catch { return '-' }
}
function Get-LMParentRows {
    # Foto instantanea; parent PIDs podem ser reutilizados.
    $result = New-Object 'System.Collections.Generic.List[object]'
    try {
        $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop)
        $byId = @{}
        foreach ($pr in $procs) { $byId[[string]$pr.ProcessId] = [string]$pr.Name }
        foreach ($pr in $procs) {
            $parentPid = [string]$pr.ParentProcessId
            $parentName = if ($byId.ContainsKey($parentPid)) { $byId[$parentPid] } else { 'Nao identificado' }
            [void]$result.Add([pscustomobject]@{
                Processo = [string]$pr.Name
                PID = [string]$pr.ProcessId
                Pai = $parentName
                PID_Pai = $parentPid
            })
        }
    } catch { }
    return $result.ToArray()
}
function Invoke-LMEventAudit {
    # Consultas passivas, apenas aos logs JA existentes. Nao habilita Sysmon.
    # O limite por consulta nao garante cobertura total; um resultado vazio
    # nunca significa que nao houve acesso ou manipulacao.
    $script:TimelineRows = @()
    $script:AccessRows = @()
    $script:ParentRows = @(Get-LMParentRows)
    $script:SysmonProcessEventsRead = 0
    $script:SysmonInteractionEventsRead = 0
    $script:SysmonRobloxEvents = 0
    $cutoff = (Get-Date).AddMinutes(-$script:EventWindowMinutes)
    $timeline = New-Object 'System.Collections.Generic.List[object]'
    $access = New-Object 'System.Collections.Generic.List[object]'
    $sysmonOk = $false
    try {
        $log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
        if ($log.IsEnabled) { $sysmonOk = $true }
    } catch { }
    if ($sysmonOk) {
        $script:TimelineSource = 'Sysmon 1 quando previamente registrado; consulta limitada.'
        $script:AccessSource = 'Sysmon 8/10/25: somente eventos observados na amostra.'
        # Ler eventos 1 e 8/10/25 SEPARADAMENTE evita que muitos eventos 1
        # esgotem o limite antes dos eventos relacionados ao Roblox.
        try {
            $evts1 = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1;StartTime=$cutoff} -MaxEvents $script:EventReadLimit -ErrorAction Stop)
            $script:SysmonProcessEventsRead = $evts1.Count
            foreach ($evt in $evts1) {
                if ($timeline.Count -ge 100) { break }
                $field = Get-LMEventFields $evt
                [void]$timeline.Add([pscustomobject]@{
                    Hora=$evt.TimeCreated.ToString('HH:mm:ss'); Fonte='Sysmon 1'
                    Processo=(Get-LMFileLabel ([string]$field['Image']))
                    Pai=(Get-LMFileLabel ([string]$field['ParentImage']))
                })
            }
        } catch {
            $script:TimelineSource = 'Sysmon: consulta de criacao de processos sem resultados acessiveis.'
        }
        try {
            $evtsX = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=@(8,10,25);StartTime=$cutoff} -MaxEvents $script:EventReadLimit -ErrorAction Stop)
            $script:SysmonInteractionEventsRead = $evtsX.Count
            foreach ($evt in $evtsX) {
                if ($access.Count -ge 80) { break }
                $field = Get-LMEventFields $evt
                # ID 25 descreve a imagem do proprio processo alterado;
                # IDs 8 e 10 descrevem origem e destino separadamente.
                $target = if ($evt.Id -eq 25) {
                    Get-LMFileLabel ([string]$field['Image'])
                } else {
                    Get-LMFileLabel ([string]$field['TargetImage'])
                }
                if ($target -notmatch '(?i)^RobloxPlayerBeta(\.exe)?$') { continue }
                $script:SysmonRobloxEvents++
                $kind = ''
                $mask = '-'
                $rights = '-'
                $source = '-'
                $note = ''
                switch ([int]$evt.Id) {
                    8 {
                        $kind = 'Thread remota (8)'
                        $source = Get-LMFileLabel ([string]$field['SourceImage'])
                        $note = 'Thread registrada; revisar contexto'
                    }
                    10 {
                        $kind = 'Acesso (10)'
                        $source = Get-LMFileLabel ([string]$field['SourceImage'])
                        $decoded = Get-LMAccessRights ([string]$field['GrantedAccess'])
                        $mask = [string]$decoded.Mask
                        $rights = [string]$decoded.Rights
                        $note = 'Direitos concedidos; nao comprova uso'
                    }
                    25 {
                        $kind = 'Alteracao (25)'
                        $note = 'Alteracao de imagem; investigar contexto'
                        $rawType = [string]$field['Type']
                        if ($rawType -match '^\d{1,3}$') { $rights = 'Tipo ' + $rawType }
                    }
                }
                [void]$access.Add([pscustomobject]@{
                    Hora=$evt.TimeCreated.ToString('HH:mm:ss')
                    Evento=$kind
                    Origem=$source
                    Destino=$target
                    Mascara=$mask
                    Permissoes=$rights
                    Nota=$note
                })
            }
        } catch {
            $script:AccessSource = 'Sysmon presente, mas eventos 8/10/25 nao acessiveis na consulta.'
        }
    } else {
        $script:TimelineSource = 'Sysmon nao disponivel; tentando auditoria nativa 4688.'
        $script:AccessSource = 'Sysmon nao disponivel; nao ha telemetria de acesso entre processos.'
    }
    if ($timeline.Count -eq 0) {
        try {
            $events4688 = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=$cutoff} -MaxEvents $script:EventReadLimit -ErrorAction Stop)
            foreach ($evt in $events4688) {
                if ($timeline.Count -ge 100) { break }
                $field = Get-LMEventFields $evt
                [void]$timeline.Add([pscustomobject]@{
                    Hora=$evt.TimeCreated.ToString('HH:mm:ss'); Fonte='Windows 4688'
                    Processo=(Get-LMFileLabel ([string]$field['NewProcessName']))
                    Pai=(Get-LMFileLabel ([string]$field['ParentProcessName']))
                })
            }
            $script:TimelineSource = 'Windows 4688 (somente se auditoria ja estava habilitada).'
        } catch {
            $script:TimelineSource = 'Criacao de processos: nenhuma fonte legivel nesta consulta.'
        }
    }
    $script:TimelineRows = $timeline.ToArray()
    $script:AccessRows = $access.ToArray()
    Check 'Eventos de processos' 'INFO' ("$($script:TimelineRows.Count) eventos para consulta visual; fonte: $script:TimelineSource")
    Check 'Acessos observados ao Roblox' 'INFO' ("$($script:AccessRows.Count) eventos 8/10/25 na amostra. Sem evento NAO significa ausencia de cheat; $script:AccessSource")
    Check 'Relacoes de processos' 'INFO' ("$($script:ParentRows.Count) processos com PID pai na leitura atual; PIDs podem ser reutilizados.")
}

function Get-LMRecentProcessRows {
    # Somente processos ativos com data de inicio acessivel, janela de 60 minutos.
    # Nao coleta argumentos de linha de comando nem historico de arquivos.
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $now = Get-Date
    try {
        $ps = @(Get-Process -ErrorAction Stop)
        foreach ($proc in $ps) {
            $start = $null
            try { $start = [datetime]$proc.StartTime } catch { continue }
            if ($start -lt $now.AddMinutes(-60) -or $start -gt $now.AddMinutes(5)) { continue }
            $mins = [int][Math]::Max(0, [Math]::Floor(($now-$start).TotalMinutes))
            [void]$entries.Add([pscustomobject]@{
                Inicio=$start.ToString('HH:mm:ss')
                Processo=[string]$proc.ProcessName
                PID=[string]$proc.Id
                Minutos=$mins.ToString()
                Nota='Ativo no instante da consulta'
            })
        }
    } catch { }
    return @($entries.ToArray() | Sort-Object Inicio -Descending | Select-Object -First 100)
}

function Get-LMNetworkSummaryRows {
    # Resumo de conexoes TCP ESTABLISHED, sem IP, DNS, portas ou URLs.
    # Nao cria conexoes: somente consulta o sistema local.
    $groups = @{}
    $out = New-Object 'System.Collections.Generic.List[object]'
    try {
        $procLookup = @{}
        foreach ($proc in @(Get-Process -ErrorAction SilentlyContinue)) {
            $procLookup[[string]$proc.Id] = [string]$proc.ProcessName
        }
        foreach ($conn in @(Get-NetTCPConnection -State Established -ErrorAction Stop)) {
            $pidKey = [string]$conn.OwningProcess
            if (-not $groups.ContainsKey($pidKey)) { $groups[$pidKey] = 0 }
            $groups[$pidKey]++
        }
        foreach ($key in $groups.Keys) {
            $name = if ($procLookup.ContainsKey($key)) { $procLookup[$key] } else { 'Nao identificado' }
            [void]$out.Add([pscustomobject]@{
                Processo = $name
                PID = $key
                TCP_ativas = [string]$groups[$key]
                Nota = 'Conexoes comuns nao indicam cheat'
            })
        }
        $script:NetworkSource = 'Conexoes TCP Established por PID; sem destinos ou portas.'
    } catch {
        $script:NetworkSource = 'Consulta de conexoes indisponivel (' + $_.Exception.GetType().Name + ').'
    }
    return @($out.ToArray() | Sort-Object { [int]$_.TCP_ativas } -Descending | Select-Object -First 100)
}

function Invoke-LMExtraAudit {
    # Cobertura explicita: falta de logs nao conta como equipamento aprovado.
    $script:RecentRows = @(Get-LMRecentProcessRows)
    $script:ActivitySource = 'Processos ainda abertos, iniciados nos ultimos 60 minutos.'
    $script:NetworkRows = @(Get-LMNetworkSummaryRows)
    $cover = New-Object 'System.Collections.Generic.List[object]'
    $sysmon = 'Nao disponivel'
    try {
        $syslog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
        if ($syslog.IsEnabled) { $sysmon = 'Log ativo; eventos dependem de filtros' }
        else { $sysmon = 'Log desabilitado' }
    } catch { $sysmon = 'Nao encontrado ou sem acesso' }
    [void]$cover.Add([pscustomobject]@{ Fonte='Sysmon'; Estado=$sysmon; Limite='Sem Sysmon, nao ha IDs 8/10/25' })
    $security = 'Nao disponivel'
    try {
        $seclog = Get-WinEvent -ListLog Security -ErrorAction Stop
        if ($seclog.IsEnabled) { $security = 'Log ativo; 4688 depende de auditoria' }
        else { $security = 'Log desabilitado' }
    } catch { $security = 'Sem permissao ou consulta indisponivel' }
    [void]$cover.Add([pscustomobject]@{ Fonte='Security / 4688'; Estado=$security; Limite='Log ativo nao garante eventos 4688' })
    [void]$cover.Add([pscustomobject]@{ Fonte='Linha do tempo'; Estado=[string]$script:TimelineSource; Limite='Ultimos 45 min, ate 250 eventos' })
    [void]$cover.Add([pscustomobject]@{ Fonte='Acesso ao Roblox'; Estado=[string]$script:AccessSource; Limite='Direitos concedidos nao provam leitura ou escrita' })
    [void]$cover.Add([pscustomobject]@{ Fonte='Sysmon 1'; Estado=([string]$script:SysmonProcessEventsRead + ' registros na amostra'); Limite='Ate 250 eventos consultados, se configurado' })
    [void]$cover.Add([pscustomobject]@{ Fonte='Sysmon 8/10/25'; Estado=([string]$script:SysmonInteractionEventsRead + ' registros consultados; ' + [string]$script:SysmonRobloxEvents + ' com alvo Roblox'); Limite='Ate 250 eventos, filtro posterior, nao exaustivo' })
    [void]$cover.Add([pscustomobject]@{ Fonte='Atividade'; Estado=[string]$script:ActivitySource; Limite='Somente processos ainda abertos' })
    [void]$cover.Add([pscustomobject]@{ Fonte='Rede'; Estado=[string]$script:NetworkSource; Limite='Sem IP, DNS, portas ou conteudo' })
    [void]$cover.Add([pscustomobject]@{ Fonte='Assinaturas'; Estado=([string]$script:Stats.Inspected + ' executaveis analisados'); Limite='Assinatura valida nao prova ausencia de cheat' })
    $script:CoverageRows = $cover.ToArray()
    Check 'Atividade recente' 'INFO' ("$($script:RecentRows.Count) processos ainda ativos iniciados nos ultimos 60 minutos; nao inclui processos ja encerrados.")
    Check 'Rede TCP' 'INFO' ("$($script:NetworkRows.Count) processos com conexoes TCP ativas nesta consulta; nenhum destino coletado. $script:NetworkSource")
    Check 'Cobertura de auditoria' 'INFO' 'Ver aba COBERTURA para fontes presentes, ausentes e limites; falta de dados nao significa aprovacao.'
}


function Get-LMCaptureRows {
    # Aplicativos conhecidos em execucao. A presenca nao comprova gravacao ativa.
    $items = New-Object 'System.Collections.Generic.List[object]'
    $found = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    try {
        foreach ($proc in @(Get-Process -ErrorAction Stop)) {
            $name = [string]$proc.ProcessName
            $app = $null
            if ($name -match '(?i)^obs(64|32)$') { $app = 'OBS Studio' }
            elseif ($name -match '(?i)^NVIDIA Share$') { $app = 'NVIDIA Share' }
            elseif ($name -match '(?i)^Medal$') { $app = 'Medal' }
            if ($null -eq $app) { continue }
            $key = $app + '|' + [string]$proc.Id
            if (-not $found.Add($key)) { continue }
            [void]$items.Add([pscustomobject]@{
                Aplicativo = $app
                Processo = $name
                PID = [string]$proc.Id
                Estado = 'Executando; gravacao NAO confirmada'
            })
        }
        $script:CaptureSource = 'Detecta somente aplicativos reconhecidos em execucao, nao confirma gravacao ou qualidade.'
    } catch { $script:CaptureSource = 'Consulta de programas de captura indisponivel.' }
    if ($items.Count -eq 0) {
        [void]$items.Add([pscustomobject]@{
            Aplicativo='Nao encontrado na amostra'; Processo='-'; PID='-'
            Estado='Nao significa que nenhuma gravacao existe'
        })
    }
    return $items.ToArray()
}

function Get-LMTaskRows {
    # Nomes de tarefas locais: nao le argumentos, acoes, usuarios ou credenciais.
    # Informacoes podem identificar preferencias; nunca salva os nomes.
    $items = New-Object 'System.Collections.Generic.List[object]'
    $number = 0
    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
            $path = [string]$task.TaskPath
            if ($path.StartsWith('\Microsoft\',[StringComparison]::OrdinalIgnoreCase)) { continue }
            $number++
            if ($items.Count -ge 80) { continue }
            [void]$items.Add([pscustomobject]@{
                Tarefa = [string]$task.TaskName
                Estado = [string]$task.State
                Escopo = 'Fora de Microsoft'
                Nota = 'Legitima ate prova em contrario'
            })
        }
        $script:TaskSource = "$number tarefa(s) fora da area Microsoft; ate 80 nomes locais. Nao foram lidas acoes."
    } catch {
        $script:TaskSource = 'Agendador de tarefas nao pode ser consultado.'
    }
    if ($items.Count -eq 0) {
        [void]$items.Add([pscustomobject]@{
            Tarefa='Nenhuma entrada nesta consulta'; Estado='-'
            Escopo='-'; Nota='Ausencia de registros nao demonstra seguranca'
        })
    }
    return $items.ToArray()
}

function Get-LMCodeIntegrityRows {
    # Eventos de diagnostico do Windows; nao comprovam uso de cheats.
    # Nao extrai Message, caminhos de executaveis ou dados pessoais.
    $items = New-Object 'System.Collections.Generic.List[object]'
    $logName = 'Microsoft-Windows-CodeIntegrity/Operational'
    try {
        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
        if (-not $log.IsEnabled) {
            $script:CodeIntegritySource = 'Log de integridade de codigo desabilitado.'
        } else {
            $script:CodeIntegritySource = 'Log ativo; amostra dos ultimos 60 minutos (ate 100 eventos).'
            $cutoff = (Get-Date).AddMinutes(-60)
            try {
                $evts = @(Get-WinEvent -FilterHashtable @{
                    LogName=$logName; StartTime=$cutoff
                } -MaxEvents 100 -ErrorAction Stop)
                foreach ($evt in $evts) {
                    [void]$items.Add([pscustomobject]@{
                        Hora = $evt.TimeCreated.ToString('HH:mm:ss')
                        Evento = [string]$evt.Id
                        Nivel = [string]$evt.LevelDisplayName
                        Observacao = 'Evento de integridade; contexto necessario'
                    })
                }
            } catch {
                $script:CodeIntegritySource = 'Log ativo; nenhum evento legivel na janela consultada.'
            }
        }
    } catch { $script:CodeIntegritySource = 'Log nao encontrado ou sem permissao.' }
    if ($items.Count -eq 0) {
        [void]$items.Add([pscustomobject]@{
            Hora='-'; Evento='-'; Nivel='INFO'; Observacao=$script:CodeIntegritySource
        })
    }
    return $items.ToArray()
}

function Invoke-LMAdditionalStages {
    $script:CaptureRows = @(Get-LMCaptureRows)
    $script:TaskRows = @(Get-LMTaskRows)
    $script:CodeIntegrityRows = @(Get-LMCodeIntegrityRows)
    Check 'Captura e gravacao' 'INFO' $script:CaptureSource
    Check 'Tarefas agendadas' 'INFO' $script:TaskSource
    Check 'Integridade de codigo (eventos)' 'INFO' $script:CodeIntegritySource
    # Adiciona as fontes da v2.11 no quadro de cobertura anterior.
    $script:CoverageRows = @($script:CoverageRows) + @(
        [pscustomobject]@{Fonte='Captura';Estado=$script:CaptureSource;Limite='Programa aberto nao confirma gravacao 60 FPS/720p'}
        [pscustomobject]@{Fonte='Tarefas';Estado=$script:TaskSource;Limite='Somente tarefas fora de Microsoft; nomes apenas locais'}
        [pscustomobject]@{Fonte='Code Integrity';Estado=$script:CodeIntegritySource;Limite='Eventos nao sao provas de cheat'}
    )
}

function Open-LMVisualInspector {
    # Local, read-only WinForms inspection. Detailed names are not written to reports.
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    } catch {
        Say ('  Windows Forms nao abriu: ' + $_.Exception.GetType().Name) Yellow
        Check 'Janela visual' 'INFO' ('Windows Forms nao abriu: ' + $_.Exception.GetType().Name + '.')
        return
    }

    $window = $null
    try {
        function script:Get-LMProcessRows {
            param([object[]]$Items)
            $out = New-Object 'System.Collections.Generic.List[object]'
            foreach ($proc in $Items) {
                $path = $null
                try { $path = $proc.Path } catch { }
                $signature = 'Nao verificada'
                if ([string]::IsNullOrWhiteSpace($path)) { $signature = 'Caminho indisponivel' }
                elseif ($script:GuiSignatureMap.ContainsKey($path)) {
                    $signature = switch ($script:GuiSignatureMap[$path]) {
                        'Valid' { 'Valida' }
                        'NotSigned' { 'Sem assinatura' }
                        default { 'Outro estado' }
                    }
                }
                $ram = '-'
                try { $ram = [string][Math]::Round($proc.WorkingSet64 / 1MB) } catch { }
                [void]$out.Add([pscustomobject]@{
                    Processo = [string]$proc.ProcessName
                    PID = [string]$proc.Id
                    RAM_MB = $ram
                    Assinatura = $signature
                })
            }
            return @($out.ToArray() | Sort-Object Processo, PID)
        }

        function script:Get-LMServiceRows {
            try {
                return @(Get-Service -ErrorAction Stop | Sort-Object Name | ForEach-Object {
                    [pscustomobject]@{
                        Servico = [string]$_.Name
                        Descricao = [string]$_.DisplayName
                        Estado = [string]$_.Status
                    }
                })
            } catch { return @() }
        }

        function script:Get-LMDriverRows {
            # Win32_SystemDriver reports service/driver state. Some drivers use catalog signatures:
            # Get-AuthenticodeSignature on a .sys file alone is not conclusive.
            $out = New-Object 'System.Collections.Generic.List[object]'
            $checked = 0
            try {
                $items = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | Sort-Object Name)
                foreach ($driver in $items) {
                    $signature = 'Nao verificada'
                    $path = [string]$driver.PathName
                    $location = $null
                    if ($path -match '(?i)([a-z]:\\[^"\r\n]+?\.sys|\\SystemRoot\\[^"\r\n]+?\.sys|System32\\[^"\r\n]+?\.sys)') {
                        $location = [string]$Matches[1]
                        if ($location.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
                            $location = Join-Path $env:SystemRoot ($location.Substring(12))
                        } elseif ($location.StartsWith('System32\', [StringComparison]::OrdinalIgnoreCase)) {
                            $location = Join-Path $env:SystemRoot $location
                        }
                    }
                    if ($checked -lt 60 -and $location -and [IO.File]::Exists($location)) {
                        $checked++
                        $signature = switch (SignatureStatus $location) {
                            'Valid' { 'Valida' }
                            'NotSigned' { 'Nao encontrada*' }
                            default { 'Indisponivel*' }
                        }
                    }
                    [void]$out.Add([pscustomobject]@{
                        Driver = [string]$driver.Name
                        Estado = [string]$driver.State
                        Inicio = [string]$driver.StartMode
                        Assinatura = $signature
                    })
                }
            } catch { return @() }
            $script:GuiDriverSignaturesChecked = $checked
            # WinPS 5.1: converte List[object] em object[] antes de retornar.
            return $out.ToArray()
        }

        function script:Get-LMStartupRows {
            try {
                return @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop | Sort-Object Name | ForEach-Object {
                    $origin = [string]$_.Location
                    $source = if ($origin -match '(?i)startup') { 'Pasta Inicializar' }
                        elseif ($origin -match '(?i)HKLM|HKCU|registry|run') { 'Registro Windows' }
                        else { 'Outra origem' }
                    [pscustomobject]@{ Programa = [string]$_.Name; Origem = $source }
                })
            } catch { return @() }
        }

        function script:Get-LMReviewRows {
            $out = New-Object 'System.Collections.Generic.List[object]'
            foreach ($entry in $script:GuiReviewItems) {
                # Avoid generic constructor overload binding issues in Windows PowerShell 5.1.
                $names = @(
                    foreach ($proc in $script:GuiProcesses) {
                        try {
                            if ($proc.Path -and [string]::Equals([string]$proc.Path, [string]$entry.Path, [StringComparison]::OrdinalIgnoreCase)) {
                                [string]$proc.ProcessName
                            }
                        } catch { }
                    }
                ) | Sort-Object -Unique | Select-Object -First 3
                $processNames = if (@($names).Count -gt 0) { (@($names) -join ', ') } else { 'Indisponivel' }
                $result = switch ([string]$entry.Signature) {
                    'NotSigned' { 'Sem assinatura' }
                    default { [string]$entry.Signature }
                }
                [void]$out.Add([pscustomobject]@{
                    Arquivo = [string]$entry.File
                    Processo = $processNames
                    Situacao = $result
                })
            }
            return @($out.ToArray() | Sort-Object Arquivo)
        }


        function script:Get-LMRobloxRows {
            param([object[]]$Items)
            # Roblox and processes first seen after the initial scan. A new
            # process is NOT necessarily linked to Roblox, nor evidence of cheats.
            $out = New-Object 'System.Collections.Generic.List[object]'
            $robloxCount = 0
            $newCount = 0
            foreach ($proc in $Items) {
                $name = [string]$proc.ProcessName
                $pidString = [string]$proc.Id
                $identity = $pidString + '|' + $name.ToLowerInvariant()
                $isRoblox = ($name -eq 'RobloxPlayerBeta')
                $isNew = (-not $script:BaselineProcessKeys.ContainsKey($identity))
                if ($isRoblox) { $robloxCount++ }
                if ($isNew) { $newCount++ }
                if (-not $isRoblox -and -not $isNew) { continue }

                $path = $null
                try { $path = [string]$proc.Path } catch { }
                $signature = 'Nao verificada'
                if ([string]::IsNullOrWhiteSpace($path)) {
                    $signature = 'Caminho indisponivel'
                } elseif ($script:GuiSignatureMap.ContainsKey($path)) {
                    $signature = switch ([string]$script:GuiSignatureMap[$path]) {
                        'Valid' { 'Valida' }
                        'NotSigned' { 'Sem assinatura' }
                        default { 'Outro estado' }
                    }
                } elseif ($isRoblox) {
                    # Inspect Roblox on refresh even if it was launched after the
                    # first scan. Other new processes are NOT signed automatically.
                    $status = SignatureStatus $path
                    $script:GuiSignatureMap[$path] = $status
                    $signature = switch ($status) {
                        'Valid' { 'Valida' }
                        'NotSigned' { 'Sem assinatura' }
                        default { 'Indisponivel' }
                    }
                }

                $type = if ($isRoblox) { 'ROBLOX' } else { 'NOVO' }
                if ($isRoblox) {
                    $ram = '-'
                    try { $ram = ([Math]::Round($proc.WorkingSet64 / 1MB)).ToString() } catch { }
                    $observation = 'RAM: ' + $ram + ' MB'
                } else {
                    $observation = 'Novo desde a primeira consulta*'
                }
                [void]$out.Add([pscustomobject]@{
                    Tipo = $type
                    Processo = $name
                    PID = $pidString
                    Assinatura = $signature
                    Observacao = $observation
                })
            }
            $script:GuiRobloxCount = $robloxCount
            $script:GuiNewCount = $newCount
            if ($out.Count -eq 0) {
                [void]$out.Add([pscustomobject]@{
                    Tipo='INFO'; Processo='Nenhum Roblox ou novo processo'
                    PID='-'; Assinatura='-'; Observacao='Clique Atualizar listas'
                })
            }
            return $out.ToArray()
        }


        function script:Get-LMInvestigationRows {
            # A focused view of the initial executable sample. Only unsigned /
            # unverifiable items and the Roblox executable are included.
            # CompanyName is supplied by the executable and is NOT trusted proof.
            $out = New-Object 'System.Collections.Generic.List[object]'
            $script:InvestigationPaths = @{}
            $observed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $items = New-Object 'System.Collections.Generic.List[object]'
            foreach ($entry in $script:GuiReviewItems) {
                if (-not [string]::IsNullOrWhiteSpace([string]$entry.Path) -and $observed.Add([string]$entry.Path)) {
                    [void]$items.Add([pscustomobject]@{ Path=[string]$entry.Path; Type='ASSINATURA'; State=[string]$entry.Signature })
                }
            }
            foreach ($proc in $script:GuiProcesses) {
                if ([string]$proc.ProcessName -ne 'RobloxPlayerBeta') { continue }
                $loc = $null
                try { $loc = [string]$proc.Path } catch { }
                if (-not [string]::IsNullOrWhiteSpace($loc) -and $observed.Add($loc)) {
                    $state = if ($script:GuiSignatureMap.ContainsKey($loc)) { [string]$script:GuiSignatureMap[$loc] } else { 'Nao verificada' }
                    [void]$items.Add([pscustomobject]@{ Path=$loc; Type='ROBLOX'; State=$state })
                }
            }
            $i = 0
            foreach ($entry in $items) {
                $loc = [string]$entry.Path
                if (-not [IO.File]::Exists($loc)) { continue }
                $i++
                $key = ('{0:000}' -f $i)
                $script:InvestigationPaths[$key] = $loc
                $procNames = @(
                    foreach ($proc in $script:GuiProcesses) {
                        try {
                            if ([string]::Equals([string]$proc.Path,$loc,[StringComparison]::OrdinalIgnoreCase)) {
                                [string]$proc.ProcessName
                            }
                        } catch { }
                    }
                ) | Sort-Object -Unique | Select-Object -First 2
                $label = if (@($procNames).Count -gt 0) { @($procNames) -join ', ' } else { 'Indisponivel' }
                $company = 'Nao informada'
                try {
                    $reported = [string]([System.Diagnostics.FileVersionInfo]::GetVersionInfo($loc).CompanyName)
                    if (-not [string]::IsNullOrWhiteSpace($reported)) { $company = $reported }
                } catch { }
                if ($company.Length -gt 55) { $company = $company.Substring(0,55) + '...' }
                $origin = 'Outro local'
                if ($loc.StartsWith(($env:SystemRoot.TrimEnd([char]92) + [char]92),[StringComparison]::OrdinalIgnoreCase)) {
                    $origin = 'Pasta Windows'
                } elseif ($loc.StartsWith(($env:ProgramFiles.TrimEnd([char]92) + [char]92),[StringComparison]::OrdinalIgnoreCase)) {
                    $origin = 'Arquivos de Programas'
                } elseif ($env:LOCALAPPDATA -and $loc.StartsWith(($env:LOCALAPPDATA.TrimEnd([char]92) + [char]92),[StringComparison]::OrdinalIgnoreCase)) {
                    $origin = 'AppData Local'
                } elseif ($env:TEMP -and $loc.StartsWith(($env:TEMP.TrimEnd([char]92) + [char]92),[StringComparison]::OrdinalIgnoreCase)) {
                    $origin = 'Pasta temporaria'
                } elseif ($env:USERPROFILE -and $loc.StartsWith(($env:USERPROFILE.TrimEnd([char]92) + [char]92),[StringComparison]::OrdinalIgnoreCase)) {
                    $origin = 'Pasta de usuario'
                }
                [void]$out.Add([pscustomobject]@{
                    ID = $key
                    Tipo = [string]$entry.Type
                    Arquivo = [IO.Path]::GetFileName($loc)
                    Processo = $label
                    Assinatura = [string]$entry.State
                    Fornecedor = $company
                    Origem = $origin
                })
            }
            if ($out.Count -eq 0) {
                [void]$out.Add([pscustomobject]@{
                    ID='-';Tipo='INFO';Arquivo='Nenhum item da amostra para revisao'
                    Processo='-';Assinatura='-';Fornecedor='-';Origem='-'
                })
            }
            return $out.ToArray()
        }

        function script:Get-LMDefenderRows {
            # Aggregate-only security observations for this session.
            $out = New-Object 'System.Collections.Generic.List[object]'
            foreach ($check in $script:Checks) {
                if ($check.Label -match '^Microsoft Defender$|^Protecao em tempo real$|^Tamper Protection$|^Firewall |^Servico WinDefend$|^Historico Defender$') {
                    [void]$out.Add([pscustomobject]@{
                        Verificacao=[string]$check.Label
                        Estado=[string]$check.State
                        Resultado=[string]$check.Explanation
                    })
                }
            }
            return $out.ToArray()
        }

        $script:GuiDriverSignaturesChecked = 0
        $categories = @('PROCESSOS','ROBLOX','CAPTURA','ATIVIDADE','REDE','COBERTURA','EVENTOS','ACESSOS','PAIS','TAREFAS','CODIGO','INVESTIGACAO','DEFENDER','SERVICOS','DRIVERS','INICIALIZACAO','REVISAO','INFORMACOES')
        $script:Gui23 = @{
            Active = 'PROCESSOS'
            Page = 0
            PageSize = 15
            Filter = ''
            Categories = $categories
            Rows = @{}
            Columns = @{
                PROCESSOS = @('Processo','PID','RAM_MB','Assinatura')
                ROBLOX = @('Tipo','Processo','PID','Assinatura','Observacao')
                CAPTURA = @('Aplicativo','Processo','PID','Estado')
                ATIVIDADE = @('Inicio','Processo','PID','Minutos','Nota')
                REDE = @('Processo','PID','TCP_ativas','Nota')
                TAREFAS = @('Tarefa','Estado','Escopo','Nota')
                CODIGO = @('Hora','Evento','Nivel','Observacao')
                COBERTURA = @('Fonte','Estado','Limite')
                EVENTOS = @('Hora','Fonte','Processo','Pai')
                ACESSOS = @('Hora','Evento','Origem','Destino','Mascara','Permissoes','Nota')
                PAIS = @('Processo','PID','Pai','PID_Pai')
                INVESTIGACAO = @('ID','Tipo','Arquivo','Processo','Assinatura','Fornecedor','Origem')
                DEFENDER = @('Verificacao','Estado','Resultado')
                SERVICOS = @('Servico','Descricao','Estado')
                DRIVERS = @('Driver','Estado','Inicio','Assinatura')
                INICIALIZACAO = @('Programa','Origem')
                REVISAO = @('Arquivo','Processo','Situacao')
            }
            Visited = @{}
        }
        foreach ($key in $categories) { $script:Gui23.Visited[$key] = @{} }
        $script:Gui23.Rows['PROCESSOS'] = @(Get-LMProcessRows -Items $script:GuiProcesses)
        $script:Gui23.Rows['ROBLOX'] = @(Get-LMRobloxRows -Items $script:GuiProcesses)
        $script:Gui23.Rows['CAPTURA'] = @($script:CaptureRows)
        $script:Gui23.Rows['ATIVIDADE'] = @($script:RecentRows)
        $script:Gui23.Rows['REDE'] = @($script:NetworkRows)
        $script:Gui23.Rows['TAREFAS'] = @($script:TaskRows)
        $script:Gui23.Rows['CODIGO'] = @($script:CodeIntegrityRows)
        $script:Gui23.Rows['COBERTURA'] = @($script:CoverageRows)
        $script:Gui23.Rows['EVENTOS'] = @($script:TimelineRows)
        $script:Gui23.Rows['ACESSOS'] = @($script:AccessRows)
        $script:Gui23.Rows['PAIS'] = @($script:ParentRows)
        $script:Gui23.Rows['INVESTIGACAO'] = @(Get-LMInvestigationRows)
        $script:Gui23.Rows['DEFENDER'] = @(Get-LMDefenderRows)
        $script:Gui23.Rows['SERVICOS'] = @(Get-LMServiceRows)
        $script:Gui23.Rows['DRIVERS'] = @(Get-LMDriverRows)
        $script:Gui23.Rows['INICIALIZACAO'] = @(Get-LMStartupRows)
        $script:Gui23.Rows['REVISAO'] = @(Get-LMReviewRows)
        Check 'Drivers' 'INFO' ("$(@($script:Gui23.Rows['DRIVERS']).Count) itens; $script:GuiDriverSignaturesChecked arquivos consultados (amostra nao conclusiva).")
        Check 'Inicializacao' 'INFO' ("$(@($script:Gui23.Rows['INICIALIZACAO']).Count) entradas listadas na janela, sem comandos/caminhos nos relatorios.")
        Check 'Itens para revisao visual' 'INFO' ("$(@($script:Gui23.Rows['REVISAO']).Count) arquivos da amostra de processos disponiveis na aba REVISAO.")
        Check 'Painel de telemetria' 'INFO' 'Eventos e relacoes de processos apenas na janela local; sem caminhos, argumentos ou nomes nos relatorios.'
        Check 'Investigacao local' 'INFO' ('Aba INVESTIGACAO disponivel; fornecedor/origem sao informativos, nao provas. Hash SHA-256 apenas sob duplo clique.')

        $dark = [System.Drawing.Color]::FromArgb(14,24,36)
        $panel = [System.Drawing.Color]::FromArgb(23,37,54)
        $cyan = [System.Drawing.Color]::FromArgb(96,220,233)
        $white = [System.Drawing.Color]::FromArgb(231,240,249)
        $muted = [System.Drawing.Color]::FromArgb(158,177,197)

        $window = New-Object System.Windows.Forms.Form
        $window.Text = 'MVS LOST MEDIA  |  T1 SYSTEM CHECK v2.11.0'
        $window.StartPosition = 'CenterScreen'
        $window.Size = New-Object System.Drawing.Size(1260,745)
        $window.MinimumSize = New-Object System.Drawing.Size(1160,620)
        $window.BackColor = $dark
        $window.ForeColor = $white
        $window.Font = New-Object System.Drawing.Font('Segoe UI',10)

        $layout = New-Object System.Windows.Forms.TableLayoutPanel
        $layout.Dock = 'Fill'
        $layout.ColumnCount = 1
        $layout.RowCount = 4
        [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,92)))
        [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,45)))
        [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent,100)))
        [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,112)))
        $window.Controls.Add($layout)

        $top = New-Object System.Windows.Forms.Panel
        $top.BackColor = $dark; $top.Dock = 'Fill'
        $title = New-Object System.Windows.Forms.Label
        $title.Text = 'MVS LOST MEDIA   /   TIER 1'
        $title.ForeColor = $cyan
        $title.Font = New-Object System.Drawing.Font('Consolas',20,[System.Drawing.FontStyle]::Bold)
        $title.Location = New-Object System.Drawing.Point(20,10)
        $title.AutoSize = $true
        $top.Controls.Add($title)
        $subtitle = New-Object System.Windows.Forms.Label
        $subtitle.Text = 'SYSTEM CHECK / ROBLOX / ATIVIDADE / AUDITORIA / BUILD 2.11.0'
        $subtitle.ForeColor = $muted
        $subtitle.Font = New-Object System.Drawing.Font('Consolas',10)
        $subtitle.Location = New-Object System.Drawing.Point(23,55)
        $subtitle.AutoSize = $true
        $top.Controls.Add($subtitle)
        $layout.Controls.Add($top,0,0)

        $filterPanel = New-Object System.Windows.Forms.Panel
        $filterPanel.Dock = 'Fill'
        $filterPanel.BackColor = $panel
        $filterLabel = New-Object System.Windows.Forms.Label
        $filterLabel.Text = 'Pesquisar (somente nesta aba):'
        $filterLabel.Location = New-Object System.Drawing.Point(20,13)
        $filterLabel.AutoSize = $true
        $filterLabel.ForeColor = $white
        $filterPanel.Controls.Add($filterLabel)
        $filterBox = New-Object System.Windows.Forms.TextBox
        $filterBox.Location = New-Object System.Drawing.Point(256,8)
        $filterBox.Size = New-Object System.Drawing.Size(410,28)
        $filterPanel.Controls.Add($filterBox)
        $filterNotice = New-Object System.Windows.Forms.Label
        $filterNotice.Text = 'Filtro ativo nao conta paginas como visitadas.'
        $filterNotice.ForeColor = $muted
        $filterNotice.Location = New-Object System.Drawing.Point(680,12)
        $filterNotice.AutoSize = $true
        $filterNotice.Visible = $false
        $filterPanel.Controls.Add($filterNotice)
        $layout.Controls.Add($filterPanel,0,1)

        $tabs = New-Object System.Windows.Forms.TabControl
        $tabs.Dock = 'Fill'
        $tabs.Multiline = $true
        $tabs.Font = New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Bold)
        $layout.Controls.Add($tabs,0,2)
        $grids = @{}
        foreach ($category in $categories) {
            $tab = New-Object System.Windows.Forms.TabPage
            $tab.Text = $category
            $tab.BackColor = $panel
            [void]$tabs.TabPages.Add($tab)
            if ($category -eq 'INFORMACOES') {
                $info = New-Object System.Windows.Forms.Label
                $info.Dock = 'Fill'; $info.Padding = New-Object System.Windows.Forms.Padding(20)
                $info.ForeColor = $white
                $info.Font = New-Object System.Drawing.Font('Consolas',11)
                $info.Text = ('SESSAO: ' + $script:Session + [Environment]::NewLine + [Environment]::NewLine +
                    'Processos na leitura inicial: ' + $script:Stats.ProcessCount + [Environment]::NewLine +
                    'Assinaturas validas: ' + $script:Stats.SignedValid + [Environment]::NewLine +
                    'Sem assinatura na amostra: ' + $script:Stats.Unsigned + [Environment]::NewLine +
                    'Drivers consultados: ' + $script:GuiDriverSignaturesChecked + ' arquivos (amostra)' + [Environment]::NewLine +
                    'Defender: ' + $script:DefenderSummary + [Environment]::NewLine +
                    'Atividade: ' + $script:ActivitySource + [Environment]::NewLine +
                    'Rede: ' + $script:NetworkSource + [Environment]::NewLine +
                    'Captura: ' + $script:CaptureSource + [Environment]::NewLine +
                    'Tarefas: ' + $script:TaskSource + [Environment]::NewLine +
                    'Code Integrity: ' + $script:CodeIntegritySource + [Environment]::NewLine +
                    'Cobertura: ausente nao quer dizer aprovado.' + [Environment]::NewLine +
                    'Historico: ' + $script:TimelineSource + [Environment]::NewLine +
                    'Acessos: ' + $script:AccessSource + [Environment]::NewLine +
                    'Ultimos ' + $script:EventWindowMinutes + ' minutos; amostragem limitada.' + [Environment]::NewLine + [Environment]::NewLine +
                    'EVENTOS: criacao de processos se ja houver auditoria habilitada.' + [Environment]::NewLine +
                    'ACESSOS: Sysmon 8/10/25, apenas se previamente coletados.' + [Environment]::NewLine +
                    'ID 10 concede direitos; nao comprova leitura ou escrita.' + [Environment]::NewLine +
                    'ID 8 e 25 exigem contexto; nenhum evento comprova cheat.' + [Environment]::NewLine +
                    'PAIS: relacoes atuais por PID; reutilizacao de PID e possivel.' + [Environment]::NewLine +
                    'Nao habilitamos auditoria nem instalamos Sysmon.' + [Environment]::NewLine +
                    'INVESTIGACAO: amostra de assinaturas e Roblox, fornecedor declarado.' + [Environment]::NewLine +
                    'CAPTURA: programa visivel nao comprova gravacao ativa.' + [Environment]::NewLine +
                    'TAREFAS: nomes locais, sem comandos ou credenciais.' + [Environment]::NewLine +
                    'CODIGO: eventos de diagnostico precisam de contexto.' + [Environment]::NewLine +
                    'Duplo clique: SHA-256 local sob demanda, sem enviar arquivo.' + [Environment]::NewLine +
                    'Aba ROBLOX: processos Roblox e novos desde a primeira leitura.' + [Environment]::NewLine +
                    'Use Atualizar listas para comparar novamente durante a inspeção.' + [Environment]::NewLine +
                    'Apenas os nomes e PIDs sao comparados; PIDs podem ser reutilizados.' + [Environment]::NewLine +
                    'Novo processo nao significa cheat, nem relacao com Roblox.' + [Environment]::NewLine +
                    'Cheats injetados ou externos por hardware podem nao aparecer.' + [Environment]::NewLine + [Environment]::NewLine +
                    'Assinatura ausente NAO comprova cheat.' + [Environment]::NewLine +
                    'Drivers podem ser assinados por catalogo; esta tela nao e definitiva.' + [Environment]::NewLine +
                    'Atualizar muda a visualizacao, nao a varredura inicial.' + [Environment]::NewLine +
                    'Paginas visitadas nao comprovam que a gravacao esteja completa.' + [Environment]::NewLine +
                    'Nenhuma alteracao de seguranca ou envio de dados e realizada.' + [Environment]::NewLine +
                    'Nomes, PIDs e programas aparecem apenas nesta janela.' + [Environment]::NewLine +
                    'Historico Defender: registros nao implicam trapaça no Roblox.')
                $tab.Controls.Add($info)
            } else {
                $grid = New-Object System.Windows.Forms.DataGridView
                $grid.Dock = 'Fill'; $grid.ReadOnly = $true
                $grid.BackgroundColor = $panel
                $grid.GridColor = [System.Drawing.Color]::FromArgb(48,64,82)
                $grid.EnableHeadersVisualStyles = $false
                $grid.ColumnHeadersDefaultCellStyle.BackColor = $dark
                $grid.ColumnHeadersDefaultCellStyle.ForeColor = $cyan
                $grid.DefaultCellStyle.BackColor = $panel
                $grid.DefaultCellStyle.ForeColor = $white
                $grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(40,93,111)
                $grid.DefaultCellStyle.SelectionForeColor = $white
                $grid.RowHeadersVisible = $false
                $grid.AllowUserToAddRows = $false; $grid.AllowUserToDeleteRows = $false
                $grid.MultiSelect = $false
                $grid.SelectionMode = 'FullRowSelect'
                $grid.AutoSizeColumnsMode = 'Fill'
                $grid.AllowUserToResizeRows = $false
                $grids[$category] = $grid
                $tab.Controls.Add($grid)
            }
        }


        # Details are only revealed on demand; they may contain a local user path.
        $grids['ROBLOX'].Add_CellDoubleClick({
            param($sender,$eventArgs)
            try {
                if ($eventArgs.RowIndex -lt 0) { return }
                $selected = $sender.Rows[$eventArgs.RowIndex]
                $idText = [string]$selected.Cells['PID'].Value
                $chosenPid = 0
                if (-not [int]::TryParse($idText,[ref]$chosenPid)) { return }
                $chosen = Get-Process -Id $chosenPid -ErrorAction Stop
                $location = 'Indisponivel'
                try {
                    if ($chosen.Path) { $location = [string]$chosen.Path }
                } catch { }
                $state = 'Nao verificada'
                if ($location -ne 'Indisponivel') {
                    $state = SignatureStatus $location
                }
                $detailText = ('Processo: ' + $chosen.ProcessName + [Environment]::NewLine +
                    'PID: ' + $chosenPid + [Environment]::NewLine +
                    'Assinatura: ' + $state + [Environment]::NewLine +
                    'Caminho: ' + $location + [Environment]::NewLine + [Environment]::NewLine +
                    'O caminho pode conter informacoes pessoais. Revise sua gravacao.' + [Environment]::NewLine +
                    'Nenhuma dessas informacoes confirma uso de cheats.')
                [void][System.Windows.Forms.MessageBox]::Show($detailText,'MVS LOST MEDIA | Detalhes do processo')
            } catch {
                [void][System.Windows.Forms.MessageBox]::Show('Processo encerrado ou dados indisponiveis.','MVS LOST MEDIA')
            }
        })


        # File hash and signer metadata are calculated ONLY after a direct user
        # double-click; full local path stays in memory, never in TXT/Discord.
        $grids['INVESTIGACAO'].Add_CellDoubleClick({
            param($sender,$eventArgs)
            try {
                if ($eventArgs.RowIndex -lt 0) { return }
                $id = [string]$sender.Rows[$eventArgs.RowIndex].Cells['ID'].Value
                if (-not $script:InvestigationPaths.ContainsKey($id)) { return }
                $loc = [string]$script:InvestigationPaths[$id]
                if (-not [IO.File]::Exists($loc)) { throw 'Arquivo nao localizado.' }
                $sig = SignatureStatus $loc
                $sizeMB = [math]::Round((Get-Item -LiteralPath $loc -ErrorAction Stop).Length/1MB,2)
                $digest = (Get-FileHash -LiteralPath $loc -Algorithm SHA256 -ErrorAction Stop).Hash
                $msg = ('Arquivo: ' + [IO.Path]::GetFileName($loc) + [Environment]::NewLine +
                    'Assinatura: ' + $sig + [Environment]::NewLine +
                    'Tamanho: ' + $sizeMB + ' MB' + [Environment]::NewLine +
                    'SHA-256: ' + $digest + [Environment]::NewLine + [Environment]::NewLine +
                    'Este hash identifica bytes, nao determina se o arquivo e malicioso.' + [Environment]::NewLine +
                    'Metadados podem ser falsificados. Nenhum dado foi enviado.')
                [void][System.Windows.Forms.MessageBox]::Show($msg,'MVS LOST MEDIA | Inspecao local do arquivo')
            } catch {
                [void][System.Windows.Forms.MessageBox]::Show('Nao foi possivel consultar este arquivo: ' + $_.Exception.GetType().Name,'MVS LOST MEDIA')
            }
        })

        $bottom = New-Object System.Windows.Forms.Panel
        $bottom.Dock = 'Fill'; $bottom.BackColor = $dark
        $privacy = New-Object System.Windows.Forms.Label
        $privacy.Text = 'PRIVACIDADE: a gravacao pode mostrar nomes de programas. Confira o video antes de enviar.'
        $privacy.ForeColor = $muted
        $privacy.Location = New-Object System.Drawing.Point(20,5)
        $privacy.AutoSize = $true
        $bottom.Controls.Add($privacy)

        $prev = New-Object System.Windows.Forms.Button
        $prev.Text = '<< Anterior'; $prev.Location = New-Object System.Drawing.Point(20,42)
        $prev.Size = New-Object System.Drawing.Size(130,35)
        $bottom.Controls.Add($prev)
        $next = New-Object System.Windows.Forms.Button
        $next.Text = 'Proxima >>'; $next.Location = New-Object System.Drawing.Point(158,42)
        $next.Size = New-Object System.Drawing.Size(130,35)
        $bottom.Controls.Add($next)
        $progress = New-Object System.Windows.Forms.Label
        $progress.ForeColor = $cyan
        $progress.Font = New-Object System.Drawing.Font('Consolas',10)
        $progress.Location = New-Object System.Drawing.Point(302,46)
        $progress.Size = New-Object System.Drawing.Size(555,32)
        $bottom.Controls.Add($progress)
        $refresh = New-Object System.Windows.Forms.Button
        $refresh.Text = 'Atualizar listas'
        $refresh.Location = New-Object System.Drawing.Point(900,42)
        $refresh.Size = New-Object System.Drawing.Size(142,35)
        $bottom.Controls.Add($refresh)
        $finish = New-Object System.Windows.Forms.Button
        $finish.Text = 'Concluir verificacao'
        $finish.Location = New-Object System.Drawing.Point(1050,42)
        $finish.Size = New-Object System.Drawing.Size(175,35)
        $finish.Add_Click({ $script:Gui23Window.Close() })
        $bottom.Controls.Add($finish)
        $layout.Controls.Add($bottom,0,3)

        $script:Gui23Window = $window
        $script:Gui23Controls = @{
            Tabs = $tabs; Filter = $filterBox; Notice = $filterNotice; Grids = $grids
            Progress = $progress; Prev = $prev; Next = $next; Refresh = $refresh
        }
        $script:Gui23Render = {
            $state = $script:Gui23
            $controls = $script:Gui23Controls
            $category = $state.Active
            if ($category -eq 'INFORMACOES') {
                $controls.Filter.Enabled = $false
                $controls.Notice.Visible = $false
                $controls.Prev.Enabled = $false; $controls.Next.Enabled = $false
                $controls.Refresh.Enabled = $false
                $controls.Progress.Text = 'Resumo da sessao'
                return
            }
            $controls.Filter.Enabled = $true
            $columns = @($state.Columns[$category])
            $items = @($state.Rows[$category])
            $filter = $state.Filter.Trim()
            if ($filter.Length -gt 0) {
                $items = @($items | Where-Object {
                    $row = $_; $matched = $false
                    foreach ($field in $columns) {
                        if ([string]$row.$field -like ('*' + $filter + '*')) { $matched = $true; break }
                    }
                    $matched
                })
            }
            $controls.Notice.Visible = ($filter.Length -gt 0)
            $total = $items.Count
            $pages = [Math]::Max(1,[int][Math]::Ceiling($total / $state.PageSize))
            if ($state.Page -ge $pages) { $state.Page = $pages - 1 }
            if ($state.Page -lt 0) { $state.Page = 0 }
            if ($filter.Length -eq 0) { $pageKey = [string]$state.Page; $state.Visited[$category][$pageKey] = $true }
            $current = @($items | Select-Object -Skip ($state.Page * $state.PageSize) -First $state.PageSize)
            $table = New-Object System.Data.DataTable
            foreach ($field in $columns) { [void]$table.Columns.Add($field,[string]) }
            foreach ($row in $current) {
                # NewRow avoids overload resolution for DataRowCollection.Add(object[]).
                $dataRow = $table.NewRow()
                foreach ($field in $columns) { $dataRow[$field] = [string]$row.$field }
                [void]$table.Rows.Add($dataRow)
            }
            $controls.Grids[$category].DataSource = $table
            $visits = $state.Visited[$category].Count
            if ($filter.Length -eq 0) {
                if ($category -eq 'ROBLOX') {
                    $controls.Progress.Text = ('Pagina {0}/{1} | Visitadas {2}/{1} | Novos: {3}' -f ($state.Page+1),$pages,$visits,$script:GuiNewCount)
                } else {
                    $controls.Progress.Text = ('Pagina {0}/{1}  |  Visitadas {2}/{1}' -f ($state.Page+1),$pages,$visits)
                }
            } else {
                $controls.Progress.Text = ('Filtrado: pagina {0}/{1}  |  {2} itens' -f ($state.Page+1),$pages,$total)
            }
            $controls.Prev.Enabled = ($state.Page -gt 0)
            $controls.Next.Enabled = ($state.Page -lt ($pages - 1))
            $controls.Refresh.Enabled = ($category -eq 'PROCESSOS' -or $category -eq 'SERVICOS' -or $category -eq 'ROBLOX' -or $category -eq 'ATIVIDADE' -or $category -eq 'REDE' -or $category -eq 'CAPTURA')
        }
        $prev.Add_Click({ $script:Gui23.Page--; & $script:Gui23Render })
        $next.Add_Click({ $script:Gui23.Page++; & $script:Gui23Render })
        $filterBox.Add_TextChanged({
            $script:Gui23.Filter = $script:Gui23Controls.Filter.Text
            $script:Gui23.Page = 0
            & $script:Gui23Render
        })
        $tabs.Add_SelectedIndexChanged({
            $script:Gui23.Active = [string]$script:Gui23.Categories[$script:Gui23Controls.Tabs.SelectedIndex]
            $script:Gui23.Page = 0
            $script:Gui23.Filter = ''
            $script:Gui23Controls.Filter.Text = ''
            & $script:Gui23Render
        })
        $refresh.Add_Click({
            try {
                $fresh = @(Get-Process -ErrorAction Stop)
                $script:Gui23.Rows['PROCESSOS'] = @(Get-LMProcessRows -Items $fresh)
                $script:Gui23.Rows['ROBLOX'] = @(Get-LMRobloxRows -Items $fresh)
                $script:Gui23.Rows['SERVICOS'] = @(Get-LMServiceRows)
                $script:Gui23.Rows['CAPTURA'] = @(Get-LMCaptureRows)
                $script:Gui23.Rows['ATIVIDADE'] = @(Get-LMRecentProcessRows)
                $script:Gui23.Rows['REDE'] = @(Get-LMNetworkSummaryRows)
                $script:Gui23.Visited['CAPTURA'] = @{}
                $script:Gui23.Visited['ATIVIDADE'] = @{}
                $script:Gui23.Visited['REDE'] = @{}
                $script:Gui23.Visited['PROCESSOS'] = @{}
                $script:Gui23.Visited['ROBLOX'] = @{}
                $script:Gui23.Visited['SERVICOS'] = @{}
                $script:Gui23.Page = 0
                & $script:Gui23Render
            } catch {
                [void][System.Windows.Forms.MessageBox]::Show('Nao foi possivel atualizar as listas.', 'MVS LOST MEDIA')
            }
        })
        & $script:Gui23Render
        # The visual panel is shown after the console summary and ENTER.
        [void]$window.ShowDialog()
        $visitedSummary = @()
        foreach ($cat in @('PROCESSOS','ROBLOX','CAPTURA','ATIVIDADE','REDE','COBERTURA','EVENTOS','ACESSOS','PAIS','TAREFAS','CODIGO','INVESTIGACAO','DEFENDER','SERVICOS','DRIVERS','INICIALIZACAO','REVISAO')) {
            $visitedSummary += ($cat + '=' + [string]$script:Gui23.Visited[$cat].Count)
        }
        Check 'Inspecao visual' 'INFO' ('Janela encerrada. Paginas visitadas (nao comprova gravacao): ' + ($visitedSummary -join ', ') + '.')
        Check 'Inspecao Roblox' 'INFO' ("Ultima leitura do painel: $script:GuiRobloxCount processo(s) Roblox; $script:GuiNewCount novo(s) processo(s) desde a primeira consulta. Nao e indicio conclusivo de cheat.")
    } catch {
        # Show a precise failure location to debug GUI compatibility without guessing.
        $detail = $_
        $line = if ($detail.InvocationInfo) { [string]$detail.InvocationInfo.ScriptLineNumber } else { '?' }
        $type = $detail.Exception.GetType().Name
        Say ('  Nao foi possivel concluir o painel: ' + $type + ' (linha ' + $line + ').') Yellow
        Say ('  Detalhe tecnico: ' + $detail.Exception.Message) DarkGray
        if ($detail.InvocationInfo -and $detail.InvocationInfo.Line) {
            Say ('  Instrucao: ' + $detail.InvocationInfo.Line.Trim()) DarkGray
        }
        Check 'Inspecao visual' 'INFO' ('Janela nao concluida: ' + $type + ' (linha ' + $line + ').')
    } finally {
        if ($null -ne $window) { $window.Dispose() }
        $script:Gui23 = $null
        $script:Gui23Controls = $null
        $script:Gui23Render = $null
        $script:Gui23Window = $null
    }
}

Write-LMIntro
Write-LMProgress 0 'Preparando a verificacao...'
Write-LMSection '01' 'Identificacao do ambiente'
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $asAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($asAdmin) { Check 'Permissoes' 'INFO' 'Administrador; algumas leituras podem ser mais completas.' }
    else { Check 'Permissoes' 'INFO' 'Usuario padrao; algumas informacoes podem ser restritas.' }
} catch { Check 'Permissoes' 'INFO' 'Nao foi possivel consultar permissoes.' }
Check 'PowerShell' 'INFO' ('Versao ' + $PSVersionTable.PSVersion.ToString())
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Check 'Windows' 'INFO' ('Build ' + [string]$os.BuildNumber)
} catch { Check 'Windows' 'INFO' 'Build indisponivel.' }

Write-LMProgress 15 'Ambiente consultado'
Write-LMSection '02' 'Protecao do dispositivo'
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    WinStatus 'Microsoft Defender' $mp.AntivirusEnabled
    WinStatus 'Protecao em tempo real' $mp.RealTimeProtectionEnabled
    WinStatus 'Tamper Protection' $mp.IsTamperProtected
} catch {
    Check 'Microsoft Defender' 'INFO' 'Consulta indisponivel; antivirus de terceiros tambem pode explicar.'
}
try {
    $firewall = @(Get-NetFirewallProfile -ErrorAction Stop)
    if ($firewall.Count -eq 0) { Check 'Firewall' 'INFO' 'Nenhum perfil retornado.' }
    foreach ($f in $firewall) {
        if ($f.Enabled -eq $true) { Check ('Firewall ' + $f.Name) 'OK' 'Habilitado.' }
        elseif ($f.Enabled -eq $false) { Check ('Firewall ' + $f.Name) 'REVIEW' 'Desabilitado; revisar politica do dispositivo.' }
        else { Check ('Firewall ' + $f.Name) 'INFO' 'Estado nao informado.' }
    }
} catch { Check 'Firewall' 'INFO' 'Nao foi possivel consultar os perfis.' }

Write-LMProgress 35 'Defender e firewall consultados'
Write-LMSection '03' 'Servicos e isolamento'
foreach ($name in @('WinDefend','mpssvc','wscsvc')) {
    try {
        $s = Get-Service -Name $name -ErrorAction Stop
        if ($s.Status -eq 'Running') { Check ('Servico ' + $name) 'OK' 'Em execucao.' }
        else { Check ('Servico ' + $name) 'REVIEW' ('Estado ' + [string]$s.Status + '; requer contexto.') }
    } catch { Check ('Servico ' + $name) 'INFO' 'Consulta nao disponivel.' }
}
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
    $running = @($dg.SecurityServicesRunning)
    if ($running -contains 2) { Check 'Integridade de memoria' 'OK' 'HVCI consta em execucao.' }
    else { Check 'Integridade de memoria' 'INFO' 'HVCI nao consta em execucao; isso nao e prova de cheat.' }
} catch { Check 'Integridade de memoria' 'INFO' 'Consulta de Device Guard indisponivel.' }

Write-LMProgress 52 'Servicos e isolamento consultados'
Write-LMSection '04' 'Processos e assinaturas'
try {
    $runningProcesses = @(Get-Process -ErrorAction Stop)
    $script:Stats.ProcessCount = $runningProcesses.Count
    # A janela pode funcionar mesmo que a etapa de assinaturas falhe depois.
    $script:GuiProcesses = @($runningProcesses)
    $script:GuiReady = $true
    foreach ($pr in $runningProcesses) {
        $baselineName = ([string]$pr.ProcessName).ToLowerInvariant()
        $baselineKey = ([string]$pr.Id) + '|' + $baselineName
        $script:BaselineProcessKeys[$baselineKey] = $true
    }
    Check 'Processos ativos' 'INFO' ([string]$runningProcesses.Count + ' processos no momento da consulta.')
    $roblox = @($runningProcesses | Where-Object { $_.ProcessName -eq 'RobloxPlayerBeta' })
    $script:Stats.RobloxRunning = ($roblox.Count -gt 0)
    if ($script:Stats.RobloxRunning) { Check 'Roblox' 'INFO' 'RobloxPlayerBeta encontrado na verificacao.' }
    else { Check 'Roblox' 'INFO' 'RobloxPlayerBeta nao encontrado neste instante.' }

    # Make a stable deduplicated list. Prioritize Roblox before sampling.
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $locations = New-Object 'System.Collections.Generic.List[string]'
    $unavailablePaths = 0
    $ordered = @($runningProcesses | Sort-Object @{Expression={ if ($_.ProcessName -eq 'RobloxPlayerBeta') { 0 } else { 1 } }}, ProcessName, Id)
    foreach ($p in $ordered) {
        $location = $null
        try { $location = $p.Path } catch { }
        if ([string]::IsNullOrWhiteSpace($location)) { $unavailablePaths++; continue }
        try {
            if ((Test-Path -LiteralPath $location -PathType Leaf -ErrorAction Stop) -and $seen.Add($location)) {
                [void]$locations.Add($location)
            }
        } catch { $unavailablePaths++ }
    }
    $script:Stats.UniqueReadable = $locations.Count
    $script:Stats.PathUnavailable = $unavailablePaths
    Check 'Cobertura de executaveis' 'INFO' ("$($locations.Count) caminhos unicos legiveis; $unavailablePaths processos sem caminho acessivel.")
    $valid = 0; $unsigned = 0; $other = 0
    $reviewLocal = New-Object 'System.Collections.Generic.List[object]'
    $robloxSignature = 'Indisponivel'
    $processed = 0
    foreach ($loc in $locations) {
        if ($processed -ge $MaxSignatureChecks) { break }
        $status = SignatureStatus $loc
        $script:GuiSignatureMap[$loc] = $status
        $processed++
        if ($processed -eq 1 -or ($processed % 10) -eq 0 -or $processed -eq [Math]::Min($locations.Count,$MaxSignatureChecks)) {
            $fraction = [Math]::Max(1,[Math]::Min($locations.Count,$MaxSignatureChecks))
            $pct = 58 + [int][Math]::Floor((26.0 * $processed)/$fraction)
            Write-LMProgress $pct ('Assinaturas ' + $processed + '/' + $fraction)
        }
        if ($status -eq 'Valid') { $valid++ }
        elseif ($status -eq 'NotSigned') { $unsigned++ }
        else { $other++ }
        if ($status -ne 'Valid') {
            [void]$reviewLocal.Add([pscustomobject]@{ File=[IO.Path]::GetFileName($loc); Signature=$status; Path=$loc })
        }
        if ($roblox.Count -gt 0) {
            foreach ($rp in $roblox) {
                try {
                    if ([string]::Equals($rp.Path, $loc, [StringComparison]::OrdinalIgnoreCase)) { $robloxSignature = $status }
                } catch { }
            }
        }
    }
    $script:Stats.Inspected = $processed
    $script:Stats.SignedValid = $valid
    $script:Stats.Unsigned = $unsigned
    $script:Stats.OtherSignature = $other
    $script:GuiProcesses = @($runningProcesses)
    $script:GuiReviewItems = $reviewLocal.ToArray()
    $script:GuiReady = $true
    Check 'Assinaturas verificadas' 'INFO' ("$processed/$($locations.Count) executaveis: $valid validos, $unsigned sem assinatura, $other outros estados.")
    if ($locations.Count -gt $processed) {
        Check 'Limite de amostragem' 'INFO' ("Restantes nao analisados: $($locations.Count - $processed). Use -MaxSignatureChecks ate 200 para ampliar.")
    }
    if ($unsigned -gt 0 -or $other -gt 0) {
        Check 'Assinaturas para revisar' 'REVIEW' 'Itens sem assinatura valida encontrados; programas legitimos tambem podem aparecer.'
    } else { Check 'Assinaturas para revisar' 'OK' 'Nenhum alerta de assinatura na amostra consultada.' }
    if ($roblox.Count -gt 0) {
        if ($robloxSignature -eq 'Valid') { Check 'Assinatura Roblox' 'OK' 'Executavel do jogo com assinatura valida.' }
        elseif ($robloxSignature -eq 'NotSigned') { Check 'Assinatura Roblox' 'REVIEW' 'Executavel do jogo sem assinatura; requer verificacao manual.' }
        elseif ($robloxSignature -eq 'Indisponivel') { Check 'Assinatura Roblox' 'INFO' 'Nao foi possivel consultar o executavel do Roblox.' }
        else { Check 'Assinatura Roblox' 'REVIEW' ('Estado da assinatura: ' + $robloxSignature + '; revisar.') }
    }
    if ($ShowDetails) {
        Write-Host ''
        Say '  DETALHES LOCAIS (NAO SALVOS) - NOMES DE ARQUIVOS' Cyan
        if ($reviewLocal.Count -eq 0) { Say '  Nenhum item adicional na amostra.' DarkGray }
        foreach ($r in @($reviewLocal | Select-Object -First 25)) {
            Say ('  [' + $r.Signature + '] ' + $r.File) Yellow
        }
        if ($reviewLocal.Count -gt 25) { Say ('  ... e mais ' + ($reviewLocal.Count - 25) + ' itens.') DarkGray }
    }
} catch {
    # Registrar o erro tecnico sem incluir caminhos, nomes de programas ou dados pessoais.
    $errType = $_.Exception.GetType().Name
    $errLine = [int]$_.InvocationInfo.ScriptLineNumber
    Check 'Processos' 'INFO' ("Leitura parcial: $errType na linha $errLine. Painel visual ainda disponivel.")
    if ($script:Stats.ProcessCount -ge 0 -and $script:Stats.Inspected -eq 0) {
        Check 'Assinaturas verificadas' 'INFO' 'Analise interrompida; nao foi possivel concluir a verificacao das assinaturas.'
    }
}

Write-LMProgress 85 'Processos e assinaturas consultados'
# Defender history is not a cheat detector. Aggregate-only; never read or
# save detection file paths, threat names, or other event-level details.
try {
    $cutoff = (Get-Date).AddDays(-7)
    $countRecent = 0
    $countChecked = 0
    Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 200 | ForEach-Object {
        $countChecked++
        try {
            $when = [datetime]$_.InitialDetectionTime
            if ($when -ge $cutoff -and $when -le (Get-Date).AddMinutes(5)) { $countRecent++ }
        } catch { }
    }
    $script:DefenderEntriesChecked = $countChecked
    $script:DefenderRecentCount = $countRecent
    $script:DefenderSummary = ("$countRecent registro(s) nos ultimos 7 dias; $countChecked registro(s) consultados (limite 200).")
    Check 'Historico Defender' 'INFO' ($script:DefenderSummary + ' Alertas podem nao estar ligados ao Roblox.')
} catch {
    $script:DefenderSummary = 'Historico nao disponivel; antivirus de terceiros ou restricoes podem explicar.'
    Check 'Historico Defender' 'INFO' $script:DefenderSummary
}
Write-LMProgress 89 'Historico de alertas consultado'
# Event logs sao opcionais. Sem Sysmon/auditoria, as abas mostram falta de dados.
try { Invoke-LMEventAudit } catch {
    Check 'Telemetria Windows' 'INFO' 'Consulta parcial de eventos; nenhuma mudanca feita no sistema.'
}
Write-LMProgress 90 'Eventos opcionais consultados'
try { Invoke-LMExtraAudit } catch { Check 'Consultas complementares' 'INFO' 'Atividade, rede ou cobertura indisponiveis nesta execucao.' }
Write-LMProgress 91 'Atividade, rede e cobertura consultadas'
try { Invoke-LMAdditionalStages } catch { Check 'Novas fontes' 'INFO' 'Etapas opcionais incompletas nesta execucao.' }
Write-LMProgress 94 'Captura, tarefas e integridade de codigo consultadas'
Write-LMSection '05' 'Comparacao entre execucoes' 
$folder = $null
$previousSnapshot = $null
try {
    $documents = [Environment]::GetFolderPath('MyDocuments')
    if ([string]::IsNullOrWhiteSpace($documents)) { throw 'Pasta Documentos indisponivel.' }
    $folder = Join-Path $documents 'MVS-Lost-Media-T1'
    New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop | Out-Null
    if (-not $NoHistory) {
        $historyPath = Join-Path $folder 'SENTINEL-LAST-SNAPSHOT.json'
        if (Test-Path -LiteralPath $historyPath) {
            try { $previousSnapshot = Get-Content -LiteralPath $historyPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
            catch { Check 'Comparacao' 'INFO' 'Registro anterior nao pode ser lido.' }
        }
    }
} catch { Check 'Pasta de relatorios' 'INFO' 'Documentos indisponivel; relatorios podem nao ser salvos.' }

if ($NoHistory) {
    Check 'Comparacao' 'INFO' 'Desativada por -NoHistory.'
} elseif ($null -eq $previousSnapshot) {
    Check 'Comparacao' 'INFO' 'Primeira execucao ou comparacao anterior indisponivel.'
} elseif ($script:Stats.ProcessCount -lt 0) {
    Check 'Comparacao' 'INFO' 'Processos nao foram consultados nesta sessao.'
} else {
    try {
        if ([int]$previousSnapshot.Schema -ne 2) { throw 'Versao de snapshot diferente.' }
        $delta = $script:Stats.ProcessCount - [int]$previousSnapshot.ProcessCount
        $sigDelta = $script:Stats.Unsigned - [int]$previousSnapshot.Unsigned
        $deltaText = if ($delta -ge 0) { '+' + $delta } else { [string]$delta }
        $sigText = if ($sigDelta -ge 0) { '+' + $sigDelta } else { [string]$sigDelta }
        Check 'Mudanca de processos' 'INFO' ("$deltaText processos desde $($previousSnapshot.Timestamp).")
        if ([int]$previousSnapshot.MaxSignatureChecks -eq $MaxSignatureChecks) {
            Check 'Mudanca de assinaturas' 'INFO' ("$sigText itens sem assinatura na amostra. Amostras podem variar.")
        } else { Check 'Mudanca de assinaturas' 'INFO' 'Limite de amostragem diferente; contagens nao comparaveis.' }
        if ([bool]$previousSnapshot.RobloxRunning -ne [bool]$script:Stats.RobloxRunning) {
            Check 'Mudanca do Roblox' 'INFO' 'Presenca do Roblox mudou desde a execucao anterior.'
        }
    } catch { Check 'Comparacao' 'INFO' 'Snapshot antigo incompativel; iniciando nova referencia.' }
}

Write-LMProgress 96 'Comparacao de execucoes concluida'
Write-LMSection '06' 'Integridade e resumo'
try {
    $hash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash
    Check 'SHA-256 deste arquivo' 'INFO' $hash
} catch { Check 'SHA-256 deste arquivo' 'INFO' 'Nao foi possivel calcular.' }

# ETAPA 1 / 3: intro + progresso ate 100%, sem resultados misturados.
Write-LMProgress 100 'Consultas concluidas'
Start-Sleep -Milliseconds 1600

# ETAPA 2 / 3: limpar o terminal antes de exibir os resultados.
Clear-Host
$script:QuietAudit = $false
Say ''
Say '  +------------------------------------------------------------------+' DarkCyan
Say '  |              MVS LOST MEDIA  |  T1 SYSTEM CHECK                  |' Cyan
Say '  |                    RESULTADOS DA VERIFICACAO                     |' White
Say '  +------------------------------------------------------------------+' DarkCyan
Say ('  Sessao: ' + $script:Session + '  |  BUILD 2.11.0') DarkGray
Say ''
# Exibe aqui os resultados mais importantes. A lista completa vai no TXT.
$highlightInfo = @('Processos ativos','Roblox','Integridade de memoria','Cobertura de executaveis','Assinaturas verificadas','Processos')
foreach ($entry in $script:Checks) {
    if ($entry.State -eq 'INFO' -and $highlightInfo -notcontains $entry.Label) { continue }
    $col = switch ($entry.State) { 'OK' { 'Green' } 'REVIEW' { 'Yellow' } default { 'Gray' } }
    Say ('  [{0,-6}] {1}: {2}' -f $entry.State,$entry.Label,$entry.Explanation) $col
}
$ok = @($script:Checks | Where-Object { $_.State -eq 'OK' }).Count
$review = @($script:Checks | Where-Object { $_.State -eq 'REVIEW' }).Count
$info = @($script:Checks | Where-Object { $_.State -eq 'INFO' }).Count
Say ''
Say (('  RESUMO | OK: {0} | REVISAO: {1} | INFO: {2}' -f $ok,$review,$info)) Cyan
if ($review -gt 0) { Say '  Existem itens para revisao humana; nao ha veredito automatico.' Yellow }
else { Say '  Nenhum alerta nesta consulta; isso nao comprova ausencia de cheats.' Green }
Say '  Proxima etapa: painel com ROBLOX, CAPTURA e auditoria opcional.'
Say '  A lista completa sera salva em Documentos\MVS-Lost-Media-T1.' DarkGray
Say '  Nenhuma consulta garante ausencia ou presenca de cheats.' DarkGray
Say ''
if (-not $NoViewer) {
    # Inspecao visual independente do sucesso da verificacao de assinaturas.
    # Caso a lista inicial esteja vazia, uma nova leitura local e tentada.
    if (@($script:GuiProcesses).Count -eq 0) {
        try {
            $script:GuiProcesses = @(Get-Process -ErrorAction Stop)
            $script:GuiReady = $true
            if ($script:BaselineProcessKeys.Count -eq 0) {
                foreach ($pr in $script:GuiProcesses) {
                    $baselineKey = ([string]$pr.Id) + '|' + ([string]$pr.ProcessName).ToLowerInvariant()
                    $script:BaselineProcessKeys[$baselineKey] = $true
                }
            }
        } catch {
            Check 'Processos do painel' 'INFO' 'Nova leitura indisponivel; outras abas ainda podem funcionar.'
        }
    }
    if (-not $NoPause) { [void](Read-Host '  Pressione ENTER para prosseguir para a proxima etapa') }
    # ETAPA 3 / 3: o painel e a proxima etapa; sem mensagem de carregamento.
    Clear-Host
    $script:QuietAudit = $true
    Open-LMVisualInspector
    $script:QuietAudit = $false
} else {
    Say '  Painel visual omitido por -NoViewer.' DarkGray
}
# After the visual inspection, its observations are included in both reports.
$ok = @($script:Checks | Where-Object { $_.State -eq 'OK' }).Count
$review = @($script:Checks | Where-Object { $_.State -eq 'REVIEW' }).Count
$info = @($script:Checks | Where-Object { $_.State -eq 'INFO' }).Count
# Relatorios sao gravados silenciosamente apos fechar o painel.
# O PowerShell retorna ao prompt automaticamente, sem ENTER extra.
if ($null -ne $folder) {
    try {
        $prefix = 'LM-T1-SYSTEM-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $script:Session
        $report = Join-Path $folder ($prefix + '.txt')
        $discordFile = Join-Path $folder ($prefix + '-DISCORD.txt')
        $reportLines = @(
            'MVS LOST MEDIA | T1 SYSTEM CHECK | BUILD 2.11.0',
            ('Sessao: ' + $script:Session),
            ('Data local: ' + $script:Started),
            'Somente leitura; sem envio de dados; sem nomes/caminhos de processos.',
            'Sysmon 8/10/25 somente se previamente registrados. Amostras limitadas e nao conclusivas.',
            ('Limite de assinaturas: ' + $MaxSignatureChecks),
            ''
        )
        $reportLines += @($script:Checks | ForEach-Object { '[{0}] {1}: {2}' -f $_.State,$_.Label,$_.Explanation })
        $reportLines += @('',"RESUMO: OK=$ok | REVIEW=$review | INFO=$info",'Sem diagnostico automatico de cheat.')
        $reportLines | Set-Content -LiteralPath $report -Encoding UTF8 -ErrorAction Stop

        $discordLines = @(
            '**MVS LOST MEDIA | T1 SYSTEM CHECK - v2.11.0**',
            ('Sessao: `' + $script:Session + '`'),
            ('Data local: ' + $script:Started),
            ("OK: **$ok** | Revisao: **$review** | Info: **$info**"),
            ("Processos: $($script:Stats.ProcessCount) | Assinaturas: $($script:Stats.Inspected) verificadas"),
            ('Roblox na verificacao: ' + $(if ($script:Stats.RobloxRunning) { 'Sim' } else { 'Nao' })),
            'Resultado observacional: revisao humana, sem prova de cheats.'
        )
        $discordLines | Set-Content -LiteralPath $discordFile -Encoding UTF8 -ErrorAction Stop

        if (-not $NoHistory -and $script:Stats.ProcessCount -ge 0) {
            # Aggregate counts only: no file names, command lines, paths, or user identifiers.
            $snapshot = [ordered]@{
                Schema = 2
                Timestamp = $script:Started
                ProcessCount = $script:Stats.ProcessCount
                RobloxRunning = $script:Stats.RobloxRunning
                Inspected = $script:Stats.Inspected
                Unsigned = $script:Stats.Unsigned
                MaxSignatureChecks = $MaxSignatureChecks
            }
            $snapshot | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $historyPath -Encoding UTF8 -ErrorAction Stop
        }
    } catch { Say ('  Falha ao salvar relatorios: ' + $_.Exception.Message) Yellow }
} else { Say '  Nao foi possivel salvar relatorios nesta execucao.' Yellow }
# Sem segunda pausa final: volta ao prompt original do PowerShell.

