#requires -Version 5.1
<#
MVS LOST MEDIA - T1 AUDIT 3.1
Leitura local e voluntaria de informacoes de seguranca do Windows.
Nenhum arquivo pessoal e examinado, nenhum dado e enviado e nenhuma
configuracao de seguranca e alterada. Nao e um detector definitivo de cheats.
#>
[CmdletBinding()]
param([switch]$NoClear)
$ErrorActionPreference = 'Continue'
$script:NowUtc = (Get-Date).ToUniversalTime()
$script:ReportLines = New-Object System.Collections.Generic.List[string]
$script:EventExecutor = New-Object System.Collections.Generic.List[object]
$script:EventExternal = New-Object System.Collections.Generic.List[object]
$script:Unsigned = New-Object System.Collections.Generic.List[object]
$script:Tampering = 0
$script:SysmonCoverage = 'NAO VERIFICADO'
$script:SysmonDetails = 'Fonte de eventos nao consultada.'
$script:Processes = @()
$script:ProcessRead = $false
$script:MaxPerGroup = 12
$documents=[Environment]::GetFolderPath('MyDocuments')
if ([string]::IsNullOrWhiteSpace($documents)) { $documents=Join-Path $env:USERPROFILE 'Documents' }
$script:Directory=Join-Path $documents 'MVS-Lost-Media-T1'

function LM-Print([string]$Text='', [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    Write-Host $Text -ForegroundColor $Color
    [void]$script:ReportLines.Add($Text)
}
function LM-IsRoblox([string]$Image) {
    if ([string]::IsNullOrWhiteSpace($Image)) { return $false }
    return ($Image -match '(?i)(^|[\\/])RobloxPlayerBeta\.exe$')
}
function LM-ShortName([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'Arquivo nao informado' }
    $name = [IO.Path]::GetFileName($Path)
    if ([string]::IsNullOrWhiteSpace($name)) { $name = $Path }
    $name = $name -replace '[\r\n`<>]', '_'
    if ($name.Length -gt 75) { $name=$name.Substring(0,75)+'...' }
    return $name
}
function LM-Section([string]$Title) {
    LM-Print ''
    LM-Print ('  ' + $Title) Cyan
    LM-Print ('  ' + ('-' * 61)) DarkCyan
}
function LM-Bar([int]$Percent, [string]$Stage) {
    $n = [Math]::Max(0,[Math]::Min(24,[int][Math]::Floor($Percent*24/100)))
    Write-Host ("`r  Verification [{0}{1}] {2,3}%  {3}     " -f ('#' * $n),('.' * (24-$n)),$Percent,$Stage) -NoNewline -ForegroundColor Cyan
    if ($Percent -ge 100) { Write-Host '' }
}
function LM-GetProcesses {
    try {
        $script:Processes = @(Get-Process -ErrorAction Stop)
        $script:ProcessRead = $true
    } catch {
        $script:Processes=@()
        $script:ProcessRead=$false
    }
}
function LM-ScanSignatures {
    $unique = @{}
    $scanned = 0
    $unavailable = 0
    foreach ($p in $script:Processes) {
        if ($scanned -ge 110) { break }
        $path = $null
        try { $path = [string]$p.Path } catch { }
        if ([string]::IsNullOrWhiteSpace($path)) { $unavailable++; continue }
        $key=$path.ToLowerInvariant()
        if ($unique.ContainsKey($key)) { continue }
        $unique[$key]=$true
        $scanned++
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
            if ($s.Status -ne 'Valid') {
                [void]$script:Unsigned.Add([pscustomobject]@{
                    Name=(LM-ShortName $path); Status=([string]$s.Status)
                })
            }
        } catch {
            [void]$script:Unsigned.Add([pscustomobject]@{
                Name=(LM-ShortName $path); Status='Assinatura nao consultada'
            })
        }
    }
    return [pscustomobject]@{Scanned=$scanned;Unaccessible=$unavailable;LimitHit=($scanned -ge 110)}
}
function LM-GetEventFields($Event) {
    $fields=@{}
    try {
        [xml]$xml=$Event.ToXml()
        foreach ($datum in $xml.Event.EventData.Data) {
            $key=[string]$datum.Name
            if (-not [string]::IsNullOrWhiteSpace($key)) { $fields[$key]=[string]$datum.'#text' }
        }
    } catch { }
    return $fields
}
function LM-ReadSysmon([datetime]$SinceUtc) {
    $name='Microsoft-Windows-Sysmon/Operational'
    try {
        $meta=Get-WinEvent -ListLog $name -ErrorAction Stop
        if (-not $meta.IsEnabled) {
            $script:SysmonDetails='Log Sysmon encontrado, mas desabilitado.'
            return
        }
    } catch {
        $script:SysmonDetails='Sysmon nao instalado, log ausente ou acesso negado.'
        return
    }
    $script:SysmonCoverage='CONSULTADO'
    $script:SysmonDetails='Eventos 8, 10 e 25, se registrados pela configuracao atual.'
    foreach ($id in @(8,10,25)) {
        $items=@()
        try {
            $items=@(Get-WinEvent -FilterHashtable @{LogName=$name;Id=$id;StartTime=$SinceUtc.ToLocalTime()} -MaxEvents 200 -ErrorAction Stop)
        } catch {
            if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*' -and
                $_.Exception.Message -notmatch 'No events were found|Nenhum evento foi encontrado') {
                $script:SysmonCoverage='PARCIAL'
                $script:SysmonDetails='Pelo menos uma consulta de eventos falhou ou nao permitiu acesso.'
            }
            continue
        }
        if ($items.Count -ge 200) {
            $script:SysmonCoverage='PARCIAL'
            $script:SysmonDetails='Limite de 200 registros atingido em uma consulta; cobertura incompleta.'
        }
        foreach ($ev in $items) {
            $f=LM-GetEventFields $ev
            if ($id -eq 8 -and (LM-IsRoblox ([string]$f['TargetImage']))) {
                [void]$script:EventExecutor.Add([pscustomobject]@{
                    Name=(LM-ShortName ([string]$f['SourceImage']))
                    Signal='Sysmon 8: thread remota registrada'
                    Time=$ev.TimeCreated
                })
            }
            if ($id -eq 10 -and (LM-IsRoblox ([string]$f['TargetImage'])) -and
                -not (LM-IsRoblox ([string]$f['SourceImage']))) {
                $raw=[string]$f['GrantedAccess']
                $mask=[long]0
                try { $mask=[Convert]::ToInt64(($raw -replace '^0[xX]',''),16) } catch { continue }
                $rights=New-Object System.Collections.Generic.List[string]
                if (($mask -band 0x10) -ne 0) { [void]$rights.Add('READ') }
                if (($mask -band 0x20) -ne 0) { [void]$rights.Add('WRITE') }
                if (($mask -band 0x08) -ne 0) { [void]$rights.Add('OPERATION') }
                if (($mask -band 0x02) -ne 0) { [void]$rights.Add('CREATE_THREAD') }
                if ($rights.Count -gt 0) {
                    [void]$script:EventExternal.Add([pscustomobject]@{
                        Name=(LM-ShortName ([string]$f['SourceImage']))
                        Signal=('Sysmon 10: permissao '+($rights.ToArray() -join ',')+' ('+$raw+')')
                        Time=$ev.TimeCreated
                    })
                }
            }
            if ($id -eq 25 -and (LM-IsRoblox ([string]$f['Image']))) {
                $script:Tampering++
            }
        }
    }
}
function LM-ShowFindings([string]$Title,[object[]]$Items) {
    LM-Section $Title
    $arr=@($Items | Sort-Object Name,Signal -Unique)
    if ($arr.Count -eq 0) {
        if ($script:SysmonCoverage -eq 'CONSULTADO') {
            LM-Print '  NONE - nenhum indicio nos registros consultados.' Green
        } else {
            LM-Print '  NAO VERIFICADO - registros ausentes ou cobertura insuficiente.' Yellow
        }
        return
    }
    $counter=0
    foreach ($item in $arr) {
        if ($counter -ge $script:MaxPerGroup) { break }
        LM-Print ('  [REVIEW] '+$item.Name) Yellow
        LM-Print ('           '+$item.Signal) Gray
        $counter++
    }
    if ($arr.Count -gt $script:MaxPerGroup) { LM-Print ('  + '+($arr.Count-$script:MaxPerGroup)+' registro(s) adicionais nao mostrados.') Gray }
    LM-Print '  Sinal tecnico para revisao; nao e identificacao comprovada de cheat.' DarkYellow
}
function LM-ShowUnsigned {
    LM-Section 'ARQUIVOS PARA REVISAO (SEM CLASSIFICACAO)'
    $arr=@($script:Unsigned.ToArray() | Sort-Object Name,Status -Unique)
    if ($arr.Count -eq 0) { LM-Print '  NONE - nenhum arquivo sinalizado na amostra de assinaturas.' Green; return }
    foreach ($item in ($arr | Select-Object -First 12)) {
        LM-Print ('  [REVIEW] '+$item.Name+' | '+$item.Status) Yellow
    }
    if ($arr.Count -gt 12) { LM-Print ('  + '+($arr.Count-12)+' outro(s) arquivo(s) na amostra.') Gray }
    LM-Print '  Ausencia de assinatura NAO significa cheat.' DarkYellow
}
function LM-ShowProtection {
    LM-Section 'PROTECOES E COBERTURA'
    try {
        $d=Get-MpComputerStatus -ErrorAction Stop
        if($d.AntivirusEnabled -and $d.RealTimeProtectionEnabled) {
            LM-Print '  [OK] Defender e protecao em tempo real ativos.' Green
        } else { LM-Print '  [REVIEW] Estado do Defender exige conferencia.' Yellow }
    } catch { LM-Print '  [NAO VERIFICADO] Defender indisponivel nesta consulta.' Yellow }
    try {
        $f=@(Get-NetFirewallProfile -ErrorAction Stop)
        if ($f.Count -gt 0 -and @($f | Where-Object {$_.Enabled -ne $true}).Count -eq 0) {
            LM-Print '  [OK] Perfis retornados do firewall habilitados.' Green
        } else { LM-Print '  [REVIEW] Perfis de firewall exigem conferencia.' Yellow }
    } catch { LM-Print '  [NAO VERIFICADO] Firewall nao consultado.' Yellow }
    LM-Print ('  [INFO] Sysmon: '+$script:SysmonCoverage+' | '+$script:SysmonDetails) Gray
    if ($script:Tampering -gt 0) {
        LM-Print ('  [REVIEW] Sysmon 25 relacionado ao Roblox: '+$script:Tampering+' registro(s).') Yellow
    }
    if ($script:ProcessRead) {
        $roblox=@($script:Processes | Where-Object {$_.ProcessName -eq 'RobloxPlayerBeta'})
        LM-Print ('  [INFO] Processos ativos: '+$script:Processes.Count+' | Roblox: '+$roblox.Count+' instancia(s).') Gray
    } else { LM-Print '  [NAO VERIFICADO] Processos nao consultados.' Yellow }
}
function LM-SaveReport([string]$Phase,[string]$Code) {
    try {
        if (-not (Test-Path -LiteralPath $script:Directory)) {
            New-Item -ItemType Directory -Path $script:Directory -Force -ErrorAction Stop | Out-Null
        }
        $stem='LM-T1-'+$Code+'-'+$Phase
        $txt=Join-Path $script:Directory ($stem+'.txt')
        $discord=Join-Path $script:Directory ($stem+'-DISCORD.txt')
        $script:ReportLines.ToArray() | Set-Content -LiteralPath $txt -Encoding UTF8 -ErrorAction Stop
        $disc=New-Object System.Collections.Generic.List[string]
        [void]$disc.Add('**MVS LOST MEDIA | T1 '+$Phase+'**')
        [void]$disc.Add('Sessao: `'+$Code+'`')
        [void]$disc.Add('```')
        foreach ($line in $script:ReportLines) {
            [void]$disc.Add(($line -replace '`','_'))
        }
        [void]$disc.Add('```')
        [void]$disc.Add('**Aviso:** alertas isolados nao comprovam trapaça. NONE e NAO VERIFICADO nao equivalem a PC limpo.')
        $disc.ToArray() | Set-Content -LiteralPath $discord -Encoding UTF8 -ErrorAction Stop
        LM-Print ''
        LM-Print ('  Relatorio: '+$txt) Green
        LM-Print ('  Texto Discord: '+$discord) Green
    } catch {
        LM-Print ('  [AVISO] Falha ao salvar relatorio: '+$_.Exception.Message) Yellow
    }
}
function LM-Heading([string]$Phase,[string]$Code) {
    if (-not $NoClear) { Clear-Host }
    LM-Print '  +---------------------------------------------------------------+' DarkCyan
    LM-Print '  |                    MVS LOST MEDIA                             |' Cyan
    LM-Print ('  |                    T1 / '+$Phase.PadRight(36)+'|') Cyan
    LM-Print '  |               AUDITORIA LOCAL - BUILD 3.1                    |' DarkCyan
    LM-Print '  +---------------------------------------------------------------+' DarkCyan
    LM-Print ('  SESSAO: '+$Code+'  |  '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) Gray
    LM-Print '  Somente leitura | Sem envio de dados | Sem veredito automatico' DarkGray
}

# FINISH: compara o checkpoint, utiliza a telemetria existente e exibe resultados.
$state=$null
$statePath=Join-Path $script:Directory 'LM-T1-SESSION.json'
try {
    if(Test-Path -LiteralPath $statePath) {
        $state=Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
} catch { $state=$null }
$script:SessionCode=if($null -ne $state -and ([string]$state.Session) -match '^[A-Fa-f0-9]{8}$') { [string]$state.Session } else { ([guid]::NewGuid().ToString('N').Substring(0,8)).ToUpperInvariant() }
LM-Heading 'FINISH' $script:SessionCode
if ($null -eq $state) { LM-Print '  [NAO VERIFICADO] START nao encontrado. Comparacao indisponivel.' Yellow }
LM-Bar 20 'Processos finais'
LM-GetProcesses
LM-Bar 42 'Assinaturas'
$coverage=LM-ScanSignatures
LM-Bar 70 'Sysmon / Roblox'
$since=$script:NowUtc.AddMinutes(-45)
if($null -ne $state){
    try {
        $startTime=[datetime]::Parse([string]$state.StartUtc).ToUniversalTime()
        if($startTime -ge $script:NowUtc.AddHours(-12) -and $startTime -le $script:NowUtc) {
            $since=$startTime
        } else {
            LM-Print '  [NAO VERIFICADO] START muito antigo ou com horario incorreto; janela de 45 minutos usada.' Yellow
        }
    } catch { LM-Print '  [NAO VERIFICADO] Horario do START nao reconhecido.' Yellow }
}
LM-ReadSysmon $since
LM-Bar 100 'Concluido'
LM-ShowFindings 'EXECUTORES - SINAIS REGISTRADOS' $script:EventExecutor.ToArray()
LM-ShowFindings 'EXTERNALS - SINAIS REGISTRADOS' $script:EventExternal.ToArray()
LM-ShowUnsigned
LM-ShowProtection
LM-Section 'COMPARACAO COM START'
if ($null -ne $state -and $script:ProcessRead) {
    $before=@($state.InitialPids | ForEach-Object {[int]$_})
    $after=@($script:Processes | ForEach-Object {[int]$_.Id})
    $new=@($after | Where-Object {$before -notcontains $_})
    $gone=@($before | Where-Object {$after -notcontains $_})
    LM-Print ('  [INFO] Processos START: '+[int]$state.InitialProcessCount+' | FINISH: '+$script:Processes.Count) Gray
    LM-Print ('  [INFO] PIDs novos: '+$new.Count+' | PIDs encerrados: '+$gone.Count) Gray
    LM-Print '  Essa comparacao nao reconstitui processos encerrados ou prova trapaça.' DarkGray
} else { LM-Print '  NAO VERIFICADO - checkpoint ou processos indisponiveis.' Yellow }
LM-Print ('  [INFO] Assinaturas consultadas: '+$coverage.Scanned+' arquivo(s).') Gray
LM-Print '  Revisao humana obrigatoria. Nenhum resultado comprova cheat.' DarkYellow
LM-SaveReport 'FINISH' $script:SessionCode
LM-Print ''
LM-Print '  FINISH CONCLUIDO. O PowerShell pode ser fechado normalmente.' Cyan
