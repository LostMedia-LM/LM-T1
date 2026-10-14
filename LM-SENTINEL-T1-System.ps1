#requires -Version 5.1
<#
MVS LOST MEDIA - T1 RECORDING CHECK - v3.0 / START
Original, read-only workflow for voluntary tournament recording review.
No elevation, registry writes, security changes, external tools, uploads or network requests.
Only writes session data (counts and PIDs), and a local report in Documents.
Run this AFTER starting the screen recording, BEFORE the match.
This does not detect or certify absence of cheats.
#>
[CmdletBinding()]
param([switch]$SkipVisualList, [switch]$NoPrompts)

$ErrorActionPreference = 'Continue'
$script:SessionCode = ([guid]::NewGuid().ToString('N').Substring(0,8)).ToUpperInvariant()
$script:StartUtc = (Get-Date).ToUniversalTime()
$script:Observations = New-Object System.Collections.ArrayList
$script:ProcessSnapshot = @()

function LM-Line([string]$Text='', [ConsoleColor]$Color=[ConsoleColor]::Gray) {
    Write-Host $Text -ForegroundColor $Color
}
function LM-Wait([string]$Message = 'Pressione ENTER para prosseguir para a proxima etapa') {
    if (-not $NoPrompts) { [void](Read-Host "`n  $Message") }
}
function LM-Stage([string]$Number,[string]$Name) {
    LM-Line ''
    LM-Line ('  [{0}]  {1}' -f $Number,$Name.ToUpperInvariant()) Cyan
    LM-Line ('  ' + ('-' * 62)) DarkCyan
}
function LM-Record([string]$Name,[string]$Status,[string]$Detail) {
    [void]$script:Observations.Add([pscustomobject]@{Name=$Name;Status=$Status;Detail=$Detail})
    $color = switch($Status) { 'OK' {'Green'} 'REVIEW' {'Yellow'} default {'DarkGray'} }
    Write-Host ('  [{0,-12}] ' -f $Status) -ForegroundColor $color -NoNewline
    LM-Line ($Name + ' - ' + $Detail)
}
function LM-Bar([int]$Percent,[string]$Activity) {
    $filled=[Math]::Max(0,[Math]::Min(28,[int][Math]::Floor($Percent*28/100)))
    $bar=('=' * $filled) + ('.' * (28-$filled))
    Write-Host ("`r  Verification [{0}] {1,3}%  {2}               " -f $bar,$Percent,$Activity) -NoNewline -ForegroundColor Cyan
    if ($Percent -ge 100) { Write-Host '' }
}
function LM-CountEntries($value) {
    return @($value | Where-Object { $null -ne $_ -and ([string]$_).Length -gt 0 }).Count
}
function LM-SecuritySummary {
    LM-Bar 12 'Windows Security'
    try {
        $d = Get-MpComputerStatus -ErrorAction Stop
        if ($d.AntivirusEnabled -and $d.RealTimeProtectionEnabled) { LM-Record 'Microsoft Defender' 'OK' 'Antivirus e monitoramento em tempo real indicados como ativos.' }
        else { LM-Record 'Microsoft Defender' 'REVIEW' 'Protecao nao indicada como inteiramente ativa; verifique o contexto.' }
    } catch { LM-Record 'Microsoft Defender' 'NAO VERIFICADO' 'Consulta indisponivel; nao equivale a aprovacao.' }
    LM-Bar 27 'Firewall'
    try {
        $fw = @(Get-NetFirewallProfile -ErrorAction Stop)
        if ($fw.Count -gt 0 -and @($fw | Where-Object {$_.Enabled -ne $true}).Count -eq 0) {
            LM-Record 'Firewall' 'OK' 'Perfis retornados pela consulta estao ativos.'
        } else { LM-Record 'Firewall' 'REVIEW' 'Um ou mais perfis consultados nao aparecem ativos.' }
    } catch { LM-Record 'Firewall' 'NAO VERIFICADO' 'Perfis nao puderam ser consultados.' }
    LM-Bar 42 'Exclusoes do Defender'
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $count=(LM-CountEntries $pref.ExclusionPath)+(LM-CountEntries $pref.ExclusionProcess)+(LM-CountEntries $pref.ExclusionExtension)
        if($count -gt 0){ LM-Record 'Exclusoes Defender' 'REVIEW' ("$count entrada(s) nas tres categorias; caminhos nao sao exibidos.") }
        else { LM-Record 'Exclusoes Defender' 'OK' 'Nenhuma entrada retornada nas tres categorias consultadas.' }
    } catch { LM-Record 'Exclusoes Defender' 'NAO VERIFICADO' 'Consulta indisponivel; nao assumir zero exclusoes.' }
}
function LM-ProcessSummary {
    LM-Bar 60 'Processos ativos'
    try {
        $script:ProcessSnapshot = @(Get-Process -ErrorAction Stop)
        LM-Record 'Processos' 'INFO' ("$($script:ProcessSnapshot.Count) processos no instante da consulta.")
    } catch { LM-Record 'Processos' 'NAO VERIFICADO' 'Consulta indisponivel.'; $script:ProcessSnapshot=@() }
    LM-Bar 75 'Roblox'
    try {
        $roblox = @($script:ProcessSnapshot | Where-Object {$_.ProcessName -eq 'RobloxPlayerBeta'})
        if ($roblox.Count -gt 0) {
            LM-Record 'Roblox' 'INFO' 'RobloxPlayerBeta encontrado.'
            try {
                $path = $roblox[0].Path
                if ([string]::IsNullOrWhiteSpace($path)) { throw 'Sem acesso ao caminho.' }
                $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
                if ($sig.Status -eq 'Valid') { LM-Record 'Assinatura Roblox' 'OK' 'Assinatura do executavel consultado valida.' }
                else { LM-Record 'Assinatura Roblox' 'REVIEW' ('Estado retornado: ' + [string]$sig.Status) }
            } catch { LM-Record 'Assinatura Roblox' 'NAO VERIFICADO' 'Caminho ou assinatura inacessivel.' }
        } else { LM-Record 'Roblox' 'NAO VERIFICADO' 'Roblox nao estava em execucao neste instante.' }
    } catch { LM-Record 'Roblox' 'NAO VERIFICADO' 'Falha na consulta.' }
    LM-Bar 90 'Cobertura de eventos'
    try {
        $sm = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
        if ($sm.IsEnabled) { LM-Record 'Sysmon' 'INFO' 'Log presente e habilitado; eventos dependem da configuracao.' }
        else { LM-Record 'Sysmon' 'NAO VERIFICADO' 'Log encontrado, mas nao habilitado.' }
    } catch { LM-Record 'Sysmon' 'NAO VERIFICADO' 'Sem log acessivel; nao ha telemetria Sysmon confirmada.' }
    LM-Bar 100 'Consultas concluidas'
}
function LM-VisualReview {
    if ($SkipVisualList) { LM-Record 'Inspecao visual' 'INFO' 'Lista visual ignorada a pedido do participante.'; return }
    LM-Stage '06' 'Inspecao visual dos processos'
    LM-Line '  Exiba os processos durante a gravacao. Role com calma; sem ocultar a janela.' White
    LM-Line '  A lista permite pesquisar e ordenar. Feche-a para continuar.' Gray
    LM-Line '  Aviso: a gravacao pode revelar nomes de programas particulares.' DarkYellow
    LM-Wait 'Pressione ENTER para mostrar a lista'
    try {
        if (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
            @(Get-Process -ErrorAction Stop | Sort-Object ProcessName |
                Select-Object @{Name='Processo';Expression={$_.ProcessName}},
                              @{Name='PID';Expression={$_.Id}},
                              @{Name='RAM_MB';Expression={[Math]::Round($_.WorkingSet64/1MB)}}) |
                Out-GridView -Title 'MVS LOST MEDIA - T1 - Inspecao de processos (feche para continuar)' -Wait -ErrorAction Stop
            LM-Record 'Inspecao visual' 'INFO' 'Janela da lista de processos exibida.'
        } else {
            LM-Line '  Out-GridView indisponivel. Abra o Gerenciador de Tarefas (Ctrl+Shift+Esc).' Yellow
            LM-Record 'Inspecao visual' 'NAO VERIFICADO' 'Lista automatica indisponivel; conferencia manual sugerida.'
            LM-Wait
        }
    } catch {
        LM-Line '  Falha ao abrir a lista. Utilize Ctrl+Shift+Esc para revisar manualmente.' Yellow
        LM-Record 'Inspecao visual' 'NAO VERIFICADO' 'Janela indisponivel; nao indica trapaça.'
        LM-Wait
    }
}

Clear-Host
LM-Line '  +------------------------------------------------------------------+' DarkCyan
LM-Line '  |  MVS LOST MEDIA                                T1 / START  01     |' Cyan
LM-Line '  |                                                                  |' DarkCyan
LM-Line '  |                       _       __  __                             |' Cyan
LM-Line '  |                      | |     |  \/  |                            |' Cyan
LM-Line '  |                      | |     | |\/| |                            |' Cyan
LM-Line '  |                      | |___  | |  | |                            |' Cyan
LM-Line '  |                      |_____| |_|  |_|                            |' Cyan
LM-Line '  |           L M  /  RECORDING CHECK - GUIADO                      |' White
LM-Line '  |             ETAPAS GUIADAS + VERIFICACAO LOCAL                    |' DarkCyan
LM-Line '  |                                                                  |' DarkCyan
LM-Line '  |  BUILD 3.0   |   SOMENTE LEITURA   |   SEM ENVIO DE DADOS         |' Cyan
LM-Line '  +------------------------------------------------------------------+' DarkCyan
LM-Line ('  SESSAO: '+$script:SessionCode+'  |  '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) Gray
LM-Line '  Este roteiro nao detecta todos os cheats nem garante PC limpo.' DarkGray
LM-Stage '00' 'Iniciar a gravacao ANTES de continuar'
LM-Line '  Comece uma gravacao continua da tela com cursor visivel.' White
LM-Line '  Confira qualidade minima da politica do torneio (ex.: 720p/60fps).' Gray
LM-Line '  Nao mostre senhas, mensagens privadas ou dados sensiveis.' Gray
LM-Wait

LM-Stage '01' 'Area de trabalho e bandeja do sistema'
LM-Line '  Na gravacao: passe o mouse sobre os icones da bandeja do sistema.' White
LM-Line '  Use Win+Tab para mostrar os desktops; confira os monitores em Configuracoes.' Gray
LM-Line '  USB, overlays e programas de acessibilidade nao sao automaticamente suspeitos.' DarkGray
LM-Wait

LM-Stage '02' 'Windows Security'
LM-Line '  Mostre a Seguranca do Windows: antivirus, firewall e isolamento do nucleo.' White
LM-Line '  Mostre apenas a CONTAGEM de exclusoes; nao exponha caminhos particulares.' Gray
LM-Line '  Nao altere UAC, Defender, firewall ou qualquer outra protecao.' DarkGray
LM-Wait

LM-Stage '03' 'Software de gravacao'
LM-Line '  Mostre aplicativo usado, fontes de captura e configuracoes de gravacao.' White
LM-Line '  Em OBS: confira Ferramentas > Scripts e os atalhos de gravacao.' Gray
LM-Line '  Nenhum script/atalho e prova de cheat por si so.' DarkGray
LM-Wait

LM-Stage '04' 'Roblox em execucao'
LM-Line '  Abra o Roblox e deixe o jogo aberto durante a proxima verificacao.' White
LM-Line '  A gravacao deve continuar sem cortes; nao precisa entrar numa partida ainda.' Gray
LM-Wait

LM-Stage '05' 'Consultas automaticas (somente leitura)'
LM-Line '  VERIFICANDO SEU PC' Cyan
LM-SecuritySummary
LM-ProcessSummary
LM-Line ''
LM-Line '  RESULTADOS PARCIAIS' Cyan
foreach($item in $script:Observations){
    LM-Line ('  [{0,-12}] {1} - {2}' -f $item.Status,$item.Name,$item.Detail)
}
LM-Wait

LM-VisualReview
LM-Stage '07' 'Iniciar a partida'
LM-Line '  Com a gravacao ainda ativa, entre na partida de Roblox/MVSD.' White
LM-Line '  Nao interrompa nem edite o video. Ao terminar a partida, execute o' Gray
LM-Line '  SEGUNDO COMANDO LM T1 / FINISH com a gravacao ainda ligada.' Gray
LM-Wait 'Pressione ENTER para salvar o checkpoint inicial'

try {
    $documents = [Environment]::GetFolderPath('MyDocuments')
    if ([string]::IsNullOrWhiteSpace($documents)) { $documents=Join-Path $env:USERPROFILE 'Documents' }
    $dir = Join-Path $documents 'MVS-Lost-Media-T1'
    New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
    $pids=@($script:ProcessSnapshot | ForEach-Object {[int]$_.Id})
    $state=[ordered]@{
        Version='3.0'; Session=$script:SessionCode; StartUtc=$script:StartUtc.ToString('o')
        InitialCount=[int]$script:ProcessSnapshot.Count; InitialPids=$pids
        InitialRobloxCount=@($script:ProcessSnapshot | Where-Object {$_.ProcessName -eq 'RobloxPlayerBeta'}).Count
        Checks=@($script:Observations.ToArray())
    }
    $jsonFile=Join-Path $dir 'LM-T1-SESSION.json'
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonFile -Encoding UTF8 -ErrorAction Stop
    $txtFile=Join-Path $dir ('LM-T1-'+$script:SessionCode+'-START.txt')
    $lines=@('MVS LOST MEDIA / T1 / START','Session: '+$script:SessionCode,'Started UTC: '+$script:StartUtc.ToString('o'),'Local report. No automatic cheating verdict.','')
    foreach($o in $script:Observations){$lines+=('[{0}] {1}: {2}' -f $o.Status,$o.Name,$o.Detail)}
    $lines | Set-Content -LiteralPath $txtFile -Encoding UTF8 -ErrorAction Stop
    LM-Line ('  Checkpoint gravado em: '+$txtFile) Green
    LM-Line '  Dados locais da sessao: contagem e PIDs; nenhum nome salvo no resumo.' DarkGray
} catch { LM-Line ('  AVISO: nao foi possivel salvar checkpoint: '+$_.Exception.Message) Yellow }
LM-Line '  T1 / START concluido. Mantenha a gravacao ativa ate terminar o FINISH.' Cyan
LM-Line '  Ao voltar para PS>, o script acabou; o terminal fica aberto normalmente.' DarkGray
