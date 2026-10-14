#requires -Version 5.1
<#
MVS LOST MEDIA - T1 RECORDING CHECK - v3.0 / FINISH
Second independent command to be run AFTER the Roblox match with recording active.
Read-only checks. Does not install or change security settings, and uploads nothing.
Uses only a local START checkpoint with PIDs and aggregate findings.
#>
[CmdletBinding()]
param([switch]$NoPrompts)
$ErrorActionPreference='Continue'
function LM-Line([string]$Text='', [ConsoleColor]$Color=[ConsoleColor]::Gray){Write-Host $Text -ForegroundColor $Color}
function LM-Wait([string]$Message='Pressione ENTER para prosseguir para a proxima etapa') {
    if(-not $NoPrompts){[void](Read-Host "`n  $Message")}
}
function LM-Stage([string]$Number,[string]$Name){
    LM-Line '';LM-Line ('  [{0}]  {1}' -f $Number,$Name.ToUpperInvariant()) Cyan
    LM-Line ('  '+('-'*62)) DarkCyan
}
function LM-Item([string]$Status,[string]$Name,[string]$Desc) {
    $color=if($Status -eq 'OK'){'Green'}elseif($Status -eq 'REVIEW'){'Yellow'}else{'Gray'}
    Write-Host ('  [{0,-12}] ' -f $Status) -ForegroundColor $color -NoNewline
    LM-Line ($Name+' - '+$Desc)
}
$docs=[Environment]::GetFolderPath('MyDocuments')
if([string]::IsNullOrWhiteSpace($docs)){$docs=Join-Path $env:USERPROFILE 'Documents'}
$dir=Join-Path $docs 'MVS-Lost-Media-T1'
$statePath=Join-Path $dir 'LM-T1-SESSION.json'
$state=$null
try{if(Test-Path -LiteralPath $statePath){$state=Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop}}catch{}
$session=if($null -ne $state -and $state.Session -match '^[A-F0-9]{8}$'){$state.Session}else{([guid]::NewGuid().ToString('N').Substring(0,8)).ToUpperInvariant()}
$ending=(Get-Date).ToUniversalTime()
$notes=New-Object System.Collections.ArrayList
function LM-Note([string]$Status,[string]$Name,[string]$Desc) {
    [void]$notes.Add([pscustomobject]@{Status=$Status;Name=$Name;Detail=$Desc})
    LM-Item $Status $Name $Desc
}
Clear-Host
LM-Line '  +------------------------------------------------------------------+' DarkMagenta
LM-Line '  |  MVS LOST MEDIA                                T1 / FINISH 02     |' Magenta
LM-Line '  |           CONFERENCIA FINAL E RELATORIO DO TICKET                |' White
LM-Line '  |             BUILD 3.0     |     SOMENTE LEITURA                  |' DarkMagenta
LM-Line '  +------------------------------------------------------------------+' DarkMagenta
LM-Line ('  SESSAO: '+$session+' | '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) Gray
if($null -eq $state){LM-Line '  AVISO: Nenhum START valido foi encontrado. Comparacao indisponivel.' Yellow}

LM-Stage '07' 'Mostrar resultado da partida'
LM-Line '  Mantenha a gravacao ativa. Mostre o placar e o resultado no Roblox.' White
LM-Line '  Nao feche a gravacao antes de concluir o segundo comando.' Gray
LM-Wait

LM-Stage '08' 'Conferencia final da area de trabalho'
LM-Line '  Abra Win+Tab, confira a bandeja e o software de gravacao novamente.' White
LM-Line '  Mostre o Gerenciador de Tarefas (Ctrl+Shift+Esc) e role os processos.' Gray
LM-Line '  Nao exponha senhas, mensagens privadas ou caminhos pessoais.' DarkGray
LM-Wait

LM-Stage '09' 'Processos e comparacao automatica'
try{
    $procs=@(Get-Process -ErrorAction Stop)
    LM-Note 'INFO' 'Processos finais' ("$($procs.Count) processos observados neste momento.")
    if ($null -ne $state) {
        $before=@($state.InitialPids | ForEach-Object {[int]$_})
        $after=@($procs | ForEach-Object {[int]$_.Id})
        $newPids=@($after | Where-Object { $before -notcontains $_ })
        $gonePids=@($before | Where-Object { $after -notcontains $_ })
        LM-Note 'INFO' 'Comparacao de PIDs' ("$($newPids.Count) novos e $($gonePids.Count) encerrados desde o START (aproximado).")
    } else { LM-Note 'NAO VERIFICADO' 'Comparacao' 'Checkpoint inicial ausente.' }
    $robloxCount=@($procs | Where-Object {$_.ProcessName -eq 'RobloxPlayerBeta'}).Count
    LM-Note 'INFO' 'Roblox' ("$robloxCount instancia(s) visivel(is) no instante final.")
}catch{LM-Note 'NAO VERIFICADO' 'Processos' 'Nao foi possivel consultar processos atuais.'}
try{
    $d=Get-MpComputerStatus -ErrorAction Stop
    if($d.RealTimeProtectionEnabled){LM-Note 'OK' 'Defender tempo real' 'Ativo na leitura final.'}
    else{LM-Note 'REVIEW' 'Defender tempo real' 'Nao indicado como ativo; requer contexto.'}
}catch{LM-Note 'NAO VERIFICADO' 'Defender tempo real' 'Consulta final indisponivel.'}
try{
    $profiles=@(Get-NetFirewallProfile -ErrorAction Stop)
    if($profiles.Count -gt 0 -and @($profiles | Where-Object {$_.Enabled -ne $true}).Count -eq 0){LM-Note 'OK' 'Firewall' 'Perfis retornados habilitados.'}
    else{LM-Note 'REVIEW' 'Firewall' 'Um ou mais perfis nao aparecem habilitados.'}
}catch{LM-Note 'NAO VERIFICADO' 'Firewall' 'Consulta final indisponivel.'}
LM-Wait

LM-Stage '10' 'Politicas do Registro (somente leitura)'
LM-Line '  Verificacoes complementares; valor ausente nao significa PC aprovado.' Gray
try {
    $rk='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $uac=Get-ItemPropertyValue -LiteralPath $rk -Name 'EnableLUA' -ErrorAction Stop
    if([int]$uac -eq 1){LM-Note 'OK' 'UAC' 'Configuracao principal de UAC habilitada.'}
    else{LM-Note 'INFO' 'UAC' 'Valor nao indica UAC ativo; isto nao comprova cheats.'}
} catch{LM-Note 'NAO VERIFICADO' 'UAC' 'Chave nao encontrada ou inacessivel.'}
try {
    $rk='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    if(Test-Path -LiteralPath $rk){
        $rt=Get-ItemPropertyValue -LiteralPath $rk -Name 'DisableRealtimeMonitoring' -ErrorAction Stop
        if([int]$rt -eq 1){LM-Note 'REVIEW' 'Politica Defender' 'Politica legada com valor 1; conferir protecao efetiva.'}
        else{LM-Note 'INFO' 'Politica Defender' ('Valor retornado: '+[string]$rt)}
    }else{LM-Note 'INFO' 'Politica Defender' 'Politica nao encontrada neste caminho.'}
} catch{LM-Note 'NAO VERIFICADO' 'Politica Defender' 'Chave ou valor nao retornado pela consulta.'}
LM-Wait

LM-Stage '11' 'Registro local e evidencias'
LM-Line '  Os relatorios nao incluem nomes de processos, contas, IPs ou caminhos deles.' Gray
LM-Line '  Revise sua gravacao antes de compartilhar com o Justice Department.' Gray
LM-Line '  ALERTAS ISOLADOS NAO SAO PROVA DE CHEAT.' Yellow
try {
    New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
    $finalFile=Join-Path $dir ('LM-T1-'+$session+'-FINISH.txt')
    $discordFile=Join-Path $dir ('LM-T1-'+$session+'-DISCORD.txt')
    $full=@('MVS LOST MEDIA / T1 / FINISH','Session: '+$session,'Finished UTC: '+$ending.ToString('o'),'T1 findings are not automatic cheating verdicts.','')
    foreach($n in $notes){$full+=('[{0}] {1}: {2}' -f $n.Status,$n.Name,$n.Detail)}
    $full | Set-Content -LiteralPath $finalFile -Encoding UTF8 -ErrorAction Stop
    $startStatus=if($null -ne $state){'Executado'}else{'Nao localizado'}
    $discord=@(
        '**MVS LOST MEDIA | T1 RECORDING REVIEW**',
        ('Sessao: `'+$session+'`'),
        'Inicio (checkpoint): '+$startStatus,
        ('Termino UTC: '+$ending.ToString('yyyy-MM-dd HH:mm:ss')),
        '---',
        'Verificacoes finais:'
    )
    foreach($n in $notes){$discord+=('- **'+$n.Status+'** | '+$n.Name+': '+$n.Detail)}
    $discord+=@('---','**Resultado:** Revisao humana necessaria; nenhum teste prova ausencia de cheats.','**Gravacao:** Anexe ao ticket somente apos conferir dados pessoais.','**Observacao:** Caso o Sysmon nao esteja configurado, nao ha prova de ausencia de acessos ao Roblox.')
    $discord | Set-Content -LiteralPath $discordFile -Encoding UTF8 -ErrorAction Stop
    LM-Line ('  Relatorio: '+$finalFile) Green
    LM-Line ('  Para Discord: '+$discordFile) Green
}catch{LM-Line ('  Nao foi possivel gravar o relatorio: '+$_.Exception.Message) Yellow}
LM-Line ''
LM-Line '  T1 FINALIZADO | Voce pode parar a gravacao agora.' Cyan
LM-Line '  Para fechar o PowerShell, digite exit ou clique no X.' DarkGray
