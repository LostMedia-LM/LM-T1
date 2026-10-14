#requires -Version 5.1
<#
MVS LOST MEDIA | T1 REGISTRY CHECK 3.4.1
Independent second verification for Windows PowerShell 5.1.
Read-only: does not change registry values, Defender settings, services,
files, or Windows execution policies. No network calls or automatic uploads.
Exclusion counts only: private paths and filenames are not stored.
#>
[CmdletBinding()]
param([switch]$NoPause)

$ErrorActionPreference = 'Continue'
$script:Findings = New-Object 'System.Collections.Generic.List[object]'
$script:Transcript = New-Object 'System.Collections.Generic.List[string]'
$script:Session = ([guid]::NewGuid().ToString('N').Substring(0,8)).ToUpperInvariant()
$script:Stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$script:Index = 0

function LM-Text([string]$Message = '', [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    Write-Host $Message -ForegroundColor $Color
    [void]$script:Transcript.Add($Message)
}
function LM-Banner {
    try { $Host.UI.RawUI.WindowTitle = 'LM / TIER ONE - REGISTRY CHECK - MVS LOST MEDIA' } catch { }
    Clear-Host
    LM-Text ('  +' + ('-' * 68) + '+') DarkCyan
    LM-Text ('  | ' + 'LM // TIER ONE'.PadRight(66) + ' |') Cyan
    LM-Text ('  |' + ('-' * 68) + '|') DarkCyan
    LM-Text ('  | ' + '        _       __  __'.PadRight(66) + ' |') Cyan
    LM-Text ('  | ' + '       | |     |  \/  |'.PadRight(66) + ' |') Cyan
    LM-Text ('  | ' + '       | |     | |\/| |   M V S   /   L O S T   M E D I A'.PadRight(66) + ' |') Cyan
    LM-Text ('  | ' + '       | |___  | |  | |   REGISTRY / DEFENDER / REVIEW'.PadRight(66) + ' |') White
    LM-Text ('  | ' + '       |_____| |_|  |_|'.PadRight(66) + ' |') Cyan
    LM-Text ('  |' + ('-' * 68) + '|') DarkCyan
    LM-Text ('  | ' + ('MODE: REGISTRY CHECK    BUILD 3.4.1    SESSION: '+$script:Session).PadRight(66) + ' |') Magenta
    LM-Text ('  +' + ('-' * 68) + '+') DarkCyan
    LM-Text '  [LOCAL CHECK] Somente leitura // Sem envio de dados' DarkGray
    LM-Text '  [NOTICE] Ausencia de alertas nao comprova ausencia de cheats.' DarkYellow
}
function LM-Stage([int]$Number, [string]$Name) {
    LM-Text ''
    LM-Text ('  <<  {0:00}  /  {1}' -f $Number, $Name.ToUpperInvariant()) Magenta
    LM-Text ('  ' + ('-' * 68)) DarkCyan
}
function LM-Progress([int]$Percent, [string]$Message) {
    $blocks=[Math]::Max(0,[Math]::Min(24,[int][Math]::Floor($Percent*24/100)))
    Write-Host ("`r  LM-SCAN [{0}{1}] {2,3}%  //  {3}      " -f ('='*$blocks),('.'*(24-$blocks)),$Percent,$Message) -ForegroundColor Cyan -NoNewline
    if($Percent -ge 100){ Write-Host '' }
}
function LM-Item([string]$Caption, [string]$Status, [string]$Detail) {
    $script:Index++
    $color=switch ($Status) { 'OK' {'Green'} 'REVIEW' {'Yellow'} 'UNVERIFIED' {'DarkYellow'} default {'Gray'} }
    LM-Text ('  {0:00}  [{1,-10}] {2} // {3}' -f $script:Index,$Status,$Caption,$Detail) $color
    [void]$script:Findings.Add([pscustomobject]@{Status=$Status;Caption=$Caption;Detail=$Detail})
}
function LM-RegistryValue([string]$Path, [string]$Name) {
    try {
        if(-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return [pscustomobject]@{State='Missing';Value=$null} }
        $item=Get-Item -LiteralPath $Path -ErrorAction Stop
        if(@($item.GetValueNames()) -notcontains $Name) { return [pscustomobject]@{State='Missing';Value=$null} }
        $value=Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop
        return [pscustomobject]@{State='Found';Value=$value}
    } catch { return [pscustomobject]@{State='Unavailable';Value=$null} }
}
function LM-DisabledPolicy([string]$Name,[string]$Path,[string]$Property) {
    $r=LM-RegistryValue $Path $Property
    if($r.State -eq 'Unavailable') { LM-Item $Name 'UNVERIFIED' 'Registro inacessivel.'; return }
    if($r.State -eq 'Missing') { LM-Item $Name 'INFO' 'Politica nao definida neste local.'; return }
    if([string]$r.Value -eq '1') { LM-Item $Name 'REVIEW' 'Politica com valor 1; verificar configuracao efetiva.' }
    else { LM-Item $Name 'INFO' ('Valor definido: '+$r.Value+'. Conferir politica efetiva.') }
}
function LM-EnabledSetting([string]$Name,[string]$Path,[string]$Property) {
    $r=LM-RegistryValue $Path $Property
    if($r.State -eq 'Unavailable') { LM-Item $Name 'UNVERIFIED' 'Registro inacessivel.'; return }
    if($r.State -eq 'Missing') { LM-Item $Name 'INFO' 'Valor nao encontrado; estado nao conclusivo.'; return }
    if([string]$r.Value -eq '1') { LM-Item $Name 'OK' 'Valor 1 informado (configuracao declarada).' }
    else { LM-Item $Name 'INFO' ('Valor '+$r.Value+'; conferir estado efetivo no Windows.') }
}
function LM-SaveReports {
    try {
        $docs=[Environment]::GetFolderPath('MyDocuments')
        if([string]::IsNullOrWhiteSpace($docs)) { $docs=Join-Path $env:USERPROFILE 'Documents' }
        $dir=Join-Path $docs 'MVS-Lost-Media-T1'
        if(-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop) }
        $root='LM-T1-'+$script:Session+'-REGISTRY'
        $fullPath=Join-Path $dir ($root+'.txt')
        $discordPath=Join-Path $dir ($root+'-DISCORD.txt')
        $script:Transcript.ToArray() | Set-Content -LiteralPath $fullPath -Encoding UTF8 -ErrorAction Stop
        $ok=@($script:Findings | Where-Object {$_.Status -eq 'OK'}).Count
        $review=@($script:Findings | Where-Object {$_.Status -eq 'REVIEW'}).Count
        $unverified=@($script:Findings | Where-Object {$_.Status -eq 'UNVERIFIED'}).Count
        $info=@($script:Findings | Where-Object {$_.Status -eq 'INFO'}).Count
        $discord=@('**MVS LOST MEDIA | T1 REGISTRY CHECK 3.4.1**',('Sessao: `'+$script:Session+'`'),"OK: $ok | Revisao: $review | Nao verificado: $unverified | Info: $info",'```')
        $discord+=@($script:Findings | ForEach-Object { '[{0}] {1}: {2}' -f $_.Status,$_.Caption,$_.Detail })
        $discord+=@('```','Este relatorio nao confirma nem exclui a presenca de cheats.')
        $discord | Set-Content -LiteralPath $discordPath -Encoding UTF8 -ErrorAction Stop
        LM-Text ('  [LOG] '+$fullPath) Green
        LM-Text ('  [TICKET] '+$discordPath) Green
    } catch { LM-Text ('  [UNVERIFIED] Nao foi possivel salvar os relatorios: '+$_.Exception.Message) DarkYellow }
}
function LM-End {
    LM-Text ''
    LM-Text ('  +' + ('-' * 68) + '+') DarkCyan
    LM-Text ('  | ' + 'REGISTRY CHECK FINALIZADO  //  MVS LOST MEDIA'.PadRight(66) + ' |') Cyan
    LM-Text ('  | ' + 'Relatorios gravados. Os resultados permanecem na tela.'.PadRight(66) + ' |') Gray
    LM-Text ('  +' + ('-' * 68) + '+') DarkCyan
    if ($NoPause) { return }
    Write-Host ''
    # Descarta teclas acumuladas antes de anunciar o encerramento.
    try {
        if ([Console]::IsInputRedirected) {
            [void](Read-Host '  Pressione ENTER para encerrar')
        } else {
            Start-Sleep -Milliseconds 350
            while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) }
            Write-Host '  >> Pressione QUALQUER TECLA para fechar...' -ForegroundColor Magenta
            [void][Console]::ReadKey($true)
        }
    } catch {
        [void](Read-Host '  Pressione ENTER para encerrar')
    }
    exit
}

LM-Banner
LM-Stage 1 'Exclusoes Microsoft Defender'
LM-Progress 15 'Consultando Defender'
try {
    $pref=Get-MpPreference -ErrorAction Stop
    foreach($spec in @(
        @{Name='Pastas';Key='ExclusionPath'},
        @{Name='Processos';Key='ExclusionProcess'},
        @{Name='Extensoes';Key='ExclusionExtension'},
        @{Name='IPs';Key='ExclusionIpAddress'}
    )) {
        $list=@($pref.($spec.Key) | Where-Object { $null -ne $_ -and ([string]$_).Length -gt 0 })
        if($list.Count -gt 0) { LM-Item ('Exclusoes '+$spec.Name) 'REVIEW' ("$($list.Count) entrada(s). Valores e caminhos nao sao armazenados.") }
        else { LM-Item ('Exclusoes '+$spec.Name) 'OK' 'Nenhuma exclusao retornada pela consulta.' }
    }
} catch { LM-Item 'Exclusoes Defender' 'UNVERIFIED' 'Consulta indisponivel; ausencia nao comprovada.' }
LM-Progress 45 'Politicas do Windows'
LM-Stage 2 'Politicas Microsoft Defender'
$root='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
LM-DisabledPolicy 'Antivirus: politica' $root 'DisableAntiSpyware'
$rt=Join-Path $root 'Real-Time Protection'
LM-DisabledPolicy 'Monitoramento em tempo real' $rt 'DisableRealtimeMonitoring'
LM-DisabledPolicy 'Monitoramento de comportamento' $rt 'DisableBehaviorMonitoring'
LM-DisabledPolicy 'Protecao de arquivos' $rt 'DisableOnAccessProtection'
LM-DisabledPolicy 'Inspecao de downloads' $rt 'DisableIOAVProtection'
LM-Progress 75 'Integridade de seguranca'
LM-Stage 3 'Controles e isolamento'
LM-EnabledSetting 'UAC' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
LM-EnabledSetting 'Integridade de memoria' 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled'
LM-EnabledSetting 'Bloqueio de drivers' 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable'
try {
    if([string]::IsNullOrWhiteSpace($PSCommandPath)) { throw 'Arquivo de script nao identificado (execucao em memoria).' }
    $sha=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash
    LM-Item 'SHA256 do verificador' 'INFO' $sha
} catch { LM-Item 'SHA256 do verificador' 'UNVERIFIED' 'Nao disponivel nesta modalidade de execucao.' }
LM-Progress 100 'Registry Check concluido'
$ok=@($script:Findings | Where-Object {$_.Status -eq 'OK'}).Count
$review=@($script:Findings | Where-Object {$_.Status -eq 'REVIEW'}).Count
$unverified=@($script:Findings | Where-Object {$_.Status -eq 'UNVERIFIED'}).Count
$info=@($script:Findings | Where-Object {$_.Status -eq 'INFO'}).Count
LM-Stage 4 'Resumo da auditoria'
LM-Text ('  [RESULTADO] OK: '+$ok+' | REVIEW: '+$review+' | NAO VERIFICADO: '+$unverified+' | INFO: '+$info) Cyan
LM-Text '  Resultados exigem contexto. Nenhum resultado comprova cheats.' DarkYellow
LM-SaveReports
LM-End
