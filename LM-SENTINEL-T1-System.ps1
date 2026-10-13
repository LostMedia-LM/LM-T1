#requires -Version 5.1
<#
MVS Lost Media - SENTINEL T1 / System Audit (1 of 2)
Read-only security inspection. Writes reports only under the user's Documents folder.
No downloads, uploads, system changes, process termination, or automatic cheat verdicts.
Run with: & '.\LM-SENTINEL-T1-System.ps1'
Optional: -ShowProcesses (local display only), -NoPause
#>
[CmdletBinding()]
param(
    [switch]$ShowProcesses,
    [switch]$NoPause
)

$ErrorActionPreference = 'Continue'
$script:Findings = New-Object 'System.Collections.Generic.List[object]'
$script:Index = 0
$script:Session = ([guid]::NewGuid().ToString('N').Substring(0,8)).ToUpperInvariant()
$script:Stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

function PrintLine([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    Write-Host $Text -ForegroundColor $Color
}
function Header([string]$Label) {
    Write-Host ''
    PrintLine ('  --- ' + $Label.ToUpperInvariant() + ' ' + ('-' * [Math]::Max(1, 52 - $Label.Length))) Cyan
}
function AddFinding([string]$Area, [string]$Status, [string]$Detail) {
    $script:Index++
    $color = switch ($Status) {
        'OK'     { [ConsoleColor]::Green }
        'REVIEW' { [ConsoleColor]::Yellow }
        default  { [ConsoleColor]::DarkGray }
    }
    Write-Host ('  {0:00}  ' -f $script:Index) -NoNewline -ForegroundColor DarkGray
    Write-Host ('[{0,-6}]' -f $Status) -NoNewline -ForegroundColor $color
    PrintLine (' ' + $Area + '  -  ' + $Detail)
    $script:Findings.Add([pscustomobject]@{ Section=$Area; Status=$Status; Detail=$Detail })
}
function IsTrue($Value) { return ($Value -eq $true) }
function FileSignatureCheck([string]$FilePath) {
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop
        return [string]$sig.Status
    } catch { return 'Unknown' }
}

Clear-Host
PrintLine '  +------------------------------------------------------------------+' DarkCyan
PrintLine '  |   MVS / LOST MEDIA                                        T1:01  |' Cyan
PrintLine '  |   S E N T I N E L                                                |' White
PrintLine '  |   SYSTEM AUDIT                                    BUILD  1.0     |' DarkCyan
PrintLine '  +------------------------------------------------------------------+' DarkCyan
PrintLine ('  SESSION  {0}       {1}' -f $script:Session, $script:Stamp) Gray
PrintLine '  READ-ONLY | SEM ENVIO DE DADOS | SEM VEREDITO AUTOMATICO' DarkGray

Header 'Ambiente'
try {
    $admin = [Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) { AddFinding 'Permissoes' 'INFO' 'Administrador; a leitura pode ser mais completa.' }
    else { AddFinding 'Permissoes' 'INFO' 'Usuario padrao; certas verificacoes podem ficar indisponiveis.' }
} catch { AddFinding 'Permissoes' 'INFO' 'Nao foi possivel identificar o nivel de acesso.' }
AddFinding 'PowerShell' 'INFO' ('Versao ' + $PSVersionTable.PSVersion.ToString())
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    AddFinding 'Sistema' 'INFO' ('Windows build ' + $os.BuildNumber)
} catch { AddFinding 'Sistema' 'INFO' 'Versao do Windows indisponivel.' }

Header 'Protecoes do Windows'
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    if ($null -ne $mp.AntivirusEnabled) {
        if (IsTrue $mp.AntivirusEnabled) { AddFinding 'Antivirus Microsoft' 'OK' 'Protecao indicada como habilitada.' }
        else { AddFinding 'Antivirus Microsoft' 'REVIEW' 'Protecao Microsoft desabilitada; verificar antivirus alternativo.' }
    } else { AddFinding 'Antivirus Microsoft' 'INFO' 'Estado nao informado.' }
    if ($null -ne $mp.RealTimeProtectionEnabled) {
        if (IsTrue $mp.RealTimeProtectionEnabled) { AddFinding 'Tempo real' 'OK' 'Ativo.' }
        else { AddFinding 'Tempo real' 'REVIEW' 'Inativo; confirmar contexto de protecao.' }
    } else { AddFinding 'Tempo real' 'INFO' 'Nao informado.' }
    if ($null -ne $mp.IsTamperProtected) {
        if (IsTrue $mp.IsTamperProtected) { AddFinding 'Tamper Protection' 'OK' 'Ativa.' }
        else { AddFinding 'Tamper Protection' 'REVIEW' 'Nao ativa ou nao disponibilizada.' }
    } else { AddFinding 'Tamper Protection' 'INFO' 'Estado nao informado.' }
} catch { AddFinding 'Windows Defender' 'INFO' 'Consulta indisponivel (permissao, versao ou antivirus de terceiros).' }

try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    foreach ($p in $profiles) {
        $name = [string]$p.Name
        if ($p.Enabled -eq $true) { AddFinding ('Firewall ' + $name) 'OK' 'Perfil habilitado.' }
        elseif ($p.Enabled -eq $false) { AddFinding ('Firewall ' + $name) 'REVIEW' 'Perfil desabilitado; verificar politica do dispositivo.' }
        else { AddFinding ('Firewall ' + $name) 'INFO' 'Estado desconhecido.' }
    }
} catch { AddFinding 'Firewall' 'INFO' 'Nao foi possivel ler perfis do firewall.' }

Header 'Servicos e isolamento'
foreach ($serviceName in @('WinDefend','mpssvc','wscsvc')) {
    try {
        $svc = Get-Service -Name $serviceName -ErrorAction Stop
        if ($svc.Status -eq 'Running') { AddFinding ('Servico ' + $serviceName) 'OK' 'Em execucao.' }
        else { AddFinding ('Servico ' + $serviceName) 'REVIEW' ('Estado: ' + $svc.Status + '; verificar antes de concluir.') }
    } catch { AddFinding ('Servico ' + $serviceName) 'INFO' 'Estado indisponivel.' }
}
try {
    $guard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
    $running = @($guard.SecurityServicesRunning)
    if ($running -contains 2) { AddFinding 'Integridade de memoria' 'OK' 'HVCI consta como em execucao.' }
    else { AddFinding 'Integridade de memoria' 'INFO' 'HVCI nao consta ativo (nao prova cheat).' }
} catch { AddFinding 'Integridade de memoria' 'INFO' 'Nao foi possivel consultar Device Guard.' }

Header 'Processos e assinaturas'
try {
    $processes = @(Get-Process -ErrorAction Stop)
    AddFinding 'Processos' 'INFO' ('Quantidade em execucao: ' + $processes.Count + '. Nomes nao salvos no relatorio.')
    $rbx = @($processes | Where-Object { $_.ProcessName -eq 'RobloxPlayerBeta' })
    if ($rbx.Count -gt 0) { AddFinding 'Roblox' 'INFO' 'RobloxPlayerBeta presente no instante da verificacao.' }
    else { AddFinding 'Roblox' 'INFO' 'RobloxPlayerBeta nao esta aberto no instante da verificacao.' }

    # Sample up to 50 distinct readable executable paths, no names/paths in saved report.
    $sample = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $processes) {
        if ($sample.Count -ge 50) { break }
        try {
            $path = $p.Path
            if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path -PathType Leaf)) { [void]$sample.Add($path) }
        } catch { }
    }
    $valid=0; $unsigned=0; $unavailable=0
    foreach ($path in $sample) {
        $state = FileSignatureCheck $path
        if ($state -eq 'Valid') { $valid++ }
        elseif ($state -eq 'NotSigned') { $unsigned++ }
        else { $unavailable++ }
    }
    AddFinding 'Amostra de assinaturas' 'INFO' ("Arquivos: $($sample.Count); validos: $valid; nao assinados: $unsigned; outros/indisponiveis: $unavailable.")
    if ($unsigned -gt 0) { AddFinding 'Assinaturas' 'REVIEW' 'Arquivos sem assinatura existem; isso NAO indica cheat por si so.' }
    if ($ShowProcesses) {
        PrintLine '  Exibicao local opcional (nao registrada no relatorio):' DarkCyan
        $processes | Sort-Object ProcessName | Select-Object -First 60 ProcessName,Id | Format-Table -AutoSize | Out-Host
    }
} catch { AddFinding 'Processos' 'INFO' 'Nao foi possivel completar a consulta.' }

Header 'Integridade do verificador'
try {
    $digest = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash
    AddFinding 'SHA-256 do script' 'INFO' $digest
} catch { AddFinding 'SHA-256 do script' 'INFO' 'Hash indisponivel.' }

Header 'Resultado e relatorios'
$reviewCount = @($script:Findings | Where-Object { $_.Status -eq 'REVIEW' }).Count
$okCount = @($script:Findings | Where-Object { $_.Status -eq 'OK' }).Count
$infoCount = @($script:Findings | Where-Object { $_.Status -eq 'INFO' }).Count
PrintLine ("  OK: $okCount   REVIEW: $reviewCount   INFO: $infoCount") White
PrintLine '  Alertas exigem revisao humana. Nenhuma etapa comprova ausencia de cheats.' Yellow
try {
    $doc = [Environment]::GetFolderPath('MyDocuments')
    if ([string]::IsNullOrWhiteSpace($doc)) { throw 'Pasta Documentos indisponivel.' }
    $dir = Join-Path $doc 'MVS-Lost-Media-T1'
    New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
    $prefix = 'SENTINEL-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $script:Session
    $fullPath = Join-Path $dir ($prefix + '.txt')
    $discordPath = Join-Path $dir ($prefix + '-DISCORD.txt')
    $lines = @('MVS LOST MEDIA - SENTINEL / T1:01','Sessao: ' + $script:Session,'Data local: ' + $script:Stamp,'Modo: somente leitura','')
    $lines += $script:Findings | ForEach-Object { '[{0}] {1}: {2}' -f $_.Status, $_.Section, $_.Detail }
    $lines += @('',"RESUMO: OK=$okCount | REVIEW=$reviewCount | INFO=$infoCount",'Sem diagnostico automatico de cheat.')
    $lines | Set-Content -LiteralPath $fullPath -Encoding UTF8 -ErrorAction Stop
    $discord = @('**MVS LOST MEDIA | SENTINEL T1:01**','Sessao: `' + $script:Session + '`',"OK: **$okCount** | Revisao: **$reviewCount** | Info: **$infoCount**",'Resultado: revisao manual necessaria; nao constitui prova de cheat.')
    $discord | Set-Content -LiteralPath $discordPath -Encoding UTF8 -ErrorAction Stop
    PrintLine ('  Relatorio: ' + $fullPath) Cyan
    PrintLine ('  Texto Discord: ' + $discordPath) Cyan
} catch { PrintLine ('  Falha ao salvar relatorio: ' + $_.Exception.Message) Yellow }

PrintLine '  FINALIZADO | MVS LOST MEDIA' DarkCyan
if (-not $NoPause) { Write-Host ''; [void](Read-Host '  Pressione ENTER para fechar') }
