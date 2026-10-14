#requires -Version 5.1
<#
MVS LOST MEDIA | T1 SYSTEM CHECK 3.4.1
Independent implementation inspired by the categories of the MCL recording checks.
Read-only security checks; optional official Microsoft Process Explorer download.
Does not delete files, stop other processes, change registry/security settings,
or send reports over the network. The Registry Check is an independent second verification.
#>
[CmdletBinding()]
param([switch]$NoPause, [switch]$SkipProcessExplorer)

$ErrorActionPreference = 'Continue'
$script:Rows = New-Object 'System.Collections.Generic.List[object]'
$script:Lines = New-Object 'System.Collections.Generic.List[string]'
$script:Session = ([guid]::NewGuid().ToString('N').Substring(0,8)).ToUpperInvariant()
$script:StartTimeUtc = (Get-Date).ToUniversalTime()
$script:Docs = [Environment]::GetFolderPath('MyDocuments')
if ([string]::IsNullOrWhiteSpace($script:Docs)) { $script:Docs = Join-Path $env:USERPROFILE 'Documents' }
$script:Folder = Join-Path $script:Docs 'MVS-Lost-Media-T1'

function LM-Banner([string]$Phase, [string]$Code) {
    try { $Host.UI.RawUI.WindowTitle = 'LM / TIER ONE - SYSTEM CHECK - MVS LOST MEDIA' } catch { }
    Clear-Host
    LM-Line ('  +' + ('-' * 68) + '+') DarkCyan
    LM-Line ('  | ' + 'LM // TIER ONE'.PadRight(66) + ' |') Cyan
    LM-Line ('  |' + ('-' * 68) + '|') DarkCyan
    LM-Line ('  | ' + '        _       __  __'.PadRight(66) + ' |') Cyan
    LM-Line ('  | ' + '       | |     |  \/  |'.PadRight(66) + ' |') Cyan
    LM-Line ('  | ' + '       | |     | |\/| |   M V S   /   L O S T   M E D I A'.PadRight(66) + ' |') Cyan
    LM-Line ('  | ' + '       | |___  | |  | |   INTEGRITY / MATCH / REVIEW'.PadRight(66) + ' |') White
    LM-Line ('  | ' + '       |_____| |_|  |_|'.PadRight(66) + ' |') Cyan
    LM-Line ('  |' + ('-' * 68) + '|') DarkCyan
    LM-Line ('  | ' + ('MODE: '+$Phase+'    BUILD 3.4.1    SESSION: '+$Code).PadRight(66) + ' |') Magenta
    LM-Line ('  +' + ('-' * 68) + '+') DarkCyan
    LM-Line '  [LOCAL CHECK] Somente leitura // Sem envio de relatorios' DarkGray
    LM-Line '  [NOTICE] Um alerta isolado nao comprova cheat.' DarkYellow
}
function LM-Ending([string]$Phase) {
    LM-Line ''
    LM-Line ('  +' + ('-' * 68) + '+') DarkCyan
    LM-Line ('  | ' + ($Phase+' FINALIZADO  //  MVS LOST MEDIA').PadRight(66) + ' |') Cyan
    LM-Line ('  | ' + 'Relatorios gravados. Os resultados permanecem na tela.'.PadRight(66) + ' |') Gray
    LM-Line ('  +' + ('-' * 68) + '+') DarkCyan
    if ($NoPause) { return }
    Write-Host ''
    # Limpa teclas antigas (incluindo o ENTER usado para executar o comando).
    # A mensagem so aparece DEPOIS de limpar a fila para nao encerrar sem querer.
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
function LM-Line([string]$Message = '', [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    Write-Host $Message -ForegroundColor $Color
    [void]$script:Lines.Add($Message)
}
function LM-Item([string]$Section, [string]$Label, [string]$Status, [string]$Detail) {
    $palette = @{ OK='Green'; REVIEW='Yellow'; INFO='Gray'; UNVERIFIED='DarkYellow' }
    $color = 'White'
    if ($palette.ContainsKey($Status)) { $color = $palette[$Status] }
    LM-Line ('  {0,-10} : {1,-28} | {2}' -f ('['+$Status+']'), $Label, $Detail) $color
    [void]$script:Rows.Add([pscustomobject]@{Section=$Section; Label=$Label; Status=$Status; Detail=$Detail})
}
function LM-Stage([string]$Title, [int]$Number) {
    LM-Line ''
    LM-Line ('  <<  {0:00}  /  {1}' -f $Number,$Title.ToUpperInvariant()) Magenta
    LM-Line ('  ' + ('-' * 68)) DarkCyan
}
function LM-Progress([int]$Percent, [string]$Text) {
    $step = [Math]::Max(0,[Math]::Min(24,[int][Math]::Floor($Percent * 24 / 100)))
    Write-Host ("`r  LM-SCAN [{0}{1}] {2,3}%  //  {3}      " -f ('=' * $step),('.' * (24-$step)),$Percent,$Text) -NoNewline -ForegroundColor Cyan
    if ($Percent -ge 100) { Write-Host '' }
}
function LM-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}
function LM-Signature([string]$FilePath) {
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return 'Indisponivel' }
    try { return [string](Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop).Status }
    catch { return 'Nao consultada' }
}
function LM-CheckModules {
    $moduleFolder = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
    if (-not (Test-Path -LiteralPath $moduleFolder)) {
        LM-Item 'MODULOS' 'Pasta de modulos' 'UNVERIFIED' 'Pasta nao encontrada.'
        return
    }
    $all = @()
    try { $all = @(Get-ChildItem -LiteralPath $moduleFolder -Directory -ErrorAction Stop) }
    catch { LM-Item 'MODULOS' 'Lista de modulos' 'UNVERIFIED' 'Sem acesso.'; return }
    LM-Item 'MODULOS' 'Modulos instalados' 'INFO' ('Encontrados: '+$all.Count+'. Nada sera removido.')
    $total = 0
    $invalid = New-Object 'System.Collections.Generic.List[string]'
    $unsigned = 0
    $skipped = 0
    foreach ($folder in $all) {
        $candidates = @()
        try {
            $candidates = @(Get-ChildItem -LiteralPath $folder.FullName -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in @('.psd1','.psm1','.dll') } | Select-Object -First 6)
        } catch { $skipped++; continue }
        foreach ($file in $candidates) {
            if ($total -ge 120) { break }
            $total++
            $status = LM-Signature $file.FullName
            if ($status -eq 'NotSigned') { $unsigned++ }
            elseif ($status -in @('HashMismatch','NotTrusted','NotSupportedFileFormat','UnknownError')) {
                if ($invalid.Count -lt 10) { [void]$invalid.Add($file.Name) }
            }
        }
        if ($total -ge 120) { break }
    }
    LM-Item 'MODULOS' 'Arquivos de modulo' 'INFO' ("Amostra de $total; sem assinatura: $unsigned; falhas de leitura: $skipped.")
    if ($invalid.Count -gt 0) {
        LM-Item 'MODULOS' 'Assinaturas para revisao' 'REVIEW' ("$($invalid.Count) arquivo(s) com estado anormal na amostra.")
        foreach($name in $invalid) { LM-Item 'MODULOS' $name 'REVIEW' 'Assinatura invalida ou nao confiavel; revisar manualmente.' }
    } else { LM-Item 'MODULOS' 'Assinaturas invalidas' 'INFO' 'Nenhum caso observado na amostra; nao e garantia de integridade.' }
    if ($unsigned -gt 0) { LM-Item 'MODULOS' 'Arquivos nao assinados' 'INFO' 'Arquivos PowerShell legitimos podem nao ter assinatura.' }
}
function LM-CheckWindows {
    if (LM-Admin) { LM-Item 'SISTEMA' 'Permissoes' 'INFO' 'Administrador; algumas consultas possuem cobertura ampliada.' }
    else { LM-Item 'SISTEMA' 'Permissoes' 'INFO' 'Usuario padrao; algumas consultas podem ser limitadas.' }
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        LM-Item 'SISTEMA' 'Windows' 'INFO' ('Build '+$os.BuildNumber)
    } catch { LM-Item 'SISTEMA' 'Windows' 'UNVERIFIED' 'Consulta indisponivel.' }
    try {
        $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
        LM-Item 'SISTEMA' 'Processador' 'INFO' (([string]$cpu.Name).Trim())
    } catch { LM-Item 'SISTEMA' 'Processador' 'UNVERIFIED' 'Consulta indisponivel.' }
    try {
        $gpus = @(Get-CimInstance Win32_VideoController -ErrorAction Stop)
        LM-Item 'SISTEMA' 'Adaptadores graficos' 'INFO' ('Quantidade: '+$gpus.Count)
    } catch { LM-Item 'SISTEMA' 'Adaptadores graficos' 'UNVERIFIED' 'Consulta indisponivel.' }
    $pwsh = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $sig = LM-Signature $pwsh
    if ($sig -eq 'Valid') { LM-Item 'SISTEMA' 'Assinatura PowerShell' 'OK' 'Valida.' }
    elseif ($sig -eq 'Indisponivel') { LM-Item 'SISTEMA' 'Assinatura PowerShell' 'UNVERIFIED' 'Arquivo nao encontrado.' }
    else { LM-Item 'SISTEMA' 'Assinatura PowerShell' 'REVIEW' $sig }
}
function LM-CheckProtections {
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        foreach ($setting in @(
            @{Name='Microsoft Defender'; Value=$st.AntivirusEnabled},
            @{Name='Tempo real'; Value=$st.RealTimeProtectionEnabled},
            @{Name='Tamper Protection'; Value=$st.IsTamperProtected}
        )) {
            if ($setting.Value -eq $true) { LM-Item 'SEGURANCA' $setting.Name 'OK' 'Habilitado.' }
            elseif ($setting.Value -eq $false) { LM-Item 'SEGURANCA' $setting.Name 'REVIEW' 'Desabilitado nesta consulta.' }
            else { LM-Item 'SEGURANCA' $setting.Name 'UNVERIFIED' 'Estado nao informado.' }
        }
    } catch { LM-Item 'SEGURANCA' 'Microsoft Defender' 'UNVERIFIED' 'Status nao acessivel.' }
    try {
        foreach ($f in @(Get-NetFirewallProfile -ErrorAction Stop)) {
            $status = if ($f.Enabled -eq $true) {'OK'} else {'REVIEW'}
            LM-Item 'SEGURANCA' ('Firewall '+$f.Name) $status $(if ($f.Enabled) {'Ativo.'} else {'Desativado.'})
        }
    } catch { LM-Item 'SEGURANCA' 'Firewall' 'UNVERIFIED' 'Consulta indisponivel.' }
    try {
        $hvci=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        if (@($hvci.SecurityServicesRunning) -contains 2) { LM-Item 'SEGURANCA' 'Integridade de memoria' 'OK' 'HVCI informado como em execucao.' }
        else { LM-Item 'SEGURANCA' 'Integridade de memoria' 'INFO' 'HVCI nao informado como em execucao; nao e prova de cheat.' }
    } catch { LM-Item 'SEGURANCA' 'Integridade de memoria' 'UNVERIFIED' 'Consulta nao disponivel.' }
}
function LM-CheckDefender {
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        foreach ($spec in @(
            @{Label='Pastas'; Prop='ExclusionPath'},
            @{Label='Processos'; Prop='ExclusionProcess'},
            @{Label='Extensoes'; Prop='ExclusionExtension'},
            @{Label='IPs'; Prop='ExclusionIpAddress'}
        )) {
            $n = @($pref.($spec.Prop) | Where-Object { $null -ne $_ -and [string]$_ -ne '' }).Count
            $status = if($n -gt 0){'REVIEW'}else{'OK'}
            LM-Item 'DEFENDER' ('Exclusoes '+$spec.Label) $status ("$n entrada(s); nenhum nome/caminho e guardado.")
        }
    } catch { LM-Item 'DEFENDER' 'Exclusoes' 'UNVERIFIED' 'Nao foi possivel consultar as exclusoes.' }
    try {
        $list = @(Get-MpThreat -ErrorAction Stop)
        LM-Item 'DEFENDER' 'Historico de ameacas' 'INFO' ("$($list.Count) registro(s) retornado(s); nao indica ameaca ativa.")
    } catch { LM-Item 'DEFENDER' 'Historico de ameacas' 'UNVERIFIED' 'Nao disponivel.' }
}
function LM-CheckRegistry {
    $keys = @(
        @{Label='Exclusoes - Pastas'; Path='HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'},
        @{Label='Exclusoes - Processos'; Path='HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes'},
        @{Label='Exclusoes - Extensoes'; Path='HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions'},
        @{Label='Exclusoes - IPs'; Path='HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses'},
        @{Label='Politica - Defender'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'}
    )
    foreach ($entry in $keys) {
        if (-not (Test-Path -LiteralPath $entry.Path)) { LM-Item 'REGISTRO' $entry.Label 'INFO' 'Chave nao encontrada.'; continue }
        try {
            $key = Get-Item -LiteralPath $entry.Path -ErrorAction Stop
            $fields = @($key.GetValueNames() | Where-Object { $_ -ne '' -and $_ -ne '(default)' })
            $status = if($fields.Count -gt 0){'REVIEW'}else{'OK'}
            LM-Item 'REGISTRO' $entry.Label $status ("$($fields.Count) valor(es) nao padrao; nao mostra dados privados.")
        } catch { LM-Item 'REGISTRO' $entry.Label 'UNVERIFIED' 'Acesso negado ou falha.' }
    }
}
function LM-CheckProcesses {
    $script:CurrentPids = @()
    try {
        $processes = @(Get-Process -ErrorAction Stop)
        $script:CurrentPids = @($processes | ForEach-Object {[int]$_.Id})
        LM-Item 'PROCESSOS' 'Em execucao' 'INFO' ("$($processes.Count) processos.")
        $roblox = @($processes | Where-Object {$_.ProcessName -eq 'RobloxPlayerBeta'})
        LM-Item 'PROCESSOS' 'RobloxPlayerBeta' 'INFO' ("$($roblox.Count) instancia(s).")
        $distinct = @{}
        $invalid = New-Object 'System.Collections.Generic.List[string]'
        $notSigned = New-Object 'System.Collections.Generic.List[string]'
        foreach ($p in $processes) {
            $path = $null
            try { $path = [string]$p.Path } catch { }
            if ([string]::IsNullOrWhiteSpace($path) -or $distinct.ContainsKey($path)) { continue }
            if ($distinct.Count -ge 130) { break }
            $distinct[$path] = $true
            $sig = LM-Signature $path
            if ($sig -eq 'NotSigned' -and $notSigned.Count -lt 10) { [void]$notSigned.Add([IO.Path]::GetFileName($path)) }
            elseif ($sig -notin @('Valid','NotSigned','Indisponivel','Nao consultada') -and $invalid.Count -lt 10) {
                [void]$invalid.Add([IO.Path]::GetFileName($path))
            }
        }
        LM-Item 'PROCESSOS' 'Assinaturas' 'INFO' ("$($distinct.Count) executaveis unicos consultados, limite 130.")
        if ($invalid.Count -gt 0) {
            foreach ($name in $invalid) { LM-Item 'PROCESSOS' $name 'REVIEW' 'Assinatura nao valida, sujeito a revisao.' }
        }
        if ($notSigned.Count -gt 0) {
            foreach($name in $notSigned) { LM-Item 'PROCESSOS' $name 'INFO' 'Sem assinatura; nao significa cheat.' }
        }
    } catch { LM-Item 'PROCESSOS' 'Lista de processos' 'UNVERIFIED' 'Falha na consulta.' }
}
function LM-SysmonCoverage {
    try {
        $log=Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
        if($log.IsEnabled) { LM-Item 'TELEMETRIA' 'Sysmon' 'INFO' 'Log disponivel; eventos dependem da configuracao previa.' }
        else { LM-Item 'TELEMETRIA' 'Sysmon' 'UNVERIFIED' 'Log desabilitado.' }
    } catch { LM-Item 'TELEMETRIA' 'Sysmon' 'UNVERIFIED' 'Nao instalado, sem acesso ou log ausente.' }
}
function LM-Export {
    try {
        if (-not (Test-Path -LiteralPath $script:Folder)) { [void](New-Item -ItemType Directory -Path $script:Folder -Force -ErrorAction Stop) }
        $out = Join-Path $script:Folder ('LM-T1-'+$script:Session+'-SYSTEM-INSPECAO.txt')
        $discord = Join-Path $script:Folder ('LM-T1-'+$script:Session+'-SYSTEM-DISCORD.txt')
        $script:Lines.ToArray() | Set-Content -LiteralPath $out -Encoding UTF8 -ErrorAction Stop
        $d = @('**MVS LOST MEDIA | T1 SYSTEM CHECK 3.4.1**',('Sessao: `'+$script:Session+'`'),'```')
        $d += @($script:Rows | ForEach-Object { '[{0}] {1}: {2}' -f $_.Status,$_.Label,$_.Detail })
        $d += @('```','Resultados sao indicios para revisao humana. Nao comprovam ausencia ou presenca de cheats.')
        $d | Set-Content -LiteralPath $discord -Encoding UTF8 -ErrorAction Stop
        Write-Host ('  [LOG] '+$out) -ForegroundColor Green
        Write-Host ('  [TICKET] '+$discord) -ForegroundColor Green
    } catch { Write-Host ('  Falha ao salvar relatorio: '+$_.Exception.Message) -ForegroundColor Yellow }
}
function LM-Explorer {
    LM-Stage 'PROCESS EXPLORER - MICROSOFT ORIGINAL' 2
    LM-Line '  Inspecao visual opcional com ferramenta oficial da Microsoft.' Gray
    if ($SkipProcessExplorer -or $NoPause) { LM-Line '  [INFO] Process Explorer ignorado nesta execucao.' Gray; return }
    $answer = Read-Host '  Baixar e abrir o Process Explorer da Microsoft? (S/N)'
    if ($answer -notmatch '^(s|sim)$') { LM-Line '  [INFO] Process Explorer ignorado por escolha do usuario.' Gray; return }
    try {
        $work = Join-Path $env:TEMP 'LM-T1-ProcessExplorer'
        if (-not (Test-Path -LiteralPath $work)) { [void](New-Item -ItemType Directory -Path $work -Force -ErrorAction Stop) }
        $zip = Join-Path $work 'ProcessExplorer.zip'
        $extracted = Join-Path $work 'Bin'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/ProcessExplorer.zip' -UseBasicParsing -OutFile $zip -ErrorAction Stop
        Expand-Archive -LiteralPath $zip -DestinationPath $extracted -Force -ErrorAction Stop
        $app = Get-ChildItem -LiteralPath $extracted -Filter 'procexp64.exe' -File -Recurse -ErrorAction Stop | Select-Object -First 1
        if ($null -eq $app) { throw 'Executavel 64-bit nao encontrado.' }
        $sig = Get-AuthenticodeSignature -LiteralPath $app.FullName -ErrorAction Stop
        $subject = if ($null -ne $sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { '' }
        if ($sig.Status -ne 'Valid' -or $subject -notmatch 'Microsoft') { throw 'Assinatura Microsoft ausente ou invalida. Execucao cancelada.' }
        LM-Item 'PROCESS EXPLORER' 'Assinatura oficial' 'OK' 'Assinatura digital Microsoft valida.'
        LM-Line '  Percorra os processos na janela e feche-a para continuar.' Cyan
        $proc=Start-Process -FilePath $app.FullName -PassThru -ErrorAction Stop
        if($null -ne $proc) { $proc.WaitForExit() }
        LM-Item 'PROCESS EXPLORER' 'Inspecao visual' 'INFO' 'Janela encerrada pelo usuario.'
    } catch { LM-Item 'PROCESS EXPLORER' 'Ferramenta opcional' 'UNVERIFIED' ('Nao iniciada: '+$_.Exception.Message) }
}

LM-Banner 'SYSTEM CHECK' $script:Session
LM-Progress 10 'Ambiente'
LM-Stage 'VERIFICACAO DE INTEGRIDADE' 1
LM-CheckWindows
LM-Progress 28 'Modulos'
LM-CheckModules
LM-Progress 50 'Seguranca do Windows'
LM-CheckProtections
LM-CheckDefender
LM-Progress 68 'Registro e processos'
LM-CheckRegistry
LM-CheckProcesses
LM-SysmonCoverage
LM-Progress 100 'Inspecao concluida'
$passed = @($script:Rows | Where-Object {$_.Status -eq 'OK'}).Count
$review = @($script:Rows | Where-Object {$_.Status -eq 'REVIEW'}).Count
$unverified = @($script:Rows | Where-Object {$_.Status -eq 'UNVERIFIED'}).Count
LM-Line ''
LM-Line ('  [RESULTADO]  OK: '+$passed+'   |   REVIEW: '+$review+'   |   NAO VERIFICADO: '+$unverified) Cyan
LM-Line '  Nenhum percentual representa um computador livre de cheats.' DarkYellow
LM-Explorer
LM-Export
LM-Line ''
LM-Line '  [INFO] Para concluir o T1, execute tambem o REGISTRY CHECK.' Cyan
LM-Ending 'SYSTEM CHECK'
