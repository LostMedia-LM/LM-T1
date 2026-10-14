#requires -Version 5.1
<#
MVS LOST MEDIA | T1 SYSTEM CHECK 3.5.0
Independent implementation inspired by the categories of the MCL recording checks.
Read-only security checks; optional official Microsoft Process Explorer download.
Does not delete files, stop other processes, change registry/security settings,
or send reports over the network. The Registry Check is an independent second verification.
#>
[CmdletBinding()]
param([switch]$NoPause, [switch]$SkipProcessExplorer, [switch]$SkipFilePicker)

$ErrorActionPreference = 'Continue'
$script:Rows = New-Object 'System.Collections.Generic.List[object]'
$script:Lines = New-Object 'System.Collections.Generic.List[string]'
$script:Session = ([guid]::NewGuid().ToString('N').Substring(0,8)).ToUpperInvariant()
$script:StartTimeUtc = (Get-Date).ToUniversalTime()
$script:Docs = [Environment]::GetFolderPath('MyDocuments')
if ([string]::IsNullOrWhiteSpace($script:Docs)) { $script:Docs = Join-Path $env:USERPROFILE 'Documents' }
$script:Folder = Join-Path $script:Docs 'MVS-Lost-Media-T1'
$script:Observations = New-Object 'System.Collections.Generic.List[object]'
$script:ReviewedNames = New-Object 'System.Collections.Generic.List[string]'
$script:RobloxRunning = $false


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
    LM-Line ('  | ' + ('MODE: '+$Phase+'    BUILD 3.5.0    SESSION: '+$Code).PadRight(66) + ' |') Magenta
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
    $palette = @{ OK='Green'; REVIEW='Red'; ATENCAO='Yellow'; INFO='Gray'; UNVERIFIED='DarkYellow' }
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
function LM-LocationClass([string]$FullPath) {
    if ([string]::IsNullOrWhiteSpace($FullPath)) { return 'Desconhecida' }
    $test = $FullPath.TrimEnd('\').ToLowerInvariant()
    $roots = @($env:TEMP, $env:TMP, $env:LOCALAPPDATA, $env:APPDATA,
        (Join-Path $env:USERPROFILE 'Downloads'), (Join-Path $env:USERPROFILE 'Desktop'))
    foreach ($root in $roots) {
        if (-not [string]::IsNullOrWhiteSpace($root)) {
            $rootText = $root.TrimEnd('\').ToLowerInvariant()
            if ($test.StartsWith($rootText + '\')) { return 'Pasta do usuario' }
        }
    }
    return 'Outra pasta'
}
function LM-InspectFile([string]$FullPath, [string]$Origin) {
    if ([string]::IsNullOrWhiteSpace($FullPath)) { return }
    try {
        $fi = Get-Item -LiteralPath $FullPath -ErrorAction Stop
        if ($fi.PSIsContainer) { return }
        $name = $fi.Name
        $signature = LM-Signature $fi.FullName
        $location = LM-LocationClass $fi.FullName
        $status = 'INFO'
        $reasons = New-Object 'System.Collections.Generic.List[string]'
        if ($signature -in @('HashMismatch', 'NotTrusted', 'UnknownError')) {
            $status='REVIEW'
            [void]$reasons.Add('assinatura invalida/nao confiavel')
        } elseif ($signature -eq 'NotSigned') {
            if ($location -eq 'Pasta do usuario') {
                $status='REVIEW'
                [void]$reasons.Add('sem assinatura e em pasta gravavel pelo usuario')
            } else {
                $status='ATENCAO'
                [void]$reasons.Add('sem assinatura digital')
            }
        } elseif ($signature -eq 'Valid') {
            [void]$reasons.Add('assinatura valida (nao garante seguranca)')
        } else {
            $status='UNVERIFIED'
            [void]$reasons.Add('assinatura nao verificada: '+$signature)
        }
        # Arquivos nao sao abertos nem executados. SHA-256 apenas para itens escolhidos
        # ou para os que precisam de revisao, com limite de tamanho para evitar travas.
        $sha = 'Nao calculado'
        if (($status -eq 'REVIEW' -or $Origin -eq 'SELECIONADO') -and $fi.Length -le 100MB) {
            try { $sha=(Get-FileHash -LiteralPath $fi.FullName -Algorithm SHA256 -ErrorAction Stop).Hash }
            catch { $sha='Indisponivel' }
        }
        $explain=[string]::Join('; ', $reasons.ToArray())
        $row=[pscustomobject]@{Name=$name; Status=$status; Origin=$Origin; Reason=$explain;
            Signature=$signature; Location=$location; SHA256=$sha }
        [void]$script:Observations.Add($row)
        if ($status -in @('REVIEW','ATENCAO') -or $Origin -eq 'SELECIONADO') {
            LM-Item 'ARQUIVOS' $name $status ("$Origin | $explain | $location | NAO COMPROVA CHEAT")
            if ($Origin -eq 'SELECIONADO') {
                LM-Item 'ARQUIVOS' ('Hash: '+$name) 'INFO' ('SHA256='+$sha)
            }
            if ($status -eq 'REVIEW') { [void]$script:ReviewedNames.Add($name) }
        }
    } catch {
        LM-Item 'ARQUIVOS' 'Arquivo inacessivel' 'UNVERIFIED' ('Nao foi possivel ler metadados. Origem: '+$Origin)
    }
}
function LM-CheckProcesses {
    try {
        $processes = @(Get-Process -ErrorAction Stop)
        LM-Item 'PROCESSOS' 'Em execucao' 'INFO' ("$($processes.Count) processos observados.")
        $roblox = @($processes | Where-Object { $_.ProcessName -eq 'RobloxPlayerBeta' })
        $script:RobloxRunning = $roblox.Count -gt 0
        LM-Item 'PROCESSOS' 'RobloxPlayerBeta' 'INFO' ("$($roblox.Count) instancia(s).")
        $distinct = @{}
        $noPath = 0
        foreach ($proc in $processes) {
            $path = $null
            try { $path = [string]$proc.Path } catch { }
            if ([string]::IsNullOrWhiteSpace($path)) { $noPath++; continue }
            if ($distinct.ContainsKey($path)) { continue }
            if ($distinct.Count -ge 130) { break }
            $distinct[$path]=$true
            LM-InspectFile $path 'PROCESSO ATIVO'
        }
        LM-Item 'PROCESSOS' 'Cobertura' 'INFO' ("$($distinct.Count) executaveis distintos; $noPath processos sem caminho acessivel; maximo 130.")
        $red=@($script:Observations | Where-Object {$_.Status -eq 'REVIEW' -and $_.Origin -eq 'PROCESSO ATIVO'}).Count
        $yellow=@($script:Observations | Where-Object {$_.Status -eq 'ATENCAO' -and $_.Origin -eq 'PROCESSO ATIVO'}).Count
        LM-Item 'PROCESSOS' 'Sinais em executaveis' 'INFO' ("Para revisar: $red; sem assinatura isolada: $yellow.")
    } catch {
        LM-Item 'PROCESSOS' 'Lista de processos' 'UNVERIFIED' 'Nao foi possivel consultar a lista completa.'
    }
}
function LM-SelectLocalFiles {
    LM-Stage 'ARQUIVOS ESCOLHIDOS PELO JOGADOR (OPCIONAL)' 2
    LM-Line '  Os arquivos so serao lidos localmente; nao serao executados ou enviados.' Gray
    LM-Line '  O nome e o SHA-256 dos arquivos selecionados podem entrar no relatorio local.' DarkYellow
    if ($NoPause -or $SkipFilePicker) {
        LM-Item 'ARQUIVOS' 'Selecao opcional' 'INFO' 'Etapa nao solicitada.'
        return
    }
    $answer=Read-Host '  Deseja escolher arquivos para analise? (S/N)'
    if ($answer -notmatch '^(s|sim)$') {
        LM-Item 'ARQUIVOS' 'Selecao opcional' 'INFO' 'Ignorada por escolha do jogador.'
        return
    }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dialog=New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title='MVS LOST MEDIA - Selecione ate 5 arquivos para inspecao local'
        $dialog.Filter='Arquivos executaveis (*.exe;*.dll;*.ps1)|*.exe;*.dll;*.ps1|Todos os arquivos (*.*)|*.*'
        $dialog.Multiselect=$true
        $dialog.CheckFileExists=$true
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
            LM-Item 'ARQUIVOS' 'Selecao opcional' 'INFO' 'Cancelada.'
            return
        }
        $fileNames=@($dialog.FileNames | Select-Object -First 5)
        foreach($file in $fileNames) { LM-InspectFile $file 'SELECIONADO' }
        LM-Item 'ARQUIVOS' 'Arquivos selecionados' 'INFO' ("$($fileNames.Count) arquivo(s) analisados localmente.")
    } catch {
        LM-Item 'ARQUIVOS' 'Selecao de arquivos' 'UNVERIFIED' 'Janela de selecao indisponivel neste host.'
    }
}
function LM-SysmonRoblox {
    LM-Stage 'REGISTROS DE INTERACAO COM ROBLOX' 3
    $logName='Microsoft-Windows-Sysmon/Operational'
    try {
        $log=Get-WinEvent -ListLog $logName -ErrorAction Stop
        if (-not $log.IsEnabled) { throw 'Log desabilitado' }
    } catch {
        LM-Item 'EXECUTORES' 'Eventos de thread/integridade' 'UNVERIFIED' 'Sysmon indisponivel; nenhuma conclusao possivel.'
        LM-Item 'EXTERNALS' 'Eventos de acesso' 'UNVERIFIED' 'Sysmon indisponivel; nenhuma conclusao possivel.'
        return
    }
    $events=@()
    try {
        $events=@(Get-WinEvent -FilterHashtable @{LogName=$logName;ID=@(8,10,25);StartTime=(Get-Date).AddMinutes(-60)} -MaxEvents 250 -ErrorAction Stop)
    } catch {
        LM-Item 'EXECUTORES' 'Eventos Sysmon' 'UNVERIFIED' 'Nao ha registros na amostra ou consulta falhou.'
        LM-Item 'EXTERNALS' 'Eventos Sysmon' 'UNVERIFIED' 'Nao ha registros na amostra ou consulta falhou.'
        return
    }
    $matching=0
    foreach ($evt in $events) {
        try {
            [xml]$xml=$evt.ToXml()
            $fields=@{}
            foreach($d in @($xml.Event.EventData.Data)) { $fields[[string]$d.Name]=[string]$d.'#text' }
            $target=[string]$fields['TargetImage']
            if ($evt.Id -eq 25) { $target=[string]$fields['Image'] }
            if ($target -notmatch '(?i)robloxplayerbeta\.exe$') { continue }
            $matching++
            $source=([IO.Path]::GetFileName([string]$fields['SourceImage']))
            if ([string]::IsNullOrWhiteSpace($source)) { $source='Origem nao informada' }
            $date=$evt.TimeCreated.ToString('HH:mm:ss')
            if ($evt.Id -eq 10) {
                $granted=[string]$fields['GrantedAccess']
                $rights='permissoes nao interpretadas'
                try {
                    $mask=[Convert]::ToInt64($granted.Replace('0x',''),16)
                    $rightsList=New-Object 'System.Collections.Generic.List[string]'
                    if (($mask -band 0x10) -ne 0) { [void]$rightsList.Add('VM_READ') }
                    if (($mask -band 0x20) -ne 0) { [void]$rightsList.Add('VM_WRITE') }
                    if (($mask -band 0x8) -ne 0) { [void]$rightsList.Add('VM_OPERATION') }
                    if (($mask -band 0x2) -ne 0) { [void]$rightsList.Add('CREATE_THREAD') }
                    $rights=if ($rightsList.Count -gt 0) {[string]::Join(',', $rightsList.ToArray())} else {'Outras permissoes'}
                } catch { }
                LM-Item 'EXTERNALS' $source 'REVIEW' ("Sysmon 10 | $date | concedido $granted ($rights); nao prova leitura/escrita de memoria.")
            } elseif ($evt.Id -eq 8) {
                LM-Item 'EXECUTORES' $source 'REVIEW' ("Sysmon 8 | $date | thread remota registrada; verificar contexto.")
            } else {
                LM-Item 'EXECUTORES' 'Roblox' 'REVIEW' ("Sysmon 25 | $date | evento de alteracao de processo; verificar contexto.")
            }
            if ($matching -ge 12) { break }
        } catch { continue }
    }
    if ($matching -eq 0) {
        LM-Item 'EXTERNALS' 'Acessos ao Roblox' 'INFO' 'Nenhum evento correspondente na amostra; nao comprova ausencia.'
        LM-Item 'EXECUTORES' 'Alteracoes remotas' 'INFO' 'Nenhum evento correspondente na amostra; nao comprova ausencia.'
    }
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
        # Nomes e SHA de arquivos analisados com permissao expressa, sem caminhos completos.
        $evidence = Join-Path $script:Folder ('LM-T1-'+$script:Session+'-ARQUIVOS.txt')
        @($script:Observations | Where-Object {$_.Status -in @('REVIEW','ATENCAO') -or $_.Origin -eq 'SELECIONADO'} |
            ForEach-Object { '{0} | {1} | {2} | {3} | SHA256={4}' -f $_.Name,$_.Status,$_.Origin,$_.Reason,$_.SHA256 }) |
            Set-Content -LiteralPath $evidence -Encoding UTF8 -ErrorAction Stop
        $d = @('**MVS LOST MEDIA | T1 SYSTEM CHECK 3.5.0**',('Sessao: `'+$script:Session+'`'),'```')
        $d += @($script:Rows | ForEach-Object { '[{0}] {1}: {2}' -f $_.Status,$_.Label,$_.Detail })
        $d += @('```','Resultados sao indicios para revisao humana. Nao comprovam ausencia ou presenca de cheats.')
        $d | Set-Content -LiteralPath $discord -Encoding UTF8 -ErrorAction Stop
        Write-Host ('  [ARQUIVOS] '+$evidence) -ForegroundColor Green
        Write-Host ('  [LOG] '+$out) -ForegroundColor Green
        Write-Host ('  [TICKET] '+$discord) -ForegroundColor Green
    } catch { Write-Host ('  Falha ao salvar relatorio: '+$_.Exception.Message) -ForegroundColor Yellow }
}
function LM-Explorer {
    LM-Stage 'PROCESS EXPLORER - MICROSOFT ORIGINAL' 4
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
LM-Progress 82 'Analise de arquivos'
LM-SelectLocalFiles
LM-Progress 91 'Eventos de processos'
LM-SysmonRoblox
LM-Progress 100 'Inspecao concluida'
$passed = @($script:Rows | Where-Object {$_.Status -eq 'OK'}).Count
$review = @($script:Rows | Where-Object {$_.Status -eq 'REVIEW'}).Count
$unverified = @($script:Rows | Where-Object {$_.Status -eq 'UNVERIFIED'}).Count
LM-Line ''
LM-Line ('  [RESULTADO]  OK: '+$passed+'   |   REVIEW: '+$review+'   |   NAO VERIFICADO: '+$unverified) Cyan
LM-Line '  [VERMELHO] = INDICIO PARA REVISAR; NAO SIGNIFICA CHEAT CONFIRMADO.' Red
LM-Line '  Metadados nao revelam automaticamente se um programa e external ou executor.' DarkYellow
LM-Line '  Nenhum percentual representa um computador livre de cheats.' DarkYellow
LM-Explorer
LM-Export
LM-Line ''
LM-Line '  [INFO] Para concluir o T1, execute tambem o REGISTRY CHECK.' Cyan
LM-Ending 'SYSTEM CHECK'
