#requires -Version 5.1
<#
  MVS LOST MEDIA | T2 RECORDING 1.0
  Implementacao independente de verificacao local e voluntaria..
  Credito da identidade MVS Lost Media: Mangak.

  Consultas de leitura. Nao desativa protecoes, nao exclui vestigios,
  nao envia informacoes para servidores. Apenas relatorios na pasta Documentos.
  Ferramentas oficiais da Microsoft so sao baixadas mediante confirmacao.
#>
[CmdletBinding()]
param(
    [switch]$NoPause,
    [switch]$SkipTools,
    [switch]$SkipViewer,
    [ValidateRange(0,120)][int]$MonitorMinutes = 0
)

$ErrorActionPreference = 'Continue'
$script:Session = [guid]::NewGuid().ToString('N').Substring(0,8).ToUpperInvariant()
$script:Rows = New-Object 'System.Collections.Generic.List[object]'
$script:Collected = New-Object 'System.Collections.Generic.List[string]'
$script:Capture = New-Object 'System.Collections.Generic.List[string]'
$script:Documents = [Environment]::GetFolderPath('MyDocuments')
if (-not $script:Documents) { $script:Documents = Join-Path $env:USERPROFILE 'Documents' }
$script:Folder = Join-Path $script:Documents 'MVS-Lost-Media-T2'
$script:Start = Get-Date
$script:BaselineProcesses = @{}

function LM-Print([string]$Text = '', [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    Write-Host $Text -ForegroundColor $Color
    [void]$script:Capture.Add($Text)
}
function LM-Result([string]$Group, [string]$Status, [string]$Name, [string]$Detail) {
    $colors = @{OK='Green'; SUSPEITO='Red'; ATENCAO='Yellow'; INFO='Gray'; INDISPONIVEL='DarkYellow'}
    $color = 'Gray'; if ($colors.ContainsKey($Status)) { $color=$colors[$Status] }
    LM-Print ('  [{0}] {1} - {2}' -f $Status,$Name,$Detail) $color
    [void]$script:Rows.Add([pscustomobject]@{Etapa=$Group; Status=$Status; Item=$Name; Detalhe=$Detail})
}
function LM-Header {
    try { $Host.UI.RawUI.WindowTitle='LOST MEDIA | T2 RECORDING' } catch {}
    Clear-Host
    LM-Print '  +------------------------------------------------------------------+' DarkCyan
    LM-Print '  |                         LOST MEDIA                               |' Cyan
    LM-Print '  |                     T2 RECORDING POLICY                             |' White
    LM-Print '  +------------------------------------------------------------------+' DarkCyan
    LM-Print '  Justice Department: https://discord.gg/gsdQbYFP79' Gray
    LM-Print '  LM Oficial:         https://discord.gg/2gP6MaKURK' Gray
    LM-Print '  Personalizacao: Mangak  |  Referencia de categorias: LOC T2 / mortrunsloc' DarkGray
    LM-Print ("  Sessao: $script:Session  |  Execucao local e voluntaria") DarkGray
    LM-Print ''
}
function LM-Stage([int]$N, [string]$Name) {
    LM-Print ''
    LM-Print ('  [{0}/8] {1}' -f $N,$Name.ToUpperInvariant()) Cyan
    LM-Print ('  '+('-'*66)) DarkCyan
}
function LM-Next {
    if (-not $NoPause) { [void](Read-Host '  Pressione ENTER para continuar') }
}
function LM-Admin {
    try {
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        $principal=New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}
function LM-GetSignature([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'Indisponivel' }
    try { return [string](Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop).Status }
    catch { return 'Indisponivel' }
}
function LM-ProcessRows {
    $list=@()
    try { $list=@(Get-CimInstance Win32_Process -ErrorAction Stop) } catch { return @() }
    foreach ($proc in $list) {
        $p=[string]$proc.ExecutablePath
        $name=[string]$proc.Name
        if (-not $p) { continue }
        [pscustomobject]@{PID=[int]$proc.ProcessId; Name=$name; Path=$p}
    }
}
function LM-CheckProcesses {
    $items=@(LM-ProcessRows | Select-Object -First 150)
    if ($items.Count -eq 0) {
        LM-Result 'SISTEMA' 'INDISPONIVEL' 'Processos' 'Lista de caminhos nao acessivel.'
        return
    }
    $seen=@{}; $review=0; $yellow=0
    $known=@{
        'svchost.exe'=@('system32\svchost.exe','syswow64\svchost.exe');
        'lsass.exe'=@('system32\lsass.exe');
        'services.exe'=@('system32\services.exe');
        'csrss.exe'=@('system32\csrss.exe');
        'winlogon.exe'=@('system32\winlogon.exe')
    }
    foreach ($proc in $items) {
        $name=$proc.Name.ToLowerInvariant(); $path=$proc.Path
        $script:BaselineProcesses[[string]$proc.PID] = $proc.Name
        if ($seen.ContainsKey($path)) { continue }
        $seen[$path]=$true
        $sig=LM-GetSignature $path
        $reason=''
        if ($known.ContainsKey($name)) {
            $good=$false
            foreach ($suffix in $known[$name]) {
                if ($path.ToLowerInvariant().EndsWith(('\'+$suffix))) { $good=$true; break }
            }
            if (-not $good) { $reason='Nome de processo do Windows em caminho inesperado' }
        }
        if ($sig -in @('HashMismatch','NotTrusted')) {
            LM-Result 'SISTEMA' 'SUSPEITO' $proc.Name ("Assinatura $sig | $path")
            $review++
        } elseif ($reason) {
            LM-Result 'SISTEMA' 'SUSPEITO' $proc.Name ("$reason | $path")
            $review++
        } elseif ($sig -eq 'NotSigned') {
            $yellow++
            if ($yellow -le 8) { LM-Result 'SISTEMA' 'ATENCAO' $proc.Name 'Executavel sem assinatura digital.' }
        }
    }
    LM-Result 'SISTEMA' 'INFO' 'Processos analisados' ("$($seen.Count) executaveis diferentes; suspeitos $review; nao assinados $yellow")
}
function LM-System {
    LM-Stage 1 'Verificacao do sistema'
    if (LM-Admin) { LM-Result 'SISTEMA' 'INFO' 'Permissoes' 'Administrador.' }
    else { LM-Result 'SISTEMA' 'ATENCAO' 'Permissoes' 'Acesso limitado; algumas consultas poderao falhar.' }
    try {
        $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        LM-Result 'SISTEMA' 'INFO' 'Windows' ([string]$os.Caption+' | Build '+[string]$os.BuildNumber)
    } catch { LM-Result 'SISTEMA' 'INDISPONIVEL' 'Windows' 'Sem acesso a consulta.' }
    try {
        $d=Get-MpComputerStatus -ErrorAction Stop
        if ($d.RealTimeProtectionEnabled) { LM-Result 'SISTEMA' 'OK' 'Microsoft Defender' 'Protecao em tempo real ativa.' }
        else { LM-Result 'SISTEMA' 'ATENCAO' 'Microsoft Defender' 'Protecao em tempo real desativada ou antivirus alternativo.' }
    } catch { LM-Result 'SISTEMA' 'INDISPONIVEL' 'Defender' 'Status indisponivel.' }
    try {
        $prefs=Get-MpPreference -ErrorAction Stop
        $exCount=@($prefs.ExclusionPath|Where-Object {$_}).Count+@($prefs.ExclusionProcess|Where-Object {$_}).Count+@($prefs.ExclusionExtension|Where-Object {$_}).Count
        if ($exCount -gt 0) { LM-Result 'SISTEMA' 'ATENCAO' 'Exclusoes do Defender' "$exCount exclusoes configuradas; revisar na interface do Windows." }
        else { LM-Result 'SISTEMA' 'OK' 'Exclusoes do Defender' 'Nenhuma nas categorias consultadas.' }
    } catch { LM-Result 'SISTEMA' 'INDISPONIVEL' 'Exclusoes do Defender' 'Consulta bloqueada.' }
    LM-CheckProcesses
}
function LM-BamEntries {
    $data=New-Object 'System.Collections.Generic.List[object]'
    foreach ($root in @('SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'SYSTEM\CurrentControlSet\Services\dam\State\UserSettings')) {
        try {
            $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($root)
            if (-not $key) { continue }
            foreach ($sid in $key.GetSubKeyNames()) {
                $sub=$key.OpenSubKey($sid)
                if (-not $sub) { continue }
                foreach ($name in $sub.GetValueNames()) {
                    if (-not $name) { continue }
                    $dt='Indefinido'
                    try {
                        $val=$sub.GetValue($name)
                        if ($val -is [byte[]] -and $val.Length -ge 8) {
                            $stamp=[BitConverter]::ToInt64($val,0)
                            $dt=[DateTime]::FromFileTimeUtc($stamp).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
                        }
                    } catch {}
                    [void]$data.Add([pscustomobject]@{Arquivo=[IO.Path]::GetFileName($name); UltimaExecucao=$dt; Caminho=$name})
                    if ($data.Count -ge 800) { break }
                }
                $sub.Close()
                if ($data.Count -ge 800) { break }
            }
            $key.Close()
        } catch {}
        if ($data.Count -ge 800) { break }
    }
    return $data.ToArray()
}
function LM-Viewer([string]$Title, [object[]]$Objects) {
    if ($SkipViewer -or $NoPause -or $Objects.Count -eq 0) { return }
    $answer=Read-Host '  Abrir lista de detalhes nesta tela? (S/N)'
    if ($answer -notmatch '^(s|sim)$') { return }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        $form=New-Object System.Windows.Forms.Form
        $form.Text=$Title
        $form.Width=1100; $form.Height=620; $form.StartPosition='CenterScreen'
        $table=New-Object System.Windows.Forms.DataGridView
        $table.Dock='Fill'; $table.ReadOnly=$true
        $table.AllowUserToAddRows=$false; $table.AllowUserToDeleteRows=$false
        $table.AutoSizeColumnsMode='Fill'; $table.SelectionMode='FullRowSelect'
        $dt=New-Object System.Data.DataTable
        foreach ($p in $Objects[0].PSObject.Properties) { [void]$dt.Columns.Add($p.Name) }
        foreach ($item in ($Objects|Select-Object -First 600)) {
            $row=$dt.NewRow()
            foreach ($p in $item.PSObject.Properties) { $row[$p.Name]=[string]$p.Value }
            $dt.Rows.Add($row)
        }
        $table.DataSource=$dt
        [void]$form.Controls.Add($table)
        [void]$form.ShowDialog()
        $form.Dispose()
    } catch { LM-Result 'VISUALIZACAO' 'INDISPONIVEL' $Title 'Janela indisponivel; dados examinados no console.' }
}
function LM-Bam {
    LM-Stage 2 'BAM / DAM - historico de execucao'
    $entries=@(LM-BamEntries)
    if ($entries.Count -eq 0) { LM-Result 'BAM' 'INDISPONIVEL' 'Historico BAM' 'Sem registros acessiveis.'; return }
    LM-Result 'BAM' 'INFO' 'Entradas encontradas' "$($entries.Count) itens (limite 800)."
    foreach ($e in ($entries|Sort-Object UltimaExecucao -Descending|Select-Object -First 15)) {
        LM-Print ('  {0}  {1}' -f $e.UltimaExecucao,$e.Arquivo) DarkGray
    }
    LM-Viewer 'Lost Media | T2 | BAM / DAM' $entries
}
function LM-Prefetch {
    LM-Stage 3 'Prefetch - vestigios de execucao'
    $folder=Join-Path $env:WINDIR 'Prefetch'
    if (-not (Test-Path -LiteralPath $folder)) { LM-Result 'PREFETCH' 'INDISPONIVEL' 'Pasta Prefetch' 'Nao encontrada.'; return }
    try { $files=@(Get-ChildItem -LiteralPath $folder -Filter '*.pf' -File -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First 900) }
    catch { LM-Result 'PREFETCH' 'INDISPONIVEL' 'Arquivos .pf' 'Permissao insuficiente.'; return }
    LM-Result 'PREFETCH' 'INFO' 'Arquivos .pf' "$($files.Count) arquivos encontrados (limite 900)."
    $rows=@(foreach ($f in $files) { [pscustomobject]@{Arquivo=$f.Name; Modificado=$f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); KB=[math]::Round($f.Length/1KB,1)} })
    foreach ($f in ($rows|Select-Object -First 15)) { LM-Print ("  $($f.Modificado)  $($f.Arquivo)") DarkGray }
    LM-Viewer 'Lost Media | T2 | Prefetch' $rows
}
function LM-MicrosoftTool([string]$Name, [string]$Url, [string[]]$Executables) {
    if ($NoPause -or $SkipTools) {
        LM-Result 'FERRAMENTAS' 'INFO' $Name 'Etapa opcional ignorada.'
        return
    }
    $answer=Read-Host ("  Baixar e abrir $Name da Microsoft? (S/N)")
    if ($answer -notmatch '^(s|sim)$') { LM-Result 'FERRAMENTAS' 'INFO' $Name 'Nao solicitado.';return }
    try {
        $root=Join-Path $env:TEMP ('LostMedia-T2-'+($Name -replace '[^a-zA-Z0-9]',''))
        [void](New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop)
        $zip=Join-Path $root 'official.zip'
        $dest=Join-Path $root 'extracted'
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Url -UseBasicParsing -OutFile $zip -TimeoutSec 70 -ErrorAction Stop
        Expand-Archive -LiteralPath $zip -DestinationPath $dest -Force -ErrorAction Stop
        $file=$null
        foreach ($fname in $Executables) {
            $file=Get-ChildItem -LiteralPath $dest -Recurse -File -Filter $fname -ErrorAction SilentlyContinue|Select-Object -First 1
            if ($file) { break }
        }
        if (-not $file) { throw 'Executavel nao encontrado no pacote oficial.' }
        $sig=Get-AuthenticodeSignature -LiteralPath $file.FullName -ErrorAction Stop
        $subject=if($sig.SignerCertificate){[string]$sig.SignerCertificate.Subject}else{''}
        if ($sig.Status -ne 'Valid' -or $subject -notmatch 'Microsoft') { throw 'Assinatura Microsoft nao validada; abertura cancelada.' }
        LM-Result 'FERRAMENTAS' 'OK' $Name 'Assinatura Microsoft validada.'
        Start-Process -FilePath $file.FullName -Wait -ErrorAction Stop
    } catch { LM-Result 'FERRAMENTAS' 'INDISPONIVEL' $Name $_.Exception.Message }
}
function LM-Logs {
    LM-Stage 5 'Eventos e auditoria do Windows'
    $since=(Get-Date).AddHours(-3)
    foreach ($spec in @(
        @{Log='Security'; IDs=@(1102,4688); Nome='Security'},
        @{Log='System'; IDs=@(104); Nome='System'},
        @{Log='Microsoft-Windows-Windows Defender/Operational'; IDs=@(1116,1117,5007); Nome='Windows Defender'},
        @{Log='Microsoft-Windows-PowerShell/Operational'; IDs=@(4104); Nome='PowerShell'},
        @{Log='Microsoft-Windows-Sysmon/Operational'; IDs=@(8,10,25); Nome='Sysmon'}
    )) {
        try {
            $log=Get-WinEvent -ListLog $spec.Log -ErrorAction Stop
            if (-not $log.IsEnabled) { LM-Result 'EVENTOS' 'INDISPONIVEL' $spec.Nome 'Canal desabilitado.'; continue }
            $events=@(Get-WinEvent -FilterHashtable @{LogName=$spec.Log;Id=$spec.IDs;StartTime=$since} -MaxEvents 160 -ErrorAction SilentlyContinue)
            if ($spec.Nome -eq 'Sysmon') {
                if ($events.Count -eq 0) { LM-Result 'EVENTOS' 'INFO' 'Sysmon' 'Sem eventos dos tipos consultados na janela.'; continue }
                $matches=0
                foreach ($evt in $events) {
                    try {
                        [xml]$xml=$evt.ToXml(); $values=@{}
                        foreach ($d in @($xml.Event.EventData.Data)) { $values[[string]$d.Name]=[string]$d.'#text' }
                        $dest=[string]$values['TargetImage']
                        if ($evt.Id -eq 25) { $dest=[string]$values['Image'] }
                        if ($dest -notmatch '(?i)RobloxPlayerBeta\.exe$') { continue }
                        $src=[IO.Path]::GetFileName([string]$values['SourceImage'])
                        if (-not $src) { $src='origem nao identificada' }
                        $matches++
                        LM-Result 'EVENTOS' 'SUSPEITO' ('Evento Sysmon '+$evt.Id) ("Roblox | fonte: $src | $($evt.TimeCreated.ToString('HH:mm:ss'))")
                        if ($matches -ge 15) { break }
                    } catch {}
                }
                LM-Result 'EVENTOS' 'INFO' 'Sysmon' "$matches eventos ligados ao Roblox (amostra de $($events.Count))."
            } elseif ($spec.Nome -eq 'Security' -or $spec.Nome -eq 'System') {
                $clear=@($events|Where-Object {$_.Id -in @(104,1102)})
                if($clear.Count){LM-Result 'EVENTOS' 'ATENCAO' $spec.Nome "$($clear.Count) eventos de limpeza de logs nas ultimas 3h."}
                else {LM-Result 'EVENTOS' 'INFO' $spec.Nome "$($events.Count) eventos consultados; nenhuma limpeza observada."}
            } else { LM-Result 'EVENTOS' 'INFO' $spec.Nome "$($events.Count) eventos recentes consultados; conteudo privado nao exportado." }
        } catch { LM-Result 'EVENTOS' 'INDISPONIVEL' $spec.Nome 'Log ausente ou acesso negado.' }
    }
}
function LM-RobloxLogs {
    $folder=Join-Path $env:LOCALAPPDATA 'Roblox\logs'
    if (-not (Test-Path -LiteralPath $folder)) { LM-Result 'ROBLOX' 'INDISPONIVEL' 'Logs Roblox' 'Pasta padrao nao encontrada.'; return }
    try {
        $logs=@(Get-ChildItem -LiteralPath $folder -Filter '*.log' -File -ErrorAction Stop|Sort-Object LastWriteTime -Descending|Select-Object -First 100)
        LM-Result 'ROBLOX' 'INFO' 'Logs Roblox' "$($logs.Count) arquivos recentes encontrados; conteudo nao coletado."
    } catch { LM-Result 'ROBLOX' 'INDISPONIVEL' 'Logs Roblox' 'Sem acesso.' }
}
function LM-Live {
    LM-Stage 8 'Monitoramento voluntario durante a partida'
    $minutes=$MonitorMinutes
    if ($minutes -le 0 -and -not $NoPause) {
        $inputMinutes=Read-Host '  Monitorar por quantos minutos? (0 para pular; maximo 120)'
        if ($inputMinutes -match '^\d{1,3}$') { $minutes=[int]$inputMinutes }
    }
    if ($minutes -gt 120) { $minutes=120 }
    if ($minutes -lt 1) { LM-Result 'MONITOR' 'INFO' 'Acompanhamento' 'Nao iniciado.'; return }
    LM-Result 'MONITOR' 'INFO' 'Duracao' "$minutes minuto(s), amostragem a cada 3 segundos."
    LM-Print '  Mantenha esta janela visivel; o monitoramento termina automaticamente.' Yellow
    $initial=@{}
    foreach ($p in @(LM-ProcessRows)) { $initial[[string]$p.PID]=$p.Name }
    $seen=@{}; $found=0; $deadline=(Get-Date).AddMinutes($minutes)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        foreach ($proc in @(LM-ProcessRows)) {
            $key=[string]$proc.PID
            if ($initial.ContainsKey($key) -or $seen.ContainsKey($key)) { continue }
            $seen[$key]=$true
            $found++
            $sig=LM-GetSignature $proc.Path
            if ($sig -in @('HashMismatch','NotTrusted')) {
                LM-Result 'MONITOR' 'SUSPEITO' $proc.Name ("Novo PID $key | assinatura $sig")
            } elseif ($sig -eq 'NotSigned') {
                LM-Result 'MONITOR' 'ATENCAO' $proc.Name ("Novo PID $key | sem assinatura")
            } else {
                LM-Result 'MONITOR' 'INFO' $proc.Name "Novo PID $key observado."
            }
        }
    }
    LM-Result 'MONITOR' 'INFO' 'Acompanhamento concluido' "$found processos novos observados; processos muito breves podem escapar."
}
function LM-Export {
    try {
        [void](New-Item -ItemType Directory -Path $script:Folder -Force -ErrorAction Stop)
        $file=Join-Path $script:Folder ("LM-T2-$script:Session-RELATORIO.txt")
        $ticket=Join-Path $script:Folder ("LM-T2-$script:Session-DISCORD.txt")
        $script:Capture.ToArray() | Set-Content -LiteralPath $file -Encoding UTF8 -ErrorAction Stop
        $r=@($script:Rows|Where-Object {$_.Status -eq 'SUSPEITO'})
        $y=@($script:Rows|Where-Object {$_.Status -eq 'ATENCAO'})
        $u=@($script:Rows|Where-Object {$_.Status -eq 'INDISPONIVEL'})
        $summary=New-Object 'System.Collections.Generic.List[string]'
        [void]$summary.Add('**MVS LOST MEDIA | T2 RECORDING**')
        [void]$summary.Add("Sessao: $script:Session")
        [void]$summary.Add("SUSPEITOS: $($r.Count) | ATENCAO: $($y.Count) | INDISPONIVEL: $($u.Count)")
        [void]$summary.Add('**Revisao prioritaria**')
        foreach ($item in ($r|Select-Object -First 5)) {
            $line='- '+$item.Item+': '+$item.Detalhe
            if($line.Length -gt 160){$line=$line.Substring(0,157)+'...'}
            [void]$summary.Add($line)
        }
        if (-not $r.Count) { [void]$summary.Add('Nenhum alerta prioritario na amostra.') }
        [void]$summary.Add('Resultados sao sinais para revisao da equipe, nao sancoes automaticas.')
        $summary.ToArray()|Set-Content -LiteralPath $ticket -Encoding UTF8 -ErrorAction Stop
        LM-Print ("  Relatorio local: $file") Green
        LM-Print ("  Resumo Discord:  $ticket") Green
    } catch { LM-Print ('  Nao foi possivel salvar os arquivos: '+$_.Exception.Message) Yellow }
}

LM-Header
LM-System
LM-Next
LM-Bam
LM-Next
LM-Prefetch
LM-Next
LM-Stage 4 'Microsoft Process Explorer (opcional)'
LM-MicrosoftTool 'Process Explorer' 'https://download.sysinternals.com/files/ProcessExplorer.zip' @('procexp64.exe','procexp.exe')
LM-Next
LM-Logs
LM-RobloxLogs
LM-Next
LM-Stage 6 'Microsoft WinObj (opcional)'
LM-MicrosoftTool 'WinObj' 'https://download.sysinternals.com/files/WinObj.zip' @('WinObj64.exe','WinObj.exe')
LM-Next
LM-Stage 7 'Microsoft Autoruns (opcional)'
LM-MicrosoftTool 'Autoruns' 'https://download.sysinternals.com/files/Autoruns.zip' @('Autoruns64.exe','Autoruns.exe')
LM-Next
LM-Live
LM-Print ''
LM-Print '  RESULTADO GERAL' Cyan
LM-Print ('  '+('-'*66)) DarkCyan
$sus=@($script:Rows|Where-Object{$_.Status -eq 'SUSPEITO'}).Count
$att=@($script:Rows|Where-Object{$_.Status -eq 'ATENCAO'}).Count
$unv=@($script:Rows|Where-Object{$_.Status -eq 'INDISPONIVEL'}).Count
LM-Print ("  SUSPEITOS: $sus | ATENCAO: $att | INDISPONIVEL: $unv") Cyan
LM-Print '  A equipe precisa conferir contexto e origem dos alertas.' Gray
LM-Export
LM-Print ''
LM-Print '  LOST MEDIA T2 FINALIZADO.' Cyan
if (-not $NoPause) { [void](Read-Host '  Pressione ENTER para fechar') }
