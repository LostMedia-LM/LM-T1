#requires -Version 5.1
<#
MVS Lost Media - REGTRACE T1 / Registry Audit (2 of 2)
Read-only checks. Does not change Windows Registry or security settings.
Summarizes counts only for Defender exclusions; never includes private file paths.
Run with: & '.\LM-REGTRACE-T1-Registry.ps1'
Optional: -NoPause
#>
[CmdletBinding()]
param([switch]$NoPause)

$ErrorActionPreference = 'Continue'
$script:Findings = New-Object 'System.Collections.Generic.List[object]'
$script:Index = 0
$script:Session = ([guid]::NewGuid().ToString('N').Substring(0,8)).ToUpperInvariant()
$script:Stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

function PrintLine([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Gray) { Write-Host $Text -ForegroundColor $Color }
function Header([string]$Label) {
    Write-Host ''
    PrintLine ('  --- ' + $Label.ToUpperInvariant() + ' ' + ('-' * [Math]::Max(1, 52 - $Label.Length))) Magenta
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
function ReadRegValue([string]$Key, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Key)) { return [pscustomobject]@{ HasValue=$false; Readable=$true; Value=$null } }
    try {
        $val = Get-ItemPropertyValue -LiteralPath $Key -Name $Name -ErrorAction Stop
        return [pscustomobject]@{ HasValue=$true; Readable=$true; Value=$val }
    } catch {
        # Distinguish absent value from access-denied when possible.
        try {
            $keyObj = Get-Item -LiteralPath $Key -ErrorAction Stop
            if ($keyObj.GetValueNames() -notcontains $Name) {
                return [pscustomobject]@{ HasValue=$false; Readable=$true; Value=$null }
            }
        } catch { }
        return [pscustomobject]@{ HasValue=$false; Readable=$false; Value=$null }
    }
}
function CheckDisablePolicy([string]$Caption, [string]$Key, [string]$Name) {
    $value = ReadRegValue $Key $Name
    if (-not $value.Readable) { AddFinding $Caption 'INFO' 'Valor inacessivel; verificacao inconclusiva.' }
    elseif (-not $value.HasValue) { AddFinding $Caption 'INFO' 'Politica nao definida neste caminho (nao significa falha).' }
    elseif ([string]$value.Value -eq '1') { AddFinding $Caption 'REVIEW' 'Politica configurada com valor 1; conferir se ha outra protecao vigente.' }
    else { AddFinding $Caption 'OK' ('Politica definida com valor ' + $value.Value + '.') }
}
function CheckOptionalEnabled([string]$Caption, [string]$Key, [string]$Name) {
    $value = ReadRegValue $Key $Name
    if (-not $value.Readable) { AddFinding $Caption 'INFO' 'Leitura indisponivel.' }
    elseif (-not $value.HasValue) { AddFinding $Caption 'INFO' 'Valor nao definido neste caminho.' }
    elseif ([string]$value.Value -eq '1') { AddFinding $Caption 'OK' 'Configuracao habilitada.' }
    else { AddFinding $Caption 'INFO' 'Configuracao nao indicada como habilitada; nao comprova cheat.' }
}

Clear-Host
PrintLine '  +------------------------------------------------------------------+' DarkMagenta
PrintLine '  |   MVS / LOST MEDIA                                        T1:02  |' Magenta
PrintLine '  |   R E G T R A C E                                                |' White
PrintLine '  |   REGISTRY INSPECTION                            BUILD  1.0     |' DarkMagenta
PrintLine '  +------------------------------------------------------------------+' DarkMagenta
PrintLine ('  SESSION  {0}       {1}' -f $script:Session, $script:Stamp) Gray
PrintLine '  READ-ONLY | SOMENTE CONTAGENS DE EXCLUSOES | SEM ENVIO DE DADOS' DarkGray

Header 'Exclusoes Microsoft Defender'
try {
    $pref = Get-MpPreference -ErrorAction Stop
    foreach ($spec in @(
        @{Label='Arquivos/pastas'; Field='ExclusionPath'},
        @{Label='Processos'; Field='ExclusionProcess'},
        @{Label='Extensoes'; Field='ExclusionExtension'},
        @{Label='IPs'; Field='ExclusionIpAddress'}
    )) {
        $values = @($pref.($spec.Field) | Where-Object { $null -ne $_ -and "$_".Length -gt 0 })
        if ($values.Count -gt 0) { AddFinding ('Exclusoes: ' + $spec.Label) 'REVIEW' ("$($values.Count) entrada(s); nomes e caminhos nao sao armazenados.") }
        else { AddFinding ('Exclusoes: ' + $spec.Label) 'OK' 'Nenhuma entrada retornada pela consulta.' }
    }
} catch { AddFinding 'Exclusoes Defender' 'INFO' 'Get-MpPreference indisponivel; nao assumir que esta vazio.' }

Header 'Politicas de protecao'
$policyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
CheckDisablePolicy 'Desativar antivirus (politica)' $policyRoot 'DisableAntiSpyware'
$rt = Join-Path $policyRoot 'Real-Time Protection'
CheckDisablePolicy 'Desativar monitoramento real' $rt 'DisableRealtimeMonitoring'
CheckDisablePolicy 'Desativar comportamento' $rt 'DisableBehaviorMonitoring'
CheckDisablePolicy 'Desativar acesso a arquivos' $rt 'DisableOnAccessProtection'
CheckDisablePolicy 'Desativar downloads/arquivos' $rt 'DisableIOAVProtection'

Header 'Integridade e configuracoes do sistema'
CheckOptionalEnabled 'UAC (EnableLUA)' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
CheckOptionalEnabled 'Integridade de memoria (registro)' 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled'
CheckOptionalEnabled 'Bloqueio de drivers vulneraveis' 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable'

try {
    $digest = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash
    AddFinding 'SHA-256 do script' 'INFO' $digest
} catch { AddFinding 'SHA-256 do script' 'INFO' 'Hash indisponivel.' }

Header 'Resultado e relatorios'
$reviewCount = @($script:Findings | Where-Object { $_.Status -eq 'REVIEW' }).Count
$okCount = @($script:Findings | Where-Object { $_.Status -eq 'OK' }).Count
$infoCount = @($script:Findings | Where-Object { $_.Status -eq 'INFO' }).Count
PrintLine ("  OK: $okCount   REVIEW: $reviewCount   INFO: $infoCount") White
PrintLine '  Ausencia de alertas NAO prova ausencia de cheats.' Yellow
try {
    $doc = [Environment]::GetFolderPath('MyDocuments')
    if ([string]::IsNullOrWhiteSpace($doc)) { throw 'Pasta Documentos indisponivel.' }
    $dir = Join-Path $doc 'MVS-Lost-Media-T1'
    New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
    $prefix = 'REGTRACE-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $script:Session
    $fullPath = Join-Path $dir ($prefix + '.txt')
    $discordPath = Join-Path $dir ($prefix + '-DISCORD.txt')
    $lines = @('MVS LOST MEDIA - REGTRACE / T1:02','Sessao: ' + $script:Session,'Data local: ' + $script:Stamp,'Modo: somente leitura','')
    $lines += $script:Findings | ForEach-Object { '[{0}] {1}: {2}' -f $_.Status, $_.Section, $_.Detail }
    $lines += @('',"RESUMO: OK=$okCount | REVIEW=$reviewCount | INFO=$infoCount",'Sem diagnostico automatico de cheat.')
    $lines | Set-Content -LiteralPath $fullPath -Encoding UTF8 -ErrorAction Stop
    $discord = @('**MVS LOST MEDIA | REGTRACE T1:02**','Sessao: `' + $script:Session + '`',"OK: **$okCount** | Revisao: **$reviewCount** | Info: **$infoCount**",'Resultado: revisao manual necessaria; nao constitui prova de cheat.')
    $discord | Set-Content -LiteralPath $discordPath -Encoding UTF8 -ErrorAction Stop
    PrintLine ('  Relatorio: ' + $fullPath) Magenta
    PrintLine ('  Texto Discord: ' + $discordPath) Magenta
} catch { PrintLine ('  Falha ao salvar relatorio: ' + $_.Exception.Message) Yellow }

PrintLine '  FINALIZADO | MVS LOST MEDIA' DarkMagenta
if (-not $NoPause) { Write-Host ''; [void](Read-Host '  Pressione ENTER para fechar') }
