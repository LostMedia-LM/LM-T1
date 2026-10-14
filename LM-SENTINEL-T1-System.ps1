#requires -Version 5.1
<#
MVS Lost Media - Launcher da LOC original (terceiros)
Autor do script original: mortrunsloc
Este arquivo NAO contem nem modifica o codigo da LOC.
Ele apenas solicita confirmacao antes de executar a revisao especifica
publicada pelo autor na URL abaixo.
A LOC realiza verificacoes locais e pode abrir utilitarios externos.
Execute somente em seu proprio computador ou com autorizacao expressa.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$locUrl = 'https://gist.githubusercontent.com/mortrunsloc/eb10fe14a0aada7072ecf3fe2a1091e1/raw/6afd1f5a70b774a93caa289ad1017205c5ce3e18/gistfile1.txt'
Write-Host 'MVS LOST MEDIA - LOC ORIGINAL' -ForegroundColor Cyan
Write-Host 'Fonte: mortrunsloc / GitHub Gist' -ForegroundColor Gray
Write-Host 'Este iniciador executa a LOC original sem qualquer modificacao.' -ForegroundColor Yellow
Write-Host 'O script de terceiros pode inspecionar o sistema, abrir programas e manter monitoramento.' -ForegroundColor Yellow
Write-Host 'Verifique a fonte e execute apenas em PCs autorizados.' -ForegroundColor Yellow
$answer = Read-Host 'Executar a LOC original? (S/N)'
if ($answer -notmatch '^(?i:s|sim)$') {
    Write-Host 'Cancelado.' -ForegroundColor Gray
    return
}
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $source = (Invoke-WebRequest -Uri $locUrl -UseBasicParsing -ErrorAction Stop).Content
    if ([string]::IsNullOrWhiteSpace($source)) { throw 'O conteudo da LOC esta vazio.' }
    Invoke-Expression $source
} catch {
    Write-Host ('Falha ao executar a LOC original: ' + $_.Exception.Message) -ForegroundColor Red
    throw
}
