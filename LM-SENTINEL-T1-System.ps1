
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$ArquivoOriginal,
    [string]$Saida = '.\LostMedia-T1-Recording.ps1'
)
$ErrorActionPreference = 'Stop'
$entrada = (Resolve-Path -LiteralPath $ArquivoOriginal).Path
$codigo = [IO.File]::ReadAllText($entrada)
$inicioMarcador = 'Write-Host "   __   ____'
$fimMarcador = 'if (-not (Test-Admin)) {'
$inicio = $codigo.IndexOf($inicioMarcador, [StringComparison]::Ordinal)
if ($inicio -lt 0) { throw 'Banner esperado nao encontrado. Confira se escolheu o codigo LOC fornecido nesta conversa.' }
$fim = $codigo.IndexOf($fimMarcador, $inicio, [StringComparison]::Ordinal)
if ($fim -lt 0) { throw 'Fim do banner nao encontrado. Nao alterei o arquivo.' }

$novoBanner = @'
$lmArt = @"
  #      ###   #### ##### #   # ##### ####  #####   #  
  #     #   # #       #   ## ## #     #   #   #    # # 
  #     #   #  ###    #   # # # ####  #   #   #   #####
  #     #   #     #   #   #   # #     #   #   #   #   #
  #####  ###  ####    #   #   # ##### ####  ##### #   #

  #####   #         ####  #####  ####  ###  ####  ####  ##### #   #  ####
    #    ##         #   # #     #     #   # #   # #   #   #   ##  # #    
    #     #         ####  ####  #     #   # ####  #   #   #   # # # # ###
    #     #         #  #  #     #     #   # #  #  #   #   #   #  ## #   #
    #   #####       #   # #####  ####  ###  #   # ####  ##### #   #  ####
"@
Write-Host $lmArt -ForegroundColor Cyan
Write-Host ''
Write-Host '  LOSTMEDIA T1 RECORDING' -ForegroundColor White
Write-Host "  Base tecnica: LOC Tier 1 v$($script:LocTier1Version)" -ForegroundColor DarkGray
Write-Host '  Etapas: System Check / Process Explorer / Live Monitor' -ForegroundColor Gray
Write-Host ''
Write-Host '  === Discord Servers ===' -ForegroundColor Cyan
Write-Host '  Justice Department: https://discord.gg/gsdQbYFP79' -ForegroundColor White
Write-Host '  LM oficial:         https://discord.gg/2gP6MaKURK' -ForegroundColor White
Write-Host ''
Write-Host '  === Credits ===' -ForegroundColor Cyan
Write-Host '  Personalizacao e comunidade: Mangak' -ForegroundColor White
Write-Host '  Codigo-base e verificacoes: autores originais da LOC' -ForegroundColor White
Write-Host ''
'@

$codigo = $codigo.Substring(0, $inicio) + $novoBanner + "`r`n" + $codigo.Substring($fim)
$codigo = $codigo.Replace('LOC Tier 1 v$($script:LocTier1Version) monitor started', 'LostMedia T1 Recording v$($script:LocTier1Version) monitor started')
$codigo = $codigo.Replace('loc_tier1_security_events.log', 'lostmedia_t1_security_events.log')

$destino = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Saida)
if ([IO.Path]::GetFullPath($entrada) -eq [IO.Path]::GetFullPath($destino)) {
    throw 'Escolha um arquivo de saida diferente do original.'
}
[IO.File]::WriteAllText($destino, $codigo, ([System.Text.UTF8Encoding]::new($true)))
Write-Host "Arquivo personalizado criado: $destino" -ForegroundColor Green
Write-Host 'As verificacoes tecnicas permanecem as do arquivo de entrada.' -ForegroundColor Yellow
Write-Host 'Para publicar no GitHub, verifique primeiro os direitos de redistribuicao da LOC.' -ForegroundColor Yellow
