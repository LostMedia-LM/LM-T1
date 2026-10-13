Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.
                                                                                                                        PS C:\WINDOWS\system32> $p=Join-Path $env:TEMP 'LM-SENTINEL-T1-System.ps1'; Invoke-WebRequest 'https://raw.githubusercontent.com/fhelipeeduardo6-lab/LM-T1/main/LM-SENTINEL-T1-System.ps1' -OutFile $p -UseBasicParsing; if($?){ & $p }         
  ===================================================================
   MVS  /  LOST MEDIA                                SECURITY : T1:01
     _____  _____  _   _  _____  ___  _   _  _____  _
    /  ___||  ___|| \ | ||_   _||_  || \ | ||  ___|| |
    \ `--. | |__  |  \| |  | |    | ||  \| || |__  | |
     `--. \|  __| | . ` |  | |    | || . ` ||  __| | |
    /\__/ /| |___ | |\  |  | | /\__/ /| |\  || |___ | |___
    \____/ \____/ \_| \_/  \_/ \____/ \_| \_/\____/ \_____/
   BUILD 2.1     |     SYSTEM OBSERVATION     |     READ ONLY
  ===================================================================
   SESSAO 7A2A46F6    2026-10-12 22:48:55
   Sem rede | Sem veredito automatico | Relatorio local sem nomes
Group-Object : Não é possível localizar um parâmetro posicional que aceite o argumento 'Identificacao do ambiente'.
No C:\Users\fhelipe\AppData\Local\Temp\LM-SENTINEL-T1-System.ps1:421 caractere:1
+ Group '01' 'Identificacao do ambiente'
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (:) [Group-Object], ParameterBindingException
    + FullyQualifiedErrorId : PositionalParameterNotFound,Microsoft.PowerShell.Commands.GroupObjectCommand

  01  [INFO  ] Permissoes | Administrador; algumas leituras podem ser mais completas.
  02  [INFO  ] PowerShell | Versao 5.1.26100.9444
  03  [INFO  ] Windows | Build 26200
Group-Object : Não é possível localizar um parâmetro posicional que aceite o argumento 'Protecao do dispositivo'.
No C:\Users\fhelipe\AppData\Local\Temp\LM-SENTINEL-T1-System.ps1:434 caractere:1
+ Group '02' 'Protecao do dispositivo'
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (:) [Group-Object], ParameterBindingException
    + FullyQualifiedErrorId : PositionalParameterNotFound,Microsoft.PowerShell.Commands.GroupObjectCommand

  04  [OK    ] Microsoft Defender | Habilitado.
  05  [OK    ] Protecao em tempo real | Habilitado.
  06  [OK    ] Tamper Protection | Habilitado.
  07  [OK    ] Firewall Domain | Habilitado.
  08  [OK    ] Firewall Private | Habilitado.
  09  [OK    ] Firewall Public | Habilitado.
Group-Object : Não é possível localizar um parâmetro posicional que aceite o argumento 'Servicos e isolamento'.
No C:\Users\fhelipe\AppData\Local\Temp\LM-SENTINEL-T1-System.ps1:453 caractere:1
+ Group '03' 'Servicos e isolamento'
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (:) [Group-Object], ParameterBindingException
    + FullyQualifiedErrorId : PositionalParameterNotFound,Microsoft.PowerShell.Commands.GroupObjectCommand

  10  [OK    ] Servico WinDefend | Em execucao.
  11  [OK    ] Servico mpssvc | Em execucao.
  12  [OK    ] Servico wscsvc | Em execucao.
  13  [INFO  ] Integridade de memoria | HVCI nao consta em execucao; isso nao e prova de cheat.
Group-Object : Não é possível localizar um parâmetro posicional que aceite o argumento 'Processos e assinaturas'.
No C:\Users\fhelipe\AppData\Local\Temp\LM-SENTINEL-T1-System.ps1:468 caractere:1
+ Group '04' 'Processos e assinaturas'
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (:) [Group-Object], ParameterBindingException
    + FullyQualifiedErrorId : PositionalParameterNotFound,Microsoft.PowerShell.Commands.GroupObjectCommand

  14  [INFO  ] Processos ativos | 214 processos no momento da consulta.
  15  [INFO  ] Roblox | RobloxPlayerBeta encontrado na verificacao.
  16  [INFO  ] Cobertura de executaveis | 71 caminhos unicos legiveis; 16 processos sem caminho acessivel.
  17  [INFO  ] Assinaturas verificadas | 71/71 executaveis: 68 validos, 3 sem assinatura, 0 outros estados.
  18  [REVIEW] Assinaturas para revisar | Itens sem assinatura valida encontrados; programas legitimos tambem podem aparecer.
  19  [OK    ] Assinatura Roblox | Executavel do jogo com assinatura valida.
  A janela visual foi aberta. Percorra as paginas e clique em Concluir verificacao.
