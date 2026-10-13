#requires -Version 5.1
<#
MVS Lost Media | SENTINEL T1:01 | Build 2.1.1
Public, read-only Windows security and process audit.
No external connections, no automatic elevation, no Registry/system changes.
Only creates local reports and an optional aggregate-only comparison snapshot.
Unsigned files or other observations are NOT proof of cheating.

Options:
  -ShowDetails             Displays names of unsigned/unverifiable executables locally.
                           Names/paths are NEVER saved to reports.
  -MaxSignatureChecks 100  Maximum distinct readable executables checked (20..200).
  -NoHistory               Does not read or write the previous-run aggregate snapshot.
  -NoViewer                Skips the read-only process/service inspection window.
  -NoPause                 Does not prompt at the end.
#>
[CmdletBinding()]
param(
    [switch]$ShowDetails,
    [ValidateRange(20,200)][int]$MaxSignatureChecks = 100,
    [switch]$NoHistory,
    [switch]$NoViewer,
    [switch]$NoPause
)

$ErrorActionPreference = 'Continue'
$script:Session = ([guid]::NewGuid().ToString('N').Substring(0,8)).ToUpperInvariant()
$script:StartedAt = Get-Date
$script:Started = $script:StartedAt.ToString('yyyy-MM-dd HH:mm:ss')
$script:Checks = New-Object 'System.Collections.Generic.List[object]'
$script:CheckIndex = 0
$script:GuiProcesses = @()
$script:GuiSignatureMap = @{}
$script:GuiReady = $false
$script:Stats = [ordered]@{
    ProcessCount = -1
    RobloxRunning = $false
    UniqueReadable = 0
    Inspected = 0
    SignedValid = 0
    Unsigned = 0
    OtherSignature = 0
    PathUnavailable = 0
}

function Say([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    Write-Host $Message -ForegroundColor $Color
}
function Write-SentinelSection([string]$Id,[string]$Heading) {
    Write-Host ''
    Say ('  [' + $Id + ']  ' + $Heading.ToUpperInvariant()) Cyan
    Say '  --------------------------------------------------------------' DarkGray
}
function Check([string]$Label,[string]$State,[string]$Explanation) {
    $script:CheckIndex++
    $color = switch ($State) {
        'OK'     { [ConsoleColor]::Green }
        'REVIEW' { [ConsoleColor]::Yellow }
        default  { [ConsoleColor]::DarkGray }
    }
    Write-Host ('  {0:00}  ' -f $script:CheckIndex) -NoNewline -ForegroundColor DarkGray
    Write-Host ('[{0,-6}] ' -f $State) -NoNewline -ForegroundColor $color
    Write-Host ($Label + ' | ' + $Explanation)
    [void]$script:Checks.Add([pscustomobject]@{
        Label=$Label; State=$State; Explanation=$Explanation
    })
}
function SignatureStatus([string]$Location) {
    try {
        $r = Get-AuthenticodeSignature -LiteralPath $Location -ErrorAction Stop
        return [string]$r.Status
    } catch { return 'Unavailable' }
}
function WinStatus([string]$Name, $Value) {
    if ($null -eq $Value) { Check $Name 'INFO' 'Estado nao informado pelo Windows.' }
    elseif ($Value -eq $true) { Check $Name 'OK' 'Habilitado.' }
    else { Check $Name 'REVIEW' 'Estado desabilitado; exige verificacao de contexto.' }
}

function Open-SentinelViewer {
    # Read-only, local GUI. Process names and PIDs are visible only on screen.
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    } catch {
        Check 'Janela de processos' 'INFO' 'Windows Forms indisponivel; lista visual nao foi aberta.'
        return
    }

    try {
        $script:Gui = @{
            Page = 0
            PageSize = 15
            Search = ''
            Tab = 0
            Processes = @()
            Services = @()
        }

        function script:Get-SentinelProcessRows {
            param([object[]]$Items)
            $rows = New-Object 'System.Collections.Generic.List[object]'
            foreach ($p in $Items) {
                $path = $null
                try { $path = $p.Path } catch { }
                $sig = 'Nao verificada'
                if ([string]::IsNullOrWhiteSpace($path)) {
                    $sig = 'Caminho indisponivel'
                } elseif ($script:GuiSignatureMap.ContainsKey($path)) {
                    $sig = switch ($script:GuiSignatureMap[$path]) {
                        'Valid' { 'Valida' }
                        'NotSigned' { 'Sem assinatura' }
                        default { 'Outra / indisponivel' }
                    }
                }
                $ram = '-'
                try { $ram = [string][math]::Round($p.WorkingSet64 / 1MB) } catch { }
                [void]$rows.Add([pscustomobject]@{
                    Nome = [string]$p.ProcessName
                    PID = [int]$p.Id
                    RAM_MB = $ram
                    Assinatura = $sig
                })
            }
            return @($rows | Sort-Object Nome, PID)
        }

        function script:Get-SentinelServiceRows {
            try {
                return @(Get-Service -ErrorAction Stop | Sort-Object DisplayName | ForEach-Object {
                    [pscustomobject]@{
                        Servico = [string]$_.Name
                        Descricao = [string]$_.DisplayName
                        Estado = [string]$_.Status
                    }
                })
            } catch { return @() }
        }

        $script:Gui.Processes = @(Get-SentinelProcessRows -Items $script:GuiProcesses)
        $script:Gui.Services = @(Get-SentinelServiceRows)

        $dark  = [System.Drawing.Color]::FromArgb(16,25,37)
        $panel = [System.Drawing.Color]::FromArgb(25,38,54)
        $cyan  = [System.Drawing.Color]::FromArgb(85,218,226)
        $white = [System.Drawing.Color]::FromArgb(234,240,249)
        $muted = [System.Drawing.Color]::FromArgb(158,175,194)

        $window = New-Object System.Windows.Forms.Form
        $window.Text = 'LM SENTINEL | Verificacao visual T1 | BUILD 2.1.1'
        $window.StartPosition = 'CenterScreen'
        $window.Size = New-Object System.Drawing.Size(1060,720)
        $window.MinimumSize = New-Object System.Drawing.Size(1000,580)
        $window.BackColor = $dark
        $window.ForeColor = $white
        $window.Font = New-Object System.Drawing.Font('Segoe UI',10)

        $top = New-Object System.Windows.Forms.Panel
        $top.Dock = 'Top'
        $top.Height = 83
        $top.BackColor = $dark


        $title = New-Object System.Windows.Forms.Label
        $title.Text = 'MVS / LOST MEDIA     S E N T I N E L'
        $title.ForeColor = $cyan
        $title.Font = New-Object System.Drawing.Font('Consolas',18,[System.Drawing.FontStyle]::Bold)
        $title.Location = New-Object System.Drawing.Point(20,12)
        $title.AutoSize = $true
        $top.Controls.Add($title)

        $subtitle = New-Object System.Windows.Forms.Label
        $subtitle.Text = 'T1:01  /  INSPECAO VISUAL  /  SEM ENVIO DE DADOS'
        $subtitle.ForeColor = $muted
        $subtitle.Font = New-Object System.Drawing.Font('Consolas',10)
        $subtitle.Location = New-Object System.Drawing.Point(22,51)
        $subtitle.AutoSize = $true
        $top.Controls.Add($subtitle)

        $bottom = New-Object System.Windows.Forms.Panel
        $bottom.Dock = 'Bottom'
        $bottom.Height = 105
        $bottom.BackColor = $dark


        $instruction = New-Object System.Windows.Forms.Label
        $instruction.Text = 'Mostre cada pagina durante a gravacao. Nomes e PIDs nao sao gravados nos relatorios.'
        $instruction.ForeColor = $muted
        $instruction.Location = New-Object System.Drawing.Point(20,6)
        $instruction.AutoSize = $true
        $bottom.Controls.Add($instruction)

        $back = New-Object System.Windows.Forms.Button
        $back.Text = '<< Anterior'
        $back.Location = New-Object System.Drawing.Point(20,36)
        $back.Size = New-Object System.Drawing.Size(126,34)
        $bottom.Controls.Add($back)

        $forward = New-Object System.Windows.Forms.Button
        $forward.Text = 'Proxima >>'
        $forward.Location = New-Object System.Drawing.Point(159,36)
        $forward.Size = New-Object System.Drawing.Size(126,34)
        $bottom.Controls.Add($forward)

        $pageInfo = New-Object System.Windows.Forms.Label
        $pageInfo.Location = New-Object System.Drawing.Point(302,43)
        $pageInfo.Size = New-Object System.Drawing.Size(258,26)
        $pageInfo.ForeColor = $cyan
        $pageInfo.Font = New-Object System.Drawing.Font('Consolas',11)
        $bottom.Controls.Add($pageInfo)

        $reload = New-Object System.Windows.Forms.Button
        $reload.Text = 'Atualizar agora'
        $reload.Location = New-Object System.Drawing.Point(580,36)
        $reload.Size = New-Object System.Drawing.Size(152,34)
        $bottom.Controls.Add($reload)

        $close = New-Object System.Windows.Forms.Button
        $close.Text = 'Concluir verificacao'
        $close.Location = New-Object System.Drawing.Point(744,36)
        $close.Size = New-Object System.Drawing.Size(190,34)
        $close.Add_Click({ $script:GuiWindow.Close() })
        $bottom.Controls.Add($close)

        $tabs = New-Object System.Windows.Forms.TabControl
        $tabs.Dock = 'Fill'
        $tabs.Font = New-Object System.Drawing.Font('Segoe UI',10,[System.Drawing.FontStyle]::Bold)
        # Table layout keeps the header, tabs and paging controls visible at any size.
        $layout = New-Object System.Windows.Forms.TableLayoutPanel
        $layout.Dock = 'Fill'
        $layout.ColumnCount = 1
        $layout.RowCount = 3
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,83))) | Out-Null
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent,100))) | Out-Null
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,105))) | Out-Null
        $window.Controls.Add($layout)
        $layout.Controls.Add($top,0,0)
        $layout.Controls.Add($tabs,0,1)
        $layout.Controls.Add($bottom,0,2)
        $script:GuiWindow = $window
        $script:GuiTabs = $tabs

        $tab1 = New-Object System.Windows.Forms.TabPage
        $tab1.Text = 'PROCESSOS'
        $tab1.BackColor = $panel
        [void]$tabs.TabPages.Add($tab1)
        $tab2 = New-Object System.Windows.Forms.TabPage
        $tab2.Text = 'SERVICOS'
        $tab2.BackColor = $panel
        [void]$tabs.TabPages.Add($tab2)
        $tab3 = New-Object System.Windows.Forms.TabPage
        $tab3.Text = 'INFORMACOES'
        $tab3.BackColor = $panel
        [void]$tabs.TabPages.Add($tab3)

        $searchPanel = New-Object System.Windows.Forms.Panel
        $searchPanel.Dock = 'Top'
        $searchPanel.Height = 43

        $searchLabel = New-Object System.Windows.Forms.Label
        $searchLabel.Text = 'Filtrar nome/PID:'
        $searchLabel.ForeColor = $white
        $searchLabel.AutoSize = $true
        $searchLabel.Location = New-Object System.Drawing.Point(10,12)
        $searchPanel.Controls.Add($searchLabel)

        $searchBox = New-Object System.Windows.Forms.TextBox
        $searchBox.Location = New-Object System.Drawing.Point(155,8)
        $searchBox.Width = 340
        $searchPanel.Controls.Add($searchBox)

        $grid = New-Object System.Windows.Forms.DataGridView
        $grid.Dock = 'Fill'
        $grid.BackgroundColor = $panel
        $grid.GridColor = [System.Drawing.Color]::FromArgb(49,66,85)
        $grid.EnableHeadersVisualStyles = $false
        $grid.ColumnHeadersDefaultCellStyle.BackColor = $dark
        $grid.ColumnHeadersDefaultCellStyle.ForeColor = $cyan
        $grid.DefaultCellStyle.BackColor = $panel
        $grid.DefaultCellStyle.ForeColor = $white
        $grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(44,100,116)
        $grid.DefaultCellStyle.SelectionForeColor = $white
        $grid.RowHeadersVisible = $false
        $grid.AllowUserToAddRows = $false
        $grid.AllowUserToDeleteRows = $false
        $grid.ReadOnly = $true
        $grid.MultiSelect = $false
        $grid.SelectionMode = 'FullRowSelect'
        $grid.AutoSizeColumnsMode = 'Fill'
        $grid.AutoGenerateColumns = $true
        $tab1Layout = New-Object System.Windows.Forms.TableLayoutPanel
        $tab1Layout.Dock = 'Fill'
        $tab1Layout.RowCount = 2
        $tab1Layout.ColumnCount = 1
        $tab1Layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,43))) | Out-Null
        $tab1Layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent,100))) | Out-Null
        $tab1.Controls.Add($tab1Layout)
        $tab1Layout.Controls.Add($searchPanel,0,0)
        $tab1Layout.Controls.Add($grid,0,1)

        $serviceGrid = New-Object System.Windows.Forms.DataGridView
        $serviceGrid.Dock = 'Fill'
        $serviceGrid.BackgroundColor = $panel
        $serviceGrid.GridColor = $grid.GridColor
        $serviceGrid.EnableHeadersVisualStyles = $false
        $serviceGrid.ColumnHeadersDefaultCellStyle.BackColor = $dark
        $serviceGrid.ColumnHeadersDefaultCellStyle.ForeColor = $cyan
        $serviceGrid.DefaultCellStyle.BackColor = $panel
        $serviceGrid.DefaultCellStyle.ForeColor = $white
        $serviceGrid.DefaultCellStyle.SelectionBackColor = $grid.DefaultCellStyle.SelectionBackColor
        $serviceGrid.RowHeadersVisible = $false
        $serviceGrid.ReadOnly = $true
        $serviceGrid.AllowUserToAddRows = $false
        $serviceGrid.AllowUserToDeleteRows = $false
        $serviceGrid.SelectionMode = 'FullRowSelect'
        $serviceGrid.AutoSizeColumnsMode = 'Fill'
        $tab2.Controls.Add($serviceGrid)

        $info = New-Object System.Windows.Forms.Label
        $info.Dock = 'Fill'
        $info.ForeColor = $white
        $info.Font = New-Object System.Drawing.Font('Consolas',12)
        $info.Padding = New-Object System.Windows.Forms.Padding(20)
        $info.Text = ('SESSAO  ' + $script:Session + [Environment]::NewLine + [Environment]::NewLine +
            'Processos na verificacao inicial: ' + $script:Stats.ProcessCount + [Environment]::NewLine +
            'Executaveis com assinatura conferida: ' + $script:Stats.Inspected + [Environment]::NewLine +
            'Assinatura valida: ' + $script:Stats.SignedValid + [Environment]::NewLine +
            'Sem assinatura: ' + $script:Stats.Unsigned + [Environment]::NewLine +
            'Outros estados: ' + $script:Stats.OtherSignature + [Environment]::NewLine + [Environment]::NewLine +
            'Esta janela NAO prova ausencia ou presenca de cheats.' + [Environment]::NewLine +
            'O botao Atualizar muda a lista visual, nao o relatorio da varredura inicial.' + [Environment]::NewLine +
            'Sem coleta continua, sem alteracao de configuracoes.')
        $tab3.Controls.Add($info)

        # These controls are needed by events while ShowDialog is active.
        $script:GuiView = @{ Grid = $grid; ServiceGrid = $serviceGrid; PageInfo = $pageInfo;
            Back = $back; Forward = $forward; SearchBox = $searchBox; Reload = $reload }
        $script:GuiRender = {
            $g = $script:Gui
            $v = $script:GuiView
            if ($g.Tab -eq 2) {
                $v.Grid.DataSource = $null
                $v.ServiceGrid.DataSource = $null
                $v.PageInfo.Text = 'Resumo da verificacao'
                $v.Back.Enabled = $false; $v.Forward.Enabled = $false; $v.Reload.Enabled = $false
                return
            }
            $currentRows = @()
            if ($g.Tab -eq 0) {
                $query = $g.Search.Trim()
                if ($query.Length -eq 0) { $currentRows = @($g.Processes) }
                else { $currentRows = @($g.Processes | Where-Object { $_.Nome -like ('*' + $query + '*') -or [string]$_.PID -like ('*' + $query + '*') }) }
            } else { $currentRows = @($g.Services) }
            $total = $currentRows.Count
            $pages = [Math]::Max(1,[Math]::Ceiling($total / $g.PageSize))
            if ($g.Page -ge $pages) { $g.Page = $pages - 1 }
            if ($g.Page -lt 0) { $g.Page = 0 }
            $from = $g.Page * $g.PageSize
            $toDisplay = @($currentRows | Select-Object -Skip $from -First $g.PageSize)
            $table = New-Object System.Data.DataTable
            $columns = if ($g.Tab -eq 0) { @('Nome','PID','RAM_MB','Assinatura') } else { @('Servico','Descricao','Estado') }
            foreach ($c in $columns) { [void]$table.Columns.Add($c,[string]) }
            foreach ($row in $toDisplay) {
                $cells = foreach ($c in $columns) { [string]$row.$c }
                [void]$table.Rows.Add([object[]]$cells)
            }
            if ($g.Tab -eq 0) { $v.Grid.DataSource = $table; $v.ServiceGrid.DataSource = $null }
            else { $v.ServiceGrid.DataSource = $table; $v.Grid.DataSource = $null }
            $v.PageInfo.Text = ('Pagina {0}/{1}   |   {2} itens' -f ($g.Page+1),$pages,$total)
            $v.Back.Enabled = $g.Page -gt 0
            $v.Forward.Enabled = $g.Page -lt ($pages - 1)
            $v.Reload.Enabled = $true
        }
        $back.Add_Click({ $script:Gui.Page--; & $script:GuiRender })
        $forward.Add_Click({ $script:Gui.Page++; & $script:GuiRender })
        $searchBox.Add_TextChanged({ $script:Gui.Search = $script:GuiView.SearchBox.Text; $script:Gui.Page = 0; & $script:GuiRender })
        $tabs.Add_SelectedIndexChanged({
            $script:Gui.Tab = $script:GuiTabs.SelectedIndex
            $script:Gui.Page = 0
            & $script:GuiRender
        })
        $reload.Add_Click({
            try {
                $script:Gui.Processes = @(Get-SentinelProcessRows -Items @(Get-Process -ErrorAction Stop))
                $script:Gui.Services = @(Get-SentinelServiceRows)
                $script:Gui.Page = 0
                & $script:GuiRender
            } catch { [System.Windows.Forms.MessageBox]::Show('Nao foi possivel atualizar a lista.', 'SENTINEL') | Out-Null }
        })
        & $script:GuiRender
        Say '  A janela visual foi aberta. Percorra as paginas e clique em Concluir verificacao.' Cyan
        [void]$window.ShowDialog()
        Check 'Inspecao visual' 'INFO' 'Janela de processos e servicos aberta e encerrada pelo usuario.'
    } catch {
        Say ('  Falha na janela: ' + $_.Exception.Message) Yellow
        Check 'Inspecao visual' 'INFO' ('Janela indisponivel: ' + $_.Exception.GetType().Name + '. A auditoria continua.')
    } finally {
        if ($null -ne $window) { $window.Dispose() }
        $script:Gui = $null
        $script:GuiView = $null
        $script:GuiRender = $null
        $script:GuiWindow = $null
        $script:GuiTabs = $null
    }
}

Say ''
Say '  ===================================================================' DarkCyan
Say '   MVS  /  LOST MEDIA                                SECURITY : T1:01' Cyan
Say '     _____  _____  _   _  _____  ___  _   _  _____  _' DarkCyan
Say '    /  ___||  ___|| \ | ||_   _||_  || \ | ||  ___|| |' Cyan
Say '    \ `--. | |__  |  \| |  | |    | ||  \| || |__  | |' Cyan
Say '     `--. \|  __| | . ` |  | |    | || . ` ||  __| | |' Cyan
Say '    /\__/ /| |___ | |\  |  | | /\__/ /| |\  || |___ | |___' Cyan
Say '    \____/ \____/ \_| \_/  \_/ \____/ \_| \_/\____/ \_____/' DarkCyan
Say '   BUILD 2.1.1     |     SYSTEM OBSERVATION     |     READ ONLY' White
Say '  ===================================================================' DarkCyan
Say ('   SESSAO ' + $script:Session + '    ' + $script:Started) Gray
Say '   Sem rede | Sem veredito automatico | Relatorio local sem nomes' DarkGray

Write-SentinelSection '01' 'Identificacao do ambiente'
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $asAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($asAdmin) { Check 'Permissoes' 'INFO' 'Administrador; algumas leituras podem ser mais completas.' }
    else { Check 'Permissoes' 'INFO' 'Usuario padrao; algumas informacoes podem ser restritas.' }
} catch { Check 'Permissoes' 'INFO' 'Nao foi possivel consultar permissoes.' }
Check 'PowerShell' 'INFO' ('Versao ' + $PSVersionTable.PSVersion.ToString())
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Check 'Windows' 'INFO' ('Build ' + [string]$os.BuildNumber)
} catch { Check 'Windows' 'INFO' 'Build indisponivel.' }

Write-SentinelSection '02' 'Protecao do dispositivo'
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    WinStatus 'Microsoft Defender' $mp.AntivirusEnabled
    WinStatus 'Protecao em tempo real' $mp.RealTimeProtectionEnabled
    WinStatus 'Tamper Protection' $mp.IsTamperProtected
} catch {
    Check 'Microsoft Defender' 'INFO' 'Consulta indisponivel; antivirus de terceiros tambem pode explicar.'
}
try {
    $firewall = @(Get-NetFirewallProfile -ErrorAction Stop)
    if ($firewall.Count -eq 0) { Check 'Firewall' 'INFO' 'Nenhum perfil retornado.' }
    foreach ($f in $firewall) {
        if ($f.Enabled -eq $true) { Check ('Firewall ' + $f.Name) 'OK' 'Habilitado.' }
        elseif ($f.Enabled -eq $false) { Check ('Firewall ' + $f.Name) 'REVIEW' 'Desabilitado; revisar politica do dispositivo.' }
        else { Check ('Firewall ' + $f.Name) 'INFO' 'Estado nao informado.' }
    }
} catch { Check 'Firewall' 'INFO' 'Nao foi possivel consultar os perfis.' }

Write-SentinelSection '03' 'Servicos e isolamento'
foreach ($name in @('WinDefend','mpssvc','wscsvc')) {
    try {
        $s = Get-Service -Name $name -ErrorAction Stop
        if ($s.Status -eq 'Running') { Check ('Servico ' + $name) 'OK' 'Em execucao.' }
        else { Check ('Servico ' + $name) 'REVIEW' ('Estado ' + [string]$s.Status + '; requer contexto.') }
    } catch { Check ('Servico ' + $name) 'INFO' 'Consulta nao disponivel.' }
}
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
    $running = @($dg.SecurityServicesRunning)
    if ($running -contains 2) { Check 'Integridade de memoria' 'OK' 'HVCI consta em execucao.' }
    else { Check 'Integridade de memoria' 'INFO' 'HVCI nao consta em execucao; isso nao e prova de cheat.' }
} catch { Check 'Integridade de memoria' 'INFO' 'Consulta de Device Guard indisponivel.' }

Write-SentinelSection '04' 'Processos e assinaturas'
try {
    $runningProcesses = @(Get-Process -ErrorAction Stop)
    $script:Stats.ProcessCount = $runningProcesses.Count
    Check 'Processos ativos' 'INFO' ([string]$runningProcesses.Count + ' processos no momento da consulta.')
    $roblox = @($runningProcesses | Where-Object { $_.ProcessName -eq 'RobloxPlayerBeta' })
    $script:Stats.RobloxRunning = ($roblox.Count -gt 0)
    if ($script:Stats.RobloxRunning) { Check 'Roblox' 'INFO' 'RobloxPlayerBeta encontrado na verificacao.' }
    else { Check 'Roblox' 'INFO' 'RobloxPlayerBeta nao encontrado neste instante.' }

    # Make a stable deduplicated list. Prioritize Roblox before sampling.
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $locations = New-Object 'System.Collections.Generic.List[string]'
    $unavailablePaths = 0
    $ordered = @($runningProcesses | Sort-Object @{Expression={ if ($_.ProcessName -eq 'RobloxPlayerBeta') { 0 } else { 1 } }}, ProcessName, Id)
    foreach ($p in $ordered) {
        $location = $null
        try { $location = $p.Path } catch { }
        if ([string]::IsNullOrWhiteSpace($location)) { $unavailablePaths++; continue }
        try {
            if ((Test-Path -LiteralPath $location -PathType Leaf -ErrorAction Stop) -and $seen.Add($location)) {
                [void]$locations.Add($location)
            }
        } catch { $unavailablePaths++ }
    }
    $script:Stats.UniqueReadable = $locations.Count
    $script:Stats.PathUnavailable = $unavailablePaths
    Check 'Cobertura de executaveis' 'INFO' ("$($locations.Count) caminhos unicos legiveis; $unavailablePaths processos sem caminho acessivel.")
    $valid = 0; $unsigned = 0; $other = 0
    $reviewLocal = New-Object 'System.Collections.Generic.List[object]'
    $robloxSignature = 'Indisponivel'
    $processed = 0
    foreach ($loc in $locations) {
        if ($processed -ge $MaxSignatureChecks) { break }
        $status = SignatureStatus $loc
        $script:GuiSignatureMap[$loc] = $status
        $processed++
        if ($status -eq 'Valid') { $valid++ }
        elseif ($status -eq 'NotSigned') { $unsigned++ }
        else { $other++ }
        if ($status -ne 'Valid') {
            [void]$reviewLocal.Add([pscustomobject]@{ File=[IO.Path]::GetFileName($loc); Signature=$status })
        }
        if ($roblox.Count -gt 0) {
            foreach ($rp in $roblox) {
                try {
                    if ([string]::Equals($rp.Path, $loc, [StringComparison]::OrdinalIgnoreCase)) { $robloxSignature = $status }
                } catch { }
            }
        }
    }
    $script:Stats.Inspected = $processed
    $script:Stats.SignedValid = $valid
    $script:Stats.Unsigned = $unsigned
    $script:Stats.OtherSignature = $other
    $script:GuiProcesses = @($runningProcesses)
    $script:GuiReady = $true
    Check 'Assinaturas verificadas' 'INFO' ("$processed/$($locations.Count) executaveis: $valid validos, $unsigned sem assinatura, $other outros estados.")
    if ($locations.Count -gt $processed) {
        Check 'Limite de amostragem' 'INFO' ("Restantes nao analisados: $($locations.Count - $processed). Use -MaxSignatureChecks ate 200 para ampliar.")
    }
    if ($unsigned -gt 0 -or $other -gt 0) {
        Check 'Assinaturas para revisar' 'REVIEW' 'Itens sem assinatura valida encontrados; programas legitimos tambem podem aparecer.'
    } else { Check 'Assinaturas para revisar' 'OK' 'Nenhum alerta de assinatura na amostra consultada.' }
    if ($roblox.Count -gt 0) {
        if ($robloxSignature -eq 'Valid') { Check 'Assinatura Roblox' 'OK' 'Executavel do jogo com assinatura valida.' }
        elseif ($robloxSignature -eq 'NotSigned') { Check 'Assinatura Roblox' 'REVIEW' 'Executavel do jogo sem assinatura; requer verificacao manual.' }
        elseif ($robloxSignature -eq 'Indisponivel') { Check 'Assinatura Roblox' 'INFO' 'Nao foi possivel consultar o executavel do Roblox.' }
        else { Check 'Assinatura Roblox' 'REVIEW' ('Estado da assinatura: ' + $robloxSignature + '; revisar.') }
    }
    if ($ShowDetails) {
        Write-Host ''
        Say '  DETALHES LOCAIS (NAO SALVOS) - NOMES DE ARQUIVOS' Cyan
        if ($reviewLocal.Count -eq 0) { Say '  Nenhum item adicional na amostra.' DarkGray }
        foreach ($r in @($reviewLocal | Select-Object -First 25)) {
            Say ('  [' + $r.Signature + '] ' + $r.File) Yellow
        }
        if ($reviewLocal.Count -gt 25) { Say ('  ... e mais ' + ($reviewLocal.Count - 25) + ' itens.') DarkGray }
    }
} catch {
    Check 'Processos' 'INFO' ('Falha de consulta: ' + $_.Exception.GetType().Name + '. Verificacao parcial.')
}

# Window is opened after the audit. This does not collect data in the background.
if (-not $NoViewer -and $script:GuiReady) {
    Open-SentinelViewer
}

Write-SentinelSection '05' 'Comparacao entre execucoes'
$folder = $null
$previousSnapshot = $null
try {
    $documents = [Environment]::GetFolderPath('MyDocuments')
    if ([string]::IsNullOrWhiteSpace($documents)) { throw 'Pasta Documentos indisponivel.' }
    $folder = Join-Path $documents 'MVS-Lost-Media-T1'
    New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop | Out-Null
    if (-not $NoHistory) {
        $historyPath = Join-Path $folder 'SENTINEL-LAST-SNAPSHOT.json'
        if (Test-Path -LiteralPath $historyPath) {
            try { $previousSnapshot = Get-Content -LiteralPath $historyPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
            catch { Check 'Comparacao' 'INFO' 'Registro anterior nao pode ser lido.' }
        }
    }
} catch { Check 'Pasta de relatorios' 'INFO' 'Documentos indisponivel; relatorios podem nao ser salvos.' }

if ($NoHistory) {
    Check 'Comparacao' 'INFO' 'Desativada por -NoHistory.'
} elseif ($null -eq $previousSnapshot) {
    Check 'Comparacao' 'INFO' 'Primeira execucao ou comparacao anterior indisponivel.'
} elseif ($script:Stats.ProcessCount -lt 0) {
    Check 'Comparacao' 'INFO' 'Processos nao foram consultados nesta sessao.'
} else {
    try {
        if ([int]$previousSnapshot.Schema -ne 2) { throw 'Versao de snapshot diferente.' }
        $delta = $script:Stats.ProcessCount - [int]$previousSnapshot.ProcessCount
        $sigDelta = $script:Stats.Unsigned - [int]$previousSnapshot.Unsigned
        $deltaText = if ($delta -ge 0) { '+' + $delta } else { [string]$delta }
        $sigText = if ($sigDelta -ge 0) { '+' + $sigDelta } else { [string]$sigDelta }
        Check 'Mudanca de processos' 'INFO' ("$deltaText processos desde $($previousSnapshot.Timestamp).")
        if ([int]$previousSnapshot.MaxSignatureChecks -eq $MaxSignatureChecks) {
            Check 'Mudanca de assinaturas' 'INFO' ("$sigText itens sem assinatura na amostra. Amostras podem variar.")
        } else { Check 'Mudanca de assinaturas' 'INFO' 'Limite de amostragem diferente; contagens nao comparaveis.' }
        if ([bool]$previousSnapshot.RobloxRunning -ne [bool]$script:Stats.RobloxRunning) {
            Check 'Mudanca do Roblox' 'INFO' 'Presenca do Roblox mudou desde a execucao anterior.'
        }
    } catch { Check 'Comparacao' 'INFO' 'Snapshot antigo incompativel; iniciando nova referencia.' }
}

Write-SentinelSection '06' 'Integridade e resumo'
try {
    $hash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash
    Check 'SHA-256 deste arquivo' 'INFO' $hash
} catch { Check 'SHA-256 deste arquivo' 'INFO' 'Nao foi possivel calcular.' }

$ok = @($script:Checks | Where-Object { $_.State -eq 'OK' }).Count
$review = @($script:Checks | Where-Object { $_.State -eq 'REVIEW' }).Count
$info = @($script:Checks | Where-Object { $_.State -eq 'INFO' }).Count
Say ''
Say '  +-----------------------------------------------------------------+' DarkCyan
Say (('  |   OK  {0,-4}   REVISAO  {1,-4}   INFO  {2,-4}                  |' -f $ok,$review,$info)) White
Say '  +-----------------------------------------------------------------+' DarkCyan
if ($review -gt 0) { Say '  RESULTADO: HA ITENS PARA REVISAO HUMANA, NAO HA VEREDITO.' Yellow }
else { Say '  RESULTADO: SEM ALERTAS NESTAS CONSULTAS, NAO HA VEREDITO.' Green }
Say '  Nenhum resultado prova presenca ou ausencia de cheats.' DarkGray

if ($null -ne $folder) {
    try {
        $prefix = 'SENTINEL-V2-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $script:Session
        $report = Join-Path $folder ($prefix + '.txt')
        $discordFile = Join-Path $folder ($prefix + '-DISCORD.txt')
        $reportLines = @(
            'MVS LOST MEDIA | SENTINEL T1:01 | BUILD 2.1.1',
            ('Sessao: ' + $script:Session),
            ('Data local: ' + $script:Started),
            'Somente leitura; sem envio de dados; sem nomes/caminhos de processos.',
            ('Limite de assinaturas: ' + $MaxSignatureChecks),
            ''
        )
        $reportLines += @($script:Checks | ForEach-Object { '[{0}] {1}: {2}' -f $_.State,$_.Label,$_.Explanation })
        $reportLines += @('',"RESUMO: OK=$ok | REVIEW=$review | INFO=$info",'Sem diagnostico automatico de cheat.')
        $reportLines | Set-Content -LiteralPath $report -Encoding UTF8 -ErrorAction Stop

        $discordLines = @(
            '**MVS LOST MEDIA | SENTINEL T1:01 - v2.1**',
            ('Sessao: `' + $script:Session + '`'),
            ('Data local: ' + $script:Started),
            ("OK: **$ok** | Revisao: **$review** | Info: **$info**"),
            ("Processos: $($script:Stats.ProcessCount) | Assinaturas: $($script:Stats.Inspected) verificadas"),
            ('Roblox na verificacao: ' + $(if ($script:Stats.RobloxRunning) { 'Sim' } else { 'Nao' })),
            'Resultado observacional: revisao humana, sem prova de cheats.'
        )
        $discordLines | Set-Content -LiteralPath $discordFile -Encoding UTF8 -ErrorAction Stop
        Say ('  Relatorio TXT: ' + $report) Cyan
        Say ('  Resumo Discord: ' + $discordFile) Cyan

        if (-not $NoHistory -and $script:Stats.ProcessCount -ge 0) {
            # Aggregate counts only: no file names, command lines, paths, or user identifiers.
            $snapshot = [ordered]@{
                Schema = 2
                Timestamp = $script:Started
                ProcessCount = $script:Stats.ProcessCount
                RobloxRunning = $script:Stats.RobloxRunning
                Inspected = $script:Stats.Inspected
                Unsigned = $script:Stats.Unsigned
                MaxSignatureChecks = $MaxSignatureChecks
            }
            $snapshot | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $historyPath -Encoding UTF8 -ErrorAction Stop
        }
    } catch { Say ('  Falha ao salvar relatorios: ' + $_.Exception.Message) Yellow }
} else { Say '  Nao foi possivel salvar relatorios nesta execucao.' Yellow }
Say '  ENCERRADO  |  MVS LOST MEDIA  |  SENTINEL 2.1.1' DarkCyan
if (-not $NoPause) { Write-Host ''; [void](Read-Host '  Pressione ENTER para fechar') }
