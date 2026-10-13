#requires -Version 5.1
<#
MVS Lost Media | T1 SYSTEM CHECK | Build 2.5.1
Public, read-only Windows security and process audit.
No external connections made by the script, no automatic elevation or system changes.
Only creates local reports and an optional aggregate-only comparison snapshot.
Unsigned files or other observations are NOT proof of cheating.

Options:
  -ShowDetails             Displays names of unsigned/unverifiable executables locally.
                           Names/paths are NEVER saved to reports.
  -MaxSignatureChecks 100  Maximum distinct readable executables checked (20..200).
  -NoHistory               Does not read or write the previous-run aggregate snapshot.
  -NoViewer                Skips the read-only visual inspection window.
  -NoPause                 Skips the ENTER prompt before the visual panel.
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
$script:QuietAudit = $true
$script:LastProgressLength = 0
$script:GuiReviewItems = @()
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
function Write-LMIntro {
    Clear-Host
    Say ''
    Say '  +------------------------------------------------------------------+' DarkCyan
    Say '  |                                                                  |' DarkCyan
    Say '  |             MVS LOST MEDIA  |  T1 RECORDING POLICY               |' Cyan
    Say '  |                                                                  |' DarkCyan
    Say '  |                       _       __  __                             |' Cyan
    Say '  |                      | |     |  \/  |                            |' Cyan
    Say '  |                      | |     | |\/| |                            |' Cyan
    Say '  |                      | |___  | |  | |                            |' Cyan
    Say '  |                      |_____| |_|  |_|                            |' Cyan
    Say '  |                                                                  |' DarkCyan
    Say '  |     SYSTEM CHECK  /  BUILD 2.5.1  /  SOMENTE LEITURA               |' White
    Say '  |                                                                  |' DarkCyan
    Say '  +------------------------------------------------------------------+' DarkCyan
    Say '  Servidor: MVS Lost Media | Dono: Mangaka' Gray
    Say ('  Sessao: ' + $script:Session + ' | ' + $script:Started) DarkGray
    Say '  Nenhum arquivo pessoal e enviado. Nenhum alerta prova cheats.' DarkGray
    Say ''
    Say '  VERIFICANDO SEU PC' Cyan
}
function Write-LMProgress([int]$Percent,[string]$Step) {
    $count = [int][Math]::Floor(([Math]::Max(0,[Math]::Min(100,$Percent)) * 26) / 100)
    $bar = ('#' * $count) + ('.' * (26-$count))
    $line = ('  Verification [{0}] {1,3}%  {2}' -f $bar,$Percent,$Step)
    $padded = $line.PadRight([Math]::Max($script:LastProgressLength,$line.Length))
    $script:LastProgressLength = $padded.Length
    Write-Host ("`r" + $padded) -NoNewline -ForegroundColor Cyan
    if ($Percent -ge 100) { Write-Host '' }
}
function Write-LMSection([string]$Id,[string]$Heading) {
    if ($script:QuietAudit) { return }
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
    if (-not $script:QuietAudit) {
        Write-Host ('  {0:00}  ' -f $script:CheckIndex) -NoNewline -ForegroundColor DarkGray
        Write-Host ('[{0,-6}] ' -f $State) -NoNewline -ForegroundColor $color
        Write-Host ($Label + ' | ' + $Explanation)
    }
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

function Open-LMVisualInspector {
    # Local, read-only WinForms inspection. Detailed names are not written to reports.
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    } catch {
        Say ('  Windows Forms nao abriu: ' + $_.Exception.GetType().Name) Yellow
        Check 'Janela visual' 'INFO' ('Windows Forms nao abriu: ' + $_.Exception.GetType().Name + '.')
        return
    }

    $window = $null
    try {
        function script:Get-LMProcessRows {
            param([object[]]$Items)
            $out = New-Object 'System.Collections.Generic.List[object]'
            foreach ($proc in $Items) {
                $path = $null
                try { $path = $proc.Path } catch { }
                $signature = 'Nao verificada'
                if ([string]::IsNullOrWhiteSpace($path)) { $signature = 'Caminho indisponivel' }
                elseif ($script:GuiSignatureMap.ContainsKey($path)) {
                    $signature = switch ($script:GuiSignatureMap[$path]) {
                        'Valid' { 'Valida' }
                        'NotSigned' { 'Sem assinatura' }
                        default { 'Outro estado' }
                    }
                }
                $ram = '-'
                try { $ram = [string][Math]::Round($proc.WorkingSet64 / 1MB) } catch { }
                [void]$out.Add([pscustomobject]@{
                    Processo = [string]$proc.ProcessName
                    PID = [string]$proc.Id
                    RAM_MB = $ram
                    Assinatura = $signature
                })
            }
            return @($out | Sort-Object Processo, PID)
        }

        function script:Get-LMServiceRows {
            try {
                return @(Get-Service -ErrorAction Stop | Sort-Object Name | ForEach-Object {
                    [pscustomobject]@{
                        Servico = [string]$_.Name
                        Descricao = [string]$_.DisplayName
                        Estado = [string]$_.Status
                    }
                })
            } catch { return @() }
        }

        function script:Get-LMDriverRows {
            # Win32_SystemDriver reports service/driver state. Some drivers use catalog signatures:
            # Get-AuthenticodeSignature on a .sys file alone is not conclusive.
            $out = New-Object 'System.Collections.Generic.List[object]'
            $checked = 0
            try {
                $items = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | Sort-Object Name)
                foreach ($driver in $items) {
                    $signature = 'Nao verificada'
                    $path = [string]$driver.PathName
                    $location = $null
                    if ($path -match '(?i)([a-z]:\\[^"\r\n]+?\.sys|\\SystemRoot\\[^"\r\n]+?\.sys|System32\\[^"\r\n]+?\.sys)') {
                        $location = [string]$Matches[1]
                        if ($location.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
                            $location = Join-Path $env:SystemRoot ($location.Substring(12))
                        } elseif ($location.StartsWith('System32\', [StringComparison]::OrdinalIgnoreCase)) {
                            $location = Join-Path $env:SystemRoot $location
                        }
                    }
                    if ($checked -lt 60 -and $location -and [IO.File]::Exists($location)) {
                        $checked++
                        $signature = switch (SignatureStatus $location) {
                            'Valid' { 'Valida' }
                            'NotSigned' { 'Nao encontrada*' }
                            default { 'Indisponivel*' }
                        }
                    }
                    [void]$out.Add([pscustomobject]@{
                        Driver = [string]$driver.Name
                        Estado = [string]$driver.State
                        Inicio = [string]$driver.StartMode
                        Assinatura = $signature
                    })
                }
            } catch { return @() }
            $script:GuiDriverSignaturesChecked = $checked
            return @($out)
        }

        function script:Get-LMStartupRows {
            try {
                return @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop | Sort-Object Name | ForEach-Object {
                    $origin = [string]$_.Location
                    $source = if ($origin -match '(?i)startup') { 'Pasta Inicializar' }
                        elseif ($origin -match '(?i)HKLM|HKCU|registry|run') { 'Registro Windows' }
                        else { 'Outra origem' }
                    [pscustomobject]@{ Programa = [string]$_.Name; Origem = $source }
                })
            } catch { return @() }
        }

        function script:Get-LMReviewRows {
            $out = New-Object 'System.Collections.Generic.List[object]'
            foreach ($entry in $script:GuiReviewItems) {
                $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                foreach ($proc in $script:GuiProcesses) {
                    try {
                        if ($proc.Path -and [string]::Equals([string]$proc.Path, [string]$entry.Path, [StringComparison]::OrdinalIgnoreCase)) {
                            [void]$names.Add([string]$proc.ProcessName)
                        }
                    } catch { }
                }
                $processNames = if ($names.Count -gt 0) { (@($names | Select-Object -First 3) -join ', ') } else { 'Indisponivel' }
                $result = switch ([string]$entry.Signature) {
                    'NotSigned' { 'Sem assinatura' }
                    default { [string]$entry.Signature }
                }
                [void]$out.Add([pscustomobject]@{
                    Arquivo = [string]$entry.File
                    Processo = $processNames
                    Situacao = $result
                })
            }
            return @($out | Sort-Object Arquivo)
        }

        $script:GuiDriverSignaturesChecked = 0
        $categories = @('PROCESSOS','SERVICOS','DRIVERS','INICIALIZACAO','REVISAO','INFORMACOES')
        $script:Gui23 = @{
            Active = 'PROCESSOS'
            Page = 0
            PageSize = 15
            Filter = ''
            Categories = $categories
            Rows = @{}
            Columns = @{
                PROCESSOS = @('Processo','PID','RAM_MB','Assinatura')
                SERVICOS = @('Servico','Descricao','Estado')
                DRIVERS = @('Driver','Estado','Inicio','Assinatura')
                INICIALIZACAO = @('Programa','Origem')
                REVISAO = @('Arquivo','Processo','Situacao')
            }
            Visited = @{}
        }
        foreach ($key in $categories) { $script:Gui23.Visited[$key] = @{} }
        $script:Gui23.Rows['PROCESSOS'] = @(Get-LMProcessRows -Items $script:GuiProcesses)
        $script:Gui23.Rows['SERVICOS'] = @(Get-LMServiceRows)
        $script:Gui23.Rows['DRIVERS'] = @(Get-LMDriverRows)
        $script:Gui23.Rows['INICIALIZACAO'] = @(Get-LMStartupRows)
        $script:Gui23.Rows['REVISAO'] = @(Get-LMReviewRows)
        Check 'Drivers' 'INFO' ("$(@($script:Gui23.Rows['DRIVERS']).Count) itens; $script:GuiDriverSignaturesChecked arquivos consultados (amostra nao conclusiva).")
        Check 'Inicializacao' 'INFO' ("$(@($script:Gui23.Rows['INICIALIZACAO']).Count) entradas listadas na janela, sem comandos/caminhos nos relatorios.")
        Check 'Itens para revisao visual' 'INFO' ("$(@($script:Gui23.Rows['REVISAO']).Count) arquivos da amostra de processos disponiveis na aba REVISAO.")

        $dark = [System.Drawing.Color]::FromArgb(14,24,36)
        $panel = [System.Drawing.Color]::FromArgb(23,37,54)
        $cyan = [System.Drawing.Color]::FromArgb(96,220,233)
        $white = [System.Drawing.Color]::FromArgb(231,240,249)
        $muted = [System.Drawing.Color]::FromArgb(158,177,197)

        $window = New-Object System.Windows.Forms.Form
        $window.Text = 'MVS LOST MEDIA  |  T1 SYSTEM CHECK v2.5.1'
        $window.StartPosition = 'CenterScreen'
        $window.Size = New-Object System.Drawing.Size(1130,745)
        $window.MinimumSize = New-Object System.Drawing.Size(1040,620)
        $window.BackColor = $dark
        $window.ForeColor = $white
        $window.Font = New-Object System.Drawing.Font('Segoe UI',10)

        $layout = New-Object System.Windows.Forms.TableLayoutPanel
        $layout.Dock = 'Fill'
        $layout.ColumnCount = 1
        $layout.RowCount = 4
        [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,92)))
        [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,45)))
        [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent,100)))
        [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,112)))
        $window.Controls.Add($layout)

        $top = New-Object System.Windows.Forms.Panel
        $top.BackColor = $dark; $top.Dock = 'Fill'
        $title = New-Object System.Windows.Forms.Label
        $title.Text = 'MVS LOST MEDIA   /   TIER 1'
        $title.ForeColor = $cyan
        $title.Font = New-Object System.Drawing.Font('Consolas',20,[System.Drawing.FontStyle]::Bold)
        $title.Location = New-Object System.Drawing.Point(20,10)
        $title.AutoSize = $true
        $top.Controls.Add($title)
        $subtitle = New-Object System.Windows.Forms.Label
        $subtitle.Text = 'SYSTEM CHECK  /  PROCESSOS / DRIVERS / INICIALIZACAO  /  BUILD 2.5.1'
        $subtitle.ForeColor = $muted
        $subtitle.Font = New-Object System.Drawing.Font('Consolas',10)
        $subtitle.Location = New-Object System.Drawing.Point(23,55)
        $subtitle.AutoSize = $true
        $top.Controls.Add($subtitle)
        $layout.Controls.Add($top,0,0)

        $filterPanel = New-Object System.Windows.Forms.Panel
        $filterPanel.Dock = 'Fill'
        $filterPanel.BackColor = $panel
        $filterLabel = New-Object System.Windows.Forms.Label
        $filterLabel.Text = 'Pesquisar (somente nesta aba):'
        $filterLabel.Location = New-Object System.Drawing.Point(20,13)
        $filterLabel.AutoSize = $true
        $filterLabel.ForeColor = $white
        $filterPanel.Controls.Add($filterLabel)
        $filterBox = New-Object System.Windows.Forms.TextBox
        $filterBox.Location = New-Object System.Drawing.Point(256,8)
        $filterBox.Size = New-Object System.Drawing.Size(410,28)
        $filterPanel.Controls.Add($filterBox)
        $filterNotice = New-Object System.Windows.Forms.Label
        $filterNotice.Text = 'Filtro ativo nao conta paginas como visitadas.'
        $filterNotice.ForeColor = $muted
        $filterNotice.Location = New-Object System.Drawing.Point(680,12)
        $filterNotice.AutoSize = $true
        $filterNotice.Visible = $false
        $filterPanel.Controls.Add($filterNotice)
        $layout.Controls.Add($filterPanel,0,1)

        $tabs = New-Object System.Windows.Forms.TabControl
        $tabs.Dock = 'Fill'
        $tabs.Font = New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Bold)
        $layout.Controls.Add($tabs,0,2)
        $grids = @{}
        foreach ($category in $categories) {
            $tab = New-Object System.Windows.Forms.TabPage
            $tab.Text = $category
            $tab.BackColor = $panel
            [void]$tabs.TabPages.Add($tab)
            if ($category -eq 'INFORMACOES') {
                $info = New-Object System.Windows.Forms.Label
                $info.Dock = 'Fill'; $info.Padding = New-Object System.Windows.Forms.Padding(20)
                $info.ForeColor = $white
                $info.Font = New-Object System.Drawing.Font('Consolas',11)
                $info.Text = ('SESSAO: ' + $script:Session + [Environment]::NewLine + [Environment]::NewLine +
                    'Processos na leitura inicial: ' + $script:Stats.ProcessCount + [Environment]::NewLine +
                    'Assinaturas validas: ' + $script:Stats.SignedValid + [Environment]::NewLine +
                    'Sem assinatura na amostra: ' + $script:Stats.Unsigned + [Environment]::NewLine +
                    'Drivers consultados: ' + $script:GuiDriverSignaturesChecked + ' arquivos (amostra)' + [Environment]::NewLine + [Environment]::NewLine +
                    'Assinatura ausente NAO comprova cheat.' + [Environment]::NewLine +
                    'Drivers podem ser assinados por catalogo; esta tela nao e definitiva.' + [Environment]::NewLine +
                    'Atualizar muda a visualizacao, nao a varredura inicial.' + [Environment]::NewLine +
                    'Paginas visitadas nao comprovam que a gravacao esteja completa.' + [Environment]::NewLine +
                    'Nenhuma alteracao de seguranca ou envio de dados e realizada.' + [Environment]::NewLine +
                    'Nomes, PIDs e programas aparecem apenas nesta janela.')
                $tab.Controls.Add($info)
            } else {
                $grid = New-Object System.Windows.Forms.DataGridView
                $grid.Dock = 'Fill'; $grid.ReadOnly = $true
                $grid.BackgroundColor = $panel
                $grid.GridColor = [System.Drawing.Color]::FromArgb(48,64,82)
                $grid.EnableHeadersVisualStyles = $false
                $grid.ColumnHeadersDefaultCellStyle.BackColor = $dark
                $grid.ColumnHeadersDefaultCellStyle.ForeColor = $cyan
                $grid.DefaultCellStyle.BackColor = $panel
                $grid.DefaultCellStyle.ForeColor = $white
                $grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(40,93,111)
                $grid.DefaultCellStyle.SelectionForeColor = $white
                $grid.RowHeadersVisible = $false
                $grid.AllowUserToAddRows = $false; $grid.AllowUserToDeleteRows = $false
                $grid.MultiSelect = $false
                $grid.SelectionMode = 'FullRowSelect'
                $grid.AutoSizeColumnsMode = 'Fill'
                $grid.AllowUserToResizeRows = $false
                $grids[$category] = $grid
                $tab.Controls.Add($grid)
            }
        }

        $bottom = New-Object System.Windows.Forms.Panel
        $bottom.Dock = 'Fill'; $bottom.BackColor = $dark
        $privacy = New-Object System.Windows.Forms.Label
        $privacy.Text = 'PRIVACIDADE: a gravacao pode mostrar nomes de programas. Confira o video antes de enviar.'
        $privacy.ForeColor = $muted
        $privacy.Location = New-Object System.Drawing.Point(20,5)
        $privacy.AutoSize = $true
        $bottom.Controls.Add($privacy)

        $prev = New-Object System.Windows.Forms.Button
        $prev.Text = '<< Anterior'; $prev.Location = New-Object System.Drawing.Point(20,42)
        $prev.Size = New-Object System.Drawing.Size(130,35)
        $bottom.Controls.Add($prev)
        $next = New-Object System.Windows.Forms.Button
        $next.Text = 'Proxima >>'; $next.Location = New-Object System.Drawing.Point(158,42)
        $next.Size = New-Object System.Drawing.Size(130,35)
        $bottom.Controls.Add($next)
        $progress = New-Object System.Windows.Forms.Label
        $progress.ForeColor = $cyan
        $progress.Font = New-Object System.Drawing.Font('Consolas',10)
        $progress.Location = New-Object System.Drawing.Point(302,46)
        $progress.Size = New-Object System.Drawing.Size(460,32)
        $bottom.Controls.Add($progress)
        $refresh = New-Object System.Windows.Forms.Button
        $refresh.Text = 'Atualizar listas'
        $refresh.Location = New-Object System.Drawing.Point(760,42)
        $refresh.Size = New-Object System.Drawing.Size(142,35)
        $bottom.Controls.Add($refresh)
        $finish = New-Object System.Windows.Forms.Button
        $finish.Text = 'Concluir verificacao'
        $finish.Location = New-Object System.Drawing.Point(915,42)
        $finish.Size = New-Object System.Drawing.Size(175,35)
        $finish.Add_Click({ $script:Gui23Window.Close() })
        $bottom.Controls.Add($finish)
        $layout.Controls.Add($bottom,0,3)

        $script:Gui23Window = $window
        $script:Gui23Controls = @{
            Tabs = $tabs; Filter = $filterBox; Notice = $filterNotice; Grids = $grids
            Progress = $progress; Prev = $prev; Next = $next; Refresh = $refresh
        }
        $script:Gui23Render = {
            $state = $script:Gui23
            $controls = $script:Gui23Controls
            $category = $state.Active
            if ($category -eq 'INFORMACOES') {
                $controls.Filter.Enabled = $false
                $controls.Notice.Visible = $false
                $controls.Prev.Enabled = $false; $controls.Next.Enabled = $false
                $controls.Refresh.Enabled = $false
                $controls.Progress.Text = 'Resumo da sessao'
                return
            }
            $controls.Filter.Enabled = $true
            $columns = @($state.Columns[$category])
            $items = @($state.Rows[$category])
            $filter = $state.Filter.Trim()
            if ($filter.Length -gt 0) {
                $items = @($items | Where-Object {
                    $row = $_; $matched = $false
                    foreach ($field in $columns) {
                        if ([string]$row.$field -like ('*' + $filter + '*')) { $matched = $true; break }
                    }
                    $matched
                })
            }
            $controls.Notice.Visible = ($filter.Length -gt 0)
            $total = $items.Count
            $pages = [Math]::Max(1,[int][Math]::Ceiling($total / $state.PageSize))
            if ($state.Page -ge $pages) { $state.Page = $pages - 1 }
            if ($state.Page -lt 0) { $state.Page = 0 }
            if ($filter.Length -eq 0) { $pageKey = [string]$state.Page; $state.Visited[$category][$pageKey] = $true }
            $current = @($items | Select-Object -Skip ($state.Page * $state.PageSize) -First $state.PageSize)
            $table = New-Object System.Data.DataTable
            foreach ($field in $columns) { [void]$table.Columns.Add($field,[string]) }
            foreach ($row in $current) {
                $cells = foreach ($field in $columns) { [string]$row.$field }
                [void]$table.Rows.Add([object[]]$cells)
            }
            $controls.Grids[$category].DataSource = $table
            $visits = $state.Visited[$category].Count
            if ($filter.Length -eq 0) {
                $controls.Progress.Text = ('Pagina {0}/{1}  |  Visitadas {2}/{1}' -f ($state.Page+1),$pages,$visits)
            } else {
                $controls.Progress.Text = ('Filtrado: pagina {0}/{1}  |  {2} itens' -f ($state.Page+1),$pages,$total)
            }
            $controls.Prev.Enabled = ($state.Page -gt 0)
            $controls.Next.Enabled = ($state.Page -lt ($pages - 1))
            $controls.Refresh.Enabled = ($category -eq 'PROCESSOS' -or $category -eq 'SERVICOS')
        }
        $prev.Add_Click({ $script:Gui23.Page--; & $script:Gui23Render })
        $next.Add_Click({ $script:Gui23.Page++; & $script:Gui23Render })
        $filterBox.Add_TextChanged({
            $script:Gui23.Filter = $script:Gui23Controls.Filter.Text
            $script:Gui23.Page = 0
            & $script:Gui23Render
        })
        $tabs.Add_SelectedIndexChanged({
            $script:Gui23.Active = [string]$script:Gui23.Categories[$script:Gui23Controls.Tabs.SelectedIndex]
            $script:Gui23.Page = 0
            $script:Gui23.Filter = ''
            $script:Gui23Controls.Filter.Text = ''
            & $script:Gui23Render
        })
        $refresh.Add_Click({
            try {
                $script:Gui23.Rows['PROCESSOS'] = @(Get-LMProcessRows -Items @(Get-Process -ErrorAction Stop))
                $script:Gui23.Rows['SERVICOS'] = @(Get-LMServiceRows)
                $script:Gui23.Visited['PROCESSOS'] = @{}
                $script:Gui23.Visited['SERVICOS'] = @{}
                $script:Gui23.Page = 0
                & $script:Gui23Render
            } catch {
                [void][System.Windows.Forms.MessageBox]::Show('Nao foi possivel atualizar as listas.', 'MVS LOST MEDIA')
            }
        })
        & $script:Gui23Render
        # The visual panel is shown after the console summary and ENTER.
        [void]$window.ShowDialog()
        $visitedSummary = @()
        foreach ($cat in @('PROCESSOS','SERVICOS','DRIVERS','INICIALIZACAO','REVISAO')) {
            $visitedSummary += ($cat + '=' + [string]$script:Gui23.Visited[$cat].Count)
        }
        Check 'Inspecao visual' 'INFO' ('Janela encerrada. Paginas visitadas (nao comprova gravacao): ' + ($visitedSummary -join ', ') + '.')
    } catch {
        Say ('  Janela indisponivel: ' + $_.Exception.Message) Yellow
        Check 'Inspecao visual' 'INFO' ('Janela nao concluida: ' + $_.Exception.GetType().Name + '.')
    } finally {
        if ($null -ne $window) { $window.Dispose() }
        $script:Gui23 = $null
        $script:Gui23Controls = $null
        $script:Gui23Render = $null
        $script:Gui23Window = $null
    }
}

Write-LMIntro
Write-LMProgress 0 'Preparando a verificacao...'
Write-LMSection '01' 'Identificacao do ambiente'
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

Write-LMProgress 15 'Ambiente consultado'
Write-LMSection '02' 'Protecao do dispositivo'
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

Write-LMProgress 35 'Defender e firewall consultados'
Write-LMSection '03' 'Servicos e isolamento'
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

Write-LMProgress 52 'Servicos e isolamento consultados'
Write-LMSection '04' 'Processos e assinaturas'
try {
    $runningProcesses = @(Get-Process -ErrorAction Stop)
    $script:Stats.ProcessCount = $runningProcesses.Count
    # A janela pode funcionar mesmo que a etapa de assinaturas falhe depois.
    $script:GuiProcesses = @($runningProcesses)
    $script:GuiReady = $true
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
        if ($processed -eq 1 -or ($processed % 10) -eq 0 -or $processed -eq [Math]::Min($locations.Count,$MaxSignatureChecks)) {
            $fraction = [Math]::Max(1,[Math]::Min($locations.Count,$MaxSignatureChecks))
            $pct = 58 + [int][Math]::Floor((26.0 * $processed)/$fraction)
            Write-LMProgress $pct ('Assinaturas ' + $processed + '/' + $fraction)
        }
        if ($status -eq 'Valid') { $valid++ }
        elseif ($status -eq 'NotSigned') { $unsigned++ }
        else { $other++ }
        if ($status -ne 'Valid') {
            [void]$reviewLocal.Add([pscustomobject]@{ File=[IO.Path]::GetFileName($loc); Signature=$status; Path=$loc })
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
    $script:GuiReviewItems = @($reviewLocal)
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
    # Registrar o erro tecnico sem incluir caminhos, nomes de programas ou dados pessoais.
    $errType = $_.Exception.GetType().Name
    $errLine = [int]$_.InvocationInfo.ScriptLineNumber
    Check 'Processos' 'INFO' ("Leitura parcial: $errType na linha $errLine. Painel visual ainda disponivel.")
    if ($script:Stats.ProcessCount -ge 0 -and $script:Stats.Inspected -eq 0) {
        Check 'Assinaturas verificadas' 'INFO' 'Analise interrompida; nao foi possivel concluir a verificacao das assinaturas.'
    }
}

Write-LMProgress 85 'Processos e assinaturas consultados'
Write-LMSection '05' 'Comparacao entre execucoes'
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

Write-LMProgress 92 'Comparacao de execucoes concluida'
Write-LMSection '06' 'Integridade e resumo'
try {
    $hash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash
    Check 'SHA-256 deste arquivo' 'INFO' $hash
} catch { Check 'SHA-256 deste arquivo' 'INFO' 'Nao foi possivel calcular.' }

# ETAPA 1 / 3: intro + progresso ate 100%, sem resultados misturados.
Write-LMProgress 100 'Consultas concluidas'
Start-Sleep -Milliseconds 1600

# ETAPA 2 / 3: limpar o terminal antes de exibir os resultados.
Clear-Host
$script:QuietAudit = $false
Say ''
Say '  +------------------------------------------------------------------+' DarkCyan
Say '  |              MVS LOST MEDIA  |  T1 SYSTEM CHECK                  |' Cyan
Say '  |                    RESULTADOS DA VERIFICACAO                     |' White
Say '  +------------------------------------------------------------------+' DarkCyan
Say ('  Sessao: ' + $script:Session + '  |  BUILD 2.5.1') DarkGray
Say ''
# Exibe aqui os resultados mais importantes. A lista completa vai no TXT.
$highlightInfo = @('Processos ativos','Roblox','Integridade de memoria','Cobertura de executaveis','Assinaturas verificadas','Processos')
foreach ($entry in $script:Checks) {
    if ($entry.State -eq 'INFO' -and $highlightInfo -notcontains $entry.Label) { continue }
    $col = switch ($entry.State) { 'OK' { 'Green' } 'REVIEW' { 'Yellow' } default { 'Gray' } }
    Say ('  [{0,-6}] {1}: {2}' -f $entry.State,$entry.Label,$entry.Explanation) $col
}
$ok = @($script:Checks | Where-Object { $_.State -eq 'OK' }).Count
$review = @($script:Checks | Where-Object { $_.State -eq 'REVIEW' }).Count
$info = @($script:Checks | Where-Object { $_.State -eq 'INFO' }).Count
Say ''
Say (('  RESUMO | OK: {0} | REVISAO: {1} | INFO: {2}' -f $ok,$review,$info)) Cyan
if ($review -gt 0) { Say '  Existem itens para revisao humana; nao ha veredito automatico.' Yellow }
else { Say '  Nenhum alerta nesta consulta; isso nao comprova ausencia de cheats.' Green }
Say '  A lista completa sera salva em Documentos\MVS-Lost-Media-T1.' DarkGray
Say '  Nenhuma consulta garante ausencia ou presenca de cheats.' DarkGray
Say ''
if (-not $NoViewer) {
    # Inspecao visual independente do sucesso da verificacao de assinaturas.
    # Caso a lista inicial esteja vazia, uma nova leitura local e tentada.
    if (@($script:GuiProcesses).Count -eq 0) {
        try {
            $script:GuiProcesses = @(Get-Process -ErrorAction Stop)
            $script:GuiReady = $true
        } catch {
            Check 'Processos do painel' 'INFO' 'Nova leitura indisponivel; outras abas ainda podem funcionar.'
        }
    }
    if (-not $NoPause) { [void](Read-Host '  Pressione ENTER para abrir o painel visual') }
    # ETAPA 3 / 3: tentar a janela mesmo se alguma verificacao anterior falhou.
    Clear-Host
    Say '  MVS LOST MEDIA | Abrindo painel visual...' Cyan
    $script:QuietAudit = $true
    Open-LMVisualInspector
    $script:QuietAudit = $false
} else {
    Say '  Painel visual omitido por -NoViewer.' DarkGray
}
# After the visual inspection, its observations are included in both reports.
$ok = @($script:Checks | Where-Object { $_.State -eq 'OK' }).Count
$review = @($script:Checks | Where-Object { $_.State -eq 'REVIEW' }).Count
$info = @($script:Checks | Where-Object { $_.State -eq 'INFO' }).Count
# Relatorios sao gravados silenciosamente apos fechar o painel.
# O PowerShell retorna ao prompt automaticamente, sem ENTER extra.
if ($null -ne $folder) {
    try {
        $prefix = 'LM-T1-SYSTEM-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $script:Session
        $report = Join-Path $folder ($prefix + '.txt')
        $discordFile = Join-Path $folder ($prefix + '-DISCORD.txt')
        $reportLines = @(
            'MVS LOST MEDIA | T1 SYSTEM CHECK | BUILD 2.5.1',
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
            '**MVS LOST MEDIA | T1 SYSTEM CHECK - v2.5.1**',
            ('Sessao: `' + $script:Session + '`'),
            ('Data local: ' + $script:Started),
            ("OK: **$ok** | Revisao: **$review** | Info: **$info**"),
            ("Processos: $($script:Stats.ProcessCount) | Assinaturas: $($script:Stats.Inspected) verificadas"),
            ('Roblox na verificacao: ' + $(if ($script:Stats.RobloxRunning) { 'Sim' } else { 'Nao' })),
            'Resultado observacional: revisao humana, sem prova de cheats.'
        )
        $discordLines | Set-Content -LiteralPath $discordFile -Encoding UTF8 -ErrorAction Stop

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
# Sem segunda pausa final: volta ao prompt original do PowerShell.

