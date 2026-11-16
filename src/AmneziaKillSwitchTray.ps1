Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$base = Split-Path -Parent $PSCommandPath
$runtimePath = Join-Path $base 'runtime.json'
if (-not (Test-Path -LiteralPath $runtimePath)) { exit }
$runtime = Get-Content -LiteralPath $runtimePath -Raw | ConvertFrom-Json

$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Shield
$notify.Text = 'Amnezia Kill Switch — защита активна'
$notify.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$state = New-Object System.Windows.Forms.ToolStripMenuItem('Защита: активна')
$state.Enabled = $false
$open = New-Object System.Windows.Forms.ToolStripMenuItem('Открыть настройки')
$refresh = New-Object System.Windows.Forms.ToolStripMenuItem('Перезапустить защиту')
$exit = New-Object System.Windows.Forms.ToolStripMenuItem('Закрыть значок в трее')
[void]$menu.Items.Add($state)
[void]$menu.Items.Add('-')
[void]$menu.Items.Add($open)
[void]$menu.Items.Add($refresh)
[void]$menu.Items.Add('-')
[void]$menu.Items.Add($exit)
$notify.ContextMenuStrip = $menu

$open.add_Click({
    $arguments = if ($runtime.script) { '"' + $runtime.script + '" --setup' } else { '--setup' }
    Start-Process -FilePath $runtime.python -ArgumentList $arguments -Verb RunAs
})
$refresh.add_Click({
    schtasks.exe /Run /TN 'Amnezia App Kill Switch Monitor' | Out-Null
    $notify.ShowBalloonTip(2000, 'Amnezia Kill Switch', 'Проверка правил запущена.', [System.Windows.Forms.ToolTipIcon]::Info)
})
$exit.add_Click({
    $notify.Visible = $false
    $notify.Dispose()
    [System.Windows.Forms.Application]::Exit()
})
$notify.add_DoubleClick({ $open.PerformClick() })

[System.Windows.Forms.Application]::Run()

