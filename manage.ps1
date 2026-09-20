param(
    [ValidateSet('Menu','List','Build','Test','Key','All','Clean')][string]$Action = 'Menu',
    [string]$App = ''
)
$ErrorActionPreference = 'Stop'
$catalog = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'apps.json') -Raw | ConvertFrom-Json
function Show-Catalog { $catalog | Select-Object app, name, category | Format-Table -AutoSize | Out-Host }
function Find-App([string]$value) {
    if ($value -match '^\d+$') { $value = 'a' + $value }
    $selected = $catalog | Where-Object { $_.app -ceq $value }
    if (!$selected) { throw 'Choose an app from a1 through a100.' }
    return $selected
}
function Invoke-Cargo([string[]]$CargoArgs) {
    & cargo @CargoArgs
    if ($LASTEXITCODE -ne 0) { throw "Cargo failed (exit $LASTEXITCODE)." }
}
function Copy-Binary([string]$name) {
    $dest = Join-Path $PSScriptRoot "dist\$name"
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "target\release\$name.exe") -Destination (Join-Path $dest "$name.exe") -Force
    Write-Host "Ready: $dest\$name.exe"
}
Push-Location $PSScriptRoot
try {
    if ($Action -eq 'List') { Show-Catalog; exit 0 }
    if ($Action -eq 'Menu') {
        Show-Catalog
        Write-Host 'Build one app: enter a1 through a100. Other actions: test a1, key a1, all, clean, q.'
        $choice = Read-Host 'Choice'
        if ($choice -eq 'q') { exit 0 }
        $parts = $choice.Trim() -split '\s+'
        switch ($parts[0]) {
            'all' { $Action = 'All' }
            'clean' { $Action = 'Clean' }
            'test' { $Action = 'Test'; $App = $parts[1] }
            'key' { $Action = 'Key'; $App = $parts[1] }
            default { $Action = 'Build'; $App = $parts[0] }
        }
    }
    if ($Action -in @('Build','Test','Key')) {
        if (!$App) { Show-Catalog; $App = Read-Host 'App (a1-a100)' }
        $selected = Find-App $App
        $App = $selected.app
        Write-Host "$App : $($selected.name) [$($selected.category)]"
    }
    switch ($Action) {
        'Build' { Invoke-Cargo @('build','--release','--locked','-p',$App); Copy-Binary $App }
        'Test' { Invoke-Cargo @('test','--locked','-p',$App) }
        'Key' {
            $dest = Join-Path $PSScriptRoot "dist\$App"
            if (!(Test-Path -LiteralPath (Join-Path $dest "$App.exe"))) { throw 'Build the app first.' }
            $generator = Join-Path $PSScriptRoot 'dist\keygen.exe'
            if (!(Test-Path -LiteralPath $generator)) {
                Invoke-Cargo @('build','--release','--locked','-p','keygen')
                Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'target\release\keygen.exe') -Destination $generator
            }
            & $generator $dest
            if ($LASTEXITCODE -ne 0) { throw "Key generation failed (exit $LASTEXITCODE). Existing keys are never replaced." }
        }
        'All' {
            Invoke-Cargo @('build','--release','--locked','--workspace','--bins')
            foreach ($entry in $catalog) { Copy-Binary $entry.app }
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'target\release\keygen.exe') -Destination (Join-Path $PSScriptRoot 'dist\keygen.exe') -Force
        }
        'Clean' { Invoke-Cargo @('clean') }
    }
} catch {
    Write-Error -Message $_ -ErrorAction Continue
    exit 1
} finally {
    Pop-Location
}
