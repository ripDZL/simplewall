$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$compatSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\routine_compat.h') -Raw
$controlsSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\controls.c') -Raw
$helperSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\helper.c') -Raw

function Assert-Contains {
    param(
        [string]$Text,
        [string]$Pattern,
        [string]$Message
    )

    if ($Text -notmatch $Pattern) {
        throw $Message
    }
}

function Assert-NotContains {
    param(
        [string]$Text,
        [string]$Pattern,
        [string]$Message
    )

    if ($Text -match $Pattern) {
        throw $Message
    }
}

Assert-Contains $compatSource '#define _r_res_queryversion\(out_buffer, ver_block\)\s+\\\s+_r_res_queryversion \(\(ver_block\), \(out_buffer\)\)' 'Compatibility shim must adapt _r_res_queryversion argument order.'
Assert-Contains $helperSource '_r_res_queryversion \(\(PVOID_PTR\)&ver_info, ver_block\.buffer\)' 'simplewall source still uses the upstream _r_res_queryversion call shape.'
Assert-NotContains $compatSource '#define _r_tab_selectitem' 'Compatibility shim must not bypass routine tab-change notifications.'
Assert-Contains $controlsSource '_r_tab_selectitem \(hwnd, IDC_TAB, i\);\s+return TRUE;' 'Tab selection must call the routine helper that sends TCN_SELCHANGING/TCN_SELCHANGE notifications.'

Write-Output 'Compatibility static checks passed.'
