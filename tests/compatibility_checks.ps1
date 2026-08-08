$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$compatSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\routine_compat.h') -Raw
$controlsSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\controls.c') -Raw
$helperSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\helper.c') -Raw
$listviewSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\listview.c') -Raw
$routineSource = Get-Content -LiteralPath (Join-Path $repoRoot 'third_party\routine\src\routine.c') -Raw

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
Assert-Contains $listviewSource '_r_listview_additem \(hwnd, IDC_NETWORK, INT_ERROR' 'Network rows depend on the upstream append sentinel.'
Assert-Contains $compatSource 'FORCEINLINE INT _r_compat_listview_additem' 'Compatibility shim must adapt the upstream append sentinel.'
Assert-Contains $compatSource 'item_id == INT_ERROR' 'Compatibility shim must detect the upstream append sentinel.'
Assert-Contains $compatSource '#define _r_listview_additem _r_compat_listview_additem' 'Compatibility shim must route list insertions through the append adapter.'
Assert-Contains $routineSource 'if \(image_id != I_IMAGENONE\)' 'Public routine toolbar updates must retain their current image-selection behavior.'
Assert-Contains $compatSource 'FORCEINLINE BOOLEAN _r_compat_toolbar_setbutton' 'Compatibility shim must adapt the upstream toolbar image sentinel.'
Assert-Contains $compatSource 'if \(image_id == I_DEFAULT\)' 'Toolbar adapter must preserve an existing icon when upstream passes I_DEFAULT.'
Assert-Contains $compatSource 'image_id = I_IMAGENONE;' 'Toolbar adapter must translate I_DEFAULT to the public routine no-image-update sentinel.'
Assert-Contains $compatSource '#define _r_toolbar_setbutton _r_compat_toolbar_setbutton' 'Compatibility shim must route toolbar updates through the image-sentinel adapter.'

Write-Output 'Compatibility static checks passed.'
