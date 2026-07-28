$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$compatSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\routine_compat.h') -Raw
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

Assert-Contains $compatSource '#define _r_res_queryversion\(out_buffer, ver_block\)\s+\\\s+_r_res_queryversion \(\(ver_block\), \(out_buffer\)\)' 'Compatibility shim must adapt _r_res_queryversion argument order.'
Assert-Contains $helperSource '_r_res_queryversion \(\(PVOID_PTR\)&ver_info, ver_block\.buffer\)' 'simplewall source still uses the upstream _r_res_queryversion call shape.'

Write-Output 'Compatibility static checks passed.'
