$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$networkSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\network.c') -Raw

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

Assert-NotContains $networkSource '_r_obj_addhashtablepointer \(network_context->checker_ptr, network_hash, NULL\)' 'Active network rows must carry a non-null checker value so already-discovered connections can be materialized into the Connections tab.'
Assert-Contains $networkSource 'VOID _app_network_addcheckeritem' 'Network monitor must route active-row markers through a single safe helper.'
Assert-Contains $networkSource '_r_obj_referencesafe \(path\)' 'Active network row markers must safely retain path references.'
Assert-Contains $networkSource '_r_obj_referenceemptystring \(\)' 'Active network row markers must remain non-null even without path evidence.'
Assert-Contains $networkSource '_app_network_addcheckeritem \(network_context, network_hash, ptr_network->path\)' 'Existing and new network rows must remain materializable into the Connections tab.'

Write-Output 'Network monitor static checks passed.'
