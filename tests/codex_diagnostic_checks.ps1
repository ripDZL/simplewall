$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$codexSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\codex.c') -Raw
$logSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\log.c') -Raw
$mainHeader = Get-Content -LiteralPath (Join-Path $repoRoot 'src\main.h') -Raw

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

Assert-Contains $codexSource 'IsCodexDiagnosticEnabled", FALSE' 'Diagnostic mode must default to disabled.'
Assert-Contains $codexSource 'ptr_log->is_allow \|\|' 'Allowed events must not enter blocked-event diagnostics.'
Assert-Contains $codexSource 'ptr_log->direction != FWP_DIRECTION_OUTBOUND' 'Diagnostics must remain outbound-only.'
Assert-Contains $codexSource 'ptr_log->is_myprovider' 'Diagnostics must be scoped to simplewall-owned block events.'
Assert-Contains $codexSource 'argument value' 'Command-line argument values must be redacted.'
Assert-Contains $codexSource '_r_str_isequal \(&process_path->sr, &ptr_log->path->sr, TRUE\)' 'PID correlation must validate image path.'
Assert-Contains $codexSource '_r_str_isequal \(&process_sid->sr, &ptr_log->user_sid->sr, TRUE\)' 'PID correlation must validate SID.'
Assert-Contains $codexSource 'creation_time > ptr_log->timestamp \+ 1' 'PID correlation must reject post-event process creation.'
Assert-Contains $codexSource '_app_codex_hasalternatestream' 'Root matching must reject alternate data streams.'
Assert-Contains $codexSource 'canonical_path->buffer\[root_chars\] == L''\\\\''' 'Root matching must enforce a path boundary.'
Assert-Contains $logSource '_app_codex_auditblocked \(ptr_log\)' 'Blocked-event flow must call the diagnostic audit.'
Assert-Contains $mainHeader 'PR_STRING user_sid;' 'Blocked-event records must retain the raw SID string.'

Assert-NotContains $codexSource 'FwpmFilterAdd' 'Diagnostic module must not add WFP filters.'
Assert-NotContains $codexSource '_wfp_create' 'Diagnostic module must not call WFP creation helpers.'
Assert-NotContains $codexSource 'FWP_ACTION_PERMIT' 'Diagnostic module must not create permit actions.'

Write-Output 'Codex diagnostic static checks passed.'
