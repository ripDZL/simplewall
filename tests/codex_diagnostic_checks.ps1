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
Assert-Contains $codexSource 'CodexDiagnosticSids' 'Diagnostics must support an explicit Codex SID association list.'
Assert-Contains $codexSource 'if \(!is_sid_match && !matched_root\)' 'Unassociated blocked events must not be audited.'
Assert-Contains $codexSource '_app_codex_sanitizecommandline' 'Command lines must pass through the sanitizer.'
Assert-Contains $codexSource '_app_codex_issafeflag' 'Only allowlisted non-secret flag names may be retained.'
Assert-Contains $codexSource 'L"<redacted>"' 'Command-line values must be redacted.'
Assert-Contains $codexSource '_r_str_isequal \(&process_path->sr, &ptr_log->path->sr, TRUE\)' 'PID correlation must validate image path.'
Assert-Contains $codexSource '_r_str_isequal \(&process_sid->sr, &ptr_log->user_sid->sr, TRUE\)' 'PID correlation must validate SID.'
Assert-Contains $codexSource 'creation_time > ptr_log->timestamp \+ 1' 'PID correlation must reject post-event process creation.'
Assert-Contains $codexSource 'opened_parent_creation\.QuadPart == parent_process->CreateTime\.QuadPart' 'Parent-chain capture must reject reused ancestor PIDs.'
Assert-Contains $codexSource '_app_codex_hasalternatestream' 'Root matching must reject alternate data streams.'
Assert-Contains $codexSource 'canonical_path->buffer\[root_chars\] == L''\\\\''' 'Root matching must enforce a path boundary.'
Assert-Contains $codexSource 'if \(is_correlated && hfile\)' 'File evidence must require a validated live process.'
Assert-Contains $codexSource '_app_codex_getsignature \(\s*hfile,\s*identity\.process_path' 'Signer evidence must use the validated process image path.'
Assert-Contains $codexSource 'file metadata is not kernel-bound to the WFP event' 'Audit output must state the file-evidence binding limitation.'
Assert-Contains $logSource '_app_codex_auditblocked \(ptr_log\)' 'Blocked-event flow must call the diagnostic audit.'
Assert-Contains $logSource 'log->event_type = evt->type;' 'The raw WFP event type must be retained.'
Assert-Contains $logSource 'ptr_log->event_type = log->event_type;' 'The WFP event type must reach the audit record.'
Assert-Contains $mainHeader 'PR_STRING user_sid;' 'Blocked-event records must retain the raw SID string.'
Assert-Contains $mainHeader 'UINT32 event_type;' 'Blocked-event records must retain the WFP event type.'

Assert-NotContains $codexSource 'FwpmFilterAdd' 'Diagnostic module must not add WFP filters.'
Assert-NotContains $codexSource '_wfp_create' 'Diagnostic module must not call WFP creation helpers.'
Assert-NotContains $codexSource 'FWP_ACTION_PERMIT' 'Diagnostic module must not create permit actions.'

$associationGateIndex = $codexSource.IndexOf('if (!is_sid_match && !matched_root)')
$enrichmentIndex = $codexSource.IndexOf('_app_codex_enrichprocessidentity (&identity)', $associationGateIndex)
$fileEvidenceIndex = $codexSource.IndexOf('if (is_correlated && hfile)', $associationGateIndex)

if (
    $associationGateIndex -lt 0 -or
    $enrichmentIndex -lt $associationGateIndex -or
    $fileEvidenceIndex -lt $associationGateIndex
) {
    throw 'Detailed process and file evidence must be collected only after Codex association.'
}

Write-Output 'Codex diagnostic static checks passed.'
