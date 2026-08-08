$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$networkSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\network.c') -Raw
$launcherSource = Get-Content -LiteralPath (Join-Path $repoRoot 'tools\Run-Network-Diagnostic.cmd') -Raw

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

Assert-Contains $networkSource 'IsNetworkDiagnosticEnabled", FALSE' 'Network diagnostic logging must default to disabled.'
Assert-Contains $networkSource 'NETWORK_DIAGNOSTIC_CMDLINE_SWITCH' 'Network diagnostic logging must support an explicit command-line opt-in.'
Assert-Contains $networkSource '_r_sys_getopt' 'The command-line opt-in must activate only the existing diagnostic mode.'
Assert-Contains $networkSource 'NetworkDiagnosticLogPath' 'Network diagnostic logging must support an explicit log path override.'
Assert-Contains $networkSource 'NETWORK_DIAGNOSTIC_PATH_DEFAULT' 'Network diagnostic logging must have a default local log path.'
Assert-Contains $networkSource '\[DEBUG-netmon\]' 'Temporary network monitor diagnostics must be grep-cleanable.'
Assert-Contains $networkSource 'first_status' 'Network diagnostics must capture first table-call status codes.'
Assert-Contains $networkSource 'second_status' 'Network diagnostics must capture second table-call status codes.'
Assert-Contains $networkSource 'path_fail_count' 'Network diagnostics must count rows dropped by process-path resolution.'
Assert-Contains $networkSource 'add_call_count' 'Network diagnostics must count listview insert attempts.'
Assert-Contains $networkSource 'thread started' 'Network diagnostics must prove whether the monitor thread started.'
Assert-Contains $networkSource 'create_status' 'Network diagnostics must capture network thread creation status.'
Assert-Contains $launcherSource '-networkdiagnostic' 'The diagnostic launcher must enable the explicit command-line opt-in.'

Assert-NotContains $networkSource 'ProcessCommandLineInformation' 'Network diagnostics must not capture process command lines.'
Assert-NotContains $networkSource 'command_line' 'Network diagnostics must not capture process command lines.'
Assert-NotContains $networkSource 'FwpmFilterAdd' 'Network diagnostics must not add WFP filters.'
Assert-NotContains $networkSource 'FWP_ACTION_PERMIT' 'Network diagnostics must not add permit actions.'

Write-Output 'Network diagnostic static checks passed.'
