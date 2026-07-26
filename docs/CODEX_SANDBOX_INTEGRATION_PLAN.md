# Codex Sandbox Integration Plan

## Gate

- Do not implement until clean Release x64 and ARM64 baseline builds pass.
- Pin or otherwise record the exact compatible `routine` revision first.

## Phase 1: diagnostic-only proof

- Add a disabled-by-default `Codex Sandbox Integration` configuration block.
- Extend blocked-event records with PID and raw user SID where WFP supplies them.
- Resolve PID with creation-time validation before collecting process metadata.
- Record canonical final image path, parent chain, command line, token SID, signer status, SHA-256, and creation time.
- Record WFP layer/filter, direction, addresses, ports, protocol, and sandbox-root classification.
- Redact environment values, file contents, command output, and secrets.
- Emit a dedicated audit log; do not create permit filters.

## Phase 2: identity decision

- Run real Codex sandbox commands and capture multiple process families.
- Prefer dedicated-SID mode only after the SID is displayed and user-confirmed.
- Reject the normal interactive user SID by default with a strong warning.
- Use dynamic exact-path mode only if dedicated-SID isolation is unavailable.

## Phase 3: minimal enforcement

- Dedicated SID: outbound-only `ALE_USER_ID` permits for configured TCP/UDP and optional ports.
- Dynamic mode: require canonical path containment plus verified Codex ancestry and process creation-time binding.
- Install exact app-path filters on process start, not after the first blocked event.
- Keep inbound filters unchanged.
- Record every match reason and generated filter GUID.

## Phase 4: lifecycle and UI

- Add emergency disable, dry-run, protocol/port controls, lifetimes, root/parent lists, and audit toggle.
- Remove filters on process exit/timeout and sweep stale generated filters at startup.
- Persist settings through the existing configuration/profile mechanisms.

## Phase 5: validation and release

- Run the matrix in `CODEX_SANDBOX_INTEGRATION_TESTING.md`.
- Perform focused threat-model and filter-lifecycle review.
- Build Release x64 and ARM64.
- Brand binaries as a modified GPLv3 fork and retain upstream attribution.
