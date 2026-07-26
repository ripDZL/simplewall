# Codex Sandbox Integration Progress

## Status

- State: diagnostic implementation complete; runtime capture and SID confirmation pending.
- Enforcement: none.
- Upstream simplewall: `0b5bd95ee6c125c2233210703cc975d406fc1d83`.
- Pinned routine: `a54794384855d749b592e7bc05204855f3ef966e`.
- Pinned builder: `74d1faba0a75feda417313909c96b256fae7e79f`.

## Baseline

- NuGet restore: passed.
- Release x64 with `/p:PlatformToolset=v143`: passed, zero warnings.
- Release ARM64 with `/p:PlatformToolset=v143`: passed, zero warnings.
- Public dependencies are internal submodules under `third_party`.

## Compatibility resolution

- Upstream did not pin the private SDK revision used for the release source.
- `src/routine_compat.h` maps API names, parameter order, and equivalent Win32 helpers to the last public SDK.
- The shim changes no WFP conditions, filter weights, direction, persistence, or default policy.

## Architecture findings

- Applications are keyed by a case-insensitive hash of their path.
- Exact executable filters use `FWPM_CONDITION_ALE_APP_ID`.
- Services use `FWPM_CONDITION_ALE_USER_ID`; UWP apps use `FWPM_CONDITION_ALE_PACKAGE_ID`.
- Blocked events already expose app/package/user identity and network tuple data.
- Existing signature verification and SHA-256 helpers are reusable.
- Active-network monitoring resolves PIDs, but blocked-event records do not retain PID or creation time.
- No process-start monitor or parent-chain policy exists.

## Preliminary Codex identity

- Current cmd, PowerShell, Python, and Node commands ran as `PRINCIPAL-OFFIC\CodexSandboxOffline`.
- Observed SID: `S-1-5-21-577596116-3012514165-3244883643-1006`.
- Observed ancestry: `codex` -> `codex-command-runner-0.144.2.exe` -> tool process.
- Runner path: `%USERPROFILE%\.codex\.sandbox-bin\codex-command-runner-0.144.2.exe`.
- Runner signature: valid, `OpenAI OpCo, LLC`.
- Runner SHA-256: `65905BDE57F03520EC791950EF622EF579440A507383A9C2272DFDF84128BDA6`.
- Dedicated-SID mode is the leading strategy, but the SID is not yet user-confirmed.

## Diagnostic implementation

- Default: disabled.
- Scope: simplewall-owned blocked outbound events associated by an explicit diagnostic SID or approved canonical root.
- Output: `%USERPROFILE%\simplewall-codex-audit.log` by default.
- Captures: WFP/validated/final paths, event type, layer/filter/tuple, username/SID, signer/status, and SHA-256.
- PID correlation: exact tuple plus image path, token SID, and creation-time validation.
- PID correlation now requires WFP path and SID evidence before scanning live connection tables.
- Ambiguous or stale PID matches are logged as unavailable rather than guessed.
- Parent chain is bounded to eight entries and each ancestor is creation-time checked against the process snapshot.
- Allowlisted non-secret command-line flag names are retained; all other arguments and option values are redacted.
- Configured roots are environment-expanded, opened by handle, final-path compared, boundary checked, and ADS rejected.
- Hash/signature evidence is collected only for a validated live process and is explicitly labeled as on-disk evidence at audit time, not kernel-bound evidence.
- The module contains no permit action or WFP filter-creation call.
- Audit writes no-op if the formatted audit record is empty.

## Crash triage

- Reported status: `0xC0000005`.
- Local Application WER events in the last 24 hours: `AUDIODG.EXE` and `Clear.vst3`; no `simplewall.exe`.
- Local crash dumps: no `simplewall.exe` dump found.
- Running simplewall process detected, but elevated path inspection was denied.
- Defensive hardening added without changing firewall policy.

## Diagnostic configuration

Add under `[simplewall]` in `simplewall.ini` while simplewall is stopped:

```ini
IsCodexDiagnosticEnabled=true
CodexDiagnosticSids=S-1-5-21-577596116-3012514165-3244883643-1006
CodexSandboxRoots=%USERPROFILE%\.codex;C:\path\to\approved\workspace
CodexDiagnosticLogPath=%USERPROFILE%\simplewall-codex-audit.log
```

- Replace the SID with the explicitly confirmed Codex sandbox SID.
- Replace the workspace example with explicit approved roots.
- At least one SID or root must match; otherwise diagnostic mode remains inert.
- Restart simplewall after editing.
- This mode observes only; it does not allow traffic.

## Next

- Run the modified build after the installed simplewall instance is stopped.
- Confirm the displayed sandbox SID.
- Do not add automatic permit filters until both steps pass.
