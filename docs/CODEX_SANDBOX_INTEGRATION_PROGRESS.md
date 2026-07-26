# Codex Sandbox Integration Progress

## Status

- State: baseline-compatible builds passed; diagnostic phase active.
- Feature source changes: none; build compatibility only.
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

- Current sandbox command ran as `PRINCIPAL-OFFIC\CodexSandboxOffline`.
- Observed SID: `S-1-5-21-577596116-3012514165-3244883643-1006`.
- Treat as a dedicated-SID candidate only; it is not yet user-confirmed or validated across Codex process types.

## Next

- Add diagnostic-only identity capture.
- Do not add automatic permit filters until identity evidence is captured and reviewed.
