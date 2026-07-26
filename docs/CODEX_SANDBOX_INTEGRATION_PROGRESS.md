# Codex Sandbox Integration Progress

## Status

- State: blocked at unmodified baseline build.
- Feature source changes: none.
- Upstream simplewall: `0b5bd95ee6c125c2233210703cc975d406fc1d83`.
- Public routine master: `a54794384855d749b592e7bc05204855f3ef966e`.

## Baseline

- NuGet restore: passed.
- Release x64 with `/p:PlatformToolset=v143`: failed during compilation.
- ARM64: not attempted after x64 failed.
- Required upstream v145 toolset is not installed; VS 2022/v143 is installed.
- Failure is not a Codex fork regression.

## Blocker evidence

- `.gitmodules` names `../routine` but the simplewall commit contains no Git link or pinned dependency revision.
- Current simplewall calls older three-argument configuration APIs and other older routine signatures.
- Current public routine master exposes incompatible signatures.
- Representative errors: `_r_config_getboolean` argument count, `_r_obj_addlistitem` argument count, `_r_theme_initialize` argument count, and missing `PCR_STRINGREF`.

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

## Resume condition

- Supply or identify the exact compatible `routine` revision and complete clean x64/ARM64 baseline builds.
