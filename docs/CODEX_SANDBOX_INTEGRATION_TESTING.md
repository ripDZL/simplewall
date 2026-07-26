# Codex Sandbox Integration Testing

## Baseline gate

- [x] Clean Release x64 compatibility baseline: zero warnings.
- [x] Clean Release ARM64 compatibility baseline: zero warnings.
- [ ] Existing profile load/save and non-Codex filters behave unchanged.

## Policy matrix

- [ ] Approved root plus valid Codex ancestry is allowed.
- [ ] Same filename outside approved root is blocked.
- [ ] Approved root plus unrelated parent is blocked.
- [ ] Codex ancestry plus path outside approved root is blocked.
- [ ] Junction/symlink escape is blocked.
- [ ] PID reuse does not inherit a decision.
- [ ] Exit removes the process rule.
- [ ] Timeout removes the process rule.
- [ ] Restart removes stale generated rules.
- [ ] Disable immediately prevents new generated rules.
- [ ] IPv4 and IPv6 both work.
- [ ] TCP and UDP controls are independent.
- [ ] Inbound traffic remains blocked.
- [ ] Windows 10 and Windows 11 are exercised.

## Diagnostics

- [x] Static check: module contains required identity, WFP, and endpoint fields.
- [x] Static check: module contains no permit/filter-creation calls.
- [x] Command-line output retains only allowlisted flag names; positional, unknown, and option values are redacted.
- [x] PID reuse guard rejects processes created after the WFP event.
- [x] Parent-chain capture creation-time validates every opened ancestor.
- [x] Ambiguous PID matches are rejected.
- [x] Root matching checks canonical boundary and rejects ADS.
- [x] Events require an explicit diagnostic SID or approved canonical root association.
- [x] Hash/signature evidence requires a validated live process path.
- [x] Raw WFP event type is retained.
- [ ] Dry-run produces decisions without adding WFP permit filters.
- [ ] Live audit output verified with the modified build.

## Repeatable evidence

- Record build command, OS build, architecture, simplewall commit, pinned routine commit, settings, generated filter GUIDs, and cleanup result.

## Commands run

- `tests\codex_diagnostic_checks.ps1`: passed.
- Release x64 `/p:PlatformToolset=v143`: passed, zero warnings.
- Release ARM64 `/p:PlatformToolset=v143`: passed, zero warnings.
- cmd, PowerShell, Python, and Node SID probes: same dedicated sandbox SID.
