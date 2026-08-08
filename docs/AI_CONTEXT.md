# AI Context

- Objective: safe unattended outbound access for Codex Desktop sandbox tools.
- Upstream: `henrypp/simplewall` at `0b5bd95ee6c125c2233210703cc975d406fc1d83`.
- Guardrails: deny-by-default; no filename-only, broad user, descendant-only, click automation, or global allow.
- Baseline gate passed with a policy-neutral compatibility shim.
- Pinned dependencies: `routine a5479438`, `builder 74d1faba`.
- Build override: VS 2022 `v143`; Release x64 and ARM64 pass with zero warnings.
- Diagnostic-only blocked-event audit is implemented and disabled by default.
- Diagnostic records require explicit SID/root association and never create permit filters.
- Enforcement remains blocked pending user confirmation of the discovered SID.
- Network-monitor diagnostic logging is disabled by default and only records API/listview counts and status codes.
- `-networkdiagnostic` is an explicit one-run opt-in that bypasses manual INI edits; it creates no filters or policy changes.
