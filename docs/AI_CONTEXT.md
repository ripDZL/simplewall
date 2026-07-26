# AI Context

- Objective: safe unattended outbound access for Codex Desktop sandbox tools.
- Upstream: `henrypp/simplewall` at `0b5bd95ee6c125c2233210703cc975d406fc1d83`.
- Guardrails: deny-by-default; no filename-only, broad user, descendant-only, click automation, or global allow.
- Baseline gate passed with a policy-neutral compatibility shim.
- Pinned dependencies: `routine a5479438`, `builder 74d1faba`.
- Build override: VS 2022 `v143`; Release x64 and ARM64 pass with zero warnings.
- No Codex integration source code has been implemented.
