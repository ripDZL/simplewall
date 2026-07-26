# AI Context

- Objective: safe unattended outbound access for Codex Desktop sandbox tools.
- Upstream: `henrypp/simplewall` at `0b5bd95ee6c125c2233210703cc975d406fc1d83`.
- Guardrails: deny-by-default; no filename-only, broad user, descendant-only, click automation, or global allow.
- Baseline gate: do not change feature source until clean x64 and ARM64 builds succeed.
- Current blocker: public `henrypp/routine` master is API-incompatible with current simplewall master.
- No Codex integration source code has been implemented.
