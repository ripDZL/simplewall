# Codex Sandbox Integration Security

## Trust boundaries

- simplewall and WFP run with administrative authority.
- Codex Desktop is a policy root, not automatic trust for every descendant.
- Sandbox roots, helper binaries, generated executables, reparse points, and network endpoints are untrusted until validated.

## Threat model

- Attacker reuses a trusted filename, path prefix, PID, parent PID, or stale filter.
- Attacker escapes an approved root through junctions, symlinks, mount points, alternate streams, or path normalization differences.
- Attacker launches unrelated code while Codex is running or injects into a trusted ancestry.
- Crash or PID reuse leaves an orphaned permit.

## Matching risks

- Filename-only matching permits unrelated binaries with common runtime names.
- Parent-only matching is vulnerable to PID reuse, spoofed ancestry assumptions, and compromised trusted parents.
- SID mode can permit every process under that account; never accept the normal interactive SID by default.
- Dynamic mode has race windows and requires final-path containment, creation-time binding, and multiple independent conditions.

## Cleanup

- Tag every generated filter with fork-owned metadata and retain its GUID.
- Remove on verified process exit or timeout.
- Sweep all generated filters at startup before accepting new matches.
- Emergency disable stops new permits and removes existing generated permits.

## Residual risks

- A compromised approved Codex process may intentionally launch malicious code.
- User-mode process monitoring can miss events during startup or service interruption.
- Signatures authenticate publishers, not runtime intent.
- Exact-path filters do not bind file content unless hash checks are also enforced.
