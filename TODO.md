# TODO

## 1. `mpa` status subcommand enhancement

- Show running status regardless of whether the agent is locked
- If the agent is not locked, also display `list` output inline
- Currently, lock state gates too much visibility — status should always report what's running

## 2. Audit `unwrap` usage across the workspace

- Search all crates for `.unwrap()` and `expect()` calls
- Identify which are genuinely safe (invariants that can't fail) vs. which should be replaced with proper error handling
- Document findings and acceptable-use policy in CLAUDE.md
