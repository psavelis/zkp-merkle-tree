# Contributing

This repository is meant to stay small, readable, and easy to validate. Contributions should improve correctness, examples, or documentation without turning the project into a framework.

## Before opening a pull request

- Run `go mod tidy`.
- Run `go test ./...`.
- Run `go vet ./...`.
- Re-run any CLI or example flow affected by the change.

## Change expectations

- Keep changes minimal and prefer fixing the root cause instead of adding layered workarounds.
- Add or update regression tests when changing validation rules, proof formats, parsing logic, or edge-case behavior.
- Preserve existing CLI behavior and JSON proof compatibility unless the change intentionally updates a public interface.
- Keep README examples, fixtures, and demo commands aligned with the code.
- Keep error messages stable when tests assert them directly.

## Review guidance

- For changes that affect proving, hashing, or proof verification, include a short note about the correctness or security impact in the pull request description.
- For changes that affect serialized proofs or CLI behavior, mention compatibility implications explicitly.
- If a change fixes a bug found in review, prefer adding the narrowest regression test that proves the issue stays fixed.

## Scope

This is a proof of concept, not production infrastructure. Contributions should reinforce that focus: clear examples, correct primitives, and reproducible validation matter more than feature breadth.