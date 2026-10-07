# Contributing

Thank you for looking. Until the first public release the project is developed
in the open but with a small team; issues and PRs are welcome, large changes
should start with a discussion.

## Ground rules

- Read `docs/04-threat-model.md` before touching anything under `crates/core/src/crypto`,
  `broker`, `handles` or `audit`.
- Every PR touching those modules needs: tests including a negative test, no new
  `unsafe`, no new dependency without a one-line justification, and an update to
  the threat model if a boundary or assumption changed.
- `cargo fmt`, `cargo clippy -D warnings`, `cargo test --workspace`,
  `cargo deny check` and `cargo audit` must pass. The desktop crate
  (`apps/desktop/src-tauri`) is outside the workspace: run `cargo fmt` and
  `cargo clippy` there too when you touch it. The browser-origin tests
  (`tests/browser`, Playwright) and the `#[ignore]` benchmarks and interop
  tests run in CI; see `.github/workflows/ci.yml` for how.
- Plaintext secret material only ever lives in `SecretBytes`. If you find
  yourself with a `Vec<u8>` or `String` holding a secret, that is a bug.
- Never log, print or include in an error message anything that could be a
  secret. Error text is tested for this.

## Decisions

Design decisions are recorded in `docs/02-brainstorm-and-decisions.md` as
numbered entries. To change one, add a new entry that supersedes it rather
than editing history.

## Licence

By contributing you agree that your contribution is licensed under Apache-2.0
(or AGPL-3.0 for cloud service crates, when they exist).
