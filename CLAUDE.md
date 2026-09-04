# CLAUDE.md

Guidance for Claude Code working in this repo.

- Keep code minimal. Fewer lines is usually clearer, a negative diff is a win, and off-the-shelf components beat code you would write and maintain yourself.
- Default to one-line doc comments and to no regular comments. Exceptions exist, but they are far rarer than they feel in the moment — the pull toward comments is nearly always a signal to simplify the code instead.
- One thing per file: a type, a trait, a function. Group functions only when closely related, and define errors where they are used. Keep files small, with unit tests at the bottom. `db.rs` (storage) and `cli.rs` (subcommands) are deliberate exceptions: each is one cohesive concern with no other caller, so splitting it further would only add indirection.
- Respect every lint in [Cargo.toml](Cargo.toml). `#[expect(lint, reason = "...")]` is permitted, but should be rare.
- Keep coverage at 100%: `cargo +nightly llvm-cov nextest --fail-uncovered-lines 0 --fail-uncovered-functions 0` (nightly for `#[coverage(off)]`).
- Never commit or push to `main`. Branch, open a PR, merge once [CI](.github/workflows/ci.yml) passes. GitHub doesn't enforce this on a private repo — follow it anyway.
- Create skills for recurring or non-obvious workflows, and keep [README.md](README.md) and this file current.
