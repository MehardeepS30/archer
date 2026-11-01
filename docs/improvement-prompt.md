You are working on ARCHER, a Rust CLI that statically detects authorization drift in
Actix-Web apps. Repo: C:\Thapar\SEM - 5\SoftwareEngineering\archer. Work on the existing
branch `improve/analyzer-hardening`; do not create a worktree and do not push or open a PR
unless I ask.

Read these first, completely: `Archer_Context.md` (project rules; follow its Engineering
Principles), `docs/improvement-plan.md` (the problems to fix, IDs A1–D4, with causes and
intended fixes), `src/analyzer.rs`, `src/main.rs`. Probe fixtures that reproduce each problem
are in `tests/fixtures/probes/`, named by problem ID.

Use the superpowers skills: writing-plans to turn docs/improvement-plan.md into an
implementation plan saved at docs/plans/analyzer-hardening.md, then executing-plans to carry it
out, test-driven-development for every behaviour change, and verification-before-completion
before you claim anything is done.

Rules:
1. Follow the "Suggested order" in the plan. Start with D4 (split analyzer.rs into modules) as a
   pure refactor: no behaviour change, all existing tests pass, `archer --json` output on
   tests/fixtures/demo.rs is byte-identical before and after.
2. For every other item: first add a failing regression test built from the matching probe
   fixture, run it and show it fails for the stated reason, then fix, then run
   `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`.
3. One commit per problem ID, message starting with the ID (e.g. "A2: resolve .configure()
   inside scopes"). Never mix the refactor with behaviour changes.
4. Keep detection deterministic and AST-based; no regex or substring searches over source text,
   no LLM calls. Preserve file:line for every piece of evidence.
5. Do not change existing test expectations to make them pass. If a planned fix conflicts with an
   existing test, stop and explain the conflict to me instead.
6. For C2, make the dominance threshold and minimum support CLI flags with documented defaults;
   do not hard-code a single threshold as "the answer".
7. If a fix turns out larger than described or needs an architectural decision (especially A1,
   A2, C3), stop and describe the options before implementing.

When finished, re-run the benchmark described in docs/evaluation/benchmark-results.md, add
before/after numbers to that file, update docs/development-log.md, and give me a short summary:
which IDs are done, test count, and any item you skipped and why.
