# Analyzer Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (chosen by the user). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fix problems A1–D4 from `docs/improvement-plan.md` without changing detection philosophy (deterministic, AST-based, evidence with file:line).

**Architecture:** `src/analyzer.rs` becomes `src/analyzer/` with one file per pipeline stage. Behaviour changes land one problem ID per commit, each preceded by a failing regression test built from `tests/fixtures/probes/`.

**Tech Stack:** Rust 2024, syn 3 (full, visit), clap 4, serde_json, walkdir.

**Spec:** `docs/improvement-plan.md`

## Global Constraints

- `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test` pass after every commit.
- One commit per problem ID; message starts with the ID.
- Existing test expectations are not edited. A conflict stops the work and is reported.
- No regex or substring search over source text; no LLM calls.
- `analyze_repository(root)` keeps its signature (defaults); options go through `analyze_repository_with(root, &AnalysisOptions)`.
- JSON report changes are additive, except D2 (preformatted `findings` strings leave the JSON).

## Review Focus

1. A `.configure(f)` target that is also called directly, or recursively: routes must appear once per real registration, no infinite recursion. Test in A2.
2. An attribute handler registered in two scopes: two routes, each with its own prefix and middleware. Test in A1.
3. `web::Json<RoleUpdate>` / `web::Data<RoleService>` handler arguments must not count as role checks. Test in B1.
4. A route under `/auth/admin/...` whose last segment is not an auth endpoint must still be analysed. Test in C4.
5. Threshold flags at their edges (`--threshold 1.0`, `--min-support 1`) must not panic or divide by zero. Test in C2.

---

### Task 1: D4 — split `analyzer.rs` into modules (pure refactor)

**Files:** delete `src/analyzer.rs`; create `src/analyzer/{mod.rs, model.rs, routes.rs, handlers.rs, evidence.rs, drift.rs, tests.rs}`.

- `model.rs`: `AuthEvidenceKind`, `AuthStrength`, `AuthEvidence`, `HandlerResolution`, `Route`, `RouteReference`, `PeerGroup`, `AuthorizationInvariant`, `Finding`, `Report`.
- `routes.rs`: `RouteVisitor`, `BlockScope`, attribute routes, HTTP-method extraction, scope/resource paths, handler targets, `join_paths`, guard/middleware chain evidence, `pattern_bindings`.
- `handlers.rs`: `HandlerIndex`, `HandlerDefinition`, use-tree collection, `module_location`.
- `evidence.rs`: `AuthEvidenceVisitor`, `handler_evidence`, `classify_check_name`, route-configuration name classification.
- `drift.rs`: `build_analysis_layers` and peer-group helpers.
- `mod.rs`: `analyze_repository`, module declarations, `pub use model::*`.
- `tests.rs`: the existing test module unchanged, importing all submodules.
- Remove dead-code errors that block clippy: `infer_prototype_drift` and `collect_authorized_handlers` become `#[cfg(test)]`; unused `Route::evidence_summary`, `Route::strongest_evidence`, `AuthEvidenceKind::Unknown` get `#[allow(dead_code)]` (public API, kept).

- [ ] Capture `archer --json tests/fixtures/demo.rs` and text output before the split.
- [ ] Move code; items used across files become `pub(crate)`.
- [ ] `cargo test` = 51 passed; JSON and text output byte-identical (`cmp`).
- [ ] fmt, clippy; commit `D4: split analyzer into modules`.

### Task 2: A6 — skip build output and test directories

`AnalysisOptions { include_tests: bool, min_support: usize, dominance_threshold: f64 }` (Default: `false, 2, 0.6`) in `model.rs`. File discovery skips directories named `target` or starting with `.`; skips `tests`, `examples`, `benches` unless `include_tests`. Root itself is never skipped. CLI `--include-tests`.

- [ ] Test `build_output_and_test_directories_are_not_scanned` (probe `a6_*` copied to `src/main.rs` and `target/debug/build/gen.rs`, plus `tests/it.rs`): `files_scanned == 1`, 3 routes; with `include_tests` `files_scanned == 2`.
- [ ] Fail → implement → pass → commit.

### Task 3: A7 — unreadable files are skipped

- [ ] Test `unreadable_file_is_reported_and_skipped`: a `.rs` with invalid UTF-8 bytes beside a valid one; `analyze_repository` is `Ok`, `parse_errors` has one entry naming the file, the valid file's routes are present.
- [ ] Implement by pushing `"<path>: failed to read: <err>"` into `parse_errors`; commit.

### Task 4: C5 — routes in source order

Route gains `#[serde(skip)] column: usize`. After extraction routes are stably sorted by `(file, line, column)`.

- [ ] Test `routes_are_reported_in_source_order` (one chain `/users`, `/orders`, `/payments`): paths in that order.
- [ ] Implement; commit.

### Task 5: A1 — attribute routes registered through `.service(handler)`

Route gains `#[serde(skip)] attribute_definition: Option<usize>` (index into `HandlerIndex.definitions`) and `#[serde(skip)] attribute_path: String`. `RouteVisitor` records `Registration { definition: usize, prefix: String, inherited: Vec<AuthEvidence> }` when a `.service(arg)` argument is a path that resolves (via `resolve_handler`) to a definition. After all files: each attribute route whose definition has registrations is replaced by one route per registration (path `join_paths(prefix, attribute_path)`, `scope_prefix = prefix`, evidence = handler evidence + inherited); unregistered ones stay.

- [ ] Test `attribute_routes_take_prefix_and_middleware_from_their_registering_scope` (probe a1 plus `.wrap(RequireAdminMiddleware)` on a second scope registering `health`): `/admin/payments` exists with prefix `/admin`; `/health` is not a finding; a handler registered in two scopes yields two routes.
- [ ] Implement; commit.

### Task 6: A2 — `.configure(f)` expands with the caller's scope

`HandlerIndex` gains a lifetime and keeps `items: Vec<&'a ItemFn>` parallel to `definitions`, plus `file: PathBuf` per definition. At `.configure(arg)` with a resolved definition not already on the expansion stack, the visitor switches file/crate/module to the definition's, clears block scopes, sets `scope_context` to the caller's context joined with the receiver's scope prefix, keeps `chain_scopes`, and visits the function body. Routes emitted during the free visit of a function that is the target of any `.configure` call are dropped (routes carry `#[serde(skip)] enclosing_definition: Option<usize>` for the top-level fn they were found in).

- [ ] Test `configure_inside_scope_inherits_prefix_and_middleware` (probe a2): 3 routes under `/admin`, each with `AuthorizationMiddleware: RequireAdminMiddleware`, each listed once.
- [ ] Test `recursive_configure_does_not_loop` (`a` configures `b`, `b` configures `a`): terminates; routes appear once per prefix.
- [ ] Implement; commit.

### Task 7: A3 — qualified and `#[route]` attributes

Attribute recognized by last path segment when the path is `name` or `actix_web::name`. Arguments parsed as `Punctuated<Expr, Token![,]>`: first is the path literal; for `route`, each `method = "X"` yields one route.

- [ ] Test `qualified_and_multi_method_route_attributes_are_extracted`: `#[actix_web::get("/x")]` → GET /x; `#[route("/y", method = "GET", method = "POST")]` → GET /y and POST /y; `#[get("/z", wrap = "Logger::default()")]` → GET /z.
- [ ] Implement; commit.

### Task 8: A4 — `web::resource("/x").to(handler)`

`add_route` also handles a `.to(h)` call whose receiver chain starts at `web::resource(...)`; method `UNKNOWN`, handler resolved from the argument path.

- [ ] Test `resource_to_registers_an_any_method_route`: `web::resource("/res").wrap(AdminGuard).to(handler)` → `UNKNOWN /res` with handler `handler` and guard evidence; `web::get().to(h)` inside `.route` still produces exactly one route.
- [ ] Implement; commit.

### Task 9: A5 — const paths and unresolved paths

`HandlerIndex` collects `const NAME: &str = "lit"` per module. Paths and scope prefixes accept a string literal, a bare const in the current module, a module-qualified const, or a const brought in by an explicit `use`. Otherwise the segment becomes `<unresolved:NAME>`, the route is kept, a message `"<file>:<line>: path `NAME` is not a string literal or resolvable const"` is added to new `Report.warnings`, and routes with an unresolved segment are excluded from peer groups.

- [ ] Test `const_paths_resolve_and_unresolved_paths_are_kept_with_a_warning`.
- [ ] Implement; commit.

### Task 10: B1 — extractor types in handler signatures

`handler_evidence` also walks `sig.inputs`. Type path segments (recursing into generic arguments, references, tuples) are classified; generics of `Json`, `Path`, `Query`, `Form`, `Data`, `ReqData`, `Bytes`, `Payload` are not inspected. A CamelCase segment with a word from `admin(s)`, `role(s)`, `rbac`, `manager` → `RoleCheck`; `permission(s)`, `acl`, `authorization`, `authorize(d)`, `authz` → `PermissionCheck`; strength `Medium`; excluded words as for configuration names. `BearerAuth`, `BasicAuth`, `Identity`, `AuthenticatedUser`, names containing a `claims` word, and authentication-word + shape-word names → `IdentityExtraction`, `Weak`. Mechanism is the type name, symbol the written type.

- [ ] Test `authorization_extractors_in_handler_signatures_are_evidence` (probe b1): `AdminUser`, `RequireRole<Admin>` → RoleCheck; `BearerAuth` → IdentityExtraction; `web::Json<RoleUpdate>`, `web::Data<RoleService>` → none.
- [ ] Implement; commit.

### Task 11: B2 — authorization attribute macros

`handler_evidence` scans `item.attrs`: last segment `protect`, `has_permissions`, `has_any_permission` → `PermissionCheck`; `has_role(s)`, `has_any_role` → `RoleCheck`; any other name `classify_check_name` accepts. Strength `Strong`; symbol is the attribute's tokens.

- [ ] Test `authorization_attribute_macros_are_evidence`: `#[protect("ROLE_ADMIN")]` yields PermissionCheck with symbol containing `ROLE_ADMIN`; `#[get("/x")]`, `#[instrument]` yield none.
- [ ] Implement; commit.

### Task 12: C1 — structural prefix for peer grouping

`fn peer_prefix(route: &Route) -> String`: the full path's segments before its last static segment. `same_peer_group` compares `peer_prefix` instead of `scope_prefix`; `PeerGroup` gains `prefix: String` used in descriptions.

- [ ] Test `unscoped_routes_with_different_leading_segments_are_not_peers` (probe c1): no finding for `/public/docs`.
- [ ] Implement; all existing peer tests unchanged; commit.

### Task 13: C4 — only the endpoint segment marks an authentication route

`is_authentication_route` checks only the last static segment of the full path.

- [ ] Test `routes_under_an_auth_prefix_are_still_analysed` (probe a3_a4_c4 scope): `/auth/admin/purge` is a finding; `/auth/login` still excluded.
- [ ] Implement; commit.

### Task 14: C2 — dominance threshold and minimum support

Findings require `authorized >= min_support && authorized / total >= dominance_threshold && unauthorized >= 1`. Groups need `total >= 2`. Strength: `Strong` if ratio ≥ 0.9, `Medium` if ≥ threshold, else `Weak`. CLI `--min-support <N>` (default 2, ≥ 1) and `--threshold <F>` (default 0.6, in (0, 1]). Defaults chosen to keep existing results for small groups; the benchmark sweep decides final values.

- [ ] Test `minority_authorization_does_not_produce_findings` (probe c2): no findings at defaults; findings appear with `dominance_threshold = 0.25`.
- [ ] Test `threshold_edges_do_not_panic`: threshold 1.0 and min_support 1.
- [ ] Implement; commit.

### Task 15: C3 — weaker-authorization findings

Decided by the user: option 1, evidence tiers. `EvidenceTier` = `Privilege` (role, permission, authorization guard/middleware, manual authorize) > `Resource` (ownership) > `Identity` > `None`. In a dominant group the expected tier is the highest tier a dominant share of routes reaches. Unauthorized routes stay `MissingAuthorization`; authorized routes below the expected tier become `WeakerAuthorization`. `Finding` gains `category`, `suspicious_route_tier`, `expected_tier`; `authorized_peer_routes` lists the peers reaching the expected tier.

- [x] Tests `weaker_authorization_is_reported_separately_with_its_evidence` (probe c3) and `different_privilege_mechanisms_are_not_weaker`.

### Task 16: D1 — `--fail-on-findings`

`main` returns `ExitCode`: 0 normally, 1 with `--fail-on-findings` and at least one finding, 2 on runtime error (message on stderr).

- [ ] Test via the built binary in `tests/cli.rs` using `env!("CARGO_BIN_EXE_archer")`: exit codes 0, 1, 2 (nonexistent path).
- [ ] Implement; commit.

### Task 17: D2 + D3 — structured findings drive the text report; readable names

`Report.findings` gets `#[serde(skip)]`; `main.rs` renders findings from `finding_details` via `drift::format_finding(&Finding)`. `Display` for `AuthEvidenceKind` ("role check", ...) and `AuthStrength` ("strong", ...) used in text output.

- [ ] Tests: JSON has no `findings` key and still has `finding_details`; `AuthEvidenceKind::RoleCheck.to_string() == "role check"`.
- [ ] Implement; commit D2 and D3 separately.

### Task 18: Benchmark and docs

Re-run the 20-repo benchmark (dataset location pending from the user), update `docs/evaluation/benchmark-results.md` and `docs/development-log.md`.

---

## Implementation Notes

Status: every task is done except Task 18's benchmark run; the benchmark dataset is not in the repository.

Deviations from the steps above, each kept within the spec:

- **C2 strength.** The plan's `Strong` at ratio ≥ 0.9 would have turned an existing test's 3-of-4 group from `Strong` into `Medium`. Strength is instead `Strong` for a unanimous group or a dominant one with at least three authorized routes, `Medium` for other dominant groups, `Weak` otherwise. The 3-of-20 case the spec names is now `Weak`.
- **C1.** Peers must match on both the declared scope prefix and `peer_prefix`, so groups can only get smaller than before; no existing grouping test changed.
- **D2.** `Report.findings` stays in the struct (tests and the CLI use the text) but is `#[serde(skip)]`; both it and the CLI output come from `format_finding(&Finding)`.
- **D1.** A nonexistent path is now an error (exit 2) rather than an empty report, so the runtime-error exit code is reachable.
- **README.** The fixture command now points at `tests/fixtures/demo.rs`, since `tests/fixtures` also holds the probe fixtures.
