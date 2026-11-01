# ARCHER improvement plan

Branch: `improve/analyzer-hardening` (cut from `fix/resource-routes`, which is `main` plus the
`web::resource(...).route(...)` fix; 51 tests pass at the branch point).

Every problem marked **Reproduced** was confirmed by running `archer --json` on a small probe
fixture. Problems marked **From code** were found by reading `src/analyzer.rs` / `src/main.rs`.
The probe sources are saved in `tests/fixtures/probes/`, named after the problem IDs below.
Problems are ordered by how much they distort findings (false negatives first, then false
positives, then robustness and tooling).

---

## A. Route extraction loses routes, prefixes, or middleware

### A1. Attribute routes registered through a scope lose the scope prefix and scope middleware — Reproduced

```rust
#[get("/payments")] async fn payments() {}
App::new().service(web::scope("/admin").service(users).service(payments)).service(health)
```

Reported as `GET /payments`, `GET /users`, `GET /health`, all with prefix `/`. `/health` is then
flagged as drift against the admin routes (false positive), and any `.wrap(...)` on the scope
never reaches these routes.

Cause: `add_attribute_routes` builds the path from `scope_context` at the point where the
function is *defined*, not where it is *registered*. `.service(users)` is never linked back to the
`#[get]` function.

Fix: split attribute routes into two phases. While indexing, record each `#[get]/#[post]/...`
function as a "route definition" (method, path literal, handler evidence) keyed through the
existing `HandlerIndex`. In `RouteVisitor::visit_expr_method_call`, when a `.service(arg)` argument
is a path that resolves to such a definition, emit the route there with the current
`scope_context` and inherited `chain_scopes` evidence. Fall back to the current behaviour
(prefix `/`) only for attribute routes that are never registered via `.service`.

### A2. `.configure(f)` inside a scope drops the prefix and the middleware — Reproduced

```rust
fn admin_routes(cfg: &mut web::ServiceConfig) { cfg.route("/payments", web::get().to(payments)); }
App::new().service(web::scope("/admin").wrap(RequireAdminMiddleware).configure(admin_routes))
```

Reported as `GET /payments` with no evidence. The scope's `RequireAdminMiddleware` is lost, so a
whole protected area looks unprotected, and its prefix is lost, so it is grouped with unrelated
routes. This is the standard way to split Actix apps across modules, so it affects most real
repositories.

Cause: `configure` functions are visited as ordinary free functions with an empty scope context.

Fix: resolve `.configure(path)` arguments through `HandlerIndex` (same resolution rules as
handlers). Visit the resolved function body with the caller's `scope_context` and `chain_scopes`
pushed. Keep a visited set keyed on (function, prefix) to avoid infinite recursion. Routes from a
configure function that is also reached with no caller should not be emitted twice: either skip
free visiting of functions that are reached via `.configure`, or emit only the configured copies
when at least one call site exists.

### A3. Qualified route attributes are ignored — Reproduced

`#[actix_web::get("/x")]` produces no route. `attribute_route_method` uses
`attribute.path().is_ident(name)`, which only matches a single-segment path.

Fix: match on the last path segment, and accept `actix_web::` / `actix_web::web::` prefixes. Also
support `#[route("/x", method = "GET", method = "POST")]` (one route per method) since it is part
of the same macro family.

### A4. `web::resource("/x").to(handler)` is dropped — Reproduced

Only `.route(...)` calls create routes, so a resource with a direct `.to(...)` (any-method
handler) disappears. Fix: treat `.to(...)` on a chain rooted in `web::resource(...)` as a route with
method `ANY` (or `UNKNOWN`, matching the current convention), resolving its handler the same way.

### A5. Non-literal paths are silently skipped — From code

`first_string_arg` returns `None` for `cfg.route(ADMIN_USERS, ...)` or `web::scope(PREFIX)`, and
`add_route` returns early. Fix: resolve `const NAME: &str = "..."` items in the same file/module
via the index; if it still cannot be resolved, emit the route with a placeholder path such as
`<unresolved:ADMIN_USERS>` and record it in a new `Report::warnings` list instead of dropping it.

### A6. Build output and vendored code are scanned — Reproduced

`WalkDir` walks everything under the root, including `target/`, so generated `.rs` files are
parsed and their routes appear twice in `routes`. Fix: skip `target`, `.git`, and hidden
directories by default (`WalkDir::filter_entry`), and add an `--include-tests` flag so `tests/`,
`examples/`, and `benches/` are excluded unless requested.

### A7. One unreadable file aborts the whole run — From code

`fs::read_to_string(...)?` in `analyze_repository` turns a non-UTF-8 or permission-denied file into
a fatal error, while parse errors are skipped. Fix: push read errors into `parse_errors` (rename
to `skipped_files` with a reason) and continue.

---

## B. Authorization evidence misses common Actix patterns

### B1. Extractor-based authorization in the handler signature is invisible — Reproduced

```rust
async fn users(_admin: AdminUser) {}
```

`handler_evidence` visits only `item.block`, so typed extractors (`AdminUser`, `RequireRole<Admin>`,
`Authenticated<Claims>`) produce no evidence. Extractors that implement `FromRequest` and reject
the request are the idiomatic Actix way to enforce roles.

Fix: in `handler_evidence`, also walk `item.sig.inputs`. Classify each argument's type path
segments with the existing `classify_route_configuration_name` word rules (type names need an
authorization word plus a shape word, or a dedicated list such as `Admin*`, `*Role*`, `*Permission*`).
Generic arguments must be inspected too (`RequireRole<Admin>`). Record the kind as `RoleCheck` /
`PermissionCheck` with mechanism `extractor`, and `IdentityExtraction` for authentication-only
extractors such as `BearerAuth` or `Identity`. Optionally strengthen this by checking for an
`impl FromRequest for AdminUser` in the index.

### B2. Authorization attribute macros on handlers are ignored — Reproduced

`#[protect("ROLE_ADMIN")]` (actix-web-grants), `#[has_role(...)]`, `#[has_permissions(...)]` give no
evidence. `visit_macro` only sees macros inside the body.

Fix: in `handler_evidence`, scan `item.attrs`; classify the last segment with
`classify_check_name` plus an explicit allow-list (`protect`, `has_role`, `has_roles`,
`has_permissions`, `has_any_role`, `has_any_permission`). Record the attribute arguments as the
`symbol` so the role string (`ROLE_ADMIN`) appears in findings.

---

## C. Peer grouping and invariant inference produce wrong findings

### C1. Unscoped routes with unrelated prefixes become peers — Reproduced

`App::new().route("/admin/users", ...).route("/admin/orders", ...).route("/public/docs", ...)` puts
all three in one group (`scope_prefix` is empty for all), and `/public/docs` is flagged.

Cause: `same_peer_group` compares `scope_prefix`, method, segment count, and dynamic shape, but
never the literal leading path segments when routes are written with full paths.

Fix: compute a "structural prefix" for every route: the declared scope prefix if non-empty,
otherwise all static segments except the last one (`/admin/users` → `/admin`). Group on that
instead of `scope_prefix`. Add the structural prefix to `Route` so the report shows it.

### C2. Findings fire even when authorized routes are a minority — Reproduced

In a scope with 7 routes where 2 have `require_admin()`, ARCHER reports 5 findings. The rule in
`build_analysis_layers` is `authorized >= 2 && unauthorized >= 1`, with no ratio. Also,
`invariant_strength` returns `Strong` for any group with ≥3 authorized routes, even 3 out of 20.

Fix: introduce an explicit, configurable dominance threshold. Report drift only when
`authorized / total >= threshold` (default e.g. 0.75) and `authorized >= min_support`
(default 3, or 2 for very small groups). Derive invariant strength from the ratio, not the raw
count. Expose `--min-support` and `--threshold` on the CLI so the benchmark in
`docs/evaluation/` can sweep them; this matches the "threshold must be evaluated experimentally"
requirement in `Archer_Context.md`.

### C3. The invariant is "some authorization", not "the same authorization" — Reproduced

Two routes with `RoleCheck: require_admin` and one route with only `OwnershipCheck: owns` produce
no finding. Any evidence kind satisfies the invariant, so a route that drifted from an admin role
check to a weaker ownership check is accepted.

Fix: make the invariant a dominant **evidence signature** rather than a boolean. For each route,
compute a normalized signature (set of `(kind, mechanism)` for authorization-kind evidence). The
invariant is the most common signature in the group; a route that is authorized but whose
signature is missing the dominant kind becomes a second finding category, `WeakerAuthorization`,
reported separately from `MissingAuthorization`. Keep `evidence_patterns` limited to
authorization-kind evidence (today it also lists `IdentityExtraction` mechanisms).

### C4. A path segment named `auth`/`token` excludes a whole area from analysis — Reproduced

Scope `/auth/admin` with two admin-checked routes and one unchecked `/auth/admin/purge` gives no
peer groups and no findings. `is_authentication_route` checks every segment of both path and
scope prefix against a word list, so any route under `/auth`, `/token`, or `/refresh` is skipped.

Fix: only treat the **last static segment** of the full path as an authentication endpoint
(`/login`, `/logout`, `/token`, `/refresh`, `/register`, ...). Keep those routes out of peer
groups, but continue analyzing everything else under the same prefix.

### C5. Route order in the report is reversed relative to the source — Reproduced

Builder chains are visited outermost-first, so `/admin/payments` is listed before
`/admin/users`. Sort `routes` by `(file, line)` before building peer groups so the report and
peer-group membership order are stable and readable.

---

## D. Report and CLI

### D1. No exit code for findings — From code

`main` always returns `Ok(())`, so ARCHER cannot gate CI. Add `--fail-on-findings` (exit code 1
when `finding_details` is non-empty, 2 for runtime errors).

### D2. Findings are stored twice, once as preformatted text — From code

`Report.findings` (strings) duplicates `finding_details`. Render text in `main.rs` from
`finding_details` and drop the string field from the JSON (or keep it behind a flag) so the
structured report is the single source of truth.

### D3. Text output prints Rust `Debug` names — From code

`{:?}` produces `RoleCheck`, `Strong`. Implement `Display` for `AuthEvidenceKind` and
`AuthStrength` and use it in the text renderer.

### D4. `analyzer.rs` is a 4,667-line module and has dead code — From code

`cargo build` warns that `infer_prototype_drift` is unused. Split `analyzer.rs` into modules
without behaviour change, for example `model.rs` (Route, AuthEvidence, Report), `routes.rs`
(RouteVisitor, scope/resource/method extraction), `handlers.rs` (HandlerIndex, resolution),
`evidence.rs` (classification), `drift.rs` (peer groups, invariants, findings). Move tests next
to the code they cover. Do this **first** or **last**, never interleaved with behaviour changes,
so diffs stay reviewable.

---

## Suggested order

1. D4 split (pure refactor, all 51 tests must still pass, no output change).
2. A6, A7, C5 (small robustness fixes).
3. A1, A2, A3, A4, A5 (extraction).
4. B1, B2 (evidence).
5. C1, C4, then C2, then C3 (inference; C3 builds on C2).
6. D1, D2, D3 (CLI).
7. Re-run the benchmark in `docs/evaluation/benchmark-results.md` and record before/after
   numbers.

Each item gets a failing regression test first (the probe fixtures above are the starting
point), then the fix, then `cargo fmt`, `cargo clippy`, `cargo test`.
