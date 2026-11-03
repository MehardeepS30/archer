# ARCHER Development Log

ARCHER is a deterministic, repository-local static analysis framework for identifying evidence-backed potential authorization drift in Rust/Actix-Web applications. Its findings support developer review and do not automatically establish confirmed vulnerabilities.

## 1. Initial Prototype

### Objective
Establish a working Rust/Actix-Web analyzer and an end-to-end command-line path.

### Work Completed
Implemented repository scanning, route extraction, basic authorization detection, initial peer grouping, and initial drift detection.

### Result
The first prototype demonstrated the core flow from Rust source to a potential-drift CLI report.

### Limitation / Learning
Authorization evidence and peer grouping were initially broad, and route source locations were imprecise. These were prototype limitations requiring more source-aware analysis.

### Next Step
Improve route context, source locations, and authorization evidence before broadening evaluation.

## 2. Scope and Source-Location Improvements

### Objective
Improve route interpretation across Actix scopes and make analysis results easier to trace to source.

### Work Completed
Added nested Actix scope tracking, more precise route locations, deterministic repository traversal, and malformed-file handling so an unparsable Rust file can be reported while other files continue to be analyzed.

### Result
The analyzer gained more reliable route paths and source references, with more predictable behavior across repository scans.

### Limitation / Learning
Route extraction remains dependent on the Actix-Web syntax patterns the analyzer recognizes; unsupported patterns can affect route coverage.

### Next Step
Associate route classifications with explicit authorization evidence and improve structural peer selection.

## 3. Authorization Evidence

### Objective
Make authorization classifications explainable and source-backed.

### Work Completed
Developed recognition for handler-level authorization calls, authorization guards, and authorization middleware, with evidence associated with routes and handlers. Evidence concepts include mechanism, symbol, source file and line, handler, and strength. Identity extraction is treated as distinct from authorization enforcement.

### Result
The analysis direction shifted from unexplained authorization labels toward evidence-backed findings that can be reviewed against source.

### Limitation / Learning
Recognition is limited to authorization idioms and source patterns that the current analyzer can identify; identity presence alone cannot establish an authorization check.

### Next Step
Use the evidence together with route structure when forming peer groups and inferring repository-local invariants.

## 4. Peer-Group Improvements

### Objective
Compare routes that are structurally meaningful peers rather than grouping by a broad prefix alone.

### Work Completed
Refined peer grouping around scope, HTTP method, route shape, path-segment structure, and dynamic parameters. Context such as handler information can be considered where appropriate. Method separation avoids treating different operations as equivalent merely because their paths share a scope.

### Result
Peer comparisons became more structurally constrained. The work also established that routes such as login, register, and logout must not automatically be grouped as authorization peers simply because they share `/api`.

### Limitation / Learning
Conservative structural constraints can leave a route with too few authorized peers to support an inferred invariant.

### Next Step
Test the threshold and structural signals against a controlled benchmark with known expected behavior.

## 5. Real Repository Evaluation

### Objective
Exercise route extraction and authorization-evidence recognition on real Actix-Web repositories.

### Work Completed
Testing against real repositories exposed framework and route-pattern limitations that are not represented by the simplest prototype cases.

### Result
The evaluation motivated explicit attention to supported Actix-Web constructs and source patterns.

### Limitation / Learning
No repository counts or quantitative metrics are recorded in this development-log milestone; no numerical result is claimed here.

### Next Step
Use a controlled dataset with explicit ground truth to measure behavior reproducibly.

## 6. Controlled Benchmark

### Objective
Measure route-level detection against a known set of clean and drift cases.

### Work Completed
Ran ARCHER against 20 controlled Actix-Web repositories containing 73 routes and explicit ground truth.

### Result
The evaluation produced 5 findings: TP=5, FP=0, FN=1, and TN=67. Precision was 100%, recall was 83.33%, F1 was 90.91%, and false positives per 1,000 routes was 0.

### Limitation / Learning
One expected drift route was missed. These controlled results do not establish general production performance or comparison with other static analysis tools.

### Next Step
Analyze the false negative and investigate whether peer evidence can be used more effectively.

## 7. Current Limitation

### Objective
Document the main limitation identified by the controlled benchmark.

### Work Completed
Reviewed the missed parameterized route in `18_parameter_drift`: `GET /admin/payments/{id}` was extracted as unauthenticated but was not reported.

### Result
The matching peer group had only one protected route with the same method and route shape, below the current two-authorized-peer threshold.

### Limitation / Learning
The result identifies a peer-grouping / invariant-inference limitation and accounts for the benchmark's one false negative.

### Next Step
Study whether additional structural evidence can support cautious inference when only one authorized peer is available.

## 8. Next Milestone

### Objective
Investigate single-peer inference while preserving the benchmark's zero-false-positive result.

### Work Completed
The next experiment is defined; no improvement result is claimed at this stage.

### Result
A repeatable comparison criterion is established using the existing controlled benchmark.

### Limitation / Learning
Lowering the peer threshold may improve recall but could introduce false positives; the tradeoff must be measured rather than assumed.

### Next Step
Evaluate changes by rerunning the same 20 repositories and comparing precision, recall, F1, and false positives.

## 9. Analyzer Hardening

### Objective
Fix the extraction, evidence, and inference problems listed in `docs/improvement-plan.md` (IDs A1-D4), each with a regression test built from a probe fixture in `tests/fixtures/probes/`.

### Work Completed
Split `src/analyzer.rs` into `src/analyzer/{model,routes,handlers,evidence,drift}.rs` with no behaviour change (D4). Route extraction now re-roots `#[get]`-style handlers at the `.service(handler)` call that registers them (A1), expands `.configure(f)` under the caller's scope prefix and middleware (A2), recognizes `#[actix_web::get]` and `#[route(..., method = ...)]` (A3), registers `web::resource(path).to(handler)` (A4), and resolves string-constant paths while keeping unresolvable ones with a warning (A5). Discovery skips `target/`, hidden directories, and by default `tests/`, `examples/`, `benches/` (A6); unreadable files are reported instead of aborting (A7); routes are reported in source order (C5). Handler signatures (authorization extractors such as `AdminUser`) and authorization attribute macros (`#[protect]`, `#[has_roles]`) now count as evidence (B1, B2). Peers must share a full-path prefix (C1); only an endpoint's last segment marks it as an authentication route (C4); findings require a configurable dominance threshold and minimum support (C2). Findings are now categorized: routes with no authorization evidence remain `MissingAuthorization`, and routes whose best evidence tier (privilege > resource > identity) is below the tier a dominant share of their peers reach are reported as `WeakerAuthorization`, with both tiers and all evidence in the finding (C3). The CLI gained `--fail-on-findings` with exit codes 0/1/2 (D1), renders findings from the structured `finding_details`, which is now the only finding list in the JSON (D2), and prints readable evidence names (D3).

### Result
70 unit tests and 3 CLI tests pass, up from 51. Every probe fixture now produces the expected routes and findings.

### Limitation / Learning
The controlled benchmark could not be re-run: its 20 repositories were never committed, so no before/after metrics are available for these changes. Extractor and attribute evidence are naming heuristics; extractor implementations are not inspected. The tier ranking treats all privilege mechanisms as equivalent, so a route that checks a different role than its peers is not flagged.

### Next Step
Restore or rebuild the benchmark dataset, rerun it at the default thresholds, then sweep `--threshold` and `--min-support` and record precision, recall, and false positives for each setting.

## 10. Analyzer Hardening, Second Pass

### Objective
Check that the section 9 fixes hold, then look for remaining detection gaps (missed or misattributed routes and evidence, which cause false negatives and false positives) and robustness failures on unusual input. Each new problem gets an ID (E1-E9), a probe fixture in `tests/fixtures/probes/e*`, and a regression test.

### Work Completed
Verification: all 73 tests passed on `improve/analyzer-hardening`, every earlier probe gave its expected routes and findings, and after this pass `tests/fixtures/demo.rs` and the `a*`/`b*`/`c*` probes produce byte-identical JSON to before.

New problems, all fixed on `improve/analyzer-hardening-2`:

| ID | Problem found | Effect before the fix | Fix |
|----|---------------|-----------------------|-----|
| E1 | A builder chain of about 800 `.route()` calls overflowed the 1 MiB Windows main-thread stack (debug; about 1,600 in release). Peer grouping compared every pair of routes and deduplicated each group pairwise, which is cubic: 2,000 routes in one group took 45 s. `Spanned::span()` on every method call in a handler body rebuilt the call's whole token stream, which is quadratic on long chains. | Crash (exit code 127) on large route files; minutes of runtime on large apps. | Analysis runs on a thread with a 512 MiB reserved stack. Routes are bucketed by peer key (scope prefix, structural prefix, method, path shape) in one pass with the same group order. Scope prefixes are read iteratively, and a method call's span is computed only when the call is evidence. A 5,000-route chain now takes 0.6 s. |
| E2 | `.service((a, b))` and `.service(services![a, b])` registrations were ignored. | Attribute routes kept bare paths and lost their scope's middleware; a missing check under `/admin` went unreported. | Each tuple element and `services!` argument is a registration. |
| E3 | A config function called directly (`admin::config(cfg)` inside another config function, or `.configure(\|c\| admin_routes(c))`) was not expanded. | Its routes lost the caller's prefix and middleware. | A call to a function with a `ServiceConfig` parameter is expanded at the call, like `.configure(f)`. |
| E4 | `.service(admin_scope())`, where the function returns a `Scope`, was not expanded. | Same as E3. | Calls to functions returning `Scope`, `Resource`, or `impl HttpServiceFactory` are expanded at the call. A factory used in two scopes yields routes in both. |
| E5 | `.wrap_fn(\|req, srv\| ...)` middleware was not read. | A scope protected by a closure calling `check_admin(&req)` looked unauthorized. | `wrap_fn` arguments are classified like `wrap` arguments. |
| E6 | `web::route().guard(guard::Get())` gave method `UNKNOWN`. | Such routes could not be peers of `web::get()` routes, hiding drift. | `guard::Get()`-style guards and `guard::Method(Method::X)` set the method. |
| E7 | Role checks written as comparisons (`user.role != Role::Admin`, `matches!(user.role, Role::Admin)`, `user.roles.contains(&Role::Admin)`, `claims.is_admin`) were not evidence. | Routes checking roles this way looked unauthorized (false positives), and could make a group non-dominant, hiding a real gap (false negative). | Comparisons where an operand is a variant of a `Role`/`Permission`-named type or a field ending in `role(s)`/`permission(s)` are `Medium` role or permission evidence. Assigning a flag, `roles.len() == 2`, and `Status::Paid` comparisons are not. |
| E8 | A check inside a called helper (`ensure_can_manage(&user)` calling `require_admin`) was not seen. | The handler was reported as missing authorization (false positive). | Each function also carries the evidence of repository functions it calls, up to 3 calls deep, with cycle protection. Only calls resolved by scoping rules count, not unique-name guesses. Evidence keeps the callee's file and line, and its symbol shows the call path. |
| E9 | A config function whose only caller was itself, or a cycle with no outside caller, had its routes dropped. | Routes disappeared from the report. | Free-visit routes are dropped only for functions reachable from a caller outside the expansion graph. |

Malformed input was also tried (attributes without arguments, `web::scope()` and `.route()` without arguments, empty `services![]`, `guard::Method()` without arguments, non-ASCII guard names, empty files, macro-only files): no panics, and syntax errors are reported in `parse_errors`.

### Result
83 unit tests and 3 CLI tests pass, up from 70 and 3. `cargo fmt` and `cargo clippy --all-targets -- -D warnings` are clean. The earlier fixtures give unchanged JSON.

### Limitation / Learning
E7 and E8 widen what counts as evidence, which removes false positives but can hide a finding if a helper or comparison is not really a check (a helper that only logs the role, for example). E8 follows only free-function calls, not method calls (`self.authz.check()`). E3/E4 recognize config and factory functions by type name (`ServiceConfig`, `Scope`, `Resource`, `HttpServiceFactory`), so type aliases are missed. A cycle of config functions with no outside caller reports some routes once per function in the cycle. Without the benchmark, the precision effect of these changes is not measured.

### Next Step
Same as section 9: rebuild the benchmark dataset and measure precision and recall before and after sections 9 and 10, paying attention to whether E7 and E8 hide any true findings.


## 11. Drift Detection Redesign

### Objective
An assessment of the detection logic (not of extraction) found six ways in which Archer did not detect authorization drift as intended:
1. The peer key included the HTTP method and the exact path shape, so CRUD drift (an unguarded `DELETE /admin/users/{id}` next to guarded GET/POST/PUT) produced no group.
2. Missing authentication was never reported, because the identity tier took no part in findings.
3. Only the evidence tier was compared, so `check_role(.., "viewer")` among `require_admin` peers looked consistent.
4. Any mention of a check counted: a role comparison for a display badge, a flag copied into a DTO, or `if is_admin() { log }`.
5. Closure handlers and unrecognized middleware produced false "missing authorization" findings.
6. Scopes held in variables lost their prefix and middleware.

### Work Completed
- **Grouping** (`drift.rs`): two levels, resource and namespace, each split into reads and writes. Routes are compared with their resource when it is informative, and with their namespace otherwise, where each resource counts once. A write is held to its resource's reads. A write alone in its namespace is also held to the namespace's reads, but only when those reads require a privilege. A resource whose routes are all public is treated as public by design.
- **Tiers and categories** (`model.rs`): the expected tier is the highest of privilege, resource, and identity that is dominant. There are new categories (`MissingAuthentication`, `DifferentAuthorization`, `UnverifiedProtection`), and every finding has a `severity` and a `rationale`. Invariants report `expected_tier` and `dominant_requirement`.
- **Requirements** (`evidence.rs`): normalized subjects are taken from names, literals, variants, type parameters, and attribute arguments, and compared within the privilege tier.
- **Enforcement-aware evidence** (`evidence.rs`): each expression has a use (statement, enforcing, scoping, value). Predicates count only where enforced. This covers `let`-bound predicates, `let ... else`, `match` arms over roles, `ensure!`/`assert!`, `?`, and returned `Result`s. `bool` helpers carry predicate evidence that a caller gains only when it enforces the call (`handlers.rs`). Ownership comes from owner-field comparisons, `filter` closures, and SQL literals.
- **Extraction** (`routes.rs`): closure handlers are analysed (`HandlerResolution::Closure`). Unrecognized `.wrap`/`.guard`/`wrap_fn` components become `Unknown` evidence, while known infrastructure is ignored and `IdentityMiddleware` no longer counts as authentication. Unresolved, ambiguous, and opaque handlers mark the route `unverified`. Builders bound to variables, reassigned, or never registered are substituted where they're used, or visited when their block ends.
- **Exemptions**: authentication and health/docs endpoints are exempt only under generic or account segments.

### Result
105 unit tests and 3 CLI tests pass. They include 16 drift fixtures (`tests/fixtures/probes/drift/f01`-`f16`) that pin each case above, the intended non-findings (public reads, public-by-design resources, per-route permissions, infrastructure middleware), and the edge cases. `cargo fmt` and `cargo clippy --all-targets -- -D warnings` are clean. A few earlier tests encoded the old semantics and were updated: the method/shape peer key, predicates in statement position counting as checks, closure handlers being `Unresolved`, and `UnauthorizedHandler` being ignored rather than infrastructure. The 10,000-route grouping test now places its routes under one namespace.

### Limitation / Learning
- Enforcement is syntactic. A rejection that happens through a callback, an error-mapping trait, or a method call (`self.policy.check()`) is not seen.
- Requirement comparison can't order roles (`superuser` vs `admin`), so a stricter role is reported as different. That is why it's medium severity.
- Namespace fallback depends on scopes or path conventions. Unscoped apps with a flat root (`/users`, `/orders`) never compare across resources.
- Builders held in struct fields, statics, or function arguments are still not followed.
- The thresholds (`min_support` 2, `threshold` 0.6) are unvalidated defaults.

### Next Step
Rebuild the benchmark dataset and measure precision and recall of this version against the hardening passes, especially for the new `MissingAuthentication` and `DifferentAuthorization` categories.
