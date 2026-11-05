# ARCHER

**Authorization Drift Detection for Actix-Web Applications**

ARCHER is a Rust-based static analysis research prototype that identifies **potential authorization drift** in Actix-Web applications. It analyzes route definitions and recognized authorization evidence, compares structurally related routes, and reports deviations from authorization patterns observed elsewhere in the repository.

The goal is to help developers identify endpoints that may have inconsistent authorization protections without relying exclusively on manually written security rules.

> **Research prototype:** ARCHER produces evidence-backed potential findings, not confirmed vulnerability verdicts. Results require developer review. "No recognized authorization evidence" never means "confirmed absence of authorization".

## How It Works

ARCHER follows a repository-local analysis pipeline:

```text
Rust Source Code
       |
       v
Route and Handler Extraction
       |
       v
Authorization Evidence Analysis
       |
       v
Structural Peer Grouping
       |
       v
Authorization Invariant Inference
       |
       v
Potential Drift Detection
       |
       v
Evidence-Backed Findings
```

1. **Route extraction:** Scans Rust source files and extracts recognized Actix-Web route definitions, HTTP methods, paths, and source locations, then resolves each route's handler to a single function definition, including handlers defined in other files.
2. **Authorization evidence analysis:** Looks for recognized authorization-related evidence in route configurations, middleware or guards, and the resolved handler's code.
3. **Structural peer grouping:** Groups the read and write routes of each resource (`/admin/users`, `/admin/users/{id}`, ...), and falls back to the whole namespace (scope) for resources too small to compare. See [Drift detection](#drift-detection).
4. **Invariant inference:** Finds the evidence tier (identity, resource ownership, privilege) and the requirement (such as `admin`) that a dominant share of each group reaches.
5. **Drift detection:** Flags routes below their group's tier (missing authentication, missing or weaker authorization), routes that require a different privilege, and gaps that only Archer's blind spots could explain (unverified protection).
6. **Evidence reporting:** Presents suspicious routes alongside supporting peer routes and the inferred invariant.

## Key Features

- Static analysis of Rust and Actix-Web source code.
- Route extraction with nested scope-prefix handling.
- HTTP method and route-path tracking.
- Cross-file handler resolution that reports how each handler was resolved and never merges evidence from same-named functions.
- Recognition of typed authorization-related evidence (role, permission, ownership, guard, middleware, manual check, identity).
- Repository-local authorization pattern inference.
- Detection of potential authorization drift among comparable routes.
- Source-location and supporting-peer evidence for findings.
- Human-readable terminal output and machine-readable JSON reports.
- Graceful reporting of source parsing errors.

## Technology Stack

| Technology | Purpose |
|---|---|
| Rust | Core analysis engine |
| `syn` | Rust syntax-tree parsing and traversal |
| `walkdir` | Repository source-file traversal |
| `clap` | Command-line interface |
| `serde` / `serde_json` | Structured report serialization |
| `anyhow` | Error handling |

## Getting Started

### Prerequisites

- Rust toolchain with Cargo
- A local Rust/Actix-Web repository to analyze

### Build

Clone the repository:

```bash
git clone https://github.com/Viditgupta-official/archer.git
cd archer
```

Build the project:

```bash
cargo build --locked
```

### Run the Analysis

Pass the path to the repository you want to analyze:

```bash
cargo run --locked -- /path/to/actix-web-project
```

To analyze the bundled test fixture:

```bash
cargo run --locked -- tests/fixtures/demo.rs
```

(`tests/fixtures/probes/` holds one small regression fixture per problem in `docs/improvement-plan.md`; analyzing all of `tests/fixtures` includes them.)

The bundled fixture yields five `/admin/*` routes and two potential drift findings, `GET /admin/payments` and `POST /admin/audit`, both supported by guard, middleware, and `require_admin` evidence on the three protected GET routes. `/admin/audit` has no read routes of its own, so the write is compared with the reads of its namespace.

### Generate JSON Output

ARCHER supports JSON output for integration with other tools and applications:

```bash
cargo run --locked -- /path/to/actix-web-project --json
```

The JSON report can be consumed by a backend or other programmatic workflow.

### Options

| Flag | Default | Effect |
|---|---|---|
| `--include-tests` | off | Also scan `tests/`, `examples/`, and `benches/`. `target/` and hidden directories are never scanned. |
| `--min-support <N>` | 2 | Authorized peers a group needs before its unauthorized routes are reported. |
| `--threshold <F>` | 0.6 | Share of a group's routes, in (0, 1], that must be authorized before its unauthorized routes are reported. |
| `--fail-on-findings` | off | Exit with status 1 when findings are reported. Status 2 always means the analysis failed. |
| `--config <FILE>` | `archer.toml` at the repository root, if present | Reviewer decisions to apply: routes that are public by design and findings that were reviewed and dismissed. |

The two inference defaults reproduce the earlier behaviour on small groups (two authorized peers out of three) and reject minority patterns (two out of seven). They are starting points for evaluation, not validated values.

### Recording review decisions (`archer.toml`)

Routes that are public on purpose, and findings that were reviewed and accepted, can be recorded so later runs do not report them again:

```toml
# Public by design: not judged, and not counted as peers of other routes.
[[public]]
path = "/api/status/**"
reason = "status pages are public"

# Reviewed and accepted: moved to `dismissed` in the report.
[[dismiss]]
method = "DELETE"                     # optional
path = "/api/keys/{key}"
category = "MissingAuthorization"     # optional
reason = "checked inside delete_key by the key store"
```

Paths match segment by segment: `*` matches one segment, `**` any number of segments (only at the end), and a `{name}` segment matches any path parameter. Methods and categories match case-insensitively. Every rule needs a `reason`, and unknown keys are rejected.

## Understanding the Results

A report includes information such as:

- **Files scanned:** Number of Rust source files processed.
- **Parse errors:** Source files that could not be parsed successfully; they are skipped.
- **Routes:** Extracted route candidates, including HTTP methods, paths, handlers, and how each handler was resolved (`handler_path`, `handler_resolution`).
- **Authorization evidence:** Recognized mechanisms, symbols, source locations, handlers, and evidence strength where available.
- **Peer groups:** Structurally comparable routes used for analysis.
- **Invariants:** Authorization patterns inferred from those groups.
- **Potential drift findings:** Routes that deviate from a supported inferred pattern, together with available supporting evidence.

### Example Scenario

Consider an application with several administrative endpoints:

| Route | Recognized authorization evidence |
|---|---|
| `GET /api/admin/users` | Present |
| `GET /api/admin/orders` | Present |
| `GET /api/admin/reports` | Present |
| `GET /api/admin/payments` | Not recognized |

If the routes are considered comparable and the evidence supports a consistent authorization invariant, ARCHER may flag `GET /api/admin/payments` as a potential authorization-drift candidate.

This does **not** automatically establish that the endpoint is exploitable. Authorization may be enforced through mechanisms that ARCHER does not recognize, including custom abstractions or protections outside the analyzed source.

## Drift detection

**Peer groups.** A route's *namespace* is its declared scope. Outside any scope, it is the leading generic segments (`/api`, `/api/v1`), or else the first segment (`/admin`). Its *resource* is the namespace plus the next static segment, so `/admin/users`, `/admin/users/{id}`, and `/admin/users/{id}/roles` share the resource `/admin/users`. Reads (GET/HEAD/OPTIONS/TRACE) and writes (POST/PUT/PATCH/DELETE, any, unknown) are grouped separately. A route is compared with its resource when the resource holds another route of its class (or, for a write, two reads). Otherwise it is compared with its namespace, where each resource counts once.

**Tiers.** Evidence is ranked none < identity < resource (ownership) < privilege (role, permission, authorization guard or middleware, explicit authorize). A group's expected tier is the highest one reached by at least `--min-support` routes making up at least `--threshold` of the group. A write is also held to the tier its resource's reads reach, and, when a write is alone in its namespace, to a privilege tier its namespace's reads require.

**Findings.**

| Category | Meaning | Severity |
|---|---|---|
| `MissingAuthentication` | No evidence; peers at least authenticate | high |
| `MissingAuthorization` | At most identity; peers reach resource or privilege | high (privilege) / medium |
| `WeakerAuthorization` | Ownership only; peers check a privilege | medium |
| `DifferentAuthorization` | Same tier, but not the requirement a dominant share of peers checks (`viewer` where peers require `admin`) | medium |
| `UnverifiedProtection` | Falls short, but has an unrecognized guard or middleware, or a handler that could not be analyzed, that its peers do not share | low |

**Requirements** are normalized subjects read from names (`require_admin`, `AdminUser`, `AdminGuard` all give `admin`), literals (`#[has_roles("ROLE_ADMIN")]`, `has_role(&u, "admin")`), variants (`Role::Admin`), and type parameters (`RequireRole<Admin>`). Routes with per-route permissions (`reports:sales`, `reports:stock`) have no dominant requirement and are never reported as different.

**Enforcement.** Extractors, authorization attributes, and imperative calls (`require_*`, `ensure_*`, `check_*`, `verify_*`, `assert_*`, `authorize*`) count when they run. Predicates (`is_admin`, `has_role`, role comparisons, `matches!`, flag fields, ownership comparisons such as `post.owner_id != user.id`) count only where their value decides a rejection: an `if`/`match`/`while` condition with a rejecting branch, `let ... else`, `ensure!`/`assert!`, an expression under `?`, a returned `Result`, or a `let` binding later used in such a condition. A display badge, a struct field copy, or `if is_admin(&u) { log(..) }` is not protection. A `bool` helper (`fn can_manage(u) -> bool { u.role == Role::Admin }`) lends its predicate only to callers that enforce it. Ownership comparisons inside `filter`/`retain`/`find` closures scope data and count; role comparisons there select records and do not.

**Unknown components.** A `.wrap`/`.guard`/`wrap_fn` argument that is neither authorization, authentication, nor known infrastructure (`Logger`, `Compress`, `Cors`, `DefaultHeaders`, `NormalizePath`, `ErrorHandlers`, tracing, metrics, sessions, rate limiting, CSRF, routing guards) is recorded as `Unknown`. `IdentityMiddleware` and `SessionMiddleware` make an identity available without requiring one, so they are not authentication.

**Exemptions.** Authentication endpoints (`login`, `logout`, `register`, `token`, `refresh`, `callback`, `reset`, ...) and health, metrics, version, and API-documentation endpoints are left out only when every segment before them is generic or about accounts (`/api/v1/auth/login`, `/healthz`). `/admin/metrics` and `/admin/settings/auth` are analysed.

## Implementation Details

### Current implementation

The analyzer (`src/analyzer.rs`):
- walks a Rust repository and parses every `.rs` file with `syn`; unparsable files are reported in `parse_errors` and skipped;
- indexes every free function in the repository by crate and module path before extracting routes;
- extracts `.route(...)` / `.resource(...)` registrations and `#[get]`/`#[post]`/... attribute routes, with nested `web::scope(...)` and `.service(...)` prefixes;
- resolves each route's `.to(...)` handler to a single definition (see below) and attaches that definition's authorization evidence;
- records typed evidence (role, permission, ownership, guard, middleware, manual check, identity) with file, line, handler, and strength; identity extraction alone is not authorization;
- groups routes by resource and method class, falling back to their namespace, infers the dominant tier and requirement per group, and reports routes that fall short of it (see [Drift detection](#drift-detection)).

### Handler resolution

Each route reports `handler_path` (the path as written) and `handler_resolution`, a tagged `kind`:

| Kind | Meaning | Evidence attached |
|---|---|---|
| `Definition` | Attribute route; the annotated function itself | yes |
| `Local` | Defined in the registering module, or a function declared in an enclosing block | yes |
| `Imported` | Explicit, renamed, grouped, or `self` `use` import, including re-exports | yes |
| `GlobImported` | Exactly one matching glob import | yes |
| `Qualified` | `handlers::x`, `crate::`, `self::`, `super::`, or an imported module alias | yes |
| `UniqueName` | Path rules found nothing; exactly one compatible definition exists in the crate | yes |
| `Closure` | A closure written at the route; its parameters and body are read in place | yes |
| `Ambiguous` | Several definitions match; `candidates` lists their Rust paths | no |
| `Unresolved` | No single definition could be identified | no |

Resolution follows Rust's order: local definitions, then explicit imports, then globs. Files map to modules by Cargo layout (`main.rs`/`lib.rs` = crate root, `foo.rs` or `foo/mod.rs` = `foo`, inline `mod`). Files outside `src/` and under `src/bin/` are isolated namespaces.

Bare names are first resolved lexically, innermost scope first:
- functions declared in an enclosing block are visible throughout that block, including before their declaration, and stay out of the repository index, so sibling functions never share them;
- `let` bindings (after their statement), function and closure parameters, `for`/`match`/`if let`/`while let` patterns, and block `const`/`static` items shadow handler names;
- a shadowed name, a duplicate block function, or a name hidden inside a function-local `mod` is `Unresolved`.

### Authorization evidence heuristics

Evidence comes from the resolved handler's body, from the route's own `.guard(...)` arguments, and from the `.guard(...)` and `.wrap(...)` calls of its scope and every enclosing scope. A scope's middleware applies to all of that scope's routes and nested scopes wherever the call appears in its builder chain, and never to sibling scopes or to a sibling route's own guards. All of it is kept: guard or middleware evidence never replaces handler evidence. Route paths and handler names are never evidence.

- **Helper calls and method calls** are classified by their snake_case words. Exact names such as `require_admin`, `has_role`, `is_admin`, `check_permission`, `authorize`, and `owns` count, as do `require_`/`check_`/`verify_`/`assert_`/`ensure_` names whose words include a role (`admin`, `manager`, `role`), permission, owner, or a final `access` (`verify_resource_access`), and `authorize_*` names.
- **Macro invocations** in a handler body, as statements (`require_admin!(user);`) or inside expressions (`if !has_role!(user, "admin") { ... }`), are classified by the macro's own name with the same rules, using the last path segment (`auth::require_admin!`). The evidence `symbol` keeps the macro path with a trailing `!`. The conditions of `ensure!`/`assert!`/`assert_eq!` are read as enforced checks; `debug_assert!` and logging or formatting macros (`info!`, `format!`) are not evidence. String literals in macros such as `sqlx::query!` count as ownership evidence when they filter on an owner column (`WHERE ... owner_id = $1`).
- Names ending in a data, lookup, or logging word are not checks: `ensure_admin_exists`, `check_admin_token`, `role_name`, `permissions_list`, `check_access_log`. Token validation, user lookups, and OAuth state checks (`verify_access_token`, `check_username`, `ensure_user_exists`, `verify_oauth_state`) are not authorization.
- Authentication helpers (`require_auth`, `is_authenticated`, `require_authenticated_user`) and identity values (`Claims`, `Identity`) are recorded as weak identity evidence, which never makes a route authorized.
- **Guard and middleware types** need an authorization word (`admin`, `role`, `permission`, `authorization`, `acl`, `rbac`) and a guard-like word (`Guard`, `Middleware`, `Filter`, `Require`, `Check`, `Only`, ...): `AdminGuard`, `RequireAdmin`, `AdminAuthMiddleware`. Authentication-only types (`AuthMiddleware`, `AuthGuard`, `JwtGuard`, `HttpAuthentication`) are identity evidence. Error-mapping and logging types (`UnauthorizedHandler`, `AuthorizationErrorMiddleware`, `RoleLogger`) and unrelated types such as `PermissionsPolicy` are ignored. Guard functions such as `guard::fn_guard(check_admin)` use the helper-name rules.

### Conservative cases

ARCHER never merges evidence from same-named functions and never guesses:
- several candidates (through globs, duplicates, or the fallback) produce `Ambiguous` with no evidence;
- `UniqueName` is used only when no path rule matched, never after an ambiguity, an explicit import that leaves the crate, or a qualifier that is not a module of this crate; a written qualifier must prefix the candidate's module;
- absolute (`::x`) and other-crate paths, `impl` methods (`Type::method`), and shadowed names are `Unresolved`, and such a route is reported only as unverified, never as missing authorization;
- evidence inside functions, `impl` methods, or `trait` methods declared within a handler body belongs to them, not to the enclosing handler.

## Testing

Run the test suite:

```bash
cargo test --locked
```

Build the optimized executable:

```bash
cargo build --locked --release
```

For reproducible evaluation, run ARCHER against controlled fixtures with known authorization patterns and compare its findings with the expected results.

### Validation status

- `cargo test --offline --locked`: 133 unit tests and 3 CLI tests pass, including 37 drift fixtures in `tests/fixtures/probes/drift/`.
- A synthetic single-file integration fixture produces its expected 16 routes, 3 peer groups, and the one intended `GET /api/admin/payments` finding.
- These are controlled synthetic checks. They do not establish accuracy or generalization on real-world Actix-Web codebases. Historical benchmark figures in `docs/evaluation/` were produced by an earlier engine version and have not been rerun.

## Limitations

ARCHER is an evolving research prototype, and its results depend on the authorization patterns and Actix-Web constructs it can recognize.

- Helper recognition is a name-based heuristic; custom authorization abstractions may not be detected, and a recognized name does not prove what a helper does. Middleware whose name says only "auth" is treated as authentication, even if it also enforces permissions.
- Scope middleware follows builder chains, `.configure(f)`, route-factory functions, and builders held in local variables (`let admin = web::scope("/admin").wrap(G);`). Builders stored in struct fields, statics, or passed as function arguments are not followed.
- Calls to repository free functions are followed three levels deep; method calls (`self.policy.check()`) are not.
- Macros are not expanded: a recognized macro name is evidence only of what its name says, a macro with an unrecognized name contributes nothing even if it enforces authorization, and calls written inside macro arguments are not seen. Attribute macros on handlers (such as `#[protect(...)]`) are not recognized.
- Not modeled: `use` declarations inside function bodies, macro-generated items and bindings, `#[path]` modules, `impl`-method handlers, cross-crate workspace dependencies, Rust 2015 crate-relative paths, and attribute routes registered through `.service(handler)` inside a scope (their scope prefix is not applied).
- `main.rs` and `lib.rs` share one namespace; same-named functions in both are `Ambiguous`.
- Structural similarity does not guarantee that two routes should have identical authorization requirements. Intentionally public reads next to protected writes are not reported, and nor are resources whose routes are all public; a lone public route in a protected namespace is.
- A group needs `--min-support` (default 2) routes reaching its tier, making up `--threshold` (default 0.6) of it. So a two-route group with one protected route is not reported by default.
- Enforcement is judged syntactically: a check counts when its result reaches a rejection (`return`, `?`, `Err`, a forbidden or unauthorized response, a panic) in the same function or in a called helper. Rejections that happen through custom control flow (callbacks, error-mapping traits) are not seen.
- Missing recognized evidence does not necessarily mean authorization is absent.
- Inferred invariants may produce false positives or miss genuine authorization inconsistencies.
- Findings should be validated against the application's intended access-control policy and runtime behavior.

ARCHER is intended to support security analysis and developer review, not replace comprehensive security testing or manual verification.

## Research Objective

ARCHER investigates whether repository-local authorization invariants can help detect authorization drift while reducing false positives compared with simpler route-level heuristics or manually specified rules.

Evaluation should measure detection precision, recall, false-positive rates, and behavior across diverse applications. Results on synthetic fixtures are useful for controlled validation but do not, by themselves, establish generalization to real-world repositories.

## Contributing

Contributions that improve route extraction, authorization evidence recognition, peer grouping, invariant inference, test coverage, or report quality are welcome.

When adding detection logic, include regression tests for both the intended finding and relevant negative cases.

## License

This repository does not currently include a license file, and `Cargo.toml` does not declare a license. Contact the maintainers for terms governing use and distribution.
