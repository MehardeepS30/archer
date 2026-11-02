# Archer changes, explained simply

Archer reads an Actix-Web project and lists its routes. For each route it records **evidence** of an authorization check, such as an admin guard, a `require_admin(...)` call, or an `AdminUser` argument. It groups similar routes as **peers** (same method, same prefix, same path shape). When most peers have evidence and one does not, Archer reports that route as a **finding**: an authorization check is probably missing there.

Archer can go wrong in three ways:

- **Missed route or lost context.** A route is not found, or it loses its scope's prefix and middleware. Archer then compares it with the wrong peers or with none.
- **Missed evidence.** A route really is checked, but Archer doesn't see the check. That gives a false finding (a false positive), and it can also make a real gap invisible (a false negative).
- **Wrong grouping or reporting.** The routes and evidence are correct, but the comparison or the output is wrong.

The first pass fixed problems A–D (18 items). The second pass fixed E1–E9. For each item below: what was wrong, what changed, and why it matters.

---

## A. Finding routes and their context

**A1. Attribute routes inside a scope**
- Wrong: `#[get("/payments")]` handlers registered with `web::scope("/admin").service(payments)` were reported at `/payments`, without `/admin` or the scope's middleware.
- Changed: these routes now take the prefix and middleware of the scope that registers them. A handler registered in two scopes gives two routes.
- Matters: they are now compared with the right peers, so a missing check under `/admin` is reported.

**A2. `.configure(f)` inside a scope**
- Wrong: routes added inside `f` lost the scope's prefix and middleware.
- Changed: Archer reads `f`'s body as if it were written at the call. Recursive `configure` calls stop instead of looping forever.
- Matters: same as A1.

**A3. Other route attribute forms**
- Wrong: `#[actix_web::get("/x")]` and `#[route("/y", method = "GET", method = "POST")]` were ignored.
- Changed: both are read. `#[route]` gives one route per method.
- Matters: these routes were invisible before.

**A4. `web::resource("/x").to(handler)`**
- Wrong: this form was dropped.
- Changed: it is now a route. Its method is `UNKNOWN`, because `.to` answers every method.
- Matters: these routes were invisible before.

**A5. Paths that are not string literals**
- Wrong: `cfg.route(USERS_PATH, ...)` was silently skipped.
- Changed: string constants are resolved to their value. A path that can't be resolved is kept as `<unresolved:NAME>` with a warning, and it is left out of peer comparison.
- Matters: no silent gaps, and no wrong comparisons based on guessed paths.

**A6. Build and test folders**
- Wrong: `target/` (generated code), hidden folders, `tests/`, `examples/` and `benches/` were scanned.
- Changed: these folders are skipped. `--include-tests` brings test folders back.
- Matters: no duplicate or fake routes from generated or test code.

**A7. One unreadable file stopped the run**
- Wrong: a file that wasn't valid UTF-8 made the whole analysis fail.
- Changed: that file is listed in `parse_errors` and the rest of the project is still analysed.
- Matters: one bad file no longer means no report at all.

## B. Seeing authorization evidence

**B1. Checks in the handler's arguments**
- Wrong: `async fn delete(_: AdminUser)` was not evidence, even though an `AdminUser` extractor rejects the request before the handler runs.
- Changed: argument types with admin/role/permission words are evidence. Request-data types such as `web::Json<RoleUpdate>` are not.
- Matters: fewer false findings on handlers protected this way.

**B2. Check attributes on handlers**
- Wrong: `#[protect("ROLE_ADMIN")]` and `#[has_roles(...)]` were ignored.
- Changed: they are strong evidence.
- Matters: same as B1.

## C. Comparing routes

**C1. Unrelated routes compared as peers**
- Wrong: `/admin/users` and `/public/docs` (both outside any scope) were peers, so `/public/docs` was flagged.
- Changed: peers must also share the path before the last fixed segment (`/admin` vs `/public`).
- Matters: removes false findings.

**C2. A minority pattern treated as the rule**
- Wrong: 2 checked routes out of 20 were enough to flag the other 18.
- Changed: a finding needs at least `--min-support` checked peers (default 2) that make up at least `--threshold` of the group (default 0.6).
- Matters: removes floods of false findings in mostly-public areas.

**C3. Weaker check than peers**
- Wrong: an ownership check counted the same as an admin check, so a route that only checks ownership, among admin-checked peers, passed.
- Changed: evidence has tiers: privilege (role, permission, guard, middleware) > resource (ownership) > identity (logged in) > none. A route below its peers' tier is reported as `WeakerAuthorization`.
- Matters: catches routes that check something, just not enough.

**C4. Everything under `/auth/...` was ignored**
- Wrong: any path with an `auth` or `token` segment was skipped, including `/auth/admin/purge`.
- Changed: only the last fixed segment decides. `/auth/login` is skipped, `/auth/admin/purge` is analysed.
- Matters: removes a blind spot.

**C5. Route order**
- Wrong: routes were listed in reverse source order.
- Changed: they are listed in the order they appear in the source.
- Matters: the report is easier to read and compare.

## D. Output and code health

**D1. Exit codes**
- Changed: `--fail-on-findings` exits with 1 when there are findings, and errors exit with 2.
- Matters: CI can fail a build on findings.

**D2. Findings stored twice**
- Changed: the JSON keeps only the structured `finding_details`, and the text output is built from it.
- Matters: the two outputs can't disagree.

**D3. Readable names**
- Changed: the text output says "role check, strong" instead of Rust `Debug` names like `RoleCheck`.

**D4. One 4,667-line file**
- Changed: split into `model`, `routes`, `handlers`, `evidence` and `drift` modules, with dead code removed and no change in behaviour.
- Matters: easier to review and change.

---

## E. Second pass

**E1. Crash and slowness on large projects**
- Wrong: about 800 chained `.route()` calls crashed Archer with a stack overflow (exit code 127). Grouping compared every route with every other route, so 2,000 routes took 45 seconds.
- Changed: analysis runs on a thread with a much larger stack. Routes are put straight into groups by a key (prefix, method, shape) in one pass. Two other steps that repeated work on long chains now do it once.
- Matters: no crash, and a 5,000-route chain takes 0.6 seconds.

**E2. `.service((a, b))` and `services![a, b]`**
- Wrong: handlers registered as a tuple, or with the `services!` macro, were not linked to their scope, so A1's fix didn't apply to them.
- Changed: each item in the tuple or macro counts as a registration.
- Matters: these routes now get their scope's prefix and middleware.

**E3. Config functions called directly**
- Wrong: `admin::config(cfg)` called inside another config function, or `.configure(|c| admin_routes(c))`, wasn't expanded, so A2's fix didn't apply.
- Changed: a call to any function that takes a `ServiceConfig` is expanded at the call.
- Matters: same as A2.

**E4. Functions that return a scope**
- Wrong: `.service(admin_scope())`, where `admin_scope()` returns a `Scope`, lost the outer prefix and middleware.
- Changed: calls to functions returning `Scope`, `Resource` or `impl HttpServiceFactory` are expanded at the call.
- Matters: same as A2.

**E5. `wrap_fn` middleware**
- Wrong: `.wrap_fn(|req, srv| { check_admin(&req)?; ... })` was ignored.
- Changed: it is read like `.wrap(...)`.
- Matters: a scope protected this way no longer looks unprotected.

**E6. Method guards**
- Wrong: `web::route().guard(guard::Get())` got method `UNKNOWN`, so it was never compared with `web::get()` routes.
- Changed: `guard::Get()` and `guard::Method(Method::GET)` set the method.
- Matters: such routes now join their peers, so a missing check can be found.

**E7. Role checks written as comparisons**
- Wrong: `if user.role != Role::Admin`, `matches!(user.role, Role::Admin)`, `user.roles.contains(&Role::Admin)` and `if !claims.is_admin` weren't evidence.
- Changed: comparing a role or permission value is evidence of medium strength. Comparisons like `order.status == Status::Paid` and `roles.len() == 2`, and assignments like `user.is_admin = true`, are not.
- Matters: fewer false findings. It also helps the other direction: unseen checks could make a group look mostly unchecked, which hid a real gap.

**E8. Checks inside helper functions**
- Wrong: `ensure_can_manage(&user)` that calls `require_admin` wasn't seen, so the handler was flagged.
- Changed: a function also carries the evidence of the project functions it calls, up to 3 calls deep, without looping on recursion. Only calls Archer can resolve exactly are followed. The evidence points at the real check's file and line.
- Matters: fewer false findings.

**E9. Routes lost in self-calling config functions**
- Wrong: a config function whose only caller was itself, with no outside caller, had all its routes dropped.
- Changed: routes are only moved to a call site when some real outside caller exists.
- Matters: no routes silently disappear.

---

## What Archer still can't do

- Evidence is still recognized by names (`admin`, `role`, `permission`, ...). Archer doesn't run the code, so a helper named like a check that doesn't actually check anything is still counted.
- E7 and E8 count more code as checks. That removes false findings, but a misleading helper could now hide a real one.
- Method calls such as `self.authz.check()` are not followed into the method.
- Type aliases for `Scope` or `ServiceConfig` are not recognized.
- The 20-project benchmark isn't in the repository, so the effect of these changes on precision and recall hasn't been measured.
