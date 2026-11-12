//! Switches of the unseen-apps precision round (what the application itself
//! declares about a route: its name, the guard it calls, its OpenAPI
//! annotation, the kind of credential it takes). `ARCHER_PU=0` turns the
//! whole round off; `ARCHER_PU_<NAME>=0` turns one change off.
//!
//! | Name | Change |
//! |---|---|
//! | `OPENAPI` | an OpenAPI annotation without a security requirement states the route as open |
//! | `PEERDOCS` | the same, judged against the annotated peers when only part of the app documents security |
//! | `NAMED` | a route named as open (`public`, `published`, `exists`, `static`, protocol endpoints) |
//! | `WEBHOOK` | a write named `webhook` is called by another service |
//! | `GUARDNAME` | the handler calls the guard the app names public or optional |
//! | `OPTIONAL` | the handler reads the caller optionally and uses what it gets |
//! | `SECRET` | a sender authenticated by a secret is another kind of caller than a user |
//! | `SELFSERVICE` | a route that holds its path record to the caller beside administration routes |
//! | `AUTHFLOW` | steps of signing in (`otp`, `webauthn`, `resend`), `sign_up` written apart |
//! | `SUBTREE` | flows below the sign-in subtree (`/auth/email/verify`), underscore mounts |
//! | `SIGNUP` | account creation outside a sign-in path (`POST /api/user` by `post_register`) |
//! | `FIELDNAMES` | `name`, `username`, `email`, `title` in a body do not address the records a path names |
//! | `OPNAMED` | a permission named after its one operation is not a different requirement |
//! | `RESPONSES` | a handler body another handler delegates to is not a caller source |
//! | `MACROS` | the app's own rejecting macros (`die!(UNAUTHORIZED, ..)`) reject |
//! | `GUARDED` | a comparison with the caller counts as the ownership check of the same resource |
//! | `FORWARDS` | middleware that forwards every request (`let fut = srv.call(req); async move { .. }`) checks nobody |

/// Whether the change `name` of this round is on.
pub(crate) fn enabled(name: &str) -> bool {
    let on = |variable: String| std::env::var(variable).map_or(true, |value| value != "0");
    on("ARCHER_PU".to_string()) && on(format!("ARCHER_PU_{name}"))
}
