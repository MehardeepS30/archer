use actix_web::dev::ServiceRequest;
use actix_web::middleware::Condition;
use actix_web::{web, App, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web_httpauth::middleware::HttpAuthentication;

// Middleware reaches each scope indirectly:
// - `/api`: through a closure applied to the builder, `.map(|s| s.wrap(..))`;
// - `/members`: through a function that returns the wrapped scope;
// - `/staff`: through `.wrap(helper(arg))`, a helper that takes an argument;
// - `/opt`: through a helper returning `Condition::from_option(..)`, so the
//   check runs only when the deployment configures it.
// `/export` has no middleware at all.
async fn validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
    if credentials.token().is_empty() {
        return Err((actix_web::error::ErrorUnauthorized("no token"), req));
    }
    Ok(req)
}

fn members() -> actix_web::Scope {
    web::scope("/members").wrap(HttpAuthentication::bearer(validator))
}

fn bearer(realm: &str) -> HttpAuthentication<BearerAuth, fn(ServiceRequest, BearerAuth) -> _> {
    HttpAuthentication::bearer(validator)
}

fn optional(enabled: Option<bool>) -> Condition<HttpAuthentication<BearerAuth, fn(ServiceRequest, BearerAuth) -> _>> {
    Condition::from_option(enabled.map(|_| HttpAuthentication::bearer(validator)))
}

async fn page() -> HttpResponse {
    HttpResponse::Ok().finish()
}

fn main() {
    let enabled = Some(true);
    App::new()
        .service(
            utoipa_actix_web::scope("/api")
                .map(|scope| scope.wrap(HttpAuthentication::bearer(validator)))
                .route("/a", web::get().to(page))
                .route("/b", web::get().to(page)),
        )
        .service(
            members()
                .route("/list", web::get().to(page))
                .route("/detail", web::get().to(page)),
        )
        .service(
            web::scope("/staff")
                .wrap(bearer("staff"))
                .route("/list", web::get().to(page))
                .route("/detail", web::get().to(page)),
        )
        .service(
            web::scope("/opt")
                .wrap(optional(enabled))
                .route("/x", web::get().to(page))
                .route("/y", web::get().to(page)),
        )
        .route("/export", web::get().to(page));
}
