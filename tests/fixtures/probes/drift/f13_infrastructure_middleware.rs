use actix_web::{middleware, web, App};
use actix_identity::IdentityMiddleware;
fn main() {
    App::new()
        .wrap(IdentityMiddleware::default())
        .wrap(middleware::Logger::default())
        .wrap(middleware::Compress::default())
        .wrap(Cors::permissive())
        .service(web::scope("/me")
            .route("/orders", web::get().to(authed))
            .route("/invoices", web::get().to(authed))
            .route("/profile", web::get().to(authed))
            .route("/exports", web::get().to(open)));
}
async fn authed(id: Identity) {}
async fn open() {}
