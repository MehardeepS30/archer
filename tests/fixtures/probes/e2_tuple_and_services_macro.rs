use actix_web::{get, web, App};
#[get("/users")] async fn users(_u: AdminUser) -> &'static str { "" }
#[get("/orders")] async fn orders(_u: AdminUser) -> &'static str { "" }
#[get("/payments")] async fn payments() -> &'static str { "" }
#[get("/health")] async fn health() -> &'static str { "" }
fn main() {
    App::new()
        .service(web::scope("/admin").service((users, orders, payments)))
        .service(web::scope("/public").wrap(RequireAdminMiddleware).service(services![health]));
}
