use actix_web::{web, App, Scope};
fn admin_scope() -> Scope {
    web::scope("/admin")
        .route("/users", web::get().to(list_users))
        .route("/orders", web::get().to(list_orders))
        .route("/payments", web::get().to(list_payments))
}
async fn list_users() -> &'static str { "" }
async fn list_orders() -> &'static str { "" }
async fn list_payments() -> &'static str { "" }
fn main() {
    App::new().service(web::scope("/api").wrap(RequireAdminMiddleware).service(admin_scope()));
}
