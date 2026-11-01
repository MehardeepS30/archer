use actix_web::{web, App};
fn admin_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/users", web::get().to(users)).route("/orders", web::get().to(orders)).route("/payments", web::get().to(payments));
}
async fn users() {} async fn orders() {} async fn payments() {}
fn main() { App::new().service(web::scope("/admin").wrap(RequireAdminMiddleware).configure(admin_routes)); }
