use actix_web::{web, App};
fn admin_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/users", web::get().to(list_users));
    cfg.route("/orders", web::get().to(list_orders));
}
async fn list_users() -> &'static str { "" }
async fn list_orders() -> &'static str { "" }
fn main() {
    App::new().service(web::scope("/admin").wrap(RequireAdminMiddleware).configure(|c| admin_routes(c)));
}
