use actix_web::{web, App};
mod admin {
    use actix_web::web;
    pub fn config(cfg: &mut web::ServiceConfig) {
        cfg.route("/users", web::get().to(list_users));
        cfg.route("/orders", web::get().to(list_orders));
        cfg.route("/payments", web::get().to(list_payments));
    }
    async fn list_users() -> &'static str { "" }
    async fn list_orders() -> &'static str { "" }
    async fn list_payments() -> &'static str { "" }
}
fn routes(cfg: &mut web::ServiceConfig) { admin::config(cfg); }
fn main() {
    App::new().service(web::scope("/admin").wrap(RequireAdminMiddleware).configure(routes));
}
