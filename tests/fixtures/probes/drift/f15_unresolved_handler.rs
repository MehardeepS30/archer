use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/admin")
        .route("/users", web::get().to(users))
        .route("/billing", web::get().to(billing))
        .route("/audit", web::get().to(audit))
        .route("/plugins", web::get().to(external_crate::plugins))
        .route("/stats", web::get().to(handlers::make_stats())));
}
async fn users(_a: AdminUser) {}
async fn billing(_a: AdminUser) {}
async fn audit(_a: AdminUser) {}
