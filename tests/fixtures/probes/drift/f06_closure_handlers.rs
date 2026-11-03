use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/admin")
        .route("/users", web::get().to(users))
        .route("/billing", web::get().to(billing))
        .route("/audit", web::get().to(audit))
        .route("/stats", web::get().to(|_a: AdminUser| async { "ok" }))
        .route("/debug", web::get().to(|| async { "open" })));
}
async fn users(_a: AdminUser) {}
async fn billing(_a: AdminUser) {}
async fn audit(_a: AdminUser) {}
