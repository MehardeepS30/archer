use actix_web::{middleware::Logger, web};
pub fn config(cfg: &mut web::ServiceConfig) {
    // Route-specific unknown gate: unverified, not missing.
    cfg.service(web::scope("/admin")
        .wrap(Logger::default())
        .route("/users", web::get().to(users))
        .route("/billing", web::get().to(billing))
        .route("/audit", web::get().to(audit))
        .service(web::resource("/stats").wrap(StaffOnlyGate).route(web::get().to(stats))));
    // A scope-wide unknown middleware cannot explain one route's gap.
    cfg.service(web::scope("/team")
        .wrap(Gatekeeper)
        .route("/users", web::get().to(users))
        .route("/billing", web::get().to(billing))
        .route("/audit", web::get().to(audit))
        .route("/stats", web::get().to(stats)));
}
async fn users(_a: AdminUser) {}
async fn billing(_a: AdminUser) {}
async fn audit(_a: AdminUser) {}
async fn stats() {}
