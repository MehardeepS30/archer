use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api")
        .route("/orders", web::get().to(authed))
        .route("/invoices", web::get().to(authed))
        .route("/profile", web::get().to(authed))
        .route("/health", web::get().to(open))
        .route("/auth/login", web::post().to(open)));
    cfg.service(web::scope("/admin")
        .route("/users", web::get().to(admin))
        .route("/orders", web::get().to(admin))
        .route("/audit", web::get().to(admin))
        .route("/metrics", web::get().to(open))
        .route("/settings/auth", web::get().to(open)));
}
async fn authed(_u: BearerAuth) {}
async fn admin(_u: AdminUser) {}
async fn open() {}
