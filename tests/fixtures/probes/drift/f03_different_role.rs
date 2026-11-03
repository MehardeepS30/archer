use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/admin")
        .route("/users", web::get().to(users))
        .route("/billing", web::get().to(billing))
        .route("/audit", web::get().to(audit))
        .route("/secrets", web::get().to(secrets)));
}
async fn users(u: User) { require_admin(&u); }
async fn billing(u: User) { require_admin(&u); }
async fn audit(u: User) { require_admin(&u); }
async fn secrets(u: User) { check_role(&u, "viewer"); }
