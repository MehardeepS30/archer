use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/admin")
        .route("/users", web::get().to(users))
        .route("/billing", web::get().to(billing))
        .route("/audit", web::get().to(audit))
        .route("/keys", web::get().to(audit))
        .route("/roles", web::get().to(audit))
        .route("/secrets", web::get().to(secrets))
        .route("/reports", web::get().to(reports))
        .route("/exports", web::get().to(exports)));
}
async fn users(u: User) { require_admin(&u); }
async fn billing(u: User) { require_admin(&u); }
async fn audit(u: User) { require_admin(&u); }
// A role comparison for display and a flag copied into a response.
async fn secrets(u: User) -> String {
    let badge = if u.role == Role::Admin { "admin" } else { "member" };
    let dto = UserView { is_admin: u.is_admin, badge };
    serde_json::to_string(&dto).unwrap()
}
// A check whose result only decides a log line.
async fn reports(u: User) { if is_admin(&u) { log::info!("admin read"); } }
// A bool helper called, but its answer ignored.
async fn exports(u: User) { let _ = can_manage(&u); }
fn can_manage(u: &User) -> bool { u.role == Role::Admin }
