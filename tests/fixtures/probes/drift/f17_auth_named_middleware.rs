use actix_web::{middleware::{from_fn, Condition}, web};
pub fn config(cfg: &mut web::ServiceConfig) {
    // A wrapped component named for authentication authenticates. Peers'
    // ownership checks do not carry across the namespace to `/logout`.
    cfg.service(web::scope("/admin")
        .wrap(from_fn(reject_anonymous_users))
        .route("/password", web::post().to(change_password))
        .route("/newsletters", web::post().to(publish))
        .route("/logout", web::post().to(log_out)));
    // Enabled by configuration, it stays unknown.
    cfg.service(web::scope("/internal")
        .wrap(Condition::new(enabled, ApiKeyAuth))
        .route("/stats", web::get().to(stats)));
}
async fn change_password(id: UserId) { sqlx::query!("UPDATE users SET pw = $1 WHERE user_id = $2", id); }
async fn publish(id: UserId) { sqlx::query!("INSERT INTO issues (user_id) VALUES ($1)", id); }
async fn log_out() {}
async fn stats() {}
