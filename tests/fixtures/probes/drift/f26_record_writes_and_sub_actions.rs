use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api")
        .route("/accounts", web::get().to(list_accounts))
        .route("/accounts/{id}", web::get().to(get_account))
        // A write to the record itself is never less protected than its reads.
        .route("/accounts/{id}", web::put().to(update_account))
        // Self-service actions below a record have their own policy.
        .route("/accounts/{id}/otp", web::post().to(enable_otp))
        .route("/accounts/{id}/self", web::put().to(update_self)));
}
async fn list_accounts(user: AuthenticatedUser) { require_admin(&user)?; }
async fn get_account(user: AuthenticatedUser) { require_admin(&user)?; }
async fn update_account(user: AuthenticatedUser) {}
async fn enable_otp(user: AuthenticatedUser) {}
async fn update_self(user: AuthenticatedUser) {}
