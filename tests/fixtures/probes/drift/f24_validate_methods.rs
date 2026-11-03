use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api/users")
        .route("", web::get().to(list_users))
        .route("", web::post().to(create_user))
        .route("/{id}", web::get().to(get_user))
        .route("/{id}", web::put().to(update_user))
        .route("/{id}", web::delete().to(delete_user))
        // Takes the caller but never checks the role its peers check.
        .route("/{id}/sessions", web::delete().to(delete_sessions)));
}
async fn list_users(principal: ReqPrincipal) { principal.validate_admin_session()?; }
// Either alternative passes, so it names no single requirement.
async fn create_user(principal: ReqPrincipal) { principal.validate_api_key_or_admin_session()?; }
async fn get_user(principal: ReqPrincipal) { principal.validate_admin_session()?; }
async fn update_user(principal: ReqPrincipal) { principal.validate_admin_session()?; }
async fn delete_user(principal: ReqPrincipal) { principal.validate_admin_session()?; }
async fn delete_sessions(principal: ReqPrincipal) {}
