use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/admin")
        .route("/users", web::get().to(list_users))
        .route("/users", web::post().to(create_user))
        .route("/users/{id}", web::get().to(get_user))
        .route("/users/{id}", web::put().to(update_user))
        .route("/users/{id}", web::delete().to(delete_user)));
}
async fn list_users(_a: AdminUser) {}
async fn create_user(_a: AdminUser) {}
async fn get_user(_a: AdminUser) {}
async fn update_user(_a: AdminUser) {}
async fn delete_user() {}
