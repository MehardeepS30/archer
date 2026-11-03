use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/admin")
        .route("/users", web::get().to(list_users))
        .service(web::scope("/applications")
            .route("", web::get().to(get_application))
            .route("/list", web::get().to(list_applications)))
        .service(web::scope("/tagline")
            .route("", web::post().to(create_tagline))
            // The only read in its scope; compared with the reads under /admin.
            .route("/list", web::get().to(list_taglines))));
}
async fn list_users(u: LocalUserView) { is_admin(&u)?; }
async fn get_application(u: LocalUserView) { is_admin(&u)?; }
async fn list_applications(u: LocalUserView) { is_admin(&u)?; }
async fn create_tagline(u: LocalUserView) { is_admin(&u)?; }
async fn list_taglines() {}
