use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    // Public reads with protected writes is a common, intended design.
    cfg.service(web::scope("/blog")
        .route("/posts", web::get().to(list))
        .route("/posts/{id}", web::get().to(show))
        .route("/posts", web::post().to(create))
        .route("/posts/{id}", web::put().to(update))
        .route("/posts/{id}", web::delete().to(remove)));
    // Writes below their resource's reads are reported.
    cfg.service(web::scope("/admin")
        .route("/settings", web::get().to(read_settings))
        .route("/settings/{key}", web::get().to(read_setting))
        .route("/settings/{key}", web::put().to(write_setting)));
}
async fn list() {}
async fn show() {}
async fn create(_u: AdminUser) {}
async fn update(_u: AdminUser) {}
async fn remove() {}
async fn read_settings(_u: AdminUser) {}
async fn read_setting(_u: AdminUser) {}
async fn write_setting() {}
