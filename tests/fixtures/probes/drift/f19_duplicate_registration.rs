use actix_web::{middleware::from_fn, web, App};
pub fn app() {
    App::new()
        .service(web::scope("/admin")
            .wrap(from_fn(reject_anonymous_users))
            .route("/newsletters", web::post().to(publish_newsletter)))
        // The same handler again, outside the authenticated scope.
        .route("/newsletters", web::post().to(publish_newsletter))
        // Registered twice with the same protection: consistent.
        .route("/feed", web::get().to(feed))
        .route("/rss", web::get().to(feed));
}
async fn publish_newsletter(user_id: web::ReqData<UserId>) {}
async fn feed() {}
