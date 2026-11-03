use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api/post")
        .route("/create", web::post().to(create_post))
        .route("/edit", web::post().to(edit_post))
        .route("/delete", web::post().to(delete_post))
        .route("/lock", web::post().to(lock_post))
        // Two routes of one resource that disagree: judged by the namespace.
        .route("/mark_as_read", web::post().to(mark_as_read))
        .route("/mark_as_read/many", web::post().to(mark_many_as_read))
        // Two routes of one resource that agree it is public: left alone.
        .route("/report_spam", web::post().to(report_spam))
        .route("/report_spam/bulk", web::post().to(report_spam_bulk)));
}
async fn create_post(user: LocalUserView) {}
async fn edit_post(user: LocalUserView) {}
async fn delete_post(user: LocalUserView) {}
async fn lock_post(user: LocalUserView) {}
async fn mark_as_read(user: LocalUserView) {}
async fn mark_many_as_read() {}
async fn report_spam() {}
async fn report_spam_bulk() {}
