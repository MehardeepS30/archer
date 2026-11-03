use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/collections")
        .route("/a", web::post().to(a))
        .route("/b", web::post().to(b))
        .route("/c", web::post().to(c))
        // Hands its identity to a service whose checks Archer cannot see.
        .route("/d", web::post().to(d))
        // Hands nothing on and checks nothing: drift.
        .route("/e", web::post().to(e)));
}
async fn a(ActixAuth(auth): ActixAuth) { check_collection_access(&auth)?; }
async fn b(ActixAuth(auth): ActixAuth) { check_collection_access(&auth)?; }
async fn c(ActixAuth(auth): ActixAuth) { check_collection_access(&auth)?; }
async fn d(ActixAuth(auth): ActixAuth, dispatcher: web::Data<Dispatcher>) {
    dispatcher.toc(&auth).delete().await;
}
async fn e(ActixAuth(_auth): ActixAuth) {}
