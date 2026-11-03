use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/portal")
        .route("/orders", web::get().to(authed))
        .route("/invoices", web::get().to(authed))
        .route("/profile", web::get().to(authed))
        // A resource whose routes are all public: consistent, not drift.
        .route("/catalog", web::get().to(open))
        .route("/catalog/{id}", web::get().to(open))
        // A lone public route among authenticated ones: drift.
        .route("/exports", web::get().to(open)));
}
async fn authed(_u: BearerAuth) {}
async fn open() {}
