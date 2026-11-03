use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api")
        .route("/orders", web::get().to(orders))
        .route("/invoices", web::get().to(invoices))
        .route("/profile", web::get().to(profile))
        .route("/exports", web::get().to(exports)));
}
async fn orders(_u: BearerAuth) {}
async fn invoices(_u: BearerAuth) {}
async fn profile(_u: BearerAuth) {}
async fn exports() {}
