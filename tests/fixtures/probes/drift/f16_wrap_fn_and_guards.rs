use actix_web::{guard, web};
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/admin")
        .route("/users", web::get().to(users))
        .route("/billing", web::get().to(billing))
        .route("/audit", web::get().to(audit))
        .service(web::resource("/hook")
            .wrap_fn(|req, srv| { let ok = req.headers().contains_key("x-sig"); srv.call(req) })
            .route(web::get().to(hook)))
        .route("/json", web::get().guard(guard::Header("content-type", "application/json")).to(json)));
}
async fn users(_a: AdminUser) {}
async fn billing(_a: AdminUser) {}
async fn audit(_a: AdminUser) {}
async fn hook() {}
async fn json() {}
