use actix_web::{guard, web, App};
async fn a(_u: AdminUser) -> &'static str { "" }
async fn b(_u: AdminUser) -> &'static str { "" }
async fn c() -> &'static str { "" }
fn main() {
    App::new().service(web::scope("/admin")
        .route("/a", web::route().guard(guard::Get()).to(a))
        .route("/b", web::get().to(b))
        .route("/c", web::route().guard(guard::Get()).to(c)));
}
