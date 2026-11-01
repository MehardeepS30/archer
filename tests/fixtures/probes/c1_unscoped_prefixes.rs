use actix_web::{web, App};
async fn a() { require_admin(); } async fn b() { require_admin(); } async fn c() {}
fn main() { App::new().route("/admin/users", web::get().to(a)).route("/admin/orders", web::get().to(b)).route("/public/docs", web::get().to(c)); }
