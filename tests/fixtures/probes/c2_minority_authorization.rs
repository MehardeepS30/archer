use actix_web::{web, App};
async fn a() { require_admin(); } async fn b() { require_admin(); } async fn c() {} async fn d() {} async fn e() {} async fn f() {} async fn g() {}
fn main() { App::new().service(web::scope("/api").route("/a", web::get().to(a)).route("/b", web::get().to(b)).route("/c", web::get().to(c)).route("/d", web::get().to(d)).route("/e", web::get().to(e)).route("/f", web::get().to(f)).route("/g", web::get().to(g))); }
