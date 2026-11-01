use actix_web::{web, App};
async fn a() { require_admin(); } async fn b() { require_admin(); } async fn c() {}
fn main() { App::new().service(web::scope("/admin").route("/users/", web::get().to(a)).route("/orders", web::get().to(b)).route("/payments", web::get().to(c))); }
