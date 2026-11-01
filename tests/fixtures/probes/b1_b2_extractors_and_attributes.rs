use actix_web::{web, App};
async fn users(_admin: AdminUser) {} async fn orders(_admin: AdminUser) {}
#[protect("ROLE_ADMIN")] async fn reports() {}
async fn payments() {}
fn main() { App::new().service(web::scope("/admin").route("/users", web::get().to(users)).route("/orders", web::get().to(orders)).route("/reports", web::get().to(reports)).route("/payments", web::get().to(payments))); }
