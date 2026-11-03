use actix_web::{web, App};
async fn users() { require_admin(); } async fn orders() { require_admin(); } async fn payments(u: User) { if !u.owns(&doc) { return; } }
fn main() { App::new().service(web::scope("/admin").route("/users", web::get().to(users)).route("/orders", web::get().to(orders)).route("/payments", web::get().to(payments))); }
