use actix_web::{get, web, App};
#[get("/users")] async fn users() { require_admin(); }
#[get("/orders")] async fn orders() { require_admin(); }
#[get("/reports")] async fn reports() { require_admin(); }
#[get("/payments")] async fn payments() {}
#[get("/health")] async fn health() {}
fn main() { App::new().service(web::scope("/admin").service(users).service(orders).service(reports).service(payments)).service(health); }
