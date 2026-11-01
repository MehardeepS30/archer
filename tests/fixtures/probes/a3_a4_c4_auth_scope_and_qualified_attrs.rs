use actix_web::{web, App};
async fn a() { require_admin(); } async fn b() { require_admin(); } async fn c() {}
#[actix_web::get("/x")] async fn x() {}
fn main() { App::new().service(web::scope("/auth/admin").route("/users", web::get().to(a)).route("/orders", web::get().to(b)).route("/purge", web::get().to(c)))
  .service(web::resource("/res").to(c)); }
