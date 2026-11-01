use actix_web::{web, App};
async fn x() -> &'static str { "" }
async fn y() -> &'static str { "" }
async fn z(_u: AdminUser) -> &'static str { "" }
fn main() {
    App::new().service(web::scope("/admin")
        .wrap_fn(|req, srv| { check_admin(&req)?; srv.call(req) })
        .route("/x", web::get().to(x)).route("/y", web::get().to(y)).route("/z", web::get().to(z)));
    App::new().service(web::scope("/staff").route("/x", web::get().to(x)).route("/y", web::get().to(y)).route("/z", web::get().to(z)));
}
