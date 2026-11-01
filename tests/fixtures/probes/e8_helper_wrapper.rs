use actix_web::{web, App};
fn ensure_can_manage(user: &User) -> Result<(), E> { require_admin(user) }
async fn a(user: User) -> &'static str { ensure_can_manage(&user).unwrap(); "" }
async fn b(user: User) -> &'static str { require_admin(&user); "" }
async fn c(user: User) -> &'static str { require_admin(&user); "" }
fn main() {
    App::new().service(web::scope("/admin")
        .route("/a", web::get().to(a)).route("/b", web::get().to(b)).route("/c", web::get().to(c)));
}
