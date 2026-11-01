use actix_web::{web, App};
async fn a(user: User) -> Result<&'static str, E> { if user.role != Role::Admin { return Err(E); } Ok("") }
async fn b(claims: Claims2) -> Result<&'static str, E> { if !claims.is_admin { return Err(E); } Ok("") }
async fn c(user: User) -> Result<&'static str, E> { if !matches!(user.role, Role::Admin) { return Err(E); } Ok("") }
async fn d(user: User) -> Result<&'static str, E> { if !user.roles.contains(&Role::Admin) { return Err(E); } Ok("") }
async fn e() -> &'static str { "" }
fn main() {
    App::new().service(web::scope("/admin")
        .route("/a", web::get().to(a)).route("/b", web::get().to(b))
        .route("/c", web::get().to(c)).route("/d", web::get().to(d))
        .route("/e", web::get().to(e)));
}
