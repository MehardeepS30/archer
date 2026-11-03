use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    // Different permissions per route by design: no dominant requirement.
    cfg.service(web::scope("/reports")
        .route("/sales", web::get().to(sales))
        .route("/stock", web::get().to(stock))
        .route("/staff", web::get().to(staff)));
    // Different mechanisms, same requirement: consistent.
    cfg.service(web::scope("/admin")
        .wrap(AdminGuard)
        .route("/a", web::get().to(plain))
        .route("/b", web::get().to(plain))
        .route("/c", web::get().to(extra_check)));
    cfg.service(web::scope("/staff")
        .route("/a", web::get().to(attr_admin))
        .route("/b", web::get().to(extractor_admin))
        .route("/c", web::get().to(call_admin))
        .route("/d", web::get().to(attr_viewer)));
}
async fn sales(u: User) -> Result<(), E> { check_permission(&u, "reports:sales")?; Ok(()) }
async fn stock(u: User) -> Result<(), E> { check_permission(&u, "reports:stock")?; Ok(()) }
async fn staff(u: User) -> Result<(), E> { check_permission(&u, "reports:staff")?; Ok(()) }
async fn plain() {}
async fn extra_check(u: User) { require_admin(&u); }
#[has_roles("ROLE_ADMIN")]
async fn attr_admin() {}
async fn extractor_admin(_a: RequireRole<Admin>) {}
async fn call_admin(u: User) { require_admin(&u); }
#[has_roles("VIEWER")]
async fn attr_viewer() {}
