use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/admin")
        .route("/try", web::get().to(with_try))
        .route("/let-else", web::get().to(with_let_else))
        .route("/match", web::get().to(with_match))
        .route("/ensure", web::get().to(with_ensure))
        .route("/bound", web::get().to(with_bound))
        .route("/helper", web::get().to(with_helper))
        .route("/tail", web::get().to(with_tail))
        .route("/else-branch", web::get().to(with_else_branch)));
}
async fn with_try(u: User) -> Result<(), E> { u.has_role("admin")?; Ok(()) }
async fn with_let_else(req: Req) -> Resp { let Some(_a) = admin_from(&req).filter(|u| is_admin(u)) else { return forbidden(); }; ok() }
async fn with_match(u: User) -> Result<(), E> { match u.role { Role::Admin => Ok(()), _ => Err(E::Forbidden) } }
async fn with_ensure(u: User) -> anyhow::Result<()> { anyhow::ensure!(u.role == Role::Admin, "forbidden"); Ok(()) }
async fn with_bound(u: User) -> Resp { let allowed = is_admin(&u); if !allowed { return HttpResponse::Forbidden().finish(); } ok() }
async fn with_helper(u: User) -> Resp { if !can_manage(&u) { return HttpResponse::Forbidden().finish(); } ok() }
async fn with_tail(u: User) -> Result<(), E> { u.has_role("admin") }
async fn with_else_branch(u: User) -> Resp { if is_admin(&u) { ok() } else { HttpResponse::Forbidden().finish() } }
fn can_manage(u: &User) -> bool { u.role == Role::Admin }
