use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api")
        .route("/posts/{id}", web::get().to(get_post))
        .route("/posts/{id}", web::put().to(update_post))
        .route("/posts/{id}", web::delete().to(delete_post))
        .route("/posts/{id}", web::patch().to(patch_post)));
}
async fn get_post(u: AuthenticatedUser, p: Path<i64>) -> Resp { let post = load(p); if post.owner_id != u.id { return forbidden(); } ok() }
async fn update_post(u: AuthenticatedUser) -> Resp { sqlx::query!("UPDATE posts SET body = $1 WHERE id = $2 AND owner_id = $3", b, id, u.id); ok() }
async fn delete_post(u: AuthenticatedUser) -> Resp { let mine = all_posts().into_iter().filter(|p| p.author_id == u.id); ok() }
// Filters by role, not by owner: selects records, protects nothing.
async fn patch_post(u: AuthenticatedUser) -> Resp { let admins = users().filter(|x| x.role == Role::Admin); ok() }
