use actix_web::{web, App};

// Reads under /board take an optional caller and pass it to the site's
// visibility check. `get_preview` requires a caller (bound to `_`), which
// rejects anonymous callers: stricter than its peers. `get_stats` takes no
// caller at all.
fn app() {
    App::new().service(
        web::scope("/board")
            .route("/threads", web::get().to(get_threads))
            .route("/replies", web::get().to(get_replies))
            .route("/topics", web::get().to(get_topics))
            .route("/authors", web::get().to(get_authors))
            .route("/preview", web::get().to(get_preview))
            .route("/stats", web::get().to(get_stats)),
    );
}

async fn get_threads(member: Option<AccountUser>, site: web::Data<Site>) {
    ensure_visible(&member, &site)?;
}
async fn get_replies(member: Option<AccountUser>, site: web::Data<Site>) {
    ensure_visible(&member, &site)?;
}
async fn get_topics(member: Option<AccountUser>, site: web::Data<Site>) {
    ensure_visible(&member, &site)?;
}
async fn get_authors(member: Option<AccountUser>, site: web::Data<Site>) {
    ensure_visible(&member, &site)?;
}
// An account is required for this one.
async fn get_preview(_member: AccountUser, query: web::Query<PreviewQuery>) {
    fetch_preview(&query.url).await?;
}
async fn get_stats(site: web::Data<Site>) {
    Stats::read(&site)?;
}
