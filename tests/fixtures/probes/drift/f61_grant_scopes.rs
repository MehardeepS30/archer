use actix_web::{web, App, HttpRequest};

// Every route passes a `DeskAuth` built with the grant it needs to `run`,
// which hands the closure the caller. The five `Grant::NotesRead` routes
// under /notes scope their query by the caller's team; `/notes/all` has the
// same grant and reads everything. `/notes/audit` has another grant, and the
// /v2 route is another API version, so neither is compared with them.
fn app() {
    App::new()
        .route("/teams/{team_id}", web::get().to(show_team))
        .route("/notes", web::get().to(list_notes))
        .route("/notes/summary", web::get().to(note_summary))
        .route("/notes/export", web::get().to(export_notes))
        .route("/notes/search", web::get().to(search_notes))
        .route("/notes/recent", web::get().to(recent_notes))
        .route("/notes/all", web::get().to(all_notes))
        .route("/notes/audit", web::get().to(audit_notes))
        .route("/v2/notes", web::get().to(list_notes_v2));
}

async fn run<F, Fut>(req: &HttpRequest, gate: &DeskAuth, inner: F) -> Reply
where
    F: Fn(AccountUser) -> Fut,
    Fut: std::future::Future<Output = Reply>,
{
    let caller = gate.admit(req).await?;
    inner(caller).await
}

async fn show_team(req: HttpRequest, pool: web::Data<Pool>) -> Reply {
    run(&req, &DeskAuth { grant: Grant::TeamsRead }, |caller: AccountUser| Team::show(&pool, caller.team)).await
}
async fn list_notes(req: HttpRequest, pool: web::Data<Pool>) -> Reply {
    run(&req, &DeskAuth { grant: Grant::NotesRead }, |caller: AccountUser| Note::list(&pool, caller.team)).await
}
async fn note_summary(req: HttpRequest, pool: web::Data<Pool>) -> Reply {
    run(&req, &DeskAuth { grant: Grant::NotesRead }, |caller: AccountUser| Note::summary(&pool, caller.team)).await
}
async fn export_notes(req: HttpRequest, pool: web::Data<Pool>) -> Reply {
    run(&req, &DeskAuth { grant: Grant::NotesRead }, |caller: AccountUser| Note::export(&pool, caller.team)).await
}
async fn search_notes(req: HttpRequest, pool: web::Data<Pool>) -> Reply {
    run(&req, &DeskAuth { grant: Grant::NotesRead }, |caller: AccountUser| Note::search(&pool, caller.team)).await
}
async fn recent_notes(req: HttpRequest, pool: web::Data<Pool>) -> Reply {
    run(&req, &DeskAuth { grant: Grant::NotesRead }, |caller: AccountUser| Note::recent(&pool, caller.team)).await
}
async fn all_notes(req: HttpRequest, pool: web::Data<Pool>) -> Reply {
    run(&req, &DeskAuth { grant: Grant::NotesRead }, |caller: AccountUser| Note::everything(&pool, caller.locale)).await
}
async fn audit_notes(req: HttpRequest, pool: web::Data<Pool>) -> Reply {
    run(&req, &DeskAuth { grant: Grant::AuditRead }, |caller: AccountUser| Note::everything(&pool, caller.locale)).await
}
async fn list_notes_v2(req: HttpRequest, pool: web::Data<Pool>) -> Reply {
    run(&req, &DeskAuth { grant: Grant::NotesRead }, |caller: AccountUser| Note::everything(&pool, caller.locale)).await
}
