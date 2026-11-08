use actix_web::{web, App, HttpRequest};

// Boxes belong to their keeper. Every route hands its body to `run_flow`,
// which identifies the caller and calls the closure with the caller and
// the body. `rename`, `paint` and `seal` reach a service that loads the box
// by the body's id and compares its keeper with the caller; `stamp` loads
// it the same way and compares nothing. `peek` loads the box together with
// the caller, which scopes the query; `tally` only converts the id.
fn app() {
    App::new().service(
        web::scope("/boxes")
            .route("/rename", web::post().to(rename_box))
            .route("/paint", web::post().to(paint_box))
            .route("/seal", web::post().to(seal_box))
            .route("/stamp", web::post().to(stamp_box))
            .route("/peek", web::post().to(peek_box))
            .route("/tally", web::post().to(tally_box)),
    );
}

async fn run_flow<F, Fut, T>(state: web::Data<Pool>, req: HttpRequest, payload: T, inner: F) -> Reply
where
    F: Fn(web::Data<Pool>, AccountUser, T) -> Fut,
    Fut: std::future::Future<Output = Reply>,
{
    let member = AccountUser::from_request(&req).await?;
    inner(state, member, payload).await
}

async fn rename_box(state: web::Data<Pool>, req: HttpRequest, body: web::Json<BoxBody>) -> Reply {
    run_flow(state, req, body.into_inner(), |state, member: AccountUser, given| rename_service(state, member, given)).await
}
async fn paint_box(state: web::Data<Pool>, req: HttpRequest, body: web::Json<BoxBody>) -> Reply {
    run_flow(state, req, body.into_inner(), |state, member: AccountUser, given| paint_service(state, member, given)).await
}
async fn seal_box(state: web::Data<Pool>, req: HttpRequest, body: web::Json<BoxBody>) -> Reply {
    run_flow(state, req, body.into_inner(), |state, member: AccountUser, given| seal_service(state, member, given)).await
}
async fn stamp_box(state: web::Data<Pool>, req: HttpRequest, body: web::Json<BoxBody>) -> Reply {
    run_flow(state, req, body.into_inner(), |state, member: AccountUser, given| stamp_service(state, member, given)).await
}
async fn peek_box(state: web::Data<Pool>, req: HttpRequest, body: web::Json<BoxBody>) -> Reply {
    run_flow(state, req, body.into_inner(), |state, member: AccountUser, given| peek_service(state, member, given)).await
}
async fn tally_box(state: web::Data<Pool>, req: HttpRequest, body: web::Json<BoxBody>) -> Reply {
    run_flow(state, req, body.into_inner(), |state, member: AccountUser, given| tally_service(state, member, given)).await
}

async fn rename_service(state: web::Data<Pool>, member: AccountUser, given: BoxBody) -> Reply {
    let found = Crate::fetch(&state, given.box_id).await?;
    if found.keeper != member.uid {
        return Err(Error::NotYours);
    }
    Crate::rename(&state, found.key, given.label).await
}
async fn paint_service(state: web::Data<Pool>, member: AccountUser, given: BoxBody) -> Reply {
    let found = Crate::fetch(&state, given.box_id).await?;
    if member.uid != found.keeper {
        return Err(Error::NotYours);
    }
    Crate::paint(&state, found.key, given.label).await
}
async fn seal_service(state: web::Data<Pool>, member: AccountUser, given: BoxBody) -> Reply {
    let found = Crate::fetch(&state, given.box_id).await?;
    if found.keeper != member.uid {
        return Err(Error::NotYours);
    }
    Crate::seal(&state, found.key).await
}
async fn stamp_service(state: web::Data<Pool>, member: AccountUser, given: BoxBody) -> Reply {
    let found = Crate::fetch(&state, given.box_id).await?;
    Crate::stamp(&state, found.key, member.uid).await
}
async fn peek_service(state: web::Data<Pool>, member: AccountUser, given: BoxBody) -> Reply {
    let found = Crate::fetch_for(&state, given.box_id, member.uid).await?;
    Ok(found.label)
}
async fn tally_service(state: web::Data<Pool>, member: AccountUser, given: BoxBody) -> Reply {
    let number = BoxNumber::from(given.box_id);
    Tally::count(&state, member.uid, number).await
}
