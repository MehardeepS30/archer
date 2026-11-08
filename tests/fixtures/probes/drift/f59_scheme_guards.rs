use actix_web::{web, App, HttpRequest};

// Links, tickets, passes and coupons are opened with `LinkAuth`, which
// admits a request that presents a code. The first three load their record
// by the path's code and compare a secret from the body with the stored
// one; `coupons/apply` loads a coupon and compares nothing. Notes use
// `SessionAuth`, and none of them compares a secret.
fn app() {
    App::new()
        .route("/links/{code}/open", web::post().to(open_link))
        .route("/tickets/{code}/redeem", web::post().to(redeem_ticket))
        .route("/passes/{code}/enter", web::post().to(enter_pass))
        .route("/coupons/{code}/apply", web::post().to(apply_coupon))
        .route("/notes/{id}", web::get().to(show_note))
        .route("/notes/{id}/copy", web::post().to(copy_note))
        .route("/notes/{id}/print", web::post().to(print_note));
}

async fn open_link(req: HttpRequest, path: web::Path<String>, body: web::Json<Given>, pool: web::Data<Pool>) -> Reply {
    authenticate(&req, &LinkAuth)?;
    let link = Link::fetch(&pool, path.into_inner()).await?;
    if !constant_time_eq(link.stored.as_bytes(), body.given.as_bytes()) {
        return Err(Error::BadCode);
    }
    Link::open(&pool, link.key).await
}
async fn redeem_ticket(req: HttpRequest, path: web::Path<String>, body: web::Json<Given>, pool: web::Data<Pool>) -> Reply {
    authenticate(&req, &LinkAuth)?;
    let ticket = Ticket::fetch(&pool, path.into_inner()).await?;
    if !constant_time_eq(ticket.stored.as_bytes(), body.given.as_bytes()) {
        return Err(Error::BadCode);
    }
    Ticket::redeem(&pool, ticket.key).await
}
async fn enter_pass(req: HttpRequest, path: web::Path<String>, body: web::Json<Given>, pool: web::Data<Pool>) -> Reply {
    authenticate(&req, &LinkAuth)?;
    let pass = Pass::fetch(&pool, path.into_inner()).await?;
    if !constant_time_eq(pass.stored.as_bytes(), body.given.as_bytes()) {
        return Err(Error::BadCode);
    }
    Pass::enter(&pool, pass.key).await
}
async fn apply_coupon(req: HttpRequest, path: web::Path<String>, body: web::Json<Given>, pool: web::Data<Pool>) -> Reply {
    authenticate(&req, &LinkAuth)?;
    let coupon = Coupon::fetch(&pool, path.into_inner()).await?;
    Coupon::apply(&pool, coupon.key, body.given.clone()).await
}

async fn show_note(req: HttpRequest, path: web::Path<u64>, pool: web::Data<Pool>) -> Reply {
    authenticate(&req, &SessionAuth)?;
    let note = Note::fetch(&pool, path.into_inner()).await?;
    Ok(note.text)
}
async fn copy_note(req: HttpRequest, path: web::Path<u64>, pool: web::Data<Pool>) -> Reply {
    authenticate(&req, &SessionAuth)?;
    let note = Note::fetch(&pool, path.into_inner()).await?;
    Note::copy(&pool, note.key).await
}
async fn print_note(req: HttpRequest, path: web::Path<u64>, pool: web::Data<Pool>) -> Reply {
    authenticate(&req, &SessionAuth)?;
    let note = Note::fetch(&pool, path.into_inner()).await?;
    Printer::print(&pool, note.text).await
}
