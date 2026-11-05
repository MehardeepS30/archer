use actix_web::{web, App, HttpRequest, HttpResponse};

// Origin writes call `authorize_session` with the origin from the path and a
// role. `rescind_invitation` passes neither: any signed-in caller may
// rescind any origin's invitation. `depart` passes no role but checks the
// caller itself. `list_events` has no origin, so the origin-scoped calls are
// not its peers. `list_members` asks for membership only: reported Low.
fn app() {
    App::new().service(
        web::scope("/origins/{origin}")
            .route("", web::put().to(update_origin))
            .route("/secrets", web::post().to(create_secret))
            .route("/secrets/{name}", web::delete().to(delete_secret))
            .route("/keys", web::post().to(create_key))
            .route("/depart", web::post().to(depart))
            .route("/invitations/{id}", web::delete().to(rescind_invitation))
            .route("/members", web::get().to(list_members))
            .route("/settings", web::get().to(read_settings))
            .route("/keys", web::get().to(list_keys))
            .route("/secrets", web::get().to(list_secrets)),
    )
    .route("/events", web::post().to(post_event));
}

pub fn authorize_session(req: &HttpRequest, origin: Option<&str>, role: Option<Role>) -> Result<Session, Error> {
    let session = match req.extensions().get::<Session>() {
        Some(session) => session.clone(),
        None => return Err(Error::Authentication),
    };
    if let Some(origin) = origin {
        check_origin_role(&session, origin, role)?;
    }
    Ok(session)
}

fn check_origin_role(session: &Session, origin: &str, role: Option<Role>) -> Result<(), Error> {
    if session.role(origin) < role.unwrap_or(Role::Member) {
        return Err(Error::Authorization);
    }
    Ok(())
}

async fn update_origin(req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    let origin = path.into_inner();
    if let Err(err) = authorize_session(&req, Some(&origin), Some(Role::Administrator)) {
        return err.into();
    }
    Origin::update(&origin);
    HttpResponse::Ok().finish()
}

async fn create_secret(req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    let origin = path.into_inner();
    if let Err(err) = authorize_session(&req, Some(&origin), Some(Role::Administrator)) {
        return err.into();
    }
    Secret::create(&origin);
    HttpResponse::Ok().finish()
}

async fn delete_secret(req: HttpRequest, path: web::Path<(String, String)>) -> HttpResponse {
    let (origin, name) = path.into_inner();
    if let Err(err) = authorize_session(&req, Some(&origin), Some(Role::Administrator)) {
        return err.into();
    }
    Secret::delete(&origin, &name);
    HttpResponse::Ok().finish()
}

async fn create_key(req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    let origin = path.into_inner();
    if let Err(err) = authorize_session(&req, Some(&origin), Some(Role::Maintainer)) {
        return err.into();
    }
    Key::create(&origin);
    HttpResponse::Ok().finish()
}

async fn depart(req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    let origin = path.into_inner();
    let session = match authorize_session(&req, None, None) {
        Ok(session) => session,
        Err(err) => return err.into(),
    };
    if Origin::owner(&origin) == session.get_id() {
        return HttpResponse::Forbidden().finish();
    }
    Origin::depart(&origin, session.get_id());
    HttpResponse::Ok().finish()
}

async fn rescind_invitation(req: HttpRequest, path: web::Path<(String, u64)>) -> HttpResponse {
    let (_origin, id) = path.into_inner();
    let _ = match authorize_session(&req, None, None) {
        Ok(session) => session.get_id(),
        Err(err) => return err.into(),
    };
    Invitation::rescind(id);
    HttpResponse::NoContent().finish()
}

async fn list_members(req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    let origin = path.into_inner();
    if let Err(err) = authorize_session(&req, Some(&origin), None) {
        return err.into();
    }
    HttpResponse::Ok().json(Origin::members(&origin))
}

async fn read_settings(req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    let origin = path.into_inner();
    if let Err(err) = authorize_session(&req, Some(&origin), Some(Role::Member)) {
        return err.into();
    }
    HttpResponse::Ok().json(Origin::settings(&origin))
}

async fn list_keys(req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    let origin = path.into_inner();
    if let Err(err) = authorize_session(&req, Some(&origin), Some(Role::Member)) {
        return err.into();
    }
    HttpResponse::Ok().json(Key::list(&origin))
}

async fn list_secrets(req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    let origin = path.into_inner();
    if let Err(err) = authorize_session(&req, Some(&origin), Some(Role::Administrator)) {
        return err.into();
    }
    HttpResponse::Ok().json(Secret::list(&origin))
}

async fn post_event(req: HttpRequest, body: web::Json<Event>) -> HttpResponse {
    let _ = match authorize_session(&req, None, None) {
        Ok(session) => session.get_id(),
        Err(err) => return err.into(),
    };
    Event::record(&body);
    HttpResponse::Ok().finish()
}
