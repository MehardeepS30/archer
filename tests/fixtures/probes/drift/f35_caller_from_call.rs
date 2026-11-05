use actix_web::{web, App, HttpRequest, HttpResponse};

// The caller comes from a call, not an extractor. Every /profile route
// keeps the session's account id except `set_license`, which discards the
// session and trusts the account id in the body. `delete_key` calls the
// same function with a requirement, which is a check of its own.
fn app() {
    App::new().service(
        web::scope("/profile")
            .route("", web::patch().to(update_account))
            .route("/tokens", web::post().to(create_token))
            .route("/tokens/{id}", web::delete().to(revoke_token))
            .route("/license", web::put().to(set_license))
            .route("/keys/{id}", web::delete().to(delete_key)),
    );
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

async fn update_account(req: HttpRequest, body: web::Json<Update>) -> HttpResponse {
    let account_id = match authorize_session(&req, None, None) {
        Ok(session) => session.get_id(),
        Err(err) => return err.into(),
    };
    Account::update(account_id, &body);
    HttpResponse::Ok().finish()
}

async fn create_token(req: HttpRequest) -> HttpResponse {
    let account_id = match authorize_session(&req, None, None) {
        Ok(session) => session.get_id(),
        Err(err) => return err.into(),
    };
    Token::create(account_id);
    HttpResponse::Ok().finish()
}

async fn revoke_token(req: HttpRequest, path: web::Path<u64>) -> HttpResponse {
    let session = authorize_session(&req, None, None)?;
    Token::delete(path.into_inner(), session.get_id());
    HttpResponse::Ok().finish()
}

async fn set_license(req: HttpRequest, body: web::Json<License>) -> HttpResponse {
    match authorize_session(&req, None, None) {
        Ok(_session) => {
            License::create(body.account_id, &body.key);
            HttpResponse::Ok().finish()
        }
        Err(err) => err.into(),
    }
}

async fn delete_key(req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    if let Err(err) = authorize_session(&req, Some(&path), Some(Role::Owner)) {
        return err.into();
    }
    Key::delete(&path);
    HttpResponse::Ok().finish()
}
