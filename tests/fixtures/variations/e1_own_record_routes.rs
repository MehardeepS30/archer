// Variation e1: routes on the caller's own record beside admin routes that
// take a record by id. The caller extractor looks in the request
// extensions first, where a pass-through middleware may have stored the
// caller, and otherwise authenticates by itself.
// Expected High/Medium findings: none.
use actix_web::{web, App, FromRequest, HttpMessage, HttpRequest, HttpResponse};
use actix_web::error::{ErrorForbidden, ErrorUnauthorized};

#[derive(Clone)]
pub struct AuthenticatedUser {
    pub user_id: u64,
    pub role: String,
}

impl AuthenticatedUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

impl FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            if let Some(user) = req.extensions().get::<AuthenticatedUser>() {
                return Ok(user.clone());
            }
            let header = match req.headers().get("authorization") {
                Some(header) => header,
                None => return Err(ErrorUnauthorized("Missing authorization header")),
            };
            match decode(header) {
                Some(user) => Ok(user),
                None => Err(ErrorUnauthorized("Invalid token")),
            }
        })
    }
}

pub struct AdminUser(pub AuthenticatedUser);

impl FromRequest for AdminUser {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {
        let authenticated = AuthenticatedUser::from_request(req, payload);
        Box::pin(async move {
            match authenticated.await {
                Ok(user) => {
                    if user.is_admin() {
                        Ok(AdminUser(user))
                    } else {
                        Err(ErrorForbidden("Admin access required"))
                    }
                }
                Err(e) => Err(e),
            }
        })
    }
}

/// Renews an expiring session when it can, and lets the request through
/// either way.
pub async fn refresh_session(
    req: actix_web::dev::ServiceRequest,
    next: actix_web::middleware::Next<impl actix_web::body::MessageBody>,
) -> Result<actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>, actix_web::Error> {
    if let Some(cookie) = req.cookie("refresh_token") {
        if let Some(user) = renew(cookie.value()) {
            req.extensions_mut().insert(user);
        }
    }
    next.call(req).await
}

pub struct Db;

#[derive(serde::Deserialize)]
pub struct Profile {
    pub name: String,
}

async fn find_me(current_user: AuthenticatedUser, db: web::Data<Db>) -> Result<HttpResponse, actix_web::Error> {
    let user = db.find_user(current_user.user_id).await?;
    Ok(HttpResponse::Ok().json(user))
}

async fn update_me(current_user: AuthenticatedUser, db: web::Data<Db>, body: web::Json<Profile>) -> Result<HttpResponse, actix_web::Error> {
    db.rename_user(current_user.user_id, &body.name).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn logout(_current_user: AuthenticatedUser, db: web::Data<Db>, req: HttpRequest) -> Result<HttpResponse, actix_web::Error> {
    db.end_session(req.cookie("refresh_token")).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn find_users(_admin: AdminUser, db: web::Data<Db>) -> Result<HttpResponse, actix_web::Error> {
    Ok(HttpResponse::Ok().json(db.all_users().await?))
}

async fn find_user(_admin: AdminUser, db: web::Data<Db>, id: web::Path<u64>) -> Result<HttpResponse, actix_web::Error> {
    Ok(HttpResponse::Ok().json(db.find_user(*id).await?))
}

async fn update_user(_admin: AdminUser, db: web::Data<Db>, id: web::Path<u64>, body: web::Json<Profile>) -> Result<HttpResponse, actix_web::Error> {
    db.rename_user(*id, &body.name).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn deactivate(_admin: AdminUser, db: web::Data<Db>, id: web::Path<u64>) -> Result<HttpResponse, actix_web::Error> {
    db.deactivate_user(*id).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn delete_user(_admin: AdminUser, db: web::Data<Db>, id: web::Path<u64>) -> Result<HttpResponse, actix_web::Error> {
    db.delete_user(*id).await?;
    Ok(HttpResponse::NoContent().finish())
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .wrap(actix_web::middleware::from_fn(refresh_session))
            .route("/auth/logout", web::post().to(logout))
            .service(
                web::scope("/users")
                    .route("/me", web::get().to(find_me))
                    .route("/me", web::patch().to(update_me))
                    .route("/{user_id}/deactivate", web::patch().to(deactivate))
                    .route("/{user_id}", web::patch().to(update_user))
                    .route("/{user_id}", web::get().to(find_user))
                    .route("/{user_id}", web::delete().to(delete_user))
                    .route("", web::get().to(find_users)),
            ),
    );
}
