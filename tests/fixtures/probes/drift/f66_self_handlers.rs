use actix_web::{web, HttpResponse};

// Handlers are associated functions registered from inside their own `impl`
// block as `Self::name`. Each protected one checks the caller with
// `require_admin`; `wipe` skips it. `Ghost::list` names a type that has no
// `impl` among the scanned files, so that route cannot be resolved.
pub struct Shelf;

#[derive(Clone)]
pub struct Member {
    is_admin: bool,
}

fn require_admin(member: &Member) -> Result<(), actix_web::Error> {
    if !member.is_admin {
        return Err(actix_web::error::ErrorForbidden("admin only"));
    }
    Ok(())
}

impl Shelf {
    pub fn routes(cfg: &mut web::ServiceConfig) {
        cfg.service(
            web::scope("/shelf")
                .route("/books", web::get().to(Self::books))
                .route("/books/{id}", web::get().to(Self::book))
                .route("/books/{id}", web::put().to(Self::edit))
                .route("/books/{id}", web::delete().to(Self::wipe)),
        );
    }

    pub async fn books(member: web::ReqData<Member>) -> Result<HttpResponse, actix_web::Error> {
        require_admin(&member)?;
        Ok(HttpResponse::Ok().finish())
    }
    pub async fn book(member: web::ReqData<Member>) -> Result<HttpResponse, actix_web::Error> {
        require_admin(&member)?;
        Ok(HttpResponse::Ok().finish())
    }
    pub async fn edit(member: web::ReqData<Member>) -> Result<HttpResponse, actix_web::Error> {
        require_admin(&member)?;
        Ok(HttpResponse::Ok().finish())
    }
    // Drift: no `require_admin`.
    pub async fn wipe(_member: web::ReqData<Member>) -> Result<HttpResponse, actix_web::Error> {
        Ok(HttpResponse::Ok().finish())
    }
    // Never routed.
    pub async fn spare(_member: web::ReqData<Member>) -> HttpResponse {
        HttpResponse::Ok().finish()
    }
}

fn main() {
    actix_web::App::new()
        .configure(Shelf::routes)
        .route("/ghost", web::get().to(Ghost::list));
}
