// P1 fixture: checks made inside methods of the caller type, in an
// associated function of another module, and behind a recursive helper.
// `create_d` and `purge` are the routes that skip them.
mod store;

use actix_web::{web, App, HttpResponse};

pub struct Fault;

/// The caller, extracted from the request; it can be anonymous.
pub struct AuthenticatedUser {
    pub account: Option<u64>,
    pub suspended: bool,
}

impl AuthenticatedUser {
    /// Two levels: a method that calls another method on `self`.
    pub fn require_account(&self) -> Result<u64, Fault> {
        self.require_active()?;
        match self.account {
            Some(account) => Ok(account),
            None => Err(Fault),
        }
    }

    fn require_active(&self) -> Result<(), Fault> {
        if self.suspended {
            return Err(Fault);
        }
        Ok(())
    }
}

fn app() {
    App::new()
        .service(
            web::scope("/notes")
                .route("/a", web::post().to(create_a))
                .route("/b", web::post().to(create_b))
                .route("/c", web::post().to(create_c))
                .route("/d", web::post().to(create_d)),
        )
        .service(
            web::scope("/boards")
                .route("/{id}", web::patch().to(rename))
                .route("/{id}", web::post().to(archive))
                .route("/{id}", web::put().to(restore))
                .route("/{id}", web::delete().to(purge)),
        );
}

async fn create_a(caller: AuthenticatedUser) -> Result<HttpResponse, Fault> {
    caller.require_account()?;
    Ok(HttpResponse::Ok().finish())
}

async fn create_b(caller: AuthenticatedUser) -> Result<HttpResponse, Fault> {
    let _account = caller.require_account()?;
    Ok(HttpResponse::Ok().finish())
}

async fn create_c(caller: AuthenticatedUser) -> Result<HttpResponse, Fault> {
    caller.require_account()?;
    Ok(HttpResponse::Created().finish())
}

/// Takes the caller and never checks it.
async fn create_d(caller: AuthenticatedUser) -> Result<HttpResponse, Fault> {
    let _ = caller.suspended;
    Ok(HttpResponse::Created().finish())
}

async fn rename(caller: AuthenticatedUser, id: web::Path<u64>) -> Result<HttpResponse, Fault> {
    store::Boards::rename(&caller, id.into_inner())?;
    Ok(HttpResponse::Ok().finish())
}

async fn archive(caller: AuthenticatedUser, id: web::Path<u64>) -> Result<HttpResponse, Fault> {
    store::archive(&caller, id.into_inner())?;
    Ok(HttpResponse::Ok().finish())
}

async fn restore(caller: AuthenticatedUser, id: web::Path<u64>) -> Result<HttpResponse, Fault> {
    store::restore(&caller, id.into_inner())?;
    Ok(HttpResponse::Ok().finish())
}

/// Calls the service layer, which skips the owner comparison.
async fn purge(caller: AuthenticatedUser, id: web::Path<u64>) -> Result<HttpResponse, Fault> {
    store::purge(&caller, id.into_inner())?;
    Ok(HttpResponse::Ok().finish())
}
