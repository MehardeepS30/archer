use actix_web::{
    body::MessageBody,
    dev::{Payload, ServiceRequest, ServiceResponse},
    http::{header, StatusCode},
    middleware::{from_fn, Next},
    web, App, Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, ResponseError,
};
use std::future::{ready, Ready};

// No identifier here names a caller, a login or a role. What the code does
// says it all: `gatekeeper` reads the `sid` cookie, rejects without it and
// stores a `Badge`; `Pass` reads the Authorization header and fails with
// `Fault::Nope`, which `ResponseError` maps to 401.
fn app() {
    App::new()
        .service(
            web::scope("/desk")
                .wrap(from_fn(gatekeeper))
                .route("/notes", web::get().to(list_notes))
                .route("/notes/{id}", web::get().to(read_note))
                .route("/notes/{id}", web::put().to(edit_note)),
        )
        .service(
            web::scope("/ledger")
                .route("/rows", web::get().to(list_rows))
                .route("/rows/{id}", web::get().to(read_row))
                .route("/rows/{id}", web::delete().to(drop_row))
                .route("/rows/{id}", web::put().to(edit_row))
                .route("/rows/{id}/close", web::post().to(close_row)),
        );
}

#[derive(Clone)]
pub struct Badge(u64);

pub enum Fault {
    Nope,
    Broken,
}

impl ResponseError for Fault {
    fn status_code(&self) -> StatusCode {
        match self {
            Fault::Nope => StatusCode::UNAUTHORIZED,
            Fault::Broken => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

async fn gatekeeper(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let Some(sid) = req.cookie("sid") else {
        return Err(actix_web::error::ErrorUnauthorized("no sid"));
    };
    let badge = Badge(lookup(sid.value()));
    req.extensions_mut().insert(badge);
    next.call(req).await
}

fn lookup(value: &str) -> u64 {
    value.len() as u64
}

pub struct Pass(u64);

impl FromRequest for Pass {
    type Error = Fault;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ready(match req.headers().get(header::AUTHORIZATION) {
            Some(value) => Ok(Pass(value.len() as u64)),
            None => Err(Fault::Nope),
        })
    }
}

async fn list_notes(badge: web::ReqData<Badge>) -> HttpResponse {
    HttpResponse::Ok().body(badge.0.to_string())
}
async fn read_note(badge: web::ReqData<Badge>, id: web::Path<u64>) -> HttpResponse {
    HttpResponse::Ok().body(format!("{} {}", badge.0, id))
}
async fn edit_note(badge: web::ReqData<Badge>, id: web::Path<u64>) -> HttpResponse {
    HttpResponse::Ok().body(format!("{} {}", badge.0, id))
}

async fn list_rows(pass: Pass) -> HttpResponse {
    HttpResponse::Ok().body(pass.0.to_string())
}
async fn read_row(pass: Pass, id: web::Path<u64>) -> HttpResponse {
    HttpResponse::Ok().body(format!("{} {}", pass.0, id))
}
async fn drop_row(pass: Pass, id: web::Path<u64>) -> HttpResponse {
    HttpResponse::Ok().body(format!("{} {}", pass.0, id))
}
async fn edit_row(pass: Pass, id: web::Path<u64>) -> HttpResponse {
    HttpResponse::Ok().body(format!("{} {}", pass.0, id))
}
// Drift: no `Pass`.
async fn close_row(id: web::Path<u64>) -> HttpResponse {
    HttpResponse::Ok().body(id.to_string())
}
