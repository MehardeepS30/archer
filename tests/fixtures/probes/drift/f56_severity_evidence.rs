use actix_web::{web, App, HttpResponse};

// Six one-route scopes whose writes and reads take `Staff`, an extractor
// that checks a role. `/flush` and `/peek` stand alone at the root, so they
// are compared with the whole application only. Nearly all of its writes
// make the check, so the unprotected write is Medium; reads are often
// public by design, so the unprotected read stays Low.
fn app() {
    App::new()
        .service(web::scope("/ledgers").route("", web::post().to(write_a)).route("", web::get().to(read_a)))
        .service(web::scope("/tickets").route("", web::post().to(write_b)).route("", web::get().to(read_b)))
        .service(web::scope("/folders").route("", web::post().to(write_c)).route("", web::get().to(read_c)))
        .service(web::scope("/badges").route("", web::post().to(write_d)).route("", web::get().to(read_d)))
        .service(web::scope("/rooms").route("", web::post().to(write_e)).route("", web::get().to(read_e)))
        .service(web::scope("/queues").route("", web::post().to(write_f)).route("", web::get().to(read_f)))
        .route("/flush", web::post().to(flush))
        .route("/peek", web::get().to(peek));
}

pub struct Denied;
pub struct Staff {
    pub id: u64,
}

impl actix_web::FromRequest for Staff {
    type Error = Denied;
    type Future = std::future::Ready<Result<Self, Denied>>;
    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let account = req.headers().get("x-session").and_then(|token| decode_account(token));
        match account {
            Some(account) if account.role == Role::Staff => std::future::ready(Ok(Staff { id: account.id })),
            _ => std::future::ready(Err(Denied)),
        }
    }
}

async fn write_a(_staff: Staff) -> HttpResponse { HttpResponse::Ok().finish() }
async fn write_b(_staff: Staff) -> HttpResponse { HttpResponse::Ok().finish() }
async fn write_c(_staff: Staff) -> HttpResponse { HttpResponse::Ok().finish() }
async fn write_d(_staff: Staff) -> HttpResponse { HttpResponse::Ok().finish() }
async fn write_e(_staff: Staff) -> HttpResponse { HttpResponse::Ok().finish() }
async fn write_f(_staff: Staff) -> HttpResponse { HttpResponse::Ok().finish() }
async fn read_a(_staff: Staff) -> HttpResponse { HttpResponse::Ok().finish() }
async fn read_b(_staff: Staff) -> HttpResponse { HttpResponse::Ok().finish() }
async fn read_c(_staff: Staff) -> HttpResponse { HttpResponse::Ok().finish() }
async fn read_d(_staff: Staff) -> HttpResponse { HttpResponse::Ok().finish() }
async fn read_e(_staff: Staff) -> HttpResponse { HttpResponse::Ok().finish() }
async fn read_f(_staff: Staff) -> HttpResponse { HttpResponse::Ok().finish() }
async fn flush() -> HttpResponse { HttpResponse::Ok().finish() }
async fn peek() -> HttpResponse { HttpResponse::Ok().finish() }
