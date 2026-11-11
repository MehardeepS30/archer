use actix_web::{get, post, web, App, HttpResponse, HttpServer};

// Three `App`s register routes, and only two are served:
// - the API server: `routes` under a `/api` scope;
// - a probe server on its own port: `/`, `/live` and `/ready`, public by
//   design. They are another application, never peers of the API's routes;
// - `openapi()` builds the API again only to get its OpenAPI document and
//   drops the `App`, and `smoke()` builds it for `test::init_service`. Those
//   registrations repeat served routes and are not counted.
// Drift: `export_notes` takes no `Member`.
pub struct Member;

impl actix_web::FromRequest for Member {
    type Error = actix_web::Error;
    type Future = std::future::Ready<Result<Self, Self::Error>>;
    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        std::future::ready(match req.cookie("sid") {
            Some(_) => Ok(Member),
            None => Err(actix_web::error::ErrorUnauthorized("log in")),
        })
    }
}

#[get("/notes")]
async fn list_notes(_member: Member) -> HttpResponse {
    HttpResponse::Ok().finish()
}
#[get("/notes/{id}")]
async fn get_note(_member: Member) -> HttpResponse {
    HttpResponse::Ok().finish()
}
#[get("/notes/{id}/export")]
async fn export_notes() -> HttpResponse {
    HttpResponse::Ok().finish()
}
#[post("/notes")]
async fn add_note(_member: Member) -> HttpResponse {
    HttpResponse::Ok().finish()
}

fn routes(cfg: &mut utoipa_actix_web::service_config::ServiceConfig) {
    cfg.service(
        utoipa_actix_web::scope("/api")
            .service(list_notes)
            .service(get_note)
            .service(export_notes)
            .service(add_note),
    );
}

async fn index() -> HttpResponse {
    HttpResponse::Ok().finish()
}
async fn live() -> HttpResponse {
    HttpResponse::Ok().finish()
}
async fn ready() -> HttpResponse {
    HttpResponse::Ok().finish()
}

pub fn openapi() -> utoipa::openapi::OpenApi {
    use utoipa_actix_web::AppExt;
    let (_, api) = App::new().into_utoipa_app().configure(routes).split_for_parts();
    api
}

pub async fn smoke() {
    use utoipa_actix_web::AppExt;
    let _app = actix_web::test::init_service(App::new().into_utoipa_app().configure(routes).into_app()).await;
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use utoipa_actix_web::AppExt;
    let api = HttpServer::new(|| App::new().into_utoipa_app().configure(routes).into_app())
        .bind(("0.0.0.0", 8080))?
        .run();
    let probes = HttpServer::new(|| {
        App::new()
            .route("/", web::post().to(index))
            .route("/live", web::get().to(live))
            .route("/ready", web::get().to(ready))
    })
    .bind(("0.0.0.0", 9010))?
    .run();
    let _ = futures::join!(api, probes);
    Ok(())
}
