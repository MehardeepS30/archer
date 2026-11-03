use actix_web::{get, web, HttpResponse};
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("").service(index));
}
#[get("/")]
async fn index() -> HttpResponse { HttpResponse::Ok().finish() }
// Never routed: counted as a likely handler that no route reaches.
async fn orphaned(body: web::Json<String>) -> HttpResponse { HttpResponse::Ok().finish() }
#[cfg(test)]
mod tests {
    use super::*;
    #[actix_web::test]
    async fn serves() {
        let app = actix_web::App::new().configure(configure).route("/test-only", web::get().to(index));
    }
}
