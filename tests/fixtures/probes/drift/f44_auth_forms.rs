// Authentication written as a helper that returns middleware, a closure
// middleware, an attribute option, a request extension, and a builder
// method named as a check.
use actix_web::{dev::ServiceRequest, get, web, App, HttpMessage};
use actix_auth_middleware::Authentication;

pub struct Claims;

pub fn get_middleware() -> Authentication<Routes> {
    Authentication::with_identity(ROUTES)
}

async fn h() {}
async fn me(_claims: web::ReqData<Claims>) {}

#[get("/attr", wrap = "crate::get_middleware()")]
async fn attr() {}

fn main() {
    App::new()
        .service(web::resource("/helper").wrap(get_middleware()).route(web::get().to(h)))
        .service(
            web::resource("/closure")
                .wrap_fn(|req: ServiceRequest, srv| {
                    if req.headers().get("Authorization").is_none() {
                        return Err(unauthorized());
                    }
                    srv.call(req)
                })
                .route(web::get().to(h)),
        )
        .service(web::resource("/me").route(web::get().to(me)))
        .service(web::resource("/alerts").route(web::put().to(h).authorize(Action::PutAlert)))
        .service(attr);
}
