use actix_web::{web, App};

// The shape of a common JWT template: the exempt list is a constant in
// another module, walked with a `for` loop that sets a flag, and a later
// `if !passed` rejects. `/api/notes/export` is exempted by mistake.
mod constants {
    pub const IGNORE_ROUTES: [&str; 4] = ["/api/ping", "/api/auth/signup", "/api/auth/login", "/api/notes/export"];
    pub const MESSAGE_LOGIN_SUCCESS: &str = "Login successfully";
}

pub struct Authentication;

impl<S, B> Transform<S, ServiceRequest> for Authentication {
    type Transform = AuthenticationMiddleware<S>;
}

pub struct AuthenticationMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthenticationMiddleware<S> {
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let mut authenticate_pass: bool = false;
        if Method::OPTIONS == *req.method() {
            authenticate_pass = true;
        } else {
            for ignore_route in constants::IGNORE_ROUTES.iter() {
                if req.path().starts_with(ignore_route) {
                    authenticate_pass = true;
                    break;
                }
            }
        }
        if !authenticate_pass {
            if let Some(header) = req.headers().get("Authorization") {
                if verify_token(header).is_ok() {
                    authenticate_pass = true;
                }
            }
        }
        if !authenticate_pass {
            let (request, _pl) = req.into_parts();
            let response = HttpResponse::Unauthorized().finish();
            return Box::pin(async { Ok(ServiceResponse::new(request, response)) });
        }
        let res = self.service.call(req);
        Box::pin(async move { res.await })
    }
}

fn app() {
    App::new()
        .wrap(Authentication)
        // Hands every request on: not protection.
        .wrap_fn(|req, srv| srv.call(req).map(|res| res))
        .service(
            web::scope("/api")
                .route("/ping", web::get().to(ping))
                .service(
                    web::scope("/auth")
                        .route("/signup", web::post().to(signup))
                        .route("/login", web::post().to(login))
                        .route("/logout", web::post().to(logout)),
                )
                .service(
                    web::scope("/notes")
                        .route("", web::get().to(list_notes))
                        .route("/{id}", web::get().to(get_note))
                        .route("/export", web::get().to(export_notes)),
                ),
        );
}

async fn ping() {}
async fn signup() {}
async fn login() {
    ResponseBody::new(constants::MESSAGE_LOGIN_SUCCESS, issue_token());
}
async fn logout(req: HttpRequest) {
    clear_token(req);
}
async fn list_notes() {}
async fn get_note() {}
async fn export_notes() {}
