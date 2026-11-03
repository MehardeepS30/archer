use actix_web::{dev::{Service, ServiceRequest, Transform}, web, App};

// Checks every request it wraps: the routes it wraps are authenticated.
pub struct RequireAuth;
impl<S> Transform<S, ServiceRequest> for RequireAuth {
    type Transform = RequireAuthMiddleware<S>;
}
pub struct RequireAuthMiddleware<S> { service: S }
impl<S> Service<ServiceRequest> for RequireAuthMiddleware<S> {
    fn call(&self, req: ServiceRequest) -> Self::Future {
        if session_user(&req).is_none() {
            return reject(req);
        }
        self.service.call(req)
    }
}

// Checks the caller only when the path matches: which routes it protects is
// decided at runtime.
pub struct AuthService;
impl<S> Transform<S, ServiceRequest> for AuthService {
    type Transform = AuthMiddleware<S>;
}
pub struct AuthMiddleware<S> { service: S }
impl<S> Service<ServiceRequest> for AuthMiddleware<S> {
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_string();
        if path.contains("/private") && session_user(&req).is_none() {
            return reject(req);
        }
        self.service.call(req)
    }
}

// The path test sits in a helper that takes the request.
pub struct Authentication;
impl<S> Transform<S, ServiceRequest> for Authentication {
    type Transform = AuthenticationMiddleware<S>;
}
pub struct AuthenticationMiddleware<S> { service: S }
impl<S> Service<ServiceRequest> for AuthenticationMiddleware<S> {
    fn call(&self, req: ServiceRequest) -> Self::Future {
        if should_skip_auth(&req) {
            return self.service.call(req);
        }
        verify_token(req, &self.service)
    }
}
fn should_skip_auth(req: &ServiceRequest) -> bool {
    SKIPPED.iter().any(|path| req.path() == *path)
}

// A function middleware with the same shape.
async fn auth_middleware(req: ServiceRequest, next: Next) -> Result<ServiceResponse, Error> {
    match req.path() {
        p if p.starts_with("/public") => next.call(req).await,
        _ => require_login(req, next).await,
    }
}

fn app() {
    App::new()
        .service(web::scope("/members")
            .wrap(RequireAuth)
            .route("/profile", web::get().to(profile))
            .route("/settings", web::get().to(settings))
            .route("/billing", web::get().to(billing)))
        .service(web::scope("/portal")
            .wrap(AuthService)
            .route("/private/notes", web::get().to(notes))
            .route("/private/files", web::get().to(files))
            .route("/private/drafts", web::get().to(drafts)))
        .service(web::scope("/desk")
            .wrap(Authentication)
            .route("/tickets", web::get().to(tickets)))
        .service(web::scope("/board")
            .wrap(from_fn(auth_middleware))
            .route("/posts", web::get().to(posts)))
        .service(web::scope("/inbox")
            .wrap_fn(|req, srv| {
                if req.path().ends_with("/open") { srv.call(req) } else { check_login(req, srv) }
            })
            .route("/messages", web::get().to(messages)));
}

async fn profile() {}
async fn settings() {}
async fn billing() {}
async fn notes(user: Identity) {}
async fn files(user: Identity) {}
async fn drafts() {}
async fn posts() {}
async fn tickets() {}
async fn messages() {}
