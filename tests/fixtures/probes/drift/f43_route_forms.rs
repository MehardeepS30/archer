// Route registration forms beyond plain `.route(..)` chains. Every route
// here should be read, each exactly once.
use actix_web::{guard, web, App, Resource};
use actix_web::web::{get as get_route};

async fn h() {}
async fn h2() {}

// A route helper macro, with a repetition.
macro_rules! get_routes {
    ($cfg:ident; $($path:literal => $handler:path),* $(,)?) => {
        $( $cfg.route($path, web::get().to($handler)); )*
    };
}

// Paths in a const route table, as codegen forks read them.
pub struct Routes {
    pub auth: Auth,
}
pub struct Auth {
    pub login: &'static str,
}
impl Routes {
    pub const fn new() -> Self {
        Self { auth: Auth::new() }
    }
}
impl Auth {
    pub const fn new() -> Auth {
        let login = "/signin";
        Auth { login }
    }
}
pub const ROUTES: Routes = Routes::new();

#[my_codegen::post(path = "crate::ROUTES.auth.login")]
async fn signin() {}

#[actix_web::scope("/admin")]
mod admin {
    #[actix_web::get("/stats")]
    pub async fn stats() {}
}

fn table(cfg: &mut web::ServiceConfig) {
    get_routes!(cfg; "/m/a" => h, "/m/b" => h2);
    for path in ["/loop/a", "/loop/b"] {
        cfg.service(web::resource(path).get(h));
    }
}

fn main() {
    let mut app = App::new();
    for path in &["/var/a", "/var/b"] {
        app = app.route(path, web::get().to(h));
    }
    app.configure(table)
        .service(web::service("/svc").finish(h))
        .service(Resource::new("/typed").post(h2))
        .service(actix_web::Scope::new("/scoped").route("/x", web::delete().to(h)))
        .service(web::resource("/alias").route(get_route().to(h)))
        .service(paperclip::actix::web::resource("/foreign").route(paperclip::actix::web::put().to(h)))
        .service(web::resource("/any").route(
            web::route().guard(guard::Any(guard::Get()).or(guard::Post())).to(h2),
        ))
        .service(signin)
        .service(admin::stats)
        .default_service(web::route().to(h));
}
