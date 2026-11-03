use actix_web::{web, App};

// The whole app is mounted under a prefix read from configuration. Every
// route carries it alike, so routes under it are still compared.
fn app(cfg: &Config) {
    App::new().service(web::scope(&cfg.base_uri).configure(api_routes));
}

fn api_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api")
        .route("/projects", web::post().to(create_project))
        .route("/projects/{id}", web::put().to(update_project))
        .route("/projects/{id}", web::delete().to(delete_project))
        .route("/healthz", web::get().to(healthz))
        // An unresolved segment inside the path is still left out.
        .route(&format!("/{}/export", EXPORT), web::post().to(export_project)));
}

async fn create_project(user: Identity) {}
async fn update_project(user: Identity) {}
async fn delete_project() {}
async fn healthz() {}
async fn export_project() {}
