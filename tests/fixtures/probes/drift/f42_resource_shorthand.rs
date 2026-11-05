use actix_web::{HttpServer, App, web};

mod auth {
    use super::*;
    pub fn configure(cfg: &mut web::ServiceConfig) {
        cfg.route("/login", web::post().to(login));
    }
    async fn login() {}
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            // A closure that only forwards to `auth::configure`: one route,
            // not one per way of reaching it.
            .service(web::scope("/auth").configure(|c| auth::configure(c)))
            .service(
                web::scope("/users")
                    // Resource's per-method shorthand for `.route(web::get().to(..))`.
                    .service(web::resource("").get(list_users).post(create_user))
                    .service(
                        web::resource("/{id}")
                            .get(get_user)
                            .put(update_user)
                            .delete(delete_user),
                    )
                    // Any logged-in user may restore an account: the drift.
                    .service(web::resource("/{id}/restore").patch(restore_user)),
            )
            // One resource answering two paths.
            .service(web::resource(["/status", "/ping"]).get(status)),
    );
}

#[actix_web::main]
async fn main() {
    HttpServer::new(|| App::new().configure(|c| routes(c)))
        .bind("0.0.0.0:8080")
        .unwrap()
        .run()
        .await
        .unwrap();
}

async fn list_users(_admin: AdminUser) {}
async fn create_user(_admin: AdminUser) {}
async fn get_user(_admin: AdminUser) {}
async fn update_user(_admin: AdminUser) {}
async fn delete_user(_admin: AdminUser) {}
async fn restore_user(_user: AuthenticatedUser) {}
async fn status() {}

fn not_a_route(map: std::collections::HashMap<&str, u32>) -> Option<u32> {
    map.get("key").copied()
}
