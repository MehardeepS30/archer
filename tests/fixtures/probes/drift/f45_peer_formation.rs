use actix_web::{web, App};

fn app() {
    App::new()
        // Each scope under /api/v1 has a single read, so no scope can say
        // what it expects; their API version root can.
        .service(
            web::scope("/api/v1")
                .service(web::scope("/projects").route("/all", web::get().to(list_projects)))
                .service(web::scope("/teams").route("/all", web::get().to(list_teams)))
                .service(web::scope("/billing").route("/all", web::get().to(list_invoices)))
                .service(web::scope("/notes").route("/all", web::get().to(list_notes))),
        )
        // No route here carries protection: a group with tier None is
        // formed, and its routes are compared, not dropped.
        .service(
            web::scope("/pages")
                .route("/about", web::get().to(about))
                .route("/terms", web::get().to(terms)),
        )
        // A GET that empties the cart writes, so it is held to the writes.
        .service(
            web::scope("/shop")
                .route("/cart/add", web::post().to(add_item))
                .route("/cart/remove", web::post().to(remove_item))
                .route("/cart/{cart}/empty", web::get().to(empty_cart)),
        )
        // `verify` names an authentication endpoint, but the handler only
        // loads a status: it is compared with its account peers. The
        // login issues a session and stays out of the comparison.
        .service(
            web::scope("/account")
                .route("/profile", web::get().to(profile))
                .route("/settings", web::get().to(settings))
                .route("/verify", web::get().to(account_status))
                .route("/login", web::post().to(login)),
        );
}

async fn list_projects(user: Identity) {}
async fn list_teams(user: Identity) {}
async fn list_invoices(user: Identity) {}
async fn list_notes() {}
async fn about() {}
async fn terms() {}
async fn add_item(user: Identity) {}
async fn remove_item(user: Identity) {}
async fn empty_cart(cart: web::Path<u32>) {
    delete_cart_items(cart.into_inner());
}
fn delete_cart_items(cart: u32) {}
async fn profile(user: Identity) {}
async fn settings(user: Identity) {}
async fn account_status() {
    load_status();
}
fn load_status() {}
async fn login() {
    issue_session();
}
fn issue_session() {}
