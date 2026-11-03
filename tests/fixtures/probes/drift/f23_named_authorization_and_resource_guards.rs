use actix_web::{guard, http::Method, web};
pub fn register(config: &mut web::ServiceConfig) {
    // An authorization layer held in a variable and named for what it does.
    let coordinator_authorization_middleware = Authorization::new(check);
    config.service(web::scope("/coordinate")
        .wrap(coordinator_authorization_middleware)
        .route("/a", web::get().to(a))
        .route("/b", web::post().to(b)));
    // A resource's method guard decides the method its handler answers.
    config.service(web::resource("/form/{id}")
        .guard(guard::Method(Method::GET))
        .to(form_page));
}
async fn a(identity: Identity) {}
async fn b() {}
async fn form_page() {}
