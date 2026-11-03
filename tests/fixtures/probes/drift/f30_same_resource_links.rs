use actix_web::{web, App, HttpResponse};

fn app() {
    App::new()
        .service(web::scope("/catalog")
            // Serves any revision, drafts included, to anyone.
            .route("/item/{id}/{rev}", web::get().to(show_revision))
            // Shares only an error constructor with the studio route.
            .route("/item/{id}", web::get().to(show_item)))
        .service(web::scope("/studio")
            .route("/item/{id}", web::get().to(edit_item)));
}

mod store {
    pub fn load_item(id: &str) -> Item { todo!() }
    pub fn load_revision(id: &str, rev: Option<i32>) -> Revision { todo!() }
    pub fn load_published(id: &str) -> Revision { todo!() }
    pub fn not_found(id: &str) -> HttpResponse { todo!() }
}

async fn show_revision(params: web::Path<(String, Option<i32>)>) -> HttpResponse {
    let (id, rev) = params.into_inner();
    let item = store::load_item(&id);
    let revision = store::load_revision(&id, rev);
    render(item, revision)
}

async fn show_item(params: web::Path<(String,)>) -> HttpResponse {
    let (id,) = params.into_inner();
    if missing(&id) {
        return store::not_found(&id);
    }
    render_published(store::load_published(&id))
}

async fn edit_item(params: web::Path<(String,)>, session: Session) -> HttpResponse {
    let (id,) = params.into_inner();
    let me = get_username_from_session(&session).unwrap();
    let item = store::load_item(&id);
    if item.maker != me {
        return store::not_found(&id);
    }
    let revision = store::load_revision(&id, None);
    render(item, revision)
}
