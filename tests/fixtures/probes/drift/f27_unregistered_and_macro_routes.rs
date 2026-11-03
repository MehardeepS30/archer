use actix_web::{get, post, web, App};
pub fn app() {
    App::new().service(get_article).service(create_article);
}
#[get("/articles/{id}")]
async fn get_article(user: AuthenticatedUser) {}
#[post("/articles")]
async fn create_article(user: AuthenticatedUser) {}
// Declared but never registered: not served, so not a route.
#[post("/articles/{id}/approve")]
async fn approve_article() {}
// Registered by a project macro Archer cannot expand.
api_routes!(list_tags, delete_tag);
async fn list_tags(query: web::Query<TagQuery>) {}
async fn delete_tag(path: web::Path<u32>) {}
