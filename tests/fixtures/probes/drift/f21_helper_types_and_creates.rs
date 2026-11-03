use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    // A helper's parameter type is not a role check.
    cfg.service(web::scope("/ogc")
        .route("/map/tiles/{id}", web::get().to(tile))
        .route("/map/tiles/{id}/info", web::get().to(tile_info))
        .route("/map/tiles", web::get().to(tiles)));
    // A create has no record to own yet.
    cfg.service(web::scope("/api")
        .route("/messages", web::post().to(create_message))
        .route("/messages", web::put().to(edit_message))
        .route("/messages", web::delete().to(delete_message)));
}
async fn tile(manager: web::Data<TileSourceManager>) { lookup(&manager); }
async fn tile_info(manager: web::Data<TileSourceManager>) { lookup(&manager); }
async fn tiles() {}
fn lookup(manager: &TileSourceManager) {}
async fn create_message(u: LocalUserView) {}
async fn edit_message(u: LocalUserView, m: Message) { if m.creator_id != u.person.id { return Err(()); } }
async fn delete_message(u: LocalUserView, m: Message) { if m.creator_id != u.person.id { return Err(()); } }
