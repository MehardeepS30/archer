use actix_web::{web, App};

// The shop's routes sit under a prefix read from the configuration at run
// time. Three of its writes check a permission; `restock` checks nothing.
fn app(cfg: &Settings) {
    App::new().service(
        web::scope("/api").service(
            web::scope(&cfg.shop_prefix)
                .route("/items", web::post().to(add_item))
                .route("/items/{id}", web::put().to(edit_item))
                .route("/items/{id}", web::delete().to(drop_item))
                .route("/items/{id}/restock", web::post().to(restock_item)),
        ),
    );
}

async fn add_item(me: AccountUser, pool: web::Data<Pool>) -> Reply {
    if !me.has_permission(Permission::ItemsWrite) {
        return Err(Error::Forbidden);
    }
    Item::add(&pool).await
}
async fn edit_item(me: AccountUser, path: web::Path<u64>, pool: web::Data<Pool>) -> Reply {
    if !me.has_permission(Permission::ItemsWrite) {
        return Err(Error::Forbidden);
    }
    Item::edit(&pool, path.into_inner()).await
}
async fn drop_item(me: AccountUser, path: web::Path<u64>, pool: web::Data<Pool>) -> Reply {
    if !me.has_permission(Permission::ItemsWrite) {
        return Err(Error::Forbidden);
    }
    Item::drop_one(&pool, path.into_inner()).await
}
async fn restock_item(me: AccountUser, path: web::Path<u64>, pool: web::Data<Pool>) -> Reply {
    Item::restock(&pool, path.into_inner(), me.uid).await
}
