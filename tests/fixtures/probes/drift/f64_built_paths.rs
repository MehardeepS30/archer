use actix_web::{web, App, HttpResponse};

// Paths built in code. The ledger's routes come from `ledger_path`, which
// formats a version and a parameter pattern around its argument; the docs
// redirect at `/` is written as a literal beside them. Two route tables
// have a `Shelf` struct each, in different modules, with different paths;
// one is re-exported under another name. The depot's routes sit under a
// prefix made with `format!` from a runtime setting. In each part, one
// write checks nothing while its peers check a permission.
const VERSION: &str = "2";
const ENTRY_ID: &str = r"[0-9]{1,8}";

pub fn ledger_path(path: &str) -> String {
    let path = path.replace("{entry}", &format!("{{entry:{}}}", ENTRY_ID));
    format!("/v{}/{{book}}{}", VERSION, path)
}

mod api {
    pub mod tables {
        pub struct Shelf {
            pub list: &'static str,
            pub item: &'static str,
            pub stamp: &'static str,
        }
        impl Shelf {
            pub const fn new() -> Self {
                let list = "/api/shelf";
                Shelf { list, item: "/api/shelf/{id}", stamp: "/api/shelf/{id}/stamp" }
            }
        }
    }
    use tables::Shelf;
    pub struct Routes {
        pub shelf: Shelf,
    }
    impl Routes {
        pub const fn new() -> Routes {
            Routes { shelf: Shelf::new() }
        }
    }
    pub const ROUTES: Routes = Routes::new();
}

mod pages {
    pub mod tables {
        pub struct Shelf {
            pub list: &'static str,
            pub item: &'static str,
            pub stamp: &'static str,
        }
        impl Shelf {
            pub const fn new() -> Self {
                Shelf { list: "/shelf", item: "/shelf/{id}", stamp: "/shelf/{id}/stamp" }
            }
        }
    }
    pub struct Routes {
        pub shelf: tables::Shelf,
    }
    impl Routes {
        pub const fn new() -> Routes {
            Routes { shelf: tables::Shelf::new() }
        }
    }
    pub const ROUTES: Routes = Routes::new();
}

pub use api::ROUTES as API_ROUTES;

fn app(cfg: &Settings) {
    let depot = format!("/{}/depot", cfg.depot_prefix);
    App::new()
        .route("/", web::get().to(docs_redirect))
        .service(web::resource(&ledger_path("/entries")).route(web::post().to(add_entry)))
        .service(web::resource(&ledger_path("/entries/{entry}")).route(web::put().to(edit_entry)))
        .service(web::resource(&ledger_path("/entries/{entry}/void")).route(web::post().to(void_entry)))
        .service(web::resource(&ledger_path("/entries/{entry}/merge")).route(web::post().to(merge_entry)))
        .route(API_ROUTES.shelf.list, web::post().to(add_item))
        .route(API_ROUTES.shelf.item, web::put().to(edit_item))
        .route(API_ROUTES.shelf.stamp, web::post().to(stamp_item))
        .route(crate::pages::ROUTES.shelf.list, web::post().to(add_item))
        .route(crate::pages::ROUTES.shelf.item, web::put().to(edit_item))
        .route(crate::pages::ROUTES.shelf.stamp, web::post().to(copy_item))
        .service(
            web::scope(&depot)
                .route("/crates", web::post().to(add_item))
                .route("/crates/{id}", web::put().to(edit_item))
                .route("/crates/{id}/seal", web::post().to(stamp_item))
                .route("/crates/{id}/open", web::post().to(open_crate)),
        );
}

async fn docs_redirect() -> HttpResponse {
    HttpResponse::Found().insert_header(("Location", "/docs")).finish()
}

async fn add_entry(me: AccountUser, pool: web::Data<Pool>) -> Reply {
    if !me.has_permission(Permission::LedgerWrite) {
        return Err(Error::Forbidden);
    }
    Entry::add(&pool).await
}
async fn edit_entry(me: AccountUser, path: web::Path<u64>, pool: web::Data<Pool>) -> Reply {
    if !me.has_permission(Permission::LedgerWrite) {
        return Err(Error::Forbidden);
    }
    Entry::edit(&pool, path.into_inner()).await
}
async fn void_entry(me: AccountUser, path: web::Path<u64>, pool: web::Data<Pool>) -> Reply {
    if !me.has_permission(Permission::LedgerWrite) {
        return Err(Error::Forbidden);
    }
    Entry::void(&pool, path.into_inner()).await
}
async fn merge_entry(path: web::Path<u64>, pool: web::Data<Pool>) -> Reply {
    Entry::merge(&pool, path.into_inner()).await
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
async fn stamp_item(me: AccountUser, path: web::Path<u64>, pool: web::Data<Pool>) -> Reply {
    if !me.has_permission(Permission::ItemsWrite) {
        return Err(Error::Forbidden);
    }
    Item::stamp(&pool, path.into_inner()).await
}
async fn copy_item(path: web::Path<u64>, pool: web::Data<Pool>) -> Reply {
    Item::copy(&pool, path.into_inner()).await
}
async fn open_crate(path: web::Path<u64>, pool: web::Data<Pool>) -> Reply {
    Item::open(&pool, path.into_inner()).await
}
