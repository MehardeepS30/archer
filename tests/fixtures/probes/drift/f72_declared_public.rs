use actix_identity::Identity;
use actix_web::{web, App, HttpResponse};

// What the application itself says about a route that takes no caller.
// Reads under /api/v2/catalog take the caller. `published/{slug}` is named
// as open to anyone, so it is kept at Low; `{item_id}/pricing` has no such
// name and stays High. Under /api/v2/ledger every handler carries an
// OpenAPI annotation with a security requirement, except `rates`, whose
// annotation declares none: the API document states it as open, Low.
// `totals` declares the requirement but takes no caller: it stays High,
// with a note that the document asks for what the handler does not enforce.
fn app() {
    App::new()
        .route("/api/v2/catalog/items", web::get().to(list_items))
        .route("/api/v2/catalog/items/{item_id}", web::get().to(show_item))
        .route("/api/v2/catalog/drafts", web::get().to(list_drafts))
        .route("/api/v2/catalog/drafts/{item_id}", web::get().to(show_draft))
        .route("/api/v2/catalog/published/{slug}", web::get().to(show_published))
        .route("/api/v2/catalog/{item_id}/pricing", web::get().to(show_pricing))
        .route("/api/v2/ledger/entries", web::get().to(list_entries))
        .route("/api/v2/ledger/entries/{entry_id}", web::get().to(show_entry))
        .route("/api/v2/ledger/accounts", web::get().to(list_accounts))
        .route("/api/v2/ledger/accounts/{account_id}", web::get().to(show_account))
        .route("/api/v2/ledger/rates", web::get().to(show_rates))
        .route("/api/v2/ledger/totals", web::get().to(show_totals));
}

async fn list_items(id: Identity, data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(data.items.for_account(&id).await?))
}

async fn show_item(id: Identity, path: web::Path<String>, data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(data.items.find(&id, &path).await?))
}

async fn list_drafts(id: Identity, data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(data.drafts.for_account(&id).await?))
}

async fn show_draft(id: Identity, path: web::Path<String>, data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(data.drafts.find(&id, &path).await?))
}

async fn show_published(path: web::Path<String>, data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(data.items.by_slug(&path).await?))
}

async fn show_pricing(path: web::Path<String>, data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(data.prices.find(&path).await?))
}

#[utoipa::path(get, path = "/api/v2/ledger/entries", security(("token" = [])))]
async fn list_entries(id: Identity, data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(data.entries.for_account(&id).await?))
}

#[utoipa::path(get, path = "/api/v2/ledger/entries/{entry_id}", security(("token" = [])))]
async fn show_entry(id: Identity, path: web::Path<String>, data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(data.entries.find(&id, &path).await?))
}

#[utoipa::path(get, path = "/api/v2/ledger/accounts", security(("token" = [])))]
async fn list_accounts(id: Identity, data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(data.accounts.for_account(&id).await?))
}

#[utoipa::path(get, path = "/api/v2/ledger/accounts/{account_id}", security(("token" = [])))]
async fn show_account(id: Identity, path: web::Path<String>, data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(data.accounts.find(&id, &path).await?))
}

#[utoipa::path(get, path = "/api/v2/ledger/rates", responses((status = 200, description = "Rates")))]
async fn show_rates(query: web::Query<RateQuery>, data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(data.rates.find(&query.currency).await?))
}

#[utoipa::path(get, path = "/api/v2/ledger/totals", security(("token" = [])))]
async fn show_totals(query: web::Query<RateQuery>, data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(data.entries.totals(&query.currency).await?))
}
