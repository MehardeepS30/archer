use actix_web::{dev::Payload, error, web, App, FromRequest, HttpRequest, HttpResponse};
use futures::future::{ready, LocalBoxFuture, Ready};

// Routes under /shelves/{shelf} take `ShelfRead` or `ShelfWrite`. Neither
// checks anything itself: each runs `Ticket`, whose helper `open` rejects a
// ticket sealed for another shelf than the one in the path. That
// comparison, two calls below the handler's argument list, is the check.
// `Stock` is the store handle every handler takes; it fails when the pool
// is missing, which says nothing about the caller. `/summary` takes only
// `Stock`, and `/preview` runs `Ticket` but discards its failure: both skip
// the check. Under /audit the handlers take `Operator`, which only
// identifies the caller, before `Stock`; `/audit/raw` takes neither.
fn app() {
    App::new()
        .route("/shelves/{shelf}/items", web::get().to(list_items))
        .route("/shelves/{shelf}/items/{item}", web::get().to(show_item))
        .route("/shelves/{shelf}/labels", web::get().to(list_labels))
        .route("/shelves/{shelf}/notes", web::get().to(list_notes))
        .route("/shelves/{shelf}/summary", web::get().to(summary))
        .route("/shelves/{shelf}/preview", web::get().to(preview))
        .route("/shelves/{shelf}/items/{item}", web::put().to(put_item))
        .route("/shelves/{shelf}/items/{item}", web::delete().to(drop_item))
        .route("/shelves/{shelf}/labels", web::put().to(put_labels))
        .route("/audit/log", web::get().to(audit_log))
        .route("/audit/export", web::get().to(audit_export))
        .route("/audit/alerts", web::get().to(audit_alerts))
        .route("/audit/raw", web::get().to(audit_raw));
}

pub struct Ticket {
    pub shelf: u64,
}

impl Ticket {
    fn shelf_of(target: &str) -> Result<u64, actix_web::Error> {
        target
            .split('/')
            .nth(2)
            .and_then(|segment| segment.parse().ok())
            .ok_or_else(|| error::ErrorBadRequest("no shelf"))
    }

    fn open(sealed: &str, target: &str) -> Result<Self, actix_web::Error> {
        let ticket = unseal(sealed)?;
        let wanted = Self::shelf_of(target)?;
        if ticket.shelf != wanted {
            return Err(error::ErrorForbidden("ticket is for another shelf"));
        }
        Ok(ticket)
    }
}

fn unseal(sealed: &str) -> Result<Ticket, actix_web::Error> {
    let shelf = SEAL.verify(sealed).map_err(error::ErrorUnauthorized)?;
    Ok(Ticket { shelf })
}

impl FromRequest for Ticket {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let Some(sealed) = req.cookie("ticket") else {
            return ready(Err(error::ErrorUnauthorized("no ticket")));
        };
        ready(Self::open(sealed.value(), req.path()))
    }
}

pub struct ShelfRead {
    pub ticket: Ticket,
    pub page: u32,
}

impl FromRequest for ShelfRead {
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            let mut payload = Payload::None;
            let (ticket, paging) =
                <(Ticket, web::Query<Paging>)>::from_request(&req, &mut payload).await?;
            Ok(ShelfRead { ticket, page: paging.page })
        })
    }
}

pub struct ShelfWrite {
    pub ticket: Ticket,
}

impl FromRequest for ShelfWrite {
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            let ticket = Ticket::extract(&req).await?;
            Ok(ShelfWrite { ticket })
        })
    }
}

pub struct Glance(pub Option<Ticket>);

impl FromRequest for Glance {
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            let ticket = Ticket::extract(&req).await.ok();
            Ok(Glance(ticket))
        })
    }
}

pub struct Stock(pub Handle);

impl FromRequest for Stock {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        match req.app_data::<web::Data<Pool>>() {
            Some(pool) => ready(Ok(Stock(pool.session()))),
            None => ready(Err(error::ErrorInternalServerError("no session pool"))),
        }
    }
}

pub struct Operator(pub String);

impl FromRequest for Operator {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        match req.headers().get("authorization").and_then(|value| value.to_str().ok()) {
            Some(value) => ready(Ok(Operator(value.to_owned()))),
            None => ready(Err(error::ErrorUnauthorized("no authorization"))),
        }
    }
}

async fn list_items(shelf: ShelfRead, stock: Stock) -> HttpResponse {
    HttpResponse::Ok().json(stock.0.items(shelf.ticket.shelf, shelf.page))
}

async fn show_item(shelf: ShelfRead, stock: Stock, item: web::Path<(u64, u64)>) -> HttpResponse {
    HttpResponse::Ok().json(stock.0.item(shelf.ticket.shelf, item.1))
}

async fn list_labels(shelf: ShelfRead, stock: Stock) -> HttpResponse {
    HttpResponse::Ok().json(stock.0.labels(shelf.ticket.shelf))
}

async fn list_notes(shelf: ShelfRead, stock: Stock) -> HttpResponse {
    HttpResponse::Ok().json(stock.0.notes(shelf.ticket.shelf))
}

async fn summary(stock: Stock, shelf: web::Path<u64>) -> HttpResponse {
    HttpResponse::Ok().json(stock.0.summary(*shelf))
}

async fn preview(glance: Glance, stock: Stock, shelf: web::Path<u64>) -> HttpResponse {
    HttpResponse::Ok().json(stock.0.preview(*shelf, glance.0.is_some()))
}

async fn put_item(shelf: ShelfWrite, stock: Stock, body: web::Json<Item>) -> HttpResponse {
    HttpResponse::Ok().json(stock.0.put(shelf.ticket.shelf, body.into_inner()))
}

async fn drop_item(shelf: ShelfWrite, stock: Stock, item: web::Path<(u64, u64)>) -> HttpResponse {
    HttpResponse::Ok().json(stock.0.drop(shelf.ticket.shelf, item.1))
}

async fn put_labels(shelf: ShelfWrite, stock: Stock, body: web::Json<Labels>) -> HttpResponse {
    HttpResponse::Ok().json(stock.0.relabel(shelf.ticket.shelf, body.into_inner()))
}

async fn audit_log(operator: Operator, stock: Stock) -> HttpResponse {
    HttpResponse::Ok().json(stock.0.log(&operator.0))
}

async fn audit_export(operator: Operator, stock: Stock) -> HttpResponse {
    HttpResponse::Ok().json(stock.0.export(&operator.0))
}

async fn audit_alerts(operator: Operator, stock: Stock) -> HttpResponse {
    HttpResponse::Ok().json(stock.0.alerts(&operator.0))
}

async fn audit_raw(data: web::Data<Pool>) -> HttpResponse {
    HttpResponse::Ok().json(data.session().raw())
}
