use actix_web::{web, App, HttpResponse, ResponseError};

// `set_setting` and `delete_setting` hand the caller and the path key to a
// service that fails with `StoreError::Stale`, which the application
// answers with 412 Precondition Failed: the stored revision has moved on.
// That is not a check of who the caller is. `get_setting` hands over the
// same two values and never fails that way, so it is not drift.
#[derive(Debug)]
pub enum StoreError {
    Stale,
    Broken,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "store error")
    }
}

impl ResponseError for StoreError {
    fn error_response(&self) -> HttpResponse {
        match self {
            StoreError::Stale => HttpResponse::PreconditionFailed().finish(),
            StoreError::Broken => HttpResponse::InternalServerError().finish(),
        }
    }
}

pub struct Account {
    pub id: u64,
}

impl actix_web::FromRequest for Account {
    type Error = actix_web::Error;
    type Future = std::future::Ready<Result<Self, Self::Error>>;
    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        std::future::ready(match req.cookie("sid") {
            Some(_) => Ok(Account { id: 1 }),
            None => Err(actix_web::error::ErrorUnauthorized("log in")),
        })
    }
}

fn write_setting(account: &Account, key: &str, revision: u64) -> Result<(), StoreError> {
    // The client sends the revision it last saw. A different stored
    // revision means someone wrote in between: 412, not 403.
    if stored_revision(account.id, key) != revision {
        return Err(StoreError::Stale);
    }
    settings::Entity::update_many().filter(settings::Column::Key.eq(key)).exec();
    Ok(())
}

fn erase_setting(account: &Account, key: &str, revision: u64) -> Result<(), StoreError> {
    // The client sends the revision it last saw. A different stored
    // revision means someone wrote in between: 412, not 403.
    if stored_revision(account.id, key) != revision {
        return Err(StoreError::Stale);
    }
    settings::Entity::delete_many().filter(settings::Column::Key.eq(key)).exec();
    Ok(())
}

fn stored_revision(account: u64, key: &str) -> u64 {
    settings::Entity::revision_of((account, key))
}

fn read_setting(account: &Account, key: &str) -> Option<String> {
    settings::Entity::find_by_id((account.id, key)).one()
}

async fn get_setting(key: web::Path<String>, account: Account) -> HttpResponse {
    match read_setting(&account, &key) {
        Some(value) => HttpResponse::Ok().body(value),
        None => HttpResponse::NotFound().finish(),
    }
}
async fn set_setting(
    key: web::Path<String>,
    account: Account,
    revision: web::Json<u64>,
) -> Result<HttpResponse, StoreError> {
    write_setting(&account, &key, revision.into_inner())?;
    Ok(HttpResponse::NoContent().finish())
}
async fn delete_setting(
    key: web::Path<String>,
    account: Account,
    revision: web::Json<u64>,
) -> Result<HttpResponse, StoreError> {
    erase_setting(&account, &key, revision.into_inner())?;
    Ok(HttpResponse::NoContent().finish())
}

fn main() {
    App::new().service(
        web::scope("/settings")
            .route("/{key}", web::get().to(get_setting))
            .route("/{key}", web::put().to(set_setting))
            .route("/{key}", web::delete().to(delete_setting)),
    );
}
