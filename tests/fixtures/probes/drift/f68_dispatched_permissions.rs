use actix_web::{dev::Payload, web, App, FromRequest, HttpRequest, HttpResponse};
use std::marker::PhantomData;

// `Gate<P>` checks nothing itself: its `from_request` calls `P::allow`, so
// the permission is the type argument. The `grant!` macro writes one type
// per permission constant.
// - `/books` and `/authors` use one permission per action, which is not
//   drift: `CreateBook`, `UpdateBook`, `DeleteAuthor` differ by design.
// - Drift 1: `GET /books/{id}/export` takes no `Gate<_>` at all.
// - Drift 2: `DELETE /books/{id}` takes `Gate<ReadBook>`, the permission
//   the read routes require.
pub enum Grant {
    ReadBook,
    CreateBook,
    UpdateBook,
    ReadAuthor,
    CreateAuthor,
    UpdateAuthor,
    DeleteAuthor,
}

pub struct Account {
    grants: Vec<u8>,
}

impl Account {
    fn holds(&self, grant: Grant) -> Result<(), actix_web::Error> {
        if self.grants.contains(&(grant as u8)) {
            Ok(())
        } else {
            Err(actix_web::error::ErrorForbidden("missing grant"))
        }
    }
}

pub trait Allow {
    fn allow(account: &Account) -> Result<(), actix_web::Error>;
}

macro_rules! grant {
    ($($name:ident),*) => {
        $(
            pub struct $name;
            impl Allow for $name {
                fn allow(account: &Account) -> Result<(), actix_web::Error> {
                    account.holds(Grant::$name)
                }
            }
        )*
    };
}

grant!(ReadBook, CreateBook, UpdateBook, ReadAuthor, CreateAuthor, UpdateAuthor, DeleteAuthor);

pub struct Gate<P: Allow>(PhantomData<P>);

impl<P: Allow> FromRequest for Gate<P> {
    type Error = actix_web::Error;
    type Future = std::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let extensions = req.extensions();
        let result = match extensions.get::<Account>() {
            Some(account) => P::allow(account).map(|()| Gate(PhantomData)),
            None => Err(actix_web::error::ErrorUnauthorized("no account")),
        };
        std::future::ready(result)
    }
}

async fn list_books(_: Gate<ReadBook>) -> HttpResponse {
    HttpResponse::Ok().finish()
}
async fn get_book(_: Gate<ReadBook>) -> HttpResponse {
    HttpResponse::Ok().finish()
}
async fn book_summary(_: Gate<ReadBook>) -> HttpResponse {
    HttpResponse::Ok().finish()
}
async fn export_book() -> HttpResponse {
    HttpResponse::Ok().finish()
}
async fn create_book(_: Gate<CreateBook>) -> HttpResponse {
    HttpResponse::Ok().finish()
}
async fn update_book(_: Gate<UpdateBook>) -> HttpResponse {
    HttpResponse::Ok().finish()
}
async fn delete_book(_: Gate<ReadBook>) -> HttpResponse {
    HttpResponse::Ok().finish()
}
async fn list_authors(_: Gate<ReadAuthor>) -> HttpResponse {
    HttpResponse::Ok().finish()
}
async fn get_author(_: Gate<ReadAuthor>) -> HttpResponse {
    HttpResponse::Ok().finish()
}
async fn create_author(_: Gate<CreateAuthor>) -> HttpResponse {
    HttpResponse::Ok().finish()
}
async fn update_author(_: Gate<UpdateAuthor>) -> HttpResponse {
    HttpResponse::Ok().finish()
}
async fn delete_author(_: Gate<DeleteAuthor>) -> HttpResponse {
    HttpResponse::Ok().finish()
}

fn main() {
    App::new()
        .service(
            web::scope("/books")
                .route("", web::get().to(list_books))
                .route("", web::post().to(create_book))
                .route("/{id}", web::get().to(get_book))
                .route("/{id}", web::put().to(update_book))
                .route("/{id}", web::delete().to(delete_book))
                .route("/{id}/summary", web::get().to(book_summary))
                .route("/{id}/export", web::get().to(export_book)),
        )
        .service(
            web::scope("/authors")
                .route("", web::get().to(list_authors))
                .route("", web::post().to(create_author))
                .route("/{id}", web::get().to(get_author))
                .route("/{id}", web::put().to(update_author))
                .route("/{id}", web::delete().to(delete_author)),
        );
}
