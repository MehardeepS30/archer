use actix_web::{web, App};

// A person's own pages hold `{who}` to the caller on the page that names
// it; the two routes under it do not. A shelf's `GET` and `PUT` hold
// `{shelf}` to the caller's shelf and its `DELETE` does not; `move` takes
// the shelf from its body and holds it to nothing. Posters are public, so
// nobody binds `{poster}`; `purge` is for administrators.
fn app() {
    App::new()
        .service(
            web::scope("/people")
                .route("/{who}", web::get().to(show_person))
                .route("/{who}/notes", web::get().to(person_notes))
                .route("/{who}/badges", web::get().to(person_badges)),
        )
        .service(
            web::scope("/shelves")
                .route("/{shelf}", web::get().to(show_shelf))
                .route("/{shelf}", web::put().to(edit_shelf))
                .route("/{shelf}", web::delete().to(drop_shelf))
                .route("/{shelf}/purge", web::post().to(purge_shelf))
                .route("/move", web::post().to(move_shelf)),
        )
        .service(
            web::scope("/posters")
                .route("/{poster}", web::get().to(show_poster))
                .route("/{poster}", web::put().to(edit_poster))
                .route("/{poster}", web::delete().to(drop_poster)),
        );
}

async fn show_person(path: web::Path<String>, me: AccountUser, pool: web::Data<Pool>) -> Reply {
    let who = path.into_inner();
    if who != me.uid {
        return Err(Error::NotYours);
    }
    Person::page(&pool, who).await
}
async fn person_notes(path: web::Path<String>, me: AccountUser, pool: web::Data<Pool>) -> Reply {
    let who = path.into_inner();
    Notebook::list(&pool, who, me.locale).await
}
async fn person_badges(path: web::Path<String>, me: AccountUser, pool: web::Data<Pool>) -> Reply {
    let who = path.into_inner();
    Badge::list(&pool, who, me.locale).await
}

async fn show_shelf(path: web::Path<String>, me: AccountUser, pool: web::Data<Pool>) -> Reply {
    let shelf = path.into_inner();
    if shelf != me.shelf {
        return Err(Error::NotYours);
    }
    Shelf::show(&pool, shelf).await
}
async fn edit_shelf(path: web::Path<String>, me: AccountUser, pool: web::Data<Pool>, body: web::Json<ShelfBody>) -> Reply {
    let shelf = path.into_inner();
    if me.shelf != shelf {
        return Err(Error::NotYours);
    }
    Shelf::edit(&pool, shelf, &body.title).await
}
async fn drop_shelf(path: web::Path<String>, me: AccountUser, pool: web::Data<Pool>) -> Reply {
    let shelf = path.into_inner();
    Shelf::drop_one(&pool, shelf, me.locale).await
}
async fn purge_shelf(path: web::Path<String>, me: AccountUser, pool: web::Data<Pool>) -> Reply {
    if !me.has_role(Role::Admin) {
        return Err(Error::Forbidden);
    }
    Shelf::purge(&pool, path.into_inner()).await
}
async fn move_shelf(body: web::Json<MoveBody>, me: AccountUser, pool: web::Data<Pool>) -> Reply {
    Shelf::relocate(&pool, &body.shelf, &body.place, me.locale).await
}

async fn show_poster(path: web::Path<String>, me: AccountUser, pool: web::Data<Pool>) -> Reply {
    Poster::show(&pool, path.into_inner(), me.locale).await
}
async fn edit_poster(path: web::Path<String>, me: AccountUser, pool: web::Data<Pool>) -> Reply {
    Poster::edit(&pool, path.into_inner(), me.locale).await
}
async fn drop_poster(path: web::Path<String>, me: AccountUser, pool: web::Data<Pool>) -> Reply {
    Poster::drop_one(&pool, path.into_inner(), me.locale).await
}
