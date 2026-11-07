use actix_web::{web, App, HttpResponse};

// `Rank` derives an order, so `role >= Rank::Editor` admits Editor and
// Chief. Under /shelves the writes admit Editor and Chief; the delete
// admits Reader as well (a superset, reported), and the lock admits only
// Chief (a subset, not reported). Under /notes the writes admit Editor and
// Chief and the pin admits Reader and Chief: neither contains the other.
// Under /cards the one update admits only Chief and the delete also admits
// Editor.
fn app() {
    App::new()
        .service(
            web::scope("/shelves")
                .route("", web::post().to(add_shelf))
                .route("/{shelf_id}", web::put().to(rename_shelf))
                .route("/{shelf_id}/title", web::patch().to(retitle_shelf))
                .route("/{shelf_id}", web::delete().to(remove_shelf))
                .route("/{shelf_id}/lock", web::post().to(lock_shelf)),
        )
        .service(
            web::scope("/notes")
                .route("", web::post().to(add_note))
                .route("/{note_id}", web::put().to(edit_note))
                .route("/{note_id}/tags", web::post().to(tag_note))
                .route("/{note_id}/pin", web::post().to(pin_note)),
        )
        .service(
            web::scope("/cards")
                .route("", web::put().to(update_card))
                .route("/{card_id}", web::delete().to(remove_card)),
        );
}

pub struct Denied;
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Rank {
    Reader = 0,
    Editor = 1,
    Chief = 2,
}
pub struct Member {
    pub id: u64,
    pub role: Rank,
}

impl actix_web::FromRequest for Member {
    type Error = Denied;
    type Future = std::future::Ready<Result<Self, Denied>>;
    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let session = req.headers().get("x-session");
        match session.and_then(|token| decode_member(token)) {
            Some(member) => std::future::ready(Ok(member)),
            None => std::future::ready(Err(Denied)),
        }
    }
}

async fn add_shelf(me: Member) -> Result<HttpResponse, Denied> {
    if me.role < Rank::Editor {
        return Err(Denied);
    }
    Ok(HttpResponse::Ok().finish())
}

async fn rename_shelf(me: Member, _shelf_id: web::Path<u64>) -> Result<HttpResponse, Denied> {
    if Rank::Editor > me.role {
        return Err(Denied);
    }
    Ok(HttpResponse::Ok().finish())
}

async fn retitle_shelf(me: Member, _shelf_id: web::Path<u64>) -> Result<HttpResponse, Denied> {
    if !matches!(me.role, Rank::Editor | Rank::Chief) {
        return Err(Denied);
    }
    Ok(HttpResponse::Ok().finish())
}

async fn remove_shelf(me: Member, _shelf_id: web::Path<u64>) -> Result<HttpResponse, Denied> {
    if me.role >= Rank::Reader {
        Ok(HttpResponse::Ok().finish())
    } else {
        Err(Denied)
    }
}

async fn lock_shelf(me: Member, _shelf_id: web::Path<u64>) -> Result<HttpResponse, Denied> {
    if me.role != Rank::Chief {
        return Err(Denied);
    }
    Ok(HttpResponse::Ok().finish())
}

async fn add_note(me: Member) -> Result<HttpResponse, Denied> {
    if me.role < Rank::Editor {
        return Err(Denied);
    }
    Ok(HttpResponse::Ok().finish())
}

async fn edit_note(me: Member, _note_id: web::Path<u64>) -> Result<HttpResponse, Denied> {
    if me.role < Rank::Editor {
        return Err(Denied);
    }
    Ok(HttpResponse::Ok().finish())
}

async fn tag_note(me: Member, _note_id: web::Path<u64>) -> Result<HttpResponse, Denied> {
    if !matches!(me.role, Rank::Editor | Rank::Chief) {
        return Err(Denied);
    }
    Ok(HttpResponse::Ok().finish())
}

async fn pin_note(me: Member, _note_id: web::Path<u64>) -> Result<HttpResponse, Denied> {
    if !matches!(me.role, Rank::Reader | Rank::Chief) {
        return Err(Denied);
    }
    Ok(HttpResponse::Ok().finish())
}

async fn update_card(me: Member) -> Result<HttpResponse, Denied> {
    if me.role != Rank::Chief {
        return Err(Denied);
    }
    Ok(HttpResponse::Ok().finish())
}

async fn remove_card(me: Member, _card_id: web::Path<u64>) -> Result<HttpResponse, Denied> {
    if me.role <= Rank::Reader {
        return Err(Denied);
    }
    Ok(HttpResponse::Ok().finish())
}
