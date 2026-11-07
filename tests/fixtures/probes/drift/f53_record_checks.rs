use actix_web::{web, App};

// Notes are private to their holder. `edit`, `remove` and `archive` load a
// note by the id in the path and hold it to the caller, each through a
// differently named field; `flag` loads one and copies its body without
// any comparison. `pin` loads the note together with the caller, which
// scopes the query; `share` checks it with a helper named for ownership.
// Invitations are opened with a secret instead of an account.
fn app() {
    App::new()
        .service(
            web::scope("/notes")
                .route("/{id}", web::put().to(edit_note))
                .route("/{id}", web::delete().to(remove_note))
                .route("/{id}/archive", web::post().to(archive_note))
                .route("/{id}/flag", web::post().to(flag_note))
                .route("/{id}/pin", web::post().to(pin_note))
                .route("/{id}/share", web::post().to(share_note)),
        )
        .service(
            web::scope("/invites")
                .route("/{code}/accept", web::post().to(accept_invite))
                .route("/{code}/confirm", web::post().to(confirm_invite))
                .route("/{code}/count", web::post().to(count_invite)),
        );
}

async fn edit_note(path: web::Path<u64>, me: AccountUser, pool: web::Data<Pool>, body: web::Json<NoteBody>) {
    let note = Note::fetch(&pool, path.into_inner()).await?;
    if note.holder != me.uid {
        return Err(Error::NotYours);
    }
    Note::save(&pool, note.key, &body.text).await?;
}
async fn remove_note(path: web::Path<u64>, me: AccountUser, pool: web::Data<Pool>) {
    let note = Note::fetch(&pool, path.into_inner()).await?;
    if me.uid != note.writer {
        return Err(Error::NotYours);
    }
    Note::drop_one(&pool, note.key).await?;
}
async fn archive_note(path: web::Path<u64>, me: AccountUser, pool: web::Data<Pool>) {
    let note = Note::fetch(&pool, path.into_inner()).await?;
    if !note.readers.contains(&me.uid) {
        return Err(Error::NotYours);
    }
    Note::shelve(&pool, note.key).await?;
}
async fn flag_note(path: web::Path<u64>, me: AccountUser, pool: web::Data<Pool>) {
    let note = Note::fetch(&pool, path.into_inner()).await?;
    Flag::open(&pool, me.uid, note.key, note.text.clone()).await?;
}
async fn pin_note(path: web::Path<u64>, me: AccountUser, pool: web::Data<Pool>) {
    let note = Note::fetch_for(&pool, path.into_inner(), me.uid).await?;
    Pin::add(&pool, me.uid, note.key).await?;
}
async fn share_note(path: web::Path<u64>, me: AccountUser, pool: web::Data<Pool>) {
    let note = Note::fetch(&pool, path.into_inner()).await?;
    if !is_owner(&me, &note) {
        return Err(Error::NotYours);
    }
    Share::add(&pool, note.key).await?;
}

async fn accept_invite(path: web::Path<String>, query: web::Query<Given>, pool: web::Data<Pool>) {
    let invite = Invite::fetch(&pool, path.into_inner()).await?;
    if invite.join_secret != query.secret {
        return Err(Error::BadLink);
    }
    Invite::accept(&pool, invite.key).await?;
}
async fn confirm_invite(path: web::Path<String>, query: web::Query<Given>, pool: web::Data<Pool>) {
    let invite = Invite::fetch(&pool, path.into_inner()).await?;
    if !constant_time_eq(invite.stored.as_bytes(), query.given.as_bytes()) {
        return Err(Error::BadLink);
    }
    Invite::confirm(&pool, invite.key).await?;
}
async fn count_invite(path: web::Path<String>, query: web::Query<Given>, pool: web::Data<Pool>) {
    let invite = Invite::fetch(&pool, path.into_inner()).await?;
    if invite.count != query.count {
        return Err(Error::Stale);
    }
}
