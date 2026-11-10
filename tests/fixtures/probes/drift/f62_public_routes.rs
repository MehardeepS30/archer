use actix_identity::Identity;
use actix_web::{web, App, HttpResponse};

// Writes under /api/v1 take the caller; sign-up beside them admits callers
// without one. `handle/taken` answers whether a handle exists for a value
// in the body, so it looks public. `/limits` serves only application
// state, but reading a field of the state looks the same as reading a
// store through it, so it stays High. `relay/pair` looks up a pairing by a token the body presents and
// rejects a miss: a secret check. `POST /boards` creates a board, so the
// owner check its item routes make on a loaded board does not apply to it.
// `boards/purge` deletes a board named in the body without a caller, and
// `account/close` an account: neither is demoted, and the second stays High.
fn app() {
    App::new()
        .route("/api/v1/signup", web::post().to(register))
        .route("/api/v1/account/handle/taken", web::post().to(handle_taken))
        .route("/api/v1/limits", web::get().to(limits))
        .route("/api/v1/relay/pair", web::post().to(pair_relay))
        .route("/api/v1/boards", web::post().to(create_board))
        .route("/api/v1/boards/{board_id}", web::put().to(rename_board))
        .route("/api/v1/boards/{board_id}", web::delete().to(delete_board))
        .route("/api/v1/boards/{board_id}/archive", web::post().to(archive_board))
        .route("/api/v1/boards/purge", web::post().to(purge_board))
        .route("/api/v1/account/handle", web::post().to(set_handle))
        .route("/api/v1/account/bio", web::post().to(set_bio))
        .route("/api/v1/account/close", web::post().to(close_account))
        .route("/api/v1/account/me", web::get().to(show_account))
        .route("/api/v1/notices", web::get().to(list_notices))
        .route("/api/v1/boards/mine", web::get().to(my_boards));
}

async fn register(form: web::Json<SignupForm>, data: web::Data<Store>) -> Reply {
    let hashed = data.hasher.password(&form.password)?;
    data.accounts.add(&form.handle, &hashed).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn handle_taken(body: web::Json<Probe>, data: web::Data<Store>) -> Reply {
    let taken = data.accounts.handle_taken(&body.val).await?;
    Ok(HttpResponse::Ok().json(Taken { taken }))
}

async fn limits(data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(&data.settings.limits))
}

async fn pair_relay(body: web::Json<PairRequest>, data: web::Data<Store>) -> Reply {
    match data.pairings.get(&body.pair_token) {
        Some(relay) => {
            data.pairings.set(relay, body.secret.clone());
            Ok(HttpResponse::Ok().finish())
        }
        None => Err(Fault::WrongPassword),
    }
}

async fn create_board(id: Identity, body: web::Json<NewBoard>, data: web::Data<Store>) -> Reply {
    let board = data.boards.insert(&id, &body.title).await?;
    Ok(HttpResponse::Ok().json(board))
}

async fn rename_board(id: Identity, path: web::Path<String>, body: web::Json<NewBoard>, data: web::Data<Store>) -> Reply {
    let owner = id.identity().unwrap();
    let board = data.boards.find(&path).await?;
    if board.owner != owner {
        return Err(Fault::Forbidden);
    }
    data.boards.rename(&board.id, &body.title).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn delete_board(id: Identity, path: web::Path<String>, data: web::Data<Store>) -> Reply {
    let owner = id.identity().unwrap();
    let board = data.boards.find(&path).await?;
    if board.owner != owner {
        return Err(Fault::Forbidden);
    }
    data.boards.remove(&board.id).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn archive_board(id: Identity, path: web::Path<String>, data: web::Data<Store>) -> Reply {
    let owner = id.identity().unwrap();
    let board = data.boards.find(&path).await?;
    if board.owner != owner {
        return Err(Fault::Forbidden);
    }
    data.boards.archive(&board.id).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn purge_board(body: web::Json<BoardRef>, data: web::Data<Store>) -> Reply {
    data.boards.remove(&body.board_id).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn set_handle(id: Identity, body: web::Json<NewHandle>, data: web::Data<Store>) -> Reply {
    let owner = id.identity().unwrap();
    data.accounts.set_handle(&owner, &body.handle).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn set_bio(id: Identity, body: web::Json<NewBio>, data: web::Data<Store>) -> Reply {
    let owner = id.identity().unwrap();
    data.accounts.set_bio(&owner, &body.bio).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn close_account(body: web::Json<NewHandle>, data: web::Data<Store>) -> Reply {
    data.accounts.remove(&body.handle).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn show_account(id: Identity, data: web::Data<Store>) -> Reply {
    let account = data.accounts.find(&id).await?;
    Ok(HttpResponse::Ok().json(account))
}

async fn list_notices(id: Identity, data: web::Data<Store>) -> Reply {
    let notices = data.notices.for_account(&id).await?;
    Ok(HttpResponse::Ok().json(notices))
}

async fn my_boards(id: Identity, data: web::Data<Store>) -> Reply {
    let boards = data.boards.owned_by(&id).await?;
    Ok(HttpResponse::Ok().json(boards))
}

impl Accounts {
    async fn handle_taken(&self, handle: &str) -> StoreResult<bool> {
        self.rows.contains(handle)
    }
}
