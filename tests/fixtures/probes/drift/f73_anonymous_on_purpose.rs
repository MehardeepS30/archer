use actix_web::{web, App, HttpRequest, HttpResponse};

// Routes that serve anonymous callers on purpose, beside routes that
// require the caller. Reads under /api/v2/library call `current_user` and
// fail without one. `shelves/{shelf_id}` calls it too but keeps a failed
// login as `None` and goes on: the anonymous case is written out, so the
// finding is kept at Low. `loans/{loan_id}` takes no caller at all and has
// nothing that says it is open: it stays High. Writes under
// /api/v2/payments require the caller; `provider` is handled by
// `provider_webhook`, a name that says another service calls it: Low.
fn app() {
    App::new()
        .route("/api/v2/library/books", web::get().to(list_books))
        .route("/api/v2/library/books/{book_id}", web::get().to(show_book))
        .route("/api/v2/library/members", web::get().to(list_members))
        .route("/api/v2/library/members/{member_id}", web::get().to(show_member))
        .route("/api/v2/library/shelves/{shelf_id}", web::get().to(show_shelf))
        .route("/api/v2/library/loans/{loan_id}", web::get().to(show_loan))
        .route("/api/v2/payments/charges", web::post().to(create_charge))
        .route("/api/v2/payments/refunds", web::post().to(create_refund))
        .route("/api/v2/payments/payouts", web::post().to(create_payout))
        .route("/api/v2/payments/provider", web::post().to(provider_webhook));
}

async fn current_user(req: &HttpRequest, data: &Store) -> Result<User, ApiError> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    let user_id = decode_token(token).map_err(|_| ApiError::Unauthorized)?;
    data.users.find(user_id).await?.ok_or(ApiError::Unauthorized)
}

async fn list_books(req: HttpRequest, data: web::Data<Store>) -> Reply {
    let user = current_user(&req, &data).await?;
    Ok(HttpResponse::Ok().json(data.books.for_user(user.id).await?))
}

async fn show_book(req: HttpRequest, path: web::Path<i64>, data: web::Data<Store>) -> Reply {
    let user = current_user(&req, &data).await?;
    Ok(HttpResponse::Ok().json(data.books.find(user.id, *path).await?))
}

async fn list_members(req: HttpRequest, data: web::Data<Store>) -> Reply {
    let user = current_user(&req, &data).await?;
    Ok(HttpResponse::Ok().json(data.members.for_user(user.id).await?))
}

async fn show_member(req: HttpRequest, path: web::Path<i64>, data: web::Data<Store>) -> Reply {
    let user = current_user(&req, &data).await?;
    Ok(HttpResponse::Ok().json(data.members.find(user.id, *path).await?))
}

async fn show_shelf(req: HttpRequest, path: web::Path<i64>, data: web::Data<Store>) -> Reply {
    let user = current_user(&req, &data).await.ok();
    let shelf = data.shelves.find(*path).await?;
    Ok(HttpResponse::Ok().json(shelf.visible_to(user.as_ref())))
}

async fn show_loan(path: web::Path<i64>, data: web::Data<Store>) -> Reply {
    Ok(HttpResponse::Ok().json(data.loans.find(*path).await?))
}

async fn create_charge(req: HttpRequest, body: web::Json<Charge>, data: web::Data<Store>) -> Reply {
    let user = current_user(&req, &data).await?;
    Ok(HttpResponse::Ok().json(data.charges.create(user.id, body.into_inner()).await?))
}

async fn create_refund(req: HttpRequest, body: web::Json<Refund>, data: web::Data<Store>) -> Reply {
    let user = current_user(&req, &data).await?;
    Ok(HttpResponse::Ok().json(data.refunds.create(user.id, body.into_inner()).await?))
}

async fn create_payout(req: HttpRequest, body: web::Json<Payout>, data: web::Data<Store>) -> Reply {
    let user = current_user(&req, &data).await?;
    Ok(HttpResponse::Ok().json(data.payouts.create(user.id, body.into_inner()).await?))
}

async fn provider_webhook(body: web::Bytes, data: web::Data<Store>) -> Reply {
    let event = data.provider.parse_event(&body)?;
    data.charges.settle(event).await?;
    Ok(HttpResponse::Ok().finish())
}
