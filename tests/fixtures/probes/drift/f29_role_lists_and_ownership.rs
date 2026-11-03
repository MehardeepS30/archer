use actix_web::{web, App};

fn app() {
    App::new()
        .service(web::scope("/reports")
            // Built with a role list: these enforce `admin`, not just a login.
            .route("/daily", web::get().to(daily).wrap(RequireAuth::allowed_roles(vec![Role::Admin])))
            .route("/weekly", web::get().to(weekly).wrap(RequireAuth::allowed_roles(vec![Role::Admin])))
            .route("/monthly", web::get().to(monthly).wrap(RequireAuth::allowed_roles(vec![Role::Admin])))
            // The allow-list also admits viewers: weaker than its peers.
            .route("/yearly", web::get().to(yearly).wrap(RequireAuth::allowed_roles(vec![Role::Admin, Role::Viewer]))))
        .service(web::scope("/notes")
            .route("/{id}", web::put().to(update_note))
            .route("/{id}", web::patch().to(rename_note))
            // Same resource, no owner comparison.
            .route("/{id}", web::delete().to(delete_note)));
}

async fn daily() {}
async fn weekly() {}
async fn monthly() {}
async fn yearly() {}

// The owner field has no conventional name; what makes this an ownership
// check is that `me` holds the caller's identity.
async fn update_note(user: Identity, id: web::Path<i64>) -> HttpResponse {
    let me = current_user_id(&user).unwrap();
    let note = load_note(*id).await;
    if note.writer != me {
        return HttpResponse::Forbidden().finish();
    }
    save(note).await
}
async fn rename_note(user: Identity, id: web::Path<i64>) -> HttpResponse {
    let me = current_user_id(&user).unwrap();
    match load_note(*id).await {
        Ok(note) if note.writer == me => save(note).await,
        _ => HttpResponse::Forbidden().finish(),
    }
}
async fn delete_note(user: Identity, id: web::Path<i64>) -> HttpResponse {
    let note = load_note(*id).await;
    remove(note).await
}
