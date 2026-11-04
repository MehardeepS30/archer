use actix_web::{web, App, HttpRequest};

// Reads under /forum take an optional caller and hand it to the instance's
// privacy check. `get_multi` takes the caller too but never checks it.
// `get_tags` makes a check of its own (`check_tag_access`), so it follows a
// different policy, not none.
fn app() {
    App::new()
        .service(
            web::scope("/forum")
                .route("/posts", web::get().to(get_posts))
                .route("/comments", web::get().to(get_comments))
                .route("/communities", web::get().to(get_communities))
                .route("/people", web::get().to(get_people))
                .route("/multi", web::get().to(get_multi))
                .route("/tags", web::get().to(get_tags)),
        )
        .service(
            web::scope("/billing")
                .route("/evidence", web::post().to(submit_evidence))
                .route("/evidence", web::put().to(attach_evidence))
                .route("/evidence", web::delete().to(delete_evidence))
                .route("/evidence/purge", web::post().to(purge_evidence))
                // An inline closure that only forwards its arguments is the
                // function it forwards to.
                .route("/evidence/{id}", web::patch().to(|req, path| update_evidence(req, path))),
        );
}

async fn get_posts(user: Option<LocalUserView>, site: web::Data<Site>) {
    check_private_instance(&user, &site)?;
}
async fn get_comments(user: Option<LocalUserView>, site: web::Data<Site>) {
    check_private_instance(&user, &site)?;
}
async fn get_communities(local_user_view: Option<LocalUserView>, site: web::Data<Site>) {
    check_private_instance(&local_user_view, &site)?;
}
async fn get_people(user: Option<LocalUserView>, site: web::Data<Site>) {
    check_private_instance(&user, &site)?;
}
async fn get_multi(user: Option<LocalUserView>, site: web::Data<Site>) {
    let multi = MultiView::read(&site, &user)?;
}
async fn get_tags(user: Option<LocalUserView>, site: web::Data<Site>) {
    check_tag_access(&user, &site)?;
}

// Writes under /billing pass the caller's profile to a service function
// that checks it against the record. `delete_evidence` binds the caller as
// `_`. `purge_evidence` uses an admin scheme that yields no caller.
async fn submit_evidence(req: HttpRequest) {
    server_wrap(req, |state, auth: AuthData, body| evidence::submit(state, auth.profile_id, body), &auth::ApiKeyAuth)
}
async fn attach_evidence(req: HttpRequest) {
    server_wrap(req, |state, auth: AuthData, body| evidence::attach(state, auth.profile_id, body), &auth::ApiKeyAuth)
}
async fn update_evidence(req: HttpRequest, path: web::Path<String>) {
    server_wrap(req, |state, auth: AuthData, body| evidence::attach(state, auth.profile_id, body), &auth::ApiKeyAuth)
}
async fn delete_evidence(req: HttpRequest) {
    server_wrap(req, |state, _, body| evidence::delete(state, body), &auth::ApiKeyAuth)
}
async fn purge_evidence(req: HttpRequest) {
    server_wrap(req, |state, _, body| evidence::purge(state, body), &auth::AdminApiAuth)
}

mod evidence {
    pub async fn submit(state: State, profile_id: Option<String>, body: Body) {
        let dispute = state.find_dispute(&body.id)?;
        validate_profile(profile_id, &dispute)?;
    }
    pub async fn attach(state: State, profile_id: Option<String>, body: Body) {
        let dispute = state.find_dispute(&body.id)?;
        validate_profile(profile_id, &dispute)?;
    }
    pub async fn delete(state: State, body: Body) {
        state.delete_evidence(&body.id)?;
    }
    pub async fn purge(state: State, body: Body) {
        state.purge(&body.id)?;
    }
}
