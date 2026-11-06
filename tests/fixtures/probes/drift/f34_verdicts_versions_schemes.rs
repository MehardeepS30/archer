use actix_web::{web, App, HttpRequest};

fn app() {
    App::new()
        // Each resource is its own scope, so only the version prefix pools
        // them. `get_multi` is alone in its scope and skips the check the
        // other reads under /api/v2 make.
        .service(
            web::scope("/api/v2")
                .service(web::scope("/posts").route("", web::get().to(get_posts)))
                .service(web::scope("/comments").route("", web::get().to(get_comments)))
                .service(web::scope("/people").route("", web::get().to(get_people)))
                .service(web::scope("/communities").route("", web::get().to(get_communities)))
                .service(web::scope("/search").route("", web::get().to(search)))
                .service(web::scope("/feeds").route("", web::get().to(get_feeds)))
                .service(web::scope("/multi").route("", web::get().to(get_multi))),
        )
        // Writes that all refresh the caller's profile: a call that returns
        // data, not a verdict. `rename` does not; it is not reported.
        .service(
            web::scope("/profile")
                .route("/bio", web::post().to(set_bio))
                .route("/avatar", web::post().to(set_avatar))
                .route("/banner", web::post().to(set_banner))
                .route("/name", web::post().to(rename)),
        )
        // Writes that authenticate with an API key. `export` admits anyone
        // but still expects a caller; `schema` admits anyone and takes none.
        .service(
            web::scope("/reports")
                .route("/run", web::post().to(run_report))
                .route("/schedule", web::post().to(schedule_report))
                .route("/cancel", web::post().to(cancel_report))
                .route("/export", web::post().to(export_report))
                .route("/schema", web::post().to(report_schema)),
        );
}

async fn get_posts(user: Option<LocalUserView>, site: web::Data<Site>) { check_private_instance(&user, &site)?; }
async fn get_comments(user: Option<LocalUserView>, site: web::Data<Site>) { check_private_instance(&user, &site)?; }
async fn get_people(user: Option<LocalUserView>, site: web::Data<Site>) { check_private_instance(&user, &site)?; }
async fn get_communities(user: Option<LocalUserView>, site: web::Data<Site>) { check_private_instance(&user, &site)?; }
async fn search(user: Option<LocalUserView>, site: web::Data<Site>) { check_private_instance(&user, &site)?; }
async fn get_feeds(user: Option<LocalUserView>, site: web::Data<Site>) { check_private_instance(&user, &site)?; }
async fn get_multi(user: Option<LocalUserView>, site: web::Data<Site>) { let multi = MultiView::read(&site, &user)?; }

// A verdict: it rejects in a branch on the caller.
fn check_private_instance(user: &Option<LocalUserView>, site: &Site) -> LemmyResult<()> {
    if user.is_none() && site.private_instance { return Err(LemmyErrorType::InstanceIsPrivate.into()); }
    Ok(())
}

async fn set_bio(user: LocalUserView) { refresh_profile(&user)?; }
async fn set_avatar(user: LocalUserView) { refresh_profile(&user)?; }
async fn set_banner(user: LocalUserView) { refresh_profile(&user)?; }
async fn rename(user: LocalUserView) { let name = user.person.name.clone(); }

fn refresh_profile(user: &LocalUserView) -> LemmyResult<Profile> { todo!() }

async fn run_report(req: HttpRequest) { server_wrap(req, |state, auth: AuthData, body| reports::run(state, auth, body), &auth::ApiKeyAuth) }
async fn schedule_report(req: HttpRequest) { server_wrap(req, |state, auth: AuthData, body| reports::run(state, auth, body), &auth::ApiKeyAuth) }
async fn cancel_report(req: HttpRequest) { server_wrap(req, |state, auth: AuthData, body| reports::run(state, auth, body), &auth::ApiKeyAuth) }
async fn export_report(req: HttpRequest) { server_wrap(req, |state, auth: AuthData, body| reports::run(state, auth, body), &auth::NoAuth) }
async fn report_schema(req: HttpRequest) { server_wrap(req, |state, (), body| reports::schema(state, body), &auth::NoAuth) }
