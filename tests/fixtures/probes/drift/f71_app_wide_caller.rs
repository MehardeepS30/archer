use actix_web::{web, App, HttpResponse};

// Every write of this application takes the signed-in `Member`, in twenty-four
// separate scopes. `import_rules` writes with no caller at all and does not
// read the request itself, so nothing in it can authenticate anyone. No
// single scope has enough peers to say so; the whole application does.
// `receive_hook` also takes no `Member`, but it reads the raw request (a
// signed webhook checks its own signature), so it stays Low.
pub struct Member {
    pub id: u64,
}

impl actix_web::FromRequest for Member {
    type Error = actix_web::Error;
    type Future = std::future::Ready<Result<Self, Self::Error>>;
    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        std::future::ready(match req.cookie("sid") {
            Some(_) => Ok(Member { id: 1 }),
            None => Err(actix_web::error::ErrorUnauthorized("log in")),
        })
    }
}

async fn create_notes(member: Member, body: web::Json<String>) -> HttpResponse {
    db::notes::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_tags(member: Member, body: web::Json<String>) -> HttpResponse {
    db::tags::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_files(member: Member, body: web::Json<String>) -> HttpResponse {
    db::files::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_teams(member: Member, body: web::Json<String>) -> HttpResponse {
    db::teams::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_plans(member: Member, body: web::Json<String>) -> HttpResponse {
    db::plans::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_labels(member: Member, body: web::Json<String>) -> HttpResponse {
    db::labels::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_boards(member: Member, body: web::Json<String>) -> HttpResponse {
    db::boards::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_cards(member: Member, body: web::Json<String>) -> HttpResponse {
    db::cards::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_lists(member: Member, body: web::Json<String>) -> HttpResponse {
    db::lists::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_rules(member: Member, body: web::Json<String>) -> HttpResponse {
    db::rules::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_hooks(member: Member, body: web::Json<String>) -> HttpResponse {
    db::hooks::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_views(member: Member, body: web::Json<String>) -> HttpResponse {
    db::views::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_pages(member: Member, body: web::Json<String>) -> HttpResponse {
    db::pages::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_posts(member: Member, body: web::Json<String>) -> HttpResponse {
    db::posts::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_drafts(member: Member, body: web::Json<String>) -> HttpResponse {
    db::drafts::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_links(member: Member, body: web::Json<String>) -> HttpResponse {
    db::links::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_votes(member: Member, body: web::Json<String>) -> HttpResponse {
    db::votes::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_flags(member: Member, body: web::Json<String>) -> HttpResponse {
    db::flags::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_roles(member: Member, body: web::Json<String>) -> HttpResponse {
    db::roles::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_users(member: Member, body: web::Json<String>) -> HttpResponse {
    db::users::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_keys(member: Member, body: web::Json<String>) -> HttpResponse {
    db::keys::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_jobs(member: Member, body: web::Json<String>) -> HttpResponse {
    db::jobs::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_runs(member: Member, body: web::Json<String>) -> HttpResponse {
    db::runs::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn create_logs(member: Member, body: web::Json<String>) -> HttpResponse {
    db::logs::insert(member.id, body.into_inner());
    HttpResponse::Created().finish()
}
async fn import_rules(body: web::Json<Vec<String>>) -> HttpResponse {
    db::rules::insert_all(body.into_inner());
    HttpResponse::Created().finish()
}
async fn receive_hook(req: actix_web::HttpRequest, body: web::Bytes) -> HttpResponse {
    if !signature::valid(&req, &body) {
        return HttpResponse::BadRequest().finish();
    }
    db::hooks::record(body);
    HttpResponse::Ok().finish()
}

fn main() {
    App::new()
        .service(web::scope("/notes").route("", web::post().to(create_notes)))
        .service(web::scope("/tags").route("", web::post().to(create_tags)))
        .service(web::scope("/files").route("", web::post().to(create_files)))
        .service(web::scope("/teams").route("", web::post().to(create_teams)))
        .service(web::scope("/plans").route("", web::post().to(create_plans)))
        .service(web::scope("/labels").route("", web::post().to(create_labels)))
        .service(web::scope("/boards").route("", web::post().to(create_boards)))
        .service(web::scope("/cards").route("", web::post().to(create_cards)))
        .service(web::scope("/lists").route("", web::post().to(create_lists)))
        .service(web::scope("/rules").route("", web::post().to(create_rules)))
        .service(web::scope("/hooks").route("", web::post().to(create_hooks)))
        .service(web::scope("/views").route("", web::post().to(create_views)))
        .service(web::scope("/pages").route("", web::post().to(create_pages)))
        .service(web::scope("/posts").route("", web::post().to(create_posts)))
        .service(web::scope("/drafts").route("", web::post().to(create_drafts)))
        .service(web::scope("/links").route("", web::post().to(create_links)))
        .service(web::scope("/votes").route("", web::post().to(create_votes)))
        .service(web::scope("/flags").route("", web::post().to(create_flags)))
        .service(web::scope("/roles").route("", web::post().to(create_roles)))
        .service(web::scope("/users").route("", web::post().to(create_users)))
        .service(web::scope("/keys").route("", web::post().to(create_keys)))
        .service(web::scope("/jobs").route("", web::post().to(create_jobs)))
        .service(web::scope("/runs").route("", web::post().to(create_runs)))
        .service(web::scope("/logs").route("", web::post().to(create_logs)))
        .service(web::scope("/imports").route("/rules", web::post().to(import_rules)))
        .service(web::scope("/incoming").route("/hook", web::post().to(receive_hook)));
}
