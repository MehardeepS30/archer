#!/usr/bin/env python3
"""Generates the variation fixtures (python3 generate.py <this directory>): one small notes app per way of writing
an authorization check. In each, three routes make the check and one
(POST /notes/{id}/share unless noted) does not."""
import os, sys, textwrap
out = sys.argv[1]

PRELUDE = '''use actix_web::{web, App, FromRequest, HttpRequest, HttpResponse, ResponseError};

#[derive(Debug)]
pub enum AppError {
    NotFound,
    Forbidden,
    Unauthorized,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error")
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            AppError::NotFound => actix_web::http::StatusCode::NOT_FOUND,
            AppError::Forbidden => actix_web::http::StatusCode::FORBIDDEN,
            AppError::Unauthorized => actix_web::http::StatusCode::UNAUTHORIZED,
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum Role {
    Admin,
    Member,
}

#[derive(Clone)]
pub struct AuthUser {
    pub id: u64,
    pub role: Role,
}

pub struct Note {
    pub id: u64,
    pub owner_id: u64,
    pub body: String,
}

#[derive(serde::Deserialize)]
pub struct NoteBody {
    pub body: String,
}

pub struct Db;

impl Db {
    pub async fn find_note(&self, id: u64) -> Result<Note, AppError> {
        sqlx::query_as("SELECT * FROM notes WHERE id = $1").bind(id).fetch_one(&self.pool).await.map_err(|_| AppError::NotFound)
    }
    pub async fn find_note_for(&self, id: u64, owner_id: u64) -> Result<Note, AppError> {
        sqlx::query_as("SELECT * FROM notes WHERE id = $1 AND owner_id = $2").bind(id).bind(owner_id).fetch_one(&self.pool).await.map_err(|_| AppError::NotFound)
    }
    pub async fn find_note_opt(&self, id: u64) -> Option<Note> {
        sqlx::query_as("SELECT * FROM notes WHERE id = $1").bind(id).fetch_optional(&self.pool).await.ok().flatten()
    }
    pub async fn save_note(&self, id: u64, body: &str) -> Result<(), AppError> {
        sqlx::query("UPDATE notes SET body = $2 WHERE id = $1").bind(id).bind(body).execute(&self.pool).await.map(|_| ()).map_err(|_| AppError::NotFound)
    }
    pub async fn delete_note(&self, id: u64) -> Result<(), AppError> {
        sqlx::query("DELETE FROM notes WHERE id = $1").bind(id).execute(&self.pool).await.map(|_| ()).map_err(|_| AppError::NotFound)
    }
    pub async fn archive_note(&self, id: u64) -> Result<(), AppError> {
        sqlx::query("UPDATE notes SET archived = true WHERE id = $1").bind(id).execute(&self.pool).await.map(|_| ()).map_err(|_| AppError::NotFound)
    }
    pub async fn pin_note(&self, id: u64) -> Result<(), AppError> {
        sqlx::query("UPDATE notes SET pinned = true WHERE id = $1").bind(id).execute(&self.pool).await.map(|_| ()).map_err(|_| AppError::NotFound)
    }
    pub async fn share_note(&self, id: u64) -> Result<(), AppError> {
        sqlx::query("UPDATE notes SET shared = true WHERE id = $1").bind(id).execute(&self.pool).await.map(|_| ()).map_err(|_| AppError::NotFound)
    }
}
'''

EXTRACTOR = '''
impl FromRequest for AuthUser {
    type Error = AppError;
    type Future = std::future::Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let token = match req.headers().get("authorization") {
            Some(token) => token,
            None => return std::future::ready(Err(AppError::Unauthorized)),
        };
        match decode(token) {
            Some(user) => std::future::ready(Ok(user)),
            None => std::future::ready(Err(AppError::Unauthorized)),
        }
    }
}
'''

ROUTES = '''
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/notes")
            .route("/{id}", web::get().to(get_note))
            .route("/{id}", web::put().to(update_note))
            .route("/{id}", web::delete().to(delete_note))
            .route("/{id}/archive", web::post().to(archive_note))
            .route("/{id}/pin", web::post().to(pin_note))
            .route("/{id}/share", web::post().to(share_note)),
    );
}
'''

ENSURE = '''
fn ensure_owner(user: &AuthUser, note: &Note) -> Result<(), AppError> {
    if note.owner_id != user.id {
        return Err(AppError::Forbidden);
    }
    Ok(())
}
'''

def handlers(sig, check, share_check, extra=''):
    """The four handlers. `check` loads `note` and holds it to `user`;
    `share_check` is what the drifting route does instead."""
    def body(text):
        return textwrap.indent(textwrap.dedent(text).strip('\n'), '    ')
    return f'''
async fn get_note({sig}) -> Result<HttpResponse, AppError> {{
{body(check)}
    Ok(HttpResponse::Ok().body(note.body))
}}

async fn update_note({sig}, body: web::Json<NoteBody>) -> Result<HttpResponse, AppError> {{
{body(check)}
    db.save_note(note.id, &body.body).await?;
    Ok(HttpResponse::Ok().finish())
}}

async fn delete_note({sig}) -> Result<HttpResponse, AppError> {{
{body(check)}
    db.delete_note(note.id).await?;
    Ok(HttpResponse::NoContent().finish())
}}

async fn archive_note({sig}) -> Result<HttpResponse, AppError> {{
{body(check)}
    db.archive_note(note.id).await?;
    Ok(HttpResponse::Ok().finish())
}}

async fn pin_note({sig}) -> Result<HttpResponse, AppError> {{
{body(check)}
    db.pin_note(note.id).await?;
    Ok(HttpResponse::Ok().finish())
}}

async fn share_note({sig}) -> Result<HttpResponse, AppError> {{
{body(share_check)}
    db.share_note(note.id).await?;
    Ok(HttpResponse::Ok().finish())
}}
{extra}'''

SIG = 'user: AuthUser, db: web::Data<Db>, id: web::Path<u64>'
PLAIN = 'let note = db.find_note(*id).await?;'
C1 = PLAIN + '''
if note.owner_id != user.id {
    return Err(AppError::Forbidden);
}'''

cases = {}

def case(name, doc, source, expected=('POST /notes/{id}/share',)):
    cases[name] = (doc, source, list(expected))

def simple(name, doc, check, share=PLAIN, extra='', sig=SIG, expected=('POST /notes/{id}/share',)):
    case(name, doc, PRELUDE + EXTRACTOR + ROUTES + handlers(sig, check, share, extra), expected)

# --- C: how the check is written, in the handler -------------------------
simple('c1_compare_and_return', 'A comparison with the caller that returns an error.', C1)
simple('c2_match_guard', 'A match guard on the loaded record.', '''
let note = match db.find_note(*id).await {
    Ok(note) if note.owner_id == user.id => note,
    _ => return Err(AppError::NotFound),
};''')
simple('c3_scoped_load', 'A load keyed by the record and the caller.', 'let note = db.find_note_for(*id, user.id).await?;')
simple('c4_check_function', 'A check function given the caller and the record.', PLAIN + '\nensure_owner(&user, &note)?;', extra=ENSURE)
simple('c5_let_else', 'A let-else on an owner test.', '''
let Some(note) = db.find_note_opt(*id).await.filter(|note| note.owner_id == user.id) else {
    return Err(AppError::NotFound);
};''', share='''
let Some(note) = db.find_note_opt(*id).await else {
    return Err(AppError::NotFound);
};''')
simple('c6_ok_or', 'A scoped lookup turned into an error with ok_or.', '''
let note = db.find_note_for(*id, user.id).await.ok().ok_or(AppError::NotFound)?;''')
simple('c7_role', 'A role comparison that returns an error.', PLAIN + '''
if user.role != Role::Admin {
    return Err(AppError::Forbidden);
}''')
simple('c8_compound_condition', 'The comparison is one side of a compound condition.', PLAIN + '''
if user.role != Role::Admin && note.owner_id != user.id {
    return Err(AppError::Forbidden);
}''')

# --- B: where the check lives -------------------------------------------
simple('b2_helper_function', 'The load and the comparison sit in a helper function.',
       'let note = load_owned(&db, &user, *id).await?;', extra='''
async fn load_owned(db: &Db, user: &AuthUser, id: u64) -> Result<Note, AppError> {
    let note = db.find_note(id).await?;
    if note.owner_id != user.id {
        return Err(AppError::Forbidden);
    }
    Ok(note)
}
''')

SERVICE = '''
pub struct NoteService {
    db: Db,
}

impl NoteService {
    pub async fn get(&self, user: &AuthUser, id: u64) -> Result<Note, AppError> {
        let note = self.db.find_note(id).await?;
        if note.owner_id != user.id {
            return Err(AppError::Forbidden);
        }
        Ok(note)
    }
    pub async fn update(&self, user: &AuthUser, id: u64, body: &str) -> Result<(), AppError> {
        let note = self.get(user, id).await?;
        self.db.save_note(note.id, body).await
    }
    pub async fn delete(&self, user: &AuthUser, id: u64) -> Result<(), AppError> {
        let note = self.get(user, id).await?;
        self.db.delete_note(note.id).await
    }
    pub async fn archive(&self, user: &AuthUser, id: u64) -> Result<(), AppError> {
        let note = self.get(user, id).await?;
        self.db.archive_note(note.id).await
    }
    pub async fn pin(&self, user: &AuthUser, id: u64) -> Result<(), AppError> {
        let note = self.get(user, id).await?;
        self.db.pin_note(note.id).await
    }
    pub async fn share(&self, user: &AuthUser, id: u64) -> Result<(), AppError> {
        let note = self.db.find_note(id).await?;
        self.db.share_note(note.id).await
    }
}

async fn get_note(user: AuthUser, service: web::Data<NoteService>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    let note = service.get(&user, *id).await?;
    Ok(HttpResponse::Ok().body(note.body))
}

async fn update_note(user: AuthUser, service: web::Data<NoteService>, id: web::Path<u64>, body: web::Json<NoteBody>) -> Result<HttpResponse, AppError> {
    service.update(&user, *id, &body.body).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn delete_note(user: AuthUser, service: web::Data<NoteService>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    service.delete(&user, *id).await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn archive_note(user: AuthUser, service: web::Data<NoteService>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    service.archive(&user, *id).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn pin_note(user: AuthUser, service: web::Data<NoteService>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    service.pin(&user, *id).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn share_note(user: AuthUser, service: web::Data<NoteService>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    service.share(&user, *id).await?;
    Ok(HttpResponse::Ok().finish())
}
'''
case('b3_service_method', 'The check sits in a service method the handler calls.', PRELUDE + EXTRACTOR + ROUTES + SERVICE)

USECASE = '''
pub struct Ctx {
    pub db: Db,
}

#[async_trait::async_trait]
pub trait UseCase {
    type Output;
    async fn execute(self, ctx: &Ctx) -> Result<Self::Output, AppError>;
}

pub async fn run<U: UseCase>(usecase: U, ctx: &Ctx) -> Result<U::Output, AppError> {
    usecase.execute(ctx).await
}

pub struct GetNote {
    pub user_id: u64,
    pub id: u64,
}

#[async_trait::async_trait]
impl UseCase for GetNote {
    type Output = Note;
    async fn execute(self, ctx: &Ctx) -> Result<Note, AppError> {
        match ctx.db.find_note(self.id).await {
            Ok(note) if note.owner_id == self.user_id => Ok(note),
            _ => Err(AppError::NotFound),
        }
    }
}

pub struct UpdateNote {
    pub user_id: u64,
    pub id: u64,
    pub body: String,
}

#[async_trait::async_trait]
impl UseCase for UpdateNote {
    type Output = ();
    async fn execute(self, ctx: &Ctx) -> Result<(), AppError> {
        let note = ctx.db.find_note(self.id).await?;
        if note.owner_id != self.user_id {
            return Err(AppError::Forbidden);
        }
        ctx.db.save_note(note.id, &self.body).await
    }
}

pub struct DeleteNote {
    pub user_id: u64,
    pub id: u64,
}

#[async_trait::async_trait]
impl UseCase for DeleteNote {
    type Output = ();
    async fn execute(self, ctx: &Ctx) -> Result<(), AppError> {
        let note = ctx.db.find_note(self.id).await?;
        if note.owner_id != self.user_id {
            return Err(AppError::Forbidden);
        }
        ctx.db.delete_note(note.id).await
    }
}

pub struct ArchiveNote {
    pub user_id: u64,
    pub id: u64,
}

#[async_trait::async_trait]
impl UseCase for ArchiveNote {
    type Output = ();
    async fn execute(self, ctx: &Ctx) -> Result<(), AppError> {
        let note = ctx.db.find_note(self.id).await?;
        if note.owner_id != self.user_id {
            return Err(AppError::Forbidden);
        }
        ctx.db.archive_note(note.id).await
    }
}

pub struct PinNote {
    pub user_id: u64,
    pub id: u64,
}

#[async_trait::async_trait]
impl UseCase for PinNote {
    type Output = ();
    async fn execute(self, ctx: &Ctx) -> Result<(), AppError> {
        let note = ctx.db.find_note(self.id).await?;
        if note.owner_id != self.user_id {
            return Err(AppError::Forbidden);
        }
        ctx.db.pin_note(note.id).await
    }
}

pub struct ShareNote {
    pub user_id: u64,
    pub id: u64,
}

#[async_trait::async_trait]
impl UseCase for ShareNote {
    type Output = ();
    async fn execute(self, ctx: &Ctx) -> Result<(), AppError> {
        let note = ctx.db.find_note(self.id).await?;
        ctx.db.share_note(note.id).await
    }
}

async fn get_note(user: AuthUser, ctx: web::Data<Ctx>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    let usecase = GetNote { user_id: user.id, id: *id };
    let note = run(usecase, &ctx).await?;
    Ok(HttpResponse::Ok().body(note.body))
}

async fn update_note(user: AuthUser, ctx: web::Data<Ctx>, id: web::Path<u64>, body: web::Json<NoteBody>) -> Result<HttpResponse, AppError> {
    let usecase = UpdateNote { user_id: user.id, id: *id, body: body.into_inner().body };
    run(usecase, &ctx).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn delete_note(user: AuthUser, ctx: web::Data<Ctx>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    let usecase = DeleteNote { user_id: user.id, id: *id };
    run(usecase, &ctx).await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn archive_note(user: AuthUser, ctx: web::Data<Ctx>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    let usecase = ArchiveNote { user_id: user.id, id: *id };
    run(usecase, &ctx).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn pin_note(user: AuthUser, ctx: web::Data<Ctx>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    let usecase = PinNote { user_id: user.id, id: *id };
    run(usecase, &ctx).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn share_note(user: AuthUser, ctx: web::Data<Ctx>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    let usecase = ShareNote { user_id: user.id, id: *id };
    run(usecase, &ctx).await?;
    Ok(HttpResponse::Ok().finish())
}
'''
case('b4_generic_use_case', 'Each route fills a use-case struct and a generic function runs it.', PRELUDE + EXTRACTOR + ROUTES + USECASE)

REPO = '''
#[async_trait::async_trait]
pub trait NoteRepo {
    async fn find_owned(&self, id: u64, owner_id: u64) -> Result<Note, AppError>;
    async fn find(&self, id: u64) -> Result<Note, AppError>;
}

pub struct PgNotes {
    db: Db,
}

#[async_trait::async_trait]
impl NoteRepo for PgNotes {
    async fn find_owned(&self, id: u64, owner_id: u64) -> Result<Note, AppError> {
        let note = self.db.find_note(id).await?;
        if note.owner_id != owner_id {
            return Err(AppError::Forbidden);
        }
        Ok(note)
    }
    async fn find(&self, id: u64) -> Result<Note, AppError> {
        self.db.find_note(id).await
    }
}
'''
case('b5_trait_object', 'The check sits behind a trait object with one implementor.',
     PRELUDE + EXTRACTOR + ROUTES + REPO + handlers(
         'user: AuthUser, repo: web::Data<std::sync::Arc<dyn NoteRepo>>, db: web::Data<Db>, id: web::Path<u64>',
         'let note = repo.find_owned(*id, user.id).await?;',
         'let note = repo.find(*id).await?;'))

# --- D: things that look like a check and are not ------------------------
def non_check(name, doc, share, extra=ENSURE):
    simple(name, doc, C1, share=PLAIN + '\n' + textwrap.dedent(share).strip('\n'), extra=extra)

non_check('d1_result_dropped_with_ok', 'The drifting route calls the check and drops its result with .ok().',
          'ensure_owner(&user, &note).ok();')
non_check('d2_result_bound_to_underscore', 'The drifting route binds the check result to _.',
          'let _ = ensure_owner(&user, &note);')
non_check('d3_only_logs', 'The drifting route compares and only logs.', '''
if note.owner_id != user.id {
    log::warn!("note {} read by another user", note.id);
}''')
non_check('d4_if_let_ok_without_else', 'The drifting route tests the check and goes on either way.', '''
if let Ok(()) = ensure_owner(&user, &note) {
    log::info!("owner");
}''')
non_check('d5_match_with_empty_error_arm', 'The drifting route matches on the check and ignores the error arm.', '''
match ensure_owner(&user, &note) {
    Ok(()) => {}
    Err(_) => {}
}''')
simple('d6_check_switched_off_by_argument', 'One function checks only when told to; the drifting route passes None.',
       PLAIN + '\ncheck_access(&user, &note, Some(note.owner_id))?;',
       share=PLAIN + '\ncheck_access(&user, &note, None)?;', extra='''
fn check_access(user: &AuthUser, note: &Note, owner: Option<u64>) -> Result<(), AppError> {
    if let Some(owner) = owner {
        if owner != user.id {
            return Err(AppError::Forbidden);
        }
    }
    Ok(())
}
''')

# --- A: where the caller comes from --------------------------------------
OPTIONAL_EXTRACTOR = '''
pub async fn authenticate(req: actix_web::dev::ServiceRequest, next: actix_web::middleware::Next<impl actix_web::body::MessageBody>) -> Result<actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>, actix_web::Error> {
    if let Some(token) = req.headers().get("authorization") {
        if let Some(user) = decode(token) {
            req.extensions_mut().insert(user);
        }
    }
    next.call(req).await
}
'''
A_ROUTES_WRAPPED = ROUTES.replace('web::scope("/notes")', 'web::scope("/notes")\n            .wrap(actix_web::middleware::from_fn(authenticate))')

simple('a2_option_extractor_with_ok_or', 'The caller is an Option extractor that each route turns into an error.',
       'let user = user.ok_or(AppError::Unauthorized)?;\n' + C1,
       share='let user = user.ok_or(AppError::Unauthorized)?;\n' + PLAIN,
       sig='user: Option<AuthUser>, db: web::Data<Db>, id: web::Path<u64>')
simple('a3_option_extractor_never_required', 'The drifting route takes the optional caller and never requires one.',
       'let user = user.ok_or(AppError::Unauthorized)?;\n' + C1,
       share=PLAIN,
       sig='user: Option<AuthUser>, db: web::Data<Db>, id: web::Path<u64>')

CURRENT_USER = '''
fn current_user(req: &HttpRequest) -> Result<AuthUser, AppError> {
    match req.extensions().get::<AuthUser>() {
        Some(user) => Ok(user.clone()),
        None => Err(AppError::Unauthorized),
    }
}
'''
case('a4_caller_from_request_extensions', 'Pass-through middleware stores the caller; a helper requires it.',
     PRELUDE + OPTIONAL_EXTRACTOR + A_ROUTES_WRAPPED + CURRENT_USER + handlers(
         'req: HttpRequest, db: web::Data<Db>, id: web::Path<u64>',
         'let user = current_user(&req)?;\n' + C1,
         'let user = current_user(&req)?;\n' + PLAIN))
case('a5_caller_never_required', 'Pass-through middleware stores the caller; the drifting route never asks for it.',
     PRELUDE + OPTIONAL_EXTRACTOR + A_ROUTES_WRAPPED + CURRENT_USER + handlers(
         'req: HttpRequest, db: web::Data<Db>, id: web::Path<u64>',
         'let user = current_user(&req)?;\n' + C1,
         PLAIN))

ACTOR = '''
#[derive(Clone)]
pub enum Actor {
    None,
    User(AuthUser),
}

impl FromRequest for Actor {
    type Error = AppError;
    type Future = std::future::Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        std::future::ready(Ok(req.extensions().get::<Actor>().cloned().unwrap_or(Actor::None)))
    }
}

pub struct ActorMiddleware<S> {
    service: S,
}

impl<S, B> actix_web::dev::Service<actix_web::dev::ServiceRequest> for ActorMiddleware<S>
where
    S: actix_web::dev::Service<actix_web::dev::ServiceRequest, Response = actix_web::dev::ServiceResponse<B>, Error = actix_web::Error>,
{
    type Response = actix_web::dev::ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = S::Future;

    fn call(&self, req: actix_web::dev::ServiceRequest) -> Self::Future {
        let mut actor = Actor::None;
        if let Some(token) = req.headers().get("authorization") {
            if let Some(user) = decode(token) {
                actor = Actor::User(user);
            }
        }
        req.extensions_mut().insert(actor);
        self.service.call(req)
    }
}

pub struct Notes {
    db: Db,
}

impl Notes {
    fn current_user(&self, actor: Actor) -> Result<AuthUser, AppError> {
        match actor {
            Actor::User(user) => Ok(user),
            _ => Err(AppError::Unauthorized),
        }
    }
    pub async fn get(&self, actor: Actor, id: u64) -> Result<Note, AppError> {
        let user = self.current_user(actor)?;
        let note = self.db.find_note(id).await?;
        if note.owner_id != user.id {
            return Err(AppError::Forbidden);
        }
        Ok(note)
    }
    pub async fn update(&self, actor: Actor, id: u64, body: &str) -> Result<(), AppError> {
        let user = self.current_user(actor)?;
        let note = self.db.find_note(id).await?;
        if note.owner_id != user.id {
            return Err(AppError::Forbidden);
        }
        self.db.save_note(note.id, body).await
    }
    pub async fn delete(&self, actor: Actor, id: u64) -> Result<(), AppError> {
        let user = self.current_user(actor)?;
        let note = self.db.find_note(id).await?;
        if note.owner_id != user.id {
            return Err(AppError::Forbidden);
        }
        self.db.delete_note(note.id).await
    }
    pub async fn archive(&self, actor: Actor, id: u64) -> Result<(), AppError> {
        let user = self.current_user(actor)?;
        let note = self.db.find_note(id).await?;
        if note.owner_id != user.id {
            return Err(AppError::Forbidden);
        }
        self.db.archive_note(note.id).await
    }
    pub async fn pin(&self, actor: Actor, id: u64) -> Result<(), AppError> {
        let user = self.current_user(actor)?;
        let note = self.db.find_note(id).await?;
        if note.owner_id != user.id {
            return Err(AppError::Forbidden);
        }
        self.db.pin_note(note.id).await
    }
    pub async fn share(&self, actor: Actor, id: u64) -> Result<(), AppError> {
        SHARE_BODY
    }
}

async fn get_note(actor: Actor, notes: web::Data<Notes>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    let note = notes.get(actor, *id).await?;
    Ok(HttpResponse::Ok().body(note.body))
}

async fn update_note(actor: Actor, notes: web::Data<Notes>, id: web::Path<u64>, body: web::Json<NoteBody>) -> Result<HttpResponse, AppError> {
    notes.update(actor, *id, &body.body).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn delete_note(actor: Actor, notes: web::Data<Notes>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    notes.delete(actor, *id).await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn archive_note(actor: Actor, notes: web::Data<Notes>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    notes.archive(actor, *id).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn pin_note(actor: Actor, notes: web::Data<Notes>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    notes.pin(actor, *id).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn share_note(actor: Actor, notes: web::Data<Notes>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    notes.share(actor, *id).await?;
    Ok(HttpResponse::Ok().finish())
}
'''
case('a6_maybe_caller_narrowed_in_service', 'A caller value that may be "no caller"; the service narrows it. The drifting route skips the owner test.',
     PRELUDE + ROUTES + ACTOR.replace('SHARE_BODY', '''let user = self.current_user(actor)?;
        let note = self.db.find_note(id).await?;
        self.db.share_note(note.id).await'''))
case('a7_maybe_caller_never_narrowed', 'A caller value that may be "no caller"; the drifting route never narrows it.',
     PRELUDE + ROUTES + ACTOR.replace('SHARE_BODY', '''let note = self.db.find_note(id).await?;
        self.db.share_note(note.id).await'''))

REJECTING = '''
pub async fn require_login(req: actix_web::dev::ServiceRequest, next: actix_web::middleware::Next<impl actix_web::body::MessageBody>) -> Result<actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>, actix_web::Error> {
    let user = match req.headers().get("authorization").and_then(decode) {
        Some(user) => user,
        None => return Err(actix_web::error::ErrorUnauthorized("log in")),
    };
    req.extensions_mut().insert(user);
    next.call(req).await
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/notes")
            .wrap(actix_web::middleware::from_fn(require_login))
            .route("/{id}", web::get().to(get_note))
            .route("/{id}", web::put().to(update_note))
            .route("/{id}", web::delete().to(delete_note))
            .route("/{id}/archive", web::post().to(archive_note))
            .route("/{id}/pin", web::post().to(pin_note)),
    )
    .route("/notes/{id}/share", web::post().to(share_note));
}
'''
case('a8_route_outside_the_wrapped_scope', 'Middleware that rejects wraps the scope; one route is registered outside it.',
     PRELUDE + REJECTING + handlers('db: web::Data<Db>, id: web::Path<u64>', PLAIN, PLAIN))

os.makedirs(out, exist_ok=True)
for name, (doc, source, expected) in cases.items():
    text = f'// Variation {name}: {doc}\n// Expected High/Medium findings: {", ".join(expected) or "none"}.\n' + source
    open(os.path.join(out, name + '.rs'), 'w').write(text)
print(len(cases), 'cases')
