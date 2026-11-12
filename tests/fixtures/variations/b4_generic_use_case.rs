// Variation b4_generic_use_case: Each route fills a use-case struct and a generic function runs it.
// Expected High/Medium findings: POST /notes/{id}/share.
use actix_web::{web, App, FromRequest, HttpRequest, HttpResponse, ResponseError};

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
