// Variation a8_route_outside_the_wrapped_scope: Middleware that rejects wraps the scope; one route is registered outside it.
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

async fn get_note(db: web::Data<Db>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    let note = db.find_note(*id).await?;
    Ok(HttpResponse::Ok().body(note.body))
}

async fn update_note(db: web::Data<Db>, id: web::Path<u64>, body: web::Json<NoteBody>) -> Result<HttpResponse, AppError> {
    let note = db.find_note(*id).await?;
    db.save_note(note.id, &body.body).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn delete_note(db: web::Data<Db>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    let note = db.find_note(*id).await?;
    db.delete_note(note.id).await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn archive_note(db: web::Data<Db>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    let note = db.find_note(*id).await?;
    db.archive_note(note.id).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn pin_note(db: web::Data<Db>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    let note = db.find_note(*id).await?;
    db.pin_note(note.id).await?;
    Ok(HttpResponse::Ok().finish())
}

async fn share_note(db: web::Data<Db>, id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    let note = db.find_note(*id).await?;
    db.share_note(note.id).await?;
    Ok(HttpResponse::Ok().finish())
}
