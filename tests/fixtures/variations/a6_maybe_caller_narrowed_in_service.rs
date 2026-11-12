// Variation a6_maybe_caller_narrowed_in_service: A caller value that may be "no caller"; the service narrows it. The drifting route skips the owner test.
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
        let user = self.current_user(actor)?;
        let note = self.db.find_note(id).await?;
        self.db.share_note(note.id).await
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
