use actix_web::{Error, FromRequest, HttpRequest, dev::Payload, error, web};
use std::future::{Ready, ready};

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/team")
            // Writes behind `StaffGate`, whose name says nothing; its body
            // rejects callers that are not admins.
            .route("/archive", web::post().to(archive_team))
            .route("/transfer", web::post().to(transfer_team))
            .route("/purge", web::post().to(purge_team))
            // Only a logged-in caller: the drift.
            .route("/rename", web::post().to(rename_team))
            .route("/members", web::get().to(list_members))
            .route("/billing", web::get().to(billing)),
    );
}

pub enum Role {
    Owner,
    Member,
}

pub struct LoggedUser {
    pub id: u64,
    pub role: Role,
    pub is_admin: bool,
}

/// Admits only owners: a role check, by the variant its body accepts.
pub struct OwnerOnly {
    pub user: LoggedUser,
}

pub struct StaffGate(LoggedUser);

/// Loads request data and rejects malformed requests; checks no caller.
pub struct TeamData {
    pub team: u64,
}

impl FromRequest for LoggedUser {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        match req.headers().get("authorization") {
            Some(token) => ready(Ok(decode(token))),
            None => ready(Err(error::ErrorUnauthorized("log in"))),
        }
    }
}

impl FromRequest for OwnerOnly {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let user = current_user(req);
        match user.role {
            Role::Owner => ready(Ok(OwnerOnly { user })),
            _ => ready(Err(error::ErrorForbidden("owners only"))),
        }
    }
}

impl FromRequest for StaffGate {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let user = current_user(req);
        if user.is_admin {
            ready(Ok(StaffGate(user)))
        } else {
            ready(Err(error::ErrorForbidden("staff only")))
        }
    }
}

impl FromRequest for TeamData {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let team = req
            .match_info()
            .get("team")
            .ok_or(error::ErrorBadRequest("team"));
        ready(team.map(|team| TeamData {
            team: team.parse().unwrap_or(0),
        }))
    }
}

async fn archive_team(_gate: StaffGate, team: TeamData) {}
async fn transfer_team(_gate: StaffGate, team: TeamData) {}
async fn purge_team(_gate: StaffGate, team: TeamData) {}
async fn rename_team(_user: LoggedUser, team: TeamData) {}
async fn list_members(_owner: OwnerOnly) {}
async fn billing(_owner: OwnerOnly) {}
