use actix_web::{http::header::HeaderMap, web, App, HttpRequest, HttpResponse};

// Handlers pass an authentication object to `guarded`, which runs its
// `admit` on the request headers. What each object checks is read from its
// `admit`: `Open` admits anyone, `Member` reads a session, `Grant` also
// checks a permission, `TeamGrant` also holds the session to the team the
// route names, `Keyed` hands the request to the object it wraps, and
// `either` picks one of two objects by a header. The label route takes a
// team but passes `Grant`, which does not hold the caller to it. `Operator`
// compares a presented key with one from the configuration.
fn app() {
    App::new()
        .service(
            web::scope("/teams/{team_id}")
                .route("/boards", web::get().to(list_boards))
                .route("/boards", web::post().to(add_board))
                .route("/boards/{board_id}", web::delete().to(remove_board))
                .route("/labels", web::post().to(add_label)),
        )
        .route("/status", web::get().to(status))
        .route("/me", web::get().to(me))
        .route("/outside", web::get().to(outside))
        .route("/maintenance/purge", web::post().to(purge));
}

pub struct Denied;
pub struct Session {
    pub team_id: String,
    pub role: String,
}
#[derive(Clone, Copy)]
pub enum Need {
    BoardRead,
    BoardWrite,
    LabelWrite,
}

pub trait Gate<T> {
    fn admit(&self, headers: &HeaderMap) -> Result<T, Denied>;
}

fn read_session(headers: &HeaderMap) -> Result<Session, Denied> {
    let value = headers.get("x-session").ok_or(Denied)?;
    decode_session(value)
}

fn require_permission(need: Need, role: &str) -> Result<(), Denied> {
    lookup_grants(role).contains(need).then_some(()).ok_or(Denied)
}

pub struct Open;
impl Gate<()> for Open {
    fn admit(&self, _headers: &HeaderMap) -> Result<(), Denied> {
        Ok(())
    }
}

pub struct Member;
impl Gate<Session> for Member {
    fn admit(&self, headers: &HeaderMap) -> Result<Session, Denied> {
        read_session(headers)
    }
}

pub struct Grant {
    pub need: Need,
}
impl Gate<Session> for Grant {
    fn admit(&self, headers: &HeaderMap) -> Result<Session, Denied> {
        let session = read_session(headers)?;
        require_permission(self.need, &session.role)?;
        Ok(session)
    }
}

pub struct TeamGrant {
    pub team_id: String,
    pub need: Need,
}
impl Gate<Session> for TeamGrant {
    fn admit(&self, headers: &HeaderMap) -> Result<Session, Denied> {
        let session = read_session(headers)?;
        require_permission(self.need, &session.role)?;
        if session.team_id != self.team_id {
            return Err(Denied);
        }
        Ok(session)
    }
}

pub struct Operator;
impl Gate<()> for Operator {
    fn admit(&self, headers: &HeaderMap) -> Result<(), Denied> {
        let presented = headers.get("x-operator").ok_or(Denied)?;
        let expected = &settings().secrets.operator_key;
        if presented != expected.as_str() {
            return Err(Denied);
        }
        Ok(())
    }
}

pub struct Keyed<G>(pub G);
impl<G: Gate<Session>> Gate<Session> for Keyed<G> {
    fn admit(&self, headers: &HeaderMap) -> Result<Session, Denied> {
        self.0.admit(headers)
    }
}

pub fn either<'a, T>(first: &'a dyn Gate<T>, second: &'a dyn Gate<T>, headers: &HeaderMap) -> &'a dyn Gate<T> {
    if headers.contains_key("x-key") {
        first
    } else {
        second
    }
}

fn guarded<T>(req: &HttpRequest, gate: &dyn Gate<T>) -> HttpResponse {
    match gate.admit(req.headers()) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(denied) => denied.into_response(),
    }
}

async fn list_boards(req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    guarded(&req, &TeamGrant { team_id: path.into_inner(), need: Need::BoardRead })
}
async fn add_board(req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    guarded(&req, &TeamGrant { team_id: path.into_inner(), need: Need::BoardWrite })
}
async fn remove_board(req: HttpRequest, path: web::Path<(String, u64)>) -> HttpResponse {
    let (team_id, _board) = path.into_inner();
    guarded(
        &req,
        either(&Keyed(Member), &TeamGrant { team_id, need: Need::BoardWrite }, req.headers()),
    )
}
async fn add_label(req: HttpRequest, _path: web::Path<String>) -> HttpResponse {
    guarded(&req, either(&Keyed(Member), &Grant { need: Need::LabelWrite }, req.headers()))
}
async fn status(req: HttpRequest) -> HttpResponse {
    guarded(&req, &Open)
}
async fn me(req: HttpRequest) -> HttpResponse {
    guarded(&req, &Member)
}
async fn outside(req: HttpRequest) -> HttpResponse {
    guarded(&req, &vendor::ExternalAuth)
}
async fn purge(req: HttpRequest) -> HttpResponse {
    guarded(&req, &Operator)
}
