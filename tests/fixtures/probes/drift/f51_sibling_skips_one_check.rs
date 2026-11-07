use actix_web::{web, App};

// Every mute write under /profile/mute rejects a suspended caller first.
// `mute_region_members` makes the same comparison as `mute_region_groups`
// but skips the suspension check. Under /profile/notice only most writes
// make the check, so `notice_seen` skipping it is a policy, not a slip.
fn app() {
    App::new()
        .service(
            web::scope("/profile/mute")
                .route("/member", web::post().to(mute_member))
                .route("/group", web::post().to(mute_group))
                .route("/region/groups", web::post().to(mute_region_groups))
                .route("/region/members", web::post().to(mute_region_members)),
        )
        .service(
            web::scope("/profile/notice")
                .route("/a", web::post().to(notice_a))
                .route("/b", web::post().to(notice_b))
                .route("/c", web::post().to(notice_c))
                .route("/d", web::post().to(notice_d))
                .route("/seen", web::post().to(notice_seen)),
        );
}

async fn mute_member(body: web::Json<MuteBody>, caller: AccountUser) {
    ensure_not_suspended(&caller)?;
    if caller.account.id == body.target_id {
        return Err(Error::SelfMute);
    }
    Mutes::add(caller.account.id, body.target_id)?;
}
async fn mute_group(body: web::Json<MuteBody>, caller: AccountUser) {
    ensure_not_suspended(&caller)?;
    if caller.account.id == body.target_id {
        return Err(Error::SelfMute);
    }
    Mutes::add(caller.account.id, body.target_id)?;
}
async fn mute_region_groups(body: web::Json<MuteBody>, caller: AccountUser) {
    ensure_not_suspended(&caller)?;
    if caller.account.region_id == body.region_id {
        return Err(Error::SameRegion);
    }
    Mutes::add(caller.account.id, body.region_id)?;
}
async fn mute_region_members(body: web::Json<MuteBody>, caller: AccountUser) {
    if caller.account.region_id == body.region_id {
        return Err(Error::SameRegion);
    }
    Mutes::add(caller.account.id, body.region_id)?;
}

async fn notice_a(body: web::Json<NoticeBody>, caller: AccountUser) {
    ensure_not_suspended(&caller)?;
    if caller.account.region_id == body.region_id { return Err(Error::SameRegion); }
}
async fn notice_b(body: web::Json<NoticeBody>, caller: AccountUser) {
    ensure_not_suspended(&caller)?;
    if caller.account.region_id == body.region_id { return Err(Error::SameRegion); }
}
async fn notice_c(body: web::Json<NoticeBody>, caller: AccountUser) {
    ensure_not_suspended(&caller)?;
    if caller.account.region_id == body.region_id { return Err(Error::SameRegion); }
}
async fn notice_d(body: web::Json<NoticeBody>, caller: AccountUser) {
    if caller.account.region_id == body.region_id { return Err(Error::SameRegion); }
}
async fn notice_seen(body: web::Json<NoticeBody>, caller: AccountUser) {
    if caller.account.region_id == body.region_id { return Err(Error::SameRegion); }
}
