use actix_web::{web, App};

// `rename_group` asks whether the caller moderates the group it names;
// `tag_group` passes the caller and a settings object, which names no record.
fn app() {
    App::new().service(
        web::scope("/groups")
            .route("/rename", web::put().to(rename_group))
            .route("/tag", web::put().to(tag_group)),
    );
}

async fn rename_group(body: web::Json<RenameBody>, caller: AccountUser, pool: web::Data<Pool>) {
    if !is_group_moderator(&caller, body.group_id, &pool).await? {
        return Err(Error::NotModerator);
    }
    Groups::rename(body.group_id, &body.name)?;
}
async fn tag_group(body: web::Json<TagBody>, caller: AccountUser, pool: web::Data<Pool>) {
    if !tag_settings_valid(&caller, &body.settings, &pool).await? {
        return Err(Error::BadSettings);
    }
}
