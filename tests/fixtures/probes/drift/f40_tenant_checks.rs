use actix_web::{error, web, Error};

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/projects")
            .route("/{project_id}", web::get().to(get_project))
            .route("/{project_id}", web::put().to(update_project))
            .route("/{project_id}", web::patch().to(rename_project))
            // Loads the record by its path id but never compares its
            // organization with the caller's: any logged-in user of any
            // organization may delete it.
            .route("/{project_id}", web::delete().to(delete_project)),
    );
    cfg.service(
        web::scope("/api/teams")
            .route("/{team_id}", web::get().to(get_team))
            .route("/{team_id}", web::put().to(update_team))
            .route("/{team_id}/name", web::get().to(team_name)),
    );
}

async fn get_project(user: AuthenticatedUser, path: web::Path<u64>) -> Result<String, Error> {
    let project = load_project(path.into_inner()).await?;
    if project.org_id != user.org_id {
        return Err(error::ErrorForbidden("not yours"));
    }
    Ok(project.name)
}
async fn update_project(user: AuthenticatedUser, path: web::Path<u64>) -> Result<String, Error> {
    let project = load_project(path.into_inner()).await?;
    if project.org_id != user.org_id {
        return Err(error::ErrorForbidden("not yours"));
    }
    save(project).await
}
async fn rename_project(user: AuthenticatedUser, path: web::Path<u64>) -> Result<String, Error> {
    let project = load_project(path.into_inner()).await?;
    if user.organization_id() != project.organization_id() {
        return Err(error::ErrorForbidden("not yours"));
    }
    save(project).await
}
async fn delete_project(user: AuthenticatedUser, path: web::Path<u64>) -> Result<String, Error> {
    let project = load_project(path.into_inner()).await?;
    remove(project).await
}

async fn get_team(user: AuthenticatedUser, path: web::Path<u64>) -> Result<String, Error> {
    verify_member(&user, path.into_inner()).await?;
    Ok(String::new())
}
async fn update_team(user: AuthenticatedUser, path: web::Path<u64>) -> Result<String, Error> {
    verify_member(&user, path.into_inner()).await?;
    Ok(String::new())
}
async fn team_name(user: AuthenticatedUser, path: web::Path<u64>) -> Result<String, Error> {
    Ok(String::new())
}
