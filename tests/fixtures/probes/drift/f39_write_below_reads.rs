use actix_web::web;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/org")
            // One read and one delete, both admin-only, beside a create open
            // to any logged-in user: too few of each class for the class
            // groups, but every other route of the resource agrees.
            .route("/api_key", web::get().to(list_org_keys))
            .route("/api_key/{key_id}", web::delete().to(delete_org_key))
            .route("/api_key", web::post().to(create_org_key))
            // Admin-only writes of another resource.
            .route("/settings", web::put().to(update_settings))
            .route("/settings/reset", web::post().to(reset_settings))
            .route("/settings/{key}", web::delete().to(delete_setting))
            .route("/settings", web::get().to(get_settings))
            .route("/settings/{key}", web::get().to(get_setting))
            // A POST that reads: held to the reads, which any member may make.
            .route("/settings/get_all_tags", web::post().to(get_all_tags)),
    );
    cfg.service(
        web::scope("/api/billing")
            .route("/plan", web::put().to(update_plan))
            .route("/card", web::put().to(update_card))
            .route("/cancel", web::post().to(cancel_plan))
            // The provider calls it; it carries a signature, not a user.
            .route("/webhook", web::post().to(billing_webhook)),
    );
}

async fn list_org_keys(_admin: AdminUser) {}
async fn delete_org_key(_admin: AdminUser) {}
async fn create_org_key(_user: AuthenticatedUser) {}
async fn update_settings(_admin: AdminUser) {}
async fn reset_settings(_admin: AdminUser) {}
async fn delete_setting(_admin: AdminUser) {}
async fn get_settings(_user: AuthenticatedUser) {}
async fn get_setting(_user: AuthenticatedUser) {}
async fn get_all_tags(_user: AuthenticatedUser) {}
async fn update_plan(_admin: AdminUser) {}
async fn update_card(_admin: AdminUser) {}
async fn cancel_plan(_admin: AdminUser) {}
async fn billing_webhook(body: web::Bytes) {}
