use actix_web::web;
pub fn config(cfg: &mut web::ServiceConfig) {
    // A scope held in a variable keeps its prefix and middleware.
    let admin = web::scope("/admin").wrap(AdminGuard);
    cfg.service(admin
        .route("/users", web::get().to(users))
        .route("/billing", web::get().to(billing))
        .route("/audit", web::get().to(audit)));

    // Reassigned in steps; the last route forgets the guarded builder.
    let guarded_get = web::get().guard(AdminGuard);
    let mut ops = web::scope("/ops");
    ops = ops.route("/a", guarded_get.clone().to(a));
    ops = ops.route("/b", web::get().guard(AdminGuard).to(b));
    ops = ops.route("/c", web::get().guard(AdminGuard).to(c));
    ops = ops.route("/d", web::get().to(d));
    cfg.service(ops);

    // Built but never registered: its routes are still reported.
    let _orphan = web::scope("/orphan").route("/x", web::get().to(a));
}
async fn users() {}
async fn billing() {}
async fn audit() {}
async fn a() {}
async fn b() {}
async fn c() {}
async fn d() {}
