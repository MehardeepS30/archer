use actix_web::{web, App};

fn app() {
    App::new()
        // A flat app: every route is one segment at the root, so each is
        // alone in its namespace. They form one root group.
        .route("/users", web::get().to(users))
        .route("/orders", web::get().to(orders))
        .route("/invoices", web::get().to(invoices))
        .route("/reports", web::get().to(reports))
        // An unrecognized middleware around the whole scope is shared by
        // every route in it: it is a caveat for the group, not a reason
        // to leave the scope ungrouped or the odd route unverified.
        .service(
            web::scope("/team")
                .wrap(TeamGate)
                .route("/members", web::get().to(members))
                .route("/roles", web::get().to(roles))
                .route("/audit", web::get().to(audit))
                .route("/export", web::get().to(export)),
        );
}

struct TeamGate;

async fn users(user: Identity) {}
async fn orders(user: Identity) {}
async fn invoices(user: Identity) {}
async fn reports() {}
async fn members(user: Identity) {}
async fn roles(user: Identity) {}
async fn audit(user: Identity) {}
async fn export() {}
