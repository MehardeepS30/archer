use actix_web::{web, App};

// Handlers written as associated functions of a type and registered as
// `.to(Admin::users)`, through an import, and through a module path. Each
// protected handler calls a helper in the enclosing module. `payments` skips
// it. The free function `audit` shares no name with the methods, and the
// method `Admin::audit` is never routed: a bare `audit` must not resolve to it.
mod admin {
    pub struct Admin;

    fn ensure_admin(user: &User) -> Result<(), Error> {
        if !user.is_admin {
            return Err(Error::Forbidden);
        }
        Ok(())
    }

    impl Admin {
        pub async fn users(user: User) -> Result<(), Error> {
            ensure_admin(&user)?;
            Ok(())
        }
        pub async fn orders(user: User) -> Result<(), Error> {
            ensure_admin(&user)?;
            Ok(())
        }
        pub async fn reports(user: User) -> Result<(), Error> {
            ensure_admin(&user)?;
            Ok(())
        }
        pub async fn payments(_user: User) -> Result<(), Error> {
            Ok(())
        }
        pub async fn audit(user: User) -> Result<(), Error> {
            ensure_admin(&user)?;
            Ok(())
        }
    }
}

use admin::Admin;

async fn audit() {}

fn main() {
    App::new().service(
        web::scope("/admin")
            .route("/users", web::get().to(Admin::users))
            .route("/orders", web::get().to(admin::Admin::orders))
            .route("/reports", web::get().to(Admin::reports))
            .route("/payments", web::get().to(Admin::payments))
            .route("/audit", web::get().to(audit)),
    );
}
