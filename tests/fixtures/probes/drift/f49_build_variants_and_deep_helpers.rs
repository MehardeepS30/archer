// P1 fixture: a service function with build variants told apart by
// `#[cfg(..)]`, and a check four calls below the handler.

use actix_web::{web, App, HttpResponse};

pub struct AuthenticatedUser {
    pub id: u64,
}

pub struct Fault;

fn app() {
    App::new().service(
        web::scope("/items")
            .route("/{id}", web::delete().to(remove_item))
            .route("/{id}", web::put().to(replace_item)),
    );
}

#[cfg(feature = "full")]
async fn remove_item(user: AuthenticatedUser) -> Result<HttpResponse, Fault> {
    ops::remove(&user)?;
    Ok(HttpResponse::Ok().finish())
}

async fn replace_item(user: AuthenticatedUser) -> Result<HttpResponse, Fault> {
    step_one(&user)?;
    Ok(HttpResponse::Ok().finish())
}

fn step_one(user: &AuthenticatedUser) -> Result<(), Fault> {
    step_two(user)
}

fn step_two(user: &AuthenticatedUser) -> Result<(), Fault> {
    step_three(user)
}

fn step_three(user: &AuthenticatedUser) -> Result<(), Fault> {
    step_four(user)
}

fn step_four(user: &AuthenticatedUser) -> Result<(), Fault> {
    require_admin(user)?;
    Ok(())
}

fn require_admin(_user: &AuthenticatedUser) -> Result<(), Fault> {
    Ok(())
}

mod ops {
    use super::{require_admin, AuthenticatedUser, Fault};

    #[cfg(feature = "full")]
    pub fn remove(user: &AuthenticatedUser) -> Result<(), Fault> {
        require_admin(user)?;
        Ok(())
    }

    #[cfg(feature = "lite")]
    pub fn remove(_user: &AuthenticatedUser) -> Result<(), Fault> {
        todo!()
    }
}
