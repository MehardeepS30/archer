use actix_web::{web, App};

fn app() {
    App::new()
        .service(web::scope("/shop")
            .service(web::scope("/orders")
                .route("/place", web::post().to(place_order))
                .route("/cancel", web::post().to(cancel_order))
                .route("/return", web::post().to(return_order)))
            // Two writes that disagree: too few to settle it, so the
            // enclosing /shop scope decides.
            .service(web::scope("/cart")
                .route("/add", web::post().to(add_to_cart))
                .route("/clear", web::post().to(clear_cart))))
        .service(web::scope("/blog")
            .route("/posts", web::get().to(list_posts))
            .route("/posts/{id}", web::get().to(show_post)))
        .service(web::scope("/misc").route("/about", web::get().to(about)));
}

async fn place_order(user: Identity) {}
async fn cancel_order(user: Identity) {}
async fn return_order(user: Identity) {}
async fn add_to_cart(user: Identity) {}
async fn clear_cart() {}
async fn list_posts() {}
async fn show_post() {}
async fn about() {}
