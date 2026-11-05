use actix_web::{App, web};

pub fn app() -> App {
    App::new().service(web::scope("/api").configure(<RootApi as Routes>::configure))
}

#[routes::routes(
    routes(
        "/health" => get(health),
        "/keys" => sub(keys::KeysApi),
        "/indexes" => sub(indexes::IndexesApi),
    ),
    tag = "Root",
)]
pub struct RootApi;

// Declared but never mounted: left out with a warning.
#[routes::routes(routes("/compact" => post(health)))]
pub struct CompactApi;

async fn health() {}

mod keys {
    #[routes::routes(routes(
        "" => [post(create_key), get(list_keys)],
        "/{key}" => [get(get_key), patch(update_key), delete(delete_key)],
    ))]
    pub struct KeysApi;

    async fn create_key(_auth: GuardedData<ActionPolicy<{ actions::KEYS_CREATE }>, Data<Auth>>) {}
    async fn list_keys(_auth: GuardedData<ActionPolicy<{ actions::KEYS_GET }>, Data<Auth>>) {}
    async fn get_key(_auth: GuardedData<ActionPolicy<{ actions::KEYS_GET }>, Data<Auth>>) {}
    async fn update_key(_auth: GuardedData<ActionPolicy<{ actions::KEYS_UPDATE }>, Data<Auth>>) {}
    // Drift: the other key writes run the policy extractor.
    async fn delete_key(_auth: Data<Auth>) {}
}

mod indexes {
    #[routes::routes(routes(
        "" => [get(list_indexes), post(create_index)],
        "/{uid}" => [get(get_index), delete(delete_index)],
        "/{uid}/stats" => get(index_stats),
    ))]
    pub struct IndexesApi;

    async fn list_indexes(_auth: GuardedData<ActionPolicy<{ actions::INDEXES_GET }>, Data<Auth>>) {}
    async fn create_index(_auth: GuardedData<ActionPolicy<{ actions::INDEXES_CREATE }>, Data<Auth>>) {}
    async fn get_index(_auth: GuardedData<ActionPolicy<{ actions::INDEXES_GET }>, Data<Auth>>) {}
    async fn delete_index(_auth: GuardedData<ActionPolicy<{ actions::INDEXES_DELETE }>, Data<Auth>>) {}
    // Its own permission by design: reported, but Low.
    async fn index_stats(_auth: GuardedData<ActionPolicy<{ actions::STATS_GET }>, Data<Auth>>) {}
}
