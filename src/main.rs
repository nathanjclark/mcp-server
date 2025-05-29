use axum::{routing::get, Router};
use shuttle_runtime::SecretStore;
use sqlx::PgPool;
mod auth;
mod database;
mod mcp;
mod registries;
mod tools;

#[shuttle_runtime::main]
async fn main(
    #[shuttle_shared_db::Postgres] pool: PgPool,
    #[shuttle_runtime::Secrets] secrets: SecretStore,
) -> shuttle_axum::ShuttleAxum {
    database::init_db(&pool)
        .await
        .expect("Failed to run DB migrations");
    let router = Router::new()
        .route("/auth/login", get(auth::handlers::login))
        .route("/auth/callback", get(auth::handlers::callback))
        .route("/auth/logout", get(auth::handlers::logout))
        .route("/auth/me", get(auth::handlers::me))
        .route("/welcome", get(auth::handlers::welcome))
        .route("/mcp", axum::routing::post(mcp::mcp_handler))
        .with_state((pool, secrets));
    Ok(router.into())
}
