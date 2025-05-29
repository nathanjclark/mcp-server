use axum::{
    routing::{get, post},
    Router,
};
use shuttle_runtime::SecretStore;
use sqlx::PgPool;
use tower_http::cors::{Any, CorsLayer};
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

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let router = Router::new()
        // OAuth 2.1 endpoints (MCP specification compliance)
        .route(
            "/.well-known/oauth-authorization-server",
            get(auth::oauth::oauth_metadata),
        )
        .route("/authorize", get(auth::oauth::oauth_authorize))
        .route("/token", post(auth::oauth::oauth_token))
        .route("/register", post(auth::oauth::oauth_register))
        // Existing auth endpoints (for web interface)
        .route("/auth/login", get(auth::handlers::login))
        .route("/auth/callback", get(auth::handlers::callback))
        .route("/auth/logout", get(auth::handlers::logout))
        .route("/auth/me", get(auth::handlers::me))
        .route("/welcome", get(auth::handlers::welcome))
        // MCP protocol endpoint
        .route("/mcp", post(mcp::mcp_handler))
        .layer(cors)
        .with_state((pool, secrets));

    Ok(router.into())
}
