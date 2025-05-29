use axum::extract::{FromRequestParts, State};
use axum::http::{header::COOKIE, request::Parts, HeaderMap, StatusCode};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use shuttle_runtime::SecretStore;
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: String,
    pub email: String,
    pub exp: usize,
}

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    (PgPool, SecretStore): axum::extract::FromRef<S>,
{
    type Rejection = (StatusCode, &'static str);

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            let State((_, secrets)): State<(PgPool, SecretStore)> =
                State::from_request_parts(parts, state)
                    .await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to extract state"))?;

            let cookies = parts
                .headers
                .get(COOKIE)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            let session_cookie = cookies
                .split(';')
                .find_map(|c| {
                    let c = c.trim();
                    if c.starts_with("session=") {
                        Some(c.trim_start_matches("session=").to_string())
                    } else {
                        None
                    }
                })
                .ok_or((StatusCode::UNAUTHORIZED, "Missing session cookie"))?;
            let jwt_secret = secrets
                .get("SESSION_JWT_SECRET")
                .unwrap_or("SESSION_SECRET".to_string());
            let token_data = decode::<SessionClaims>(
                &session_cookie,
                &DecodingKey::from_secret(jwt_secret.as_ref()),
                &Validation::new(Algorithm::HS256),
            )
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired session token"))?;
            Ok(AuthenticatedUser {
                user_id: token_data.claims.sub,
                email: token_data.claims.email,
            })
        }
    }
}

/// Extract authenticated user from request headers manually
/// Returns a JsonRpcResponse error for use in MCP protocol
pub async fn extract_authenticated_user_for_mcp(
    headers: &HeaderMap,
    secrets: &SecretStore,
) -> Result<AuthenticatedUser, serde_json::Value> {
    let cookies = headers
        .get(COOKIE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let session_cookie = cookies
        .split(';')
        .find_map(|c| {
            let c = c.trim();
            if c.starts_with("session=") {
                Some(c.trim_start_matches("session=").to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| serde_json::json!({
            "code": -32001,
            "message": "Authentication required. Missing session cookie. Please authenticate via /auth/login first."
        }))?;

    let jwt_secret = secrets
        .get("SESSION_JWT_SECRET")
        .unwrap_or("SESSION_SECRET".to_string());

    let token_data = decode::<SessionClaims>(
        &session_cookie,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| serde_json::json!({
        "code": -32001,
        "message": "Authentication required. Invalid or expired session token. Please authenticate via /auth/login first."
    }))?;

    Ok(AuthenticatedUser {
        user_id: token_data.claims.sub,
        email: token_data.claims.email,
    })
}
