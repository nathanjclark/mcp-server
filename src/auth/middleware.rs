use crate::auth::models::{AccessTokenClaims, User};
use async_trait::async_trait;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use cookie::Cookie;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde_json::json;
use shuttle_runtime::SecretStore;
use tracing::{error, info};

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub email: String,
}

#[async_trait]
impl<S> axum::extract::FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    (sqlx::PgPool, SecretStore): axum::extract::FromRef<S>,
{
    type Rejection = (StatusCode, &'static str);

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let fut = async move {
            let State((_, secrets)): State<(sqlx::PgPool, SecretStore)> =
                State::from_request_parts(parts, state)
                    .await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to extract state"))?;
            let cookies = parts
                .headers
                .get("cookie")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            let session_token = extract_session_token_from_cookies(cookies)
                .ok_or((StatusCode::UNAUTHORIZED, "Missing session cookie"))?;
            let jwt_secret = secrets
                .get("SESSION_JWT_SECRET")
                .unwrap_or("SESSION_SECRET".to_string());
            #[derive(serde::Deserialize)]
            struct SessionClaims {
                sub: String,
                email: String,
            }
            let token_data = decode::<SessionClaims>(
                &session_token,
                &DecodingKey::from_secret(jwt_secret.as_ref()),
                &Validation::default(),
            )
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired session token"))?;
            Ok(AuthenticatedUser {
                user_id: token_data.claims.sub,
                email: token_data.claims.email,
            })
        };
        fut
    }
}

/// Extract authenticated user from either session cookie or Bearer token
/// Supports both web interface (cookies) and MCP clients (Bearer tokens)
pub async fn extract_authenticated_user_for_mcp(
    headers: &HeaderMap,
    secrets: &SecretStore,
) -> Result<User, serde_json::Value> {
    // Try Bearer token first (for MCP clients)
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..]; // Remove "Bearer " prefix
                return extract_user_from_bearer_token(token, secrets).await;
            }
        }
    }

    // Fallback to session cookie (for web interface)
    extract_user_from_session_cookie(headers, secrets).await
}

/// Extract user from Bearer token (OAuth 2.1 access token)
async fn extract_user_from_bearer_token(
    token: &str,
    secrets: &SecretStore,
) -> Result<User, serde_json::Value> {
    let jwt_secret = secrets
        .get("SESSION_JWT_SECRET")
        .ok_or_else(|| create_oauth_error("server_error", "Missing JWT secret"))?;

    let token_data = decode::<AccessTokenClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|e| {
        error!("Failed to decode access token: {}", e);
        create_oauth_error("invalid_token", "Invalid or expired access token")
    })?;

    // Validate token expiration
    let now = Utc::now().timestamp() as usize;
    if token_data.claims.exp < now {
        return Err(create_oauth_error("invalid_token", "Access token expired"));
    }

    // Create user from token claims
    let user = User {
        id: token_data.claims.sub.clone(),
        username: token_data.claims.email.clone(),
        email: token_data.claims.email,
        created_at: Utc::now(), // We don't have this in the token, use current time
        name: token_data.claims.name,
        picture: None, // Not included in access token for now
    };

    info!("Authenticated user via Bearer token: {}", user.email);
    Ok(user)
}

/// Extract user from session cookie (existing implementation)
async fn extract_user_from_session_cookie(
    headers: &HeaderMap,
    secrets: &SecretStore,
) -> Result<User, serde_json::Value> {
    let cookies = headers
        .get("cookie")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    let session_token = extract_session_token_from_cookies(cookies)
        .ok_or_else(|| create_oauth_error("invalid_token", "Missing session token"))?;

    let jwt_secret = secrets
        .get("SESSION_JWT_SECRET")
        .ok_or_else(|| create_oauth_error("server_error", "Missing JWT secret"))?;

    #[derive(serde::Deserialize)]
    struct SessionClaims {
        sub: String,
        email: String,
        name: Option<String>,
        picture: Option<String>,
        exp: usize,
    }

    let token_data = decode::<SessionClaims>(
        &session_token,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|e| {
        error!("Failed to decode session token: {}", e);
        create_oauth_error("invalid_token", "Invalid or expired session token")
    })?;

    // Validate token expiration
    let now = Utc::now().timestamp() as usize;
    if token_data.claims.exp < now {
        return Err(create_oauth_error("invalid_token", "Session token expired"));
    }

    let user = User {
        id: token_data.claims.sub.clone(),
        username: token_data.claims.email.clone(),
        email: token_data.claims.email,
        created_at: Utc::now(),
        name: token_data.claims.name,
        picture: token_data.claims.picture,
    };

    info!("Authenticated user via session: {}", user.email);
    Ok(user)
}

fn extract_session_token_from_cookies(cookies: &str) -> Option<String> {
    for cookie_str in cookies.split(';') {
        if let Ok(cookie) = Cookie::parse(cookie_str.trim()) {
            if cookie.name() == "session" {
                return Some(cookie.value().to_string());
            }
        }
    }
    None
}

/// Create OAuth 2.1 compliant error response
fn create_oauth_error(error: &str, description: &str) -> serde_json::Value {
    json!({
        "code": -32001, // JSON-RPC error code for authentication failure
        "message": "Authentication required",
        "data": {
            "error": error,
            "error_description": description
        }
    })
}
