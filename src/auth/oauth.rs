use crate::auth::models::{
    AccessTokenClaims, AuthorizationRequest, AuthorizationServerMetadata,
    ClientRegistrationRequest, ClientRegistrationResponse, OAuthAuthorizationCode, OAuthError,
    RegisteredClient, TokenRequest, TokenResponse,
};
use axum::{
    extract::{Form, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use sha2::{Digest, Sha256};
use shuttle_runtime::SecretStore;
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::{error, info};
use urlencoding;
use uuid::Uuid;

// In-memory storage for demo purposes - in production, use database or Redis
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};

static REGISTERED_CLIENTS: Lazy<Arc<Mutex<HashMap<String, RegisteredClient>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// OAuth 2.1 Authorization Server Metadata (RFC8414)
/// https://tools.ietf.org/html/rfc8414
pub async fn oauth_metadata(
    State((_, secrets)): State<(PgPool, SecretStore)>,
) -> impl IntoResponse {
    let base_url = get_base_url(&secrets);

    let metadata = AuthorizationServerMetadata {
        issuer: base_url.clone(),
        authorization_endpoint: format!("{}/authorize", base_url),
        token_endpoint: format!("{}/token", base_url),
        registration_endpoint: Some(format!("{}/register", base_url)),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        token_endpoint_auth_methods_supported: vec![
            "none".to_string(),
            "client_secret_post".to_string(),
        ],
    };

    Json(metadata)
}

/// OAuth 2.1 Authorization Endpoint
/// Handles authorization requests with PKCE support
pub async fn oauth_authorize(
    Query(params): Query<AuthorizationRequest>,
    State((pool, secrets)): State<(PgPool, SecretStore)>,
) -> impl IntoResponse {
    info!(
        "OAuth authorization request: client_id={}",
        params.client_id
    );

    // Validate required parameters
    if params.response_type != "code" {
        return create_error_response(
            "unsupported_response_type",
            Some("Only 'code' response type is supported"),
        );
    }

    // Validate PKCE (required for public clients)
    if params.code_challenge.is_none() {
        return create_error_response("invalid_request", Some("code_challenge is required"));
    }

    if params.code_challenge_method.as_deref() != Some("S256") {
        return create_error_response(
            "invalid_request",
            Some("Only S256 code_challenge_method is supported"),
        );
    }

    // Generate authorization code
    let auth_code = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(10);

    // Store authorization details in the database (user_id is NULL for now)
    let _ = sqlx::query(
        r#"INSERT INTO oauth_authorization_codes
            (code, client_id, redirect_uri, scope, user_id, code_challenge, code_challenge_method, expires_at)
            VALUES ($1, $2, $3, $4, NULL, $5, $6, $7)"#
    )
    .bind(&auth_code)
    .bind(&params.client_id)
    .bind(&params.redirect_uri)
    .bind(&params.scope)
    .bind(&params.code_challenge)
    .bind(&params.code_challenge_method)
    .bind(expires_at)
    .execute(&pool)
    .await;

    // Redirect to Auth0 login with state=auth_code
    let auth0_domain = secrets
        .get("AUTH0_DOMAIN")
        .unwrap_or("YOUR_AUTH0_DOMAIN".to_string());
    let client_id = secrets
        .get("AUTH0_CLIENT_ID")
        .unwrap_or("YOUR_AUTH0_CLIENT_ID".to_string());
    let callback_url = secrets
        .get("AUTH0_CALLBACK_URL")
        .unwrap_or("http://localhost:8000/auth/callback".to_string());
    let auth0_redirect = format!(
        "https://{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email&state={}",
        auth0_domain,
        client_id,
        urlencoding::encode(&callback_url),
        auth_code // <-- this is the state!
    );

    info!("Redirecting to Auth0 login with OAuth context and state param");
    Redirect::temporary(&auth0_redirect).into_response()
}

/// OAuth 2.1 Token Endpoint
/// Exchanges authorization codes for access tokens
pub async fn oauth_token(
    State((pool, secrets)): State<(PgPool, SecretStore)>,
    Form(token_request): Form<TokenRequest>,
) -> impl IntoResponse {
    info!(
        "/token request: grant_type={:?}, client_id={:?}, code={:?}, code_verifier={:?}",
        token_request.grant_type,
        token_request.client_id,
        token_request.code,
        token_request.code_verifier
    );

    // Validate grant type
    if token_request.grant_type != "authorization_code" {
        info!("Invalid grant_type: {}", token_request.grant_type);
        return create_token_error_response(
            "unsupported_grant_type",
            Some("Only authorization_code grant type is supported"),
        );
    }

    // Validate required parameters
    let auth_code = match &token_request.code {
        Some(code) => code,
        None => {
            info!("Missing authorization code");
            return create_token_error_response(
                "invalid_request",
                Some("Missing authorization code"),
            );
        }
    };

    // Retrieve and validate authorization code from DB
    let row = match sqlx::query_as::<_, OAuthAuthorizationCode>(
        "SELECT * FROM oauth_authorization_codes WHERE code = $1",
    )
    .bind(auth_code)
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(row)) => row,
        _ => {
            info!("Code not found or expired: {}", auth_code);
            return create_token_error_response(
                "invalid_grant",
                Some("Invalid or expired authorization code"),
            );
        }
    };

    info!(
        "DB row for code: client_id={:?}, user_id={:?}, expires_at={:?}, code_challenge={:?}",
        row.client_id, row.user_id, row.expires_at, row.code_challenge
    );

    // Validate client
    if row.client_id != token_request.client_id {
        info!(
            "Client ID mismatch: got {}, expected {}",
            token_request.client_id, row.client_id
        );
        return create_token_error_response("invalid_client", Some("Client ID mismatch"));
    }

    // Validate PKCE code verifier
    if let (Some(code_verifier), Some(code_challenge)) =
        (&token_request.code_verifier, &row.code_challenge)
    {
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let computed_challenge = general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
        info!(
            "PKCE: code_verifier={}, code_challenge(stored)={}, code_challenge(computed)={}",
            code_verifier, code_challenge, computed_challenge
        );
        if computed_challenge != *code_challenge {
            info!("PKCE code verifier mismatch");
            return create_token_error_response(
                "invalid_grant",
                Some("Invalid PKCE code verifier"),
            );
        }
    } else {
        info!("Missing PKCE code_verifier or code_challenge");
        return create_token_error_response("invalid_request", Some("Missing PKCE code verifier"));
    }

    // Check expiration
    if Utc::now() > row.expires_at {
        info!(
            "Authorization code expired: expires_at={:?}",
            row.expires_at
        );
        return create_token_error_response("invalid_grant", Some("Authorization code expired"));
    }

    // Check user binding
    let user_id = match row.user_id.clone() {
        Some(uid) => uid,
        None => {
            info!("Authorization code not bound to user");
            return create_token_error_response(
                "invalid_grant",
                Some("Authorization code not bound to user (login not completed)"),
            );
        }
    };

    // Look up user info from DB
    let user =
        match sqlx::query_as::<_, crate::auth::models::User>("SELECT * FROM users WHERE id = $1")
            .bind(&user_id)
            .fetch_optional(&pool)
            .await
        {
            Ok(Some(user)) => user,
            _ => {
                info!("User not found for user_id: {}", user_id);
                return create_token_error_response("invalid_grant", Some("User not found"));
            }
        };

    info!("Token issued for user: {} ({})", user.email, user.id);

    // Generate access token (JWT)
    let access_token = match generate_access_token_for_user(&user, &row, &secrets) {
        Ok(token) => token,
        Err(e) => {
            error!("Failed to generate access token: {}", e);
            return create_token_error_response(
                "server_error",
                Some("Failed to generate access token"),
            );
        }
    };

    // Optionally: delete the code from DB (single-use)
    let _ = sqlx::query("DELETE FROM oauth_authorization_codes WHERE code = $1")
        .bind(auth_code)
        .execute(&pool)
        .await;

    let token_response = TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: Some(3600), // 1 hour
        refresh_token: None,    // Not implemented yet
        scope: row.scope,
    };

    (StatusCode::OK, Json(token_response)).into_response()
}

/// Dynamic Client Registration (RFC7591)
/// https://tools.ietf.org/html/rfc7591
pub async fn oauth_register(
    State((_, _)): State<(PgPool, SecretStore)>,
    Json(registration_request): Json<ClientRegistrationRequest>,
) -> impl IntoResponse {
    info!("OAuth client registration request");

    // Generate client credentials
    let client_id = Uuid::new_v4().to_string();
    let client_secret = Uuid::new_v4().to_string(); // For confidential clients
    let issued_at = Utc::now().timestamp() as u64;

    // Set defaults
    let redirect_uris = registration_request
        .redirect_uris
        .unwrap_or_else(|| vec!["http://localhost".to_string()]);
    let grant_types = registration_request
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".to_string()]);
    let response_types = registration_request
        .response_types
        .unwrap_or_else(|| vec!["code".to_string()]);

    // Store registered client
    let registered_client = RegisteredClient {
        client_id: client_id.clone(),
        client_secret: Some(client_secret.clone()),
        redirect_uris: redirect_uris.clone(),
        client_name: registration_request.client_name.clone(),
        client_uri: registration_request.client_uri.clone(),
        logo_uri: registration_request.logo_uri.clone(),
        grant_types: grant_types.clone(),
        response_types: response_types.clone(),
        scope: registration_request.scope.clone(),
        created_at: Utc::now(),
    };

    {
        let mut clients = REGISTERED_CLIENTS.lock().unwrap();
        clients.insert(client_id.clone(), registered_client);
    }

    let registration_response = ClientRegistrationResponse {
        client_id,
        client_secret: Some(client_secret),
        client_id_issued_at: Some(issued_at),
        client_secret_expires_at: None, // Never expires for demo
        redirect_uris: Some(redirect_uris),
        grant_types: Some(grant_types),
        response_types: Some(response_types),
        client_name: registration_request.client_name,
        client_uri: registration_request.client_uri,
        logo_uri: registration_request.logo_uri,
        scope: registration_request.scope,
    };

    (StatusCode::CREATED, Json(registration_response)).into_response()
}

// Helper functions

fn get_base_url(secrets: &SecretStore) -> String {
    // In production, get this from environment or request headers
    secrets
        .get("BASE_URL")
        .unwrap_or_else(|| "http://localhost:8000".to_string())
}

fn create_error_response(error: &str, description: Option<&str>) -> axum::response::Response {
    let oauth_error = OAuthError {
        error: error.to_string(),
        error_description: description.map(|s| s.to_string()),
        error_uri: None,
    };

    (StatusCode::BAD_REQUEST, Json(oauth_error)).into_response()
}

fn create_token_error_response(error: &str, description: Option<&str>) -> axum::response::Response {
    let oauth_error = OAuthError {
        error: error.to_string(),
        error_description: description.map(|s| s.to_string()),
        error_uri: None,
    };

    (StatusCode::BAD_REQUEST, Json(oauth_error)).into_response()
}

fn _verify_pkce_challenge(code_verifier: &str, code_challenge: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let challenge = general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
    challenge == code_challenge
}

fn generate_access_token_for_user(
    user: &crate::auth::models::User,
    row: &OAuthAuthorizationCode,
    secrets: &SecretStore,
) -> Result<String, Box<dyn std::error::Error>> {
    let jwt_secret = secrets
        .get("SESSION_JWT_SECRET")
        .ok_or("Missing SESSION_JWT_SECRET")?;

    let now = Utc::now().timestamp() as usize;
    let exp = (Utc::now() + Duration::hours(1)).timestamp() as usize;

    let claims = AccessTokenClaims {
        sub: user.id.to_string(),
        iss: get_base_url(secrets),
        aud: get_base_url(secrets),
        exp,
        iat: now,
        client_id: row.client_id.clone(),
        scope: row.scope.clone(),
        email: user.email.clone(),
        name: user.name.clone(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )?;

    Ok(token)
}
