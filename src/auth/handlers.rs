use crate::auth::middleware::AuthenticatedUser;
use crate::auth::models::OAuthAuthorizationCode;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shuttle_runtime::SecretStore;
use sqlx::PgPool;
use std::collections::HashMap;
use urlencoding;

#[derive(Debug, Deserialize)]
pub struct AuthCallbackQuery {
    pub code: String,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub exp: usize,
    pub iss: String,
    pub aud: Value,
}

async fn fetch_jwks(auth0_domain: &str) -> Result<Value, reqwest::Error> {
    let jwks_url = format!("https://{}/.well-known/jwks.json", auth0_domain);
    reqwest::get(&jwks_url).await?.json().await
}

pub async fn login(State((_pool, secrets)): State<(PgPool, SecretStore)>) -> impl IntoResponse {
    let auth0_domain = secrets
        .get("AUTH0_DOMAIN")
        .unwrap_or("YOUR_AUTH0_DOMAIN".to_string());
    let client_id = secrets
        .get("AUTH0_CLIENT_ID")
        .unwrap_or("YOUR_AUTH0_CLIENT_ID".to_string());
    let callback_url = secrets
        .get("AUTH0_CALLBACK_URL")
        .unwrap_or("http://localhost:8000/auth/callback".to_string());

    let auth_url = format!(
        "https://{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email",
        auth0_domain,
        client_id,
        urlencoding::encode(&callback_url)
    );
    Redirect::temporary(&auth_url)
}

pub async fn callback(
    State((pool, secrets)): State<(PgPool, SecretStore)>,
    Query(query): Query<AuthCallbackQuery>,
    _headers: HeaderMap,
) -> impl IntoResponse {
    let auth0_domain = secrets
        .get("AUTH0_DOMAIN")
        .unwrap_or("YOUR_AUTH0_DOMAIN".to_string());
    let client_id = secrets
        .get("AUTH0_CLIENT_ID")
        .unwrap_or("YOUR_AUTH0_CLIENT_ID".to_string());
    let client_secret = secrets
        .get("AUTH0_CLIENT_SECRET")
        .unwrap_or("YOUR_AUTH0_CLIENT_SECRET".to_string());
    let callback_url = secrets
        .get("AUTH0_CALLBACK_URL")
        .unwrap_or("http://localhost:8000/auth/callback".to_string());

    // Exchange code for tokens
    let token_url = format!("https://{}/oauth/token", auth0_domain);
    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("client_id", &client_id);
    params.insert("client_secret", &client_secret);
    params.insert("code", &query.code);
    params.insert("redirect_uri", &callback_url);

    let client = reqwest::Client::new();
    let token_res = client.post(&token_url).form(&params).send().await;
    let token_res = match token_res {
        Ok(res) => res,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Failed to contact Auth0").into_response(),
    };
    if !token_res.status().is_success() {
        return (StatusCode::BAD_GATEWAY, "Auth0 token exchange failed").into_response();
    }
    let token_json: serde_json::Value = match token_res.json().await {
        Ok(json) => json,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Invalid token response").into_response(),
    };
    let id_token = match token_json.get("id_token").and_then(|v| v.as_str()) {
        Some(token) => token,
        None => return (StatusCode::BAD_GATEWAY, "No id_token in response").into_response(),
    };

    // Validate the ID token signature using Auth0's JWKS
    let header = match decode_header(id_token) {
        Ok(h) => h,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Invalid id_token header").into_response(),
    };
    let kid = match header.kid {
        Some(k) => k,
        None => return (StatusCode::BAD_GATEWAY, "No kid in id_token header").into_response(),
    };
    let jwks = match fetch_jwks(&auth0_domain).await {
        Ok(j) => j,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Failed to fetch JWKS").into_response(),
    };
    let empty_keys: Vec<Value> = Vec::new();
    let keys_array = jwks
        .get("keys")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_keys);
    let jwk = match keys_array
        .iter()
        .find(|k| k.get("kid") == Some(&Value::String(kid.clone())))
    {
        Some(j) => j,
        None => return (StatusCode::BAD_GATEWAY, "No matching JWK").into_response(),
    };
    let n = jwk.get("n").and_then(|v| v.as_str()).unwrap_or("");
    let e = jwk.get("e").and_then(|v| v.as_str()).unwrap_or("");
    let decoding_key = match DecodingKey::from_rsa_components(n, e) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Invalid JWK components").into_response(),
    };
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&client_id]);
    validation.set_issuer(&[format!("https://{}/", auth0_domain)]);
    let token_data: TokenData<IdTokenClaims> =
        match decode::<IdTokenClaims>(id_token, &decoding_key, &validation) {
            Ok(data) => data,
            Err(_) => {
                return (StatusCode::BAD_GATEWAY, "Invalid id_token signature").into_response()
            }
        };
    let claims = token_data.claims;

    // Upsert user in the database
    let user_id = claims.sub.clone();
    let email = claims.email.clone().unwrap_or_default();
    let name = claims.name.clone().unwrap_or_default();
    let _ = sqlx::query(
        r#"
        INSERT INTO users (id, username, email, created_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (id) DO UPDATE SET username = $2, email = $3
        "#,
    )
    .bind(&user_id)
    .bind(&name)
    .bind(&email)
    .execute(&pool)
    .await;

    // Always try to bind the user to the code and redirect to the original redirect_uri
    if let Some(oauth_code) = query.state.clone() {
        // Update the pending code in the DB to set user_id
        let _ = sqlx::query("UPDATE oauth_authorization_codes SET user_id = $1 WHERE code = $2")
            .bind(&user_id)
            .bind(&oauth_code)
            .execute(&pool)
            .await;

        // Look up the redirect_uri for this code
        if let Ok(Some(row)) = sqlx::query_as::<_, OAuthAuthorizationCode>(
            "SELECT * FROM oauth_authorization_codes WHERE code = $1",
        )
        .bind(&oauth_code)
        .fetch_optional(&pool)
        .await
        {
            if let Some(redirect_uri) = row.redirect_uri {
                // Redirect to client with code
                let uri = format!("{}?code={}", redirect_uri, oauth_code);
                return Redirect::temporary(&uri).into_response();
            }
        }
        // If we can't find a redirect_uri, return an error
        return (
            StatusCode::BAD_REQUEST,
            "OAuth flow error: missing or invalid redirect_uri for code",
        )
            .into_response();
    }

    // If not an OAuth flow, return an error
    (
        StatusCode::BAD_REQUEST,
        "OAuth flow error: missing state (code) in callback",
    )
        .into_response()
}

pub async fn welcome() -> Html<&'static str> {
    Html(r#"<h1>Welcome! You are now logged in via Auth0.</h1>"#)
}

pub async fn logout() -> impl IntoResponse {
    let cookie = "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
    let response = Response::builder()
        .status(StatusCode::FOUND)
        .header(header::SET_COOKIE, cookie)
        .header(header::LOCATION, "/")
        .body(axum::body::Body::empty())
        .unwrap();
    response
}

pub async fn me(AuthenticatedUser { user_id, email }: AuthenticatedUser) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "user_id": user_id,
        "email": email,
    }))
}
