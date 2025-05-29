use serde::Serialize;
use sqlx::{PgPool, Row};

#[derive(Debug, Serialize)]
pub struct UserStats {
    pub user_count: i64,
    pub latest_user: Option<String>,
}

pub async fn user_stats(pool: &PgPool) -> Result<UserStats, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) as user_count, MAX(created_at)::text as latest_user FROM users",
    )
    .fetch_one(pool)
    .await?;

    let user_count: i64 = row.try_get("user_count").unwrap_or(0);
    let latest_user: Option<String> = row.try_get("latest_user").ok();

    Ok(UserStats {
        user_count,
        latest_user,
    })
}
