use sqlx::postgres::PgPool;

pub async fn init_db(pool: &PgPool) -> Result<(), sqlx::Error> {
    // Run migrations using sqlx::migrate! macro (recommended by Shuttle)
    sqlx::migrate!().run(pool).await?;
    Ok(())
}
