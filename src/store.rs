//! Customer `api_keys` data access — the single seam between the HTTP handlers
//! and Postgres. Every operation is **org-scoped**: reads and mutations only ever
//! touch rows in the caller's org(s), so a customer can never see or change
//! another tenant's keys.
//!
//! This module is the abstraction boundary the storage backend lives behind. It
//! returns the shared [`ApiKeysRow`] contract type regardless of implementation,
//! so handlers, broadcast, and tests are decoupled from the query engine. The
//! DB-behavior tests in `tests/api_keys_store.rs` pin this seam's semantics so an
//! engine swap (raw SQL → ORM) is provably behaviour-preserving.

use fiducia_interfaces_db::customer::ApiKeysRow;
use sqlx::PgPool;
use uuid::Uuid;

/// Fields for a new api_keys row. The secret is never stored — only its hash.
pub struct NewApiKey<'a> {
    pub key_id: &'a str,
    pub org_id: Uuid,
    pub name: &'a str,
    pub secret_hash: String,
    pub scopes: serde_json::Value,
    pub env: &'a str,
}

/// Patch for a sync upsert. `None` leaves a column untouched (COALESCE).
#[derive(Default)]
pub struct ApiKeyPatch {
    pub name: Option<String>,
    pub scopes: Option<serde_json::Value>,
    pub env: Option<String>,
    pub revoked: Option<bool>,
}

/// List the caller's api keys (org-scoped), newest first.
pub async fn list_api_keys(pool: &PgPool, orgs: &[Uuid]) -> Result<Vec<ApiKeysRow>, sqlx::Error> {
    sqlx::query_as::<_, ApiKeysRow>(
        "select * from api_keys where org_id = any($1) order by created_at asc",
    )
    .bind(orgs)
    .fetch_all(pool)
    .await
}

/// Insert a key under `new.org_id` and return the committed row.
pub async fn insert_api_key(pool: &PgPool, new: NewApiKey<'_>) -> Result<ApiKeysRow, sqlx::Error> {
    sqlx::query_as::<_, ApiKeysRow>(
        "insert into api_keys (key_id, org_id, name, secret_hash, scopes, env) \
         values ($1, $2, $3, $4, $5, $6) returning *",
    )
    .bind(new.key_id)
    .bind(new.org_id)
    .bind(new.name)
    .bind(new.secret_hash)
    .bind(new.scopes)
    .bind(new.env)
    .fetch_one(pool)
    .await
}

/// Rotate the stored secret hash for a key, scoped to the caller's org(s).
/// Returns `None` when no row in those orgs matches the prefix.
pub async fn rotate_secret(
    pool: &PgPool,
    key_id: &str,
    secret_hash: String,
    orgs: &[Uuid],
) -> Result<Option<ApiKeysRow>, sqlx::Error> {
    sqlx::query_as::<_, ApiKeysRow>(
        "update api_keys set secret_hash = $1 where key_id = $2 and org_id = any($3) returning *",
    )
    .bind(secret_hash)
    .bind(key_id)
    .bind(orgs)
    .fetch_optional(pool)
    .await
}

/// Soft-revoke a key by id, scoped to the caller's org(s).
pub async fn soft_delete(
    pool: &PgPool,
    id: Uuid,
    orgs: &[Uuid],
) -> Result<Option<ApiKeysRow>, sqlx::Error> {
    sqlx::query_as::<_, ApiKeysRow>(
        "update api_keys set revoked = true where id = $1 and org_id = any($2) returning *",
    )
    .bind(id)
    .bind(orgs)
    .fetch_optional(pool)
    .await
}

/// Apply a sync upsert patch to a key by id, scoped to the caller's org(s).
pub async fn upsert_fields(
    pool: &PgPool,
    id: Uuid,
    orgs: &[Uuid],
    patch: ApiKeyPatch,
) -> Result<Option<ApiKeysRow>, sqlx::Error> {
    sqlx::query_as::<_, ApiKeysRow>(
        "update api_keys set \
            name = coalesce($2, name), \
            scopes = coalesce($3, scopes), \
            env = coalesce($4, env), \
            revoked = coalesce($5, revoked) \
         where id = $1 and org_id = any($6) returning *",
    )
    .bind(id)
    .bind(patch.name)
    .bind(patch.scopes)
    .bind(patch.env)
    .bind(patch.revoked)
    .bind(orgs)
    .fetch_optional(pool)
    .await
}
