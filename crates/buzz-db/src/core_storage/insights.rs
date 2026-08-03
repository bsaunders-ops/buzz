use buzz_core::CommunityId;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::{
    require_hash, require_pubkey, AssistantInsightRecord, InsightClaimDecision,
    InsightClaimOutcome, NewAssistantInsight,
};

/// Atomically claim one visible insight under the owner's New York daily cap.
///
/// The budget row is locked before dedupe and count evaluation, serializing all
/// runners for one owner/day. Duplicate and exhausted claims commit no insight
/// row and do not consume budget.
pub async fn claim_insight_slot(
    pool: &PgPool,
    community_id: CommunityId,
    insight: NewAssistantInsight<'_>,
) -> crate::Result<InsightClaimOutcome> {
    require_pubkey("owner_pubkey", insight.owner_pubkey)?;
    require_hash("dedupe_key", insight.dedupe_key)?;
    require_hash("evidence_hash", insight.evidence_hash)?;
    if insight.evidence_count <= 0 {
        return Err(crate::DbError::InvalidData(
            "evidence_count must be positive".into(),
        ));
    }

    let mut tx = pool.begin().await?;
    let current_private_member: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM channels channel \
             JOIN channel_members member \
               ON member.community_id=channel.community_id AND member.channel_id=channel.id \
             WHERE channel.community_id=$1 AND channel.id=$2 AND channel.visibility='private' \
               AND member.pubkey=$3 AND member.removed_at IS NULL \
         )",
    )
    .bind(community_id.as_uuid())
    .bind(insight.channel_id)
    .bind(insight.owner_pubkey)
    .fetch_one(&mut *tx)
    .await?;
    if !current_private_member {
        return Err(crate::DbError::InvalidData(
            "insight owner must be a current member of the private destination channel".into(),
        ));
    }
    let new_york_date = sqlx::query_scalar(
        "SELECT (transaction_timestamp() AT TIME ZONE 'America/New_York')::date",
    )
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO insight_daily_budgets \
         (community_id, owner_pubkey, new_york_date) VALUES ($1, $2, $3) \
         ON CONFLICT (community_id, owner_pubkey, new_york_date) DO NOTHING",
    )
    .bind(community_id.as_uuid())
    .bind(insight.owner_pubkey)
    .bind(new_york_date)
    .execute(&mut *tx)
    .await?;

    let accepted_count: i16 = sqlx::query_scalar(
        "SELECT accepted_count FROM insight_daily_budgets \
         WHERE community_id=$1 AND owner_pubkey=$2 AND new_york_date=$3 FOR UPDATE",
    )
    .bind(community_id.as_uuid())
    .bind(insight.owner_pubkey)
    .bind(new_york_date)
    .fetch_one(&mut *tx)
    .await?;
    let duplicate: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM assistant_insights \
         WHERE community_id=$1 AND owner_pubkey=$2 AND new_york_date=$3 AND dedupe_key=$4)",
    )
    .bind(community_id.as_uuid())
    .bind(insight.owner_pubkey)
    .bind(new_york_date)
    .bind(insight.dedupe_key)
    .fetch_one(&mut *tx)
    .await?;

    match InsightClaimDecision::evaluate(duplicate, accepted_count) {
        InsightClaimDecision::Duplicate => {
            tx.commit().await?;
            Ok(InsightClaimOutcome::Duplicate)
        }
        InsightClaimDecision::BudgetExhausted => {
            tx.commit().await?;
            Ok(InsightClaimOutcome::BudgetExhausted)
        }
        InsightClaimDecision::Claim => {
            let id = Uuid::new_v4();
            let row = sqlx::query(
                "INSERT INTO assistant_insights \
                 (community_id, id, owner_pubkey, channel_id, new_york_date, dedupe_key, priority, evidence_hash, evidence_count, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                 RETURNING status, created_at",
            )
            .bind(community_id.as_uuid())
            .bind(id)
            .bind(insight.owner_pubkey)
            .bind(insight.channel_id)
            .bind(new_york_date)
            .bind(insight.dedupe_key)
            .bind(insight.priority.as_i16())
            .bind(insight.evidence_hash)
            .bind(insight.evidence_count)
            .bind(insight.expires_at)
            .fetch_one(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE insight_daily_budgets \
                 SET accepted_count=accepted_count+1, updated_at=NOW() \
                 WHERE community_id=$1 AND owner_pubkey=$2 AND new_york_date=$3",
            )
            .bind(community_id.as_uuid())
            .bind(insight.owner_pubkey)
            .bind(new_york_date)
            .execute(&mut *tx)
            .await?;
            let record = AssistantInsightRecord {
                community_id,
                id,
                owner_pubkey: insight.owner_pubkey.to_vec(),
                channel_id: insight.channel_id,
                new_york_date,
                dedupe_key: insight.dedupe_key.to_vec(),
                priority: insight.priority,
                status: row.try_get("status")?,
                evidence_hash: insight.evidence_hash.to_vec(),
                evidence_count: insight.evidence_count,
                created_at: row.try_get("created_at")?,
            };
            tx.commit().await?;
            Ok(InsightClaimOutcome::Claimed(record))
        }
    }
}
