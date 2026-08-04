//! Embedded SQLx migrations for Buzz.
//!
//! Fresh deployments apply the checked-in SQL files under `migrations/`. The
//! multi-tenant rewrite owns a clean consolidated `0001`; legacy single-tenant
//! cutover/backfill is a separate operator script, not startup migration state.

use sqlx::PgPool;

use crate::Result;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// Run all pending Buzz database migrations.
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    reject_legacy_nip_rs_cardinality_ambiguity(pool).await?;
    MIGRATOR.run(pool).await?;
    // The replica-fence proof (see `replica_fence`) requires the commit-time
    // `created_at` floor trigger from migration 0021 — correctly shaped — on
    // the `events` parent and every partition. `CREATE TABLE .. PARTITION OF`
    // clones parent triggers, but a partition attached with `ATTACH
    // PARTITION` or created by an older code path would silently escape the
    // guard, so migration fails closed if any is missing. (The fence probe
    // re-runs this same check at startup on non-migrating relays.)
    crate::replica_fence::verify_floor_guard_catalog(pool).await?;
    Ok(())
}

/// Migration 0007 is checksum-frozen and predates exact NIP-RS tag-cardinality
/// enforcement. A populated database still on 0001-0006 must not let 0007
/// irreversibly purge duplicate-tag history. Fail before sqlx starts its
/// migration transaction so an operator can inspect and repair those rows.
async fn reject_legacy_nip_rs_cardinality_ambiguity(pool: &PgPool) -> Result<()> {
    let migrations_table: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations')::text")
            .fetch_one(pool)
            .await?;
    if migrations_table.is_none() {
        return Ok(());
    }
    let applied: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success")
            .fetch_one(pool)
            .await?;
    if applied.is_none_or(|version| version >= 7) {
        return Ok(());
    }

    let ambiguous: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
             SELECT 1 FROM events e \
             WHERE e.kind = 30078 \
               AND e.d_tag ~ '^read-state:[0-9a-f]{32}$' \
               AND (\
                   jsonb_typeof(e.tags) IS DISTINCT FROM 'array' \
                   OR (\
                       EXISTS (\
                           SELECT 1 FROM jsonb_array_elements(\
                               CASE WHEN jsonb_typeof(e.tags) = 'array' THEN e.tags ELSE '[]'::jsonb END\
                           ) tag \
                           WHERE tag = '[\"t\", \"read-state\"]'::jsonb\
                       ) \
                       AND (\
                           (SELECT count(*) FROM jsonb_array_elements(\
                               CASE WHEN jsonb_typeof(e.tags) = 'array' THEN e.tags ELSE '[]'::jsonb END\
                            ) tag \
                            WHERE jsonb_typeof(tag) = 'array' \
                              AND tag->0 = '\"d\"'::jsonb) <> 1 \
                           OR NOT EXISTS (\
                               SELECT 1 FROM jsonb_array_elements(\
                                   CASE WHEN jsonb_typeof(e.tags) = 'array' THEN e.tags ELSE '[]'::jsonb END\
                               ) tag \
                               WHERE jsonb_typeof(tag) = 'array' \
                                 AND jsonb_array_length(tag) >= 2 \
                                 AND jsonb_typeof(tag->1) = 'string' \
                                 AND tag->>0 = 'd' \
                                 AND tag->>1 = e.d_tag\
                           ) \
                           OR (SELECT count(*) FROM jsonb_array_elements(\
                               CASE WHEN jsonb_typeof(e.tags) = 'array' THEN e.tags ELSE '[]'::jsonb END\
                           ) tag WHERE tag = '[\"t\", \"read-state\"]'::jsonb) <> 1\
                       )\
                   )\
               )\
         )",
    )
    .fetch_one(pool)
    .await?;

    if ambiguous {
        return Err(crate::DbError::InvalidData(
            "NIP-RS migration blocked: pre-0007 database contains kind-30078 rows with ambiguous d/t tag cardinality; repair or remove those nonconforming rows before retrying"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ConstraintKind {
        ForeignKey,
        PrimaryKey,
        Unique,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ConstraintLint {
        table: String,
        kind: ConstraintKind,
        description: String,
        columns: Vec<String>,
    }

    /// Concatenated SQL of every embedded migration, in version order.
    ///
    /// The tenant-isolation lints must cover objects introduced by *any*
    /// migration, not just the consolidated `0001`. Concatenating keeps that
    /// coverage honest as additive migrations (e.g. `0002_git_repo_names`) land.
    fn migration_sql() -> String {
        let mut migrations: Vec<_> = MIGRATOR.iter().collect();
        migrations.sort_by_key(|migration| migration.version);
        assert!(
            !migrations.is_empty(),
            "at least the initial migration must exist"
        );
        migrations
            .iter()
            .map(|migration| migration.sql.as_ref())
            .collect::<Vec<&str>>()
            .join("\n")
    }

    fn strip_sql_comments(sql: &str) -> String {
        sql.lines()
            .map(|line| line.split_once("--").map_or(line, |(before, _)| before))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn normalize_sql(sql: &str) -> String {
        strip_sql_comments(sql)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase()
    }

    fn split_sql_statements(sql: &str) -> Vec<String> {
        let sql = strip_sql_comments(sql);
        let bytes = sql.as_bytes();
        let mut statements = Vec::new();
        let mut start = 0usize;
        let mut idx = 0usize;
        let mut in_single_quote = false;
        let mut in_dollar_quote = false;

        while idx < bytes.len() {
            match bytes[idx] {
                b'\'' if !in_dollar_quote => {
                    in_single_quote = !in_single_quote;
                    idx += 1;
                }
                b'$' if !in_single_quote && idx + 1 < bytes.len() && bytes[idx + 1] == b'$' => {
                    in_dollar_quote = !in_dollar_quote;
                    idx += 2;
                }
                b';' if !in_single_quote && !in_dollar_quote => {
                    let statement = sql[start..idx].trim();
                    if !statement.is_empty() {
                        statements.push(statement.to_owned());
                    }
                    start = idx + 1;
                    idx += 1;
                }
                _ => idx += 1,
            }
        }

        let tail = sql[start..].trim();
        if !tail.is_empty() {
            statements.push(tail.to_owned());
        }

        statements
    }

    fn find_matching_paren(sql: &str, open: usize) -> Option<usize> {
        let mut depth = 0usize;
        for (offset, byte) in sql.as_bytes()[open..].iter().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(open + offset);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn split_top_level_csv(input: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut start = 0usize;
        let mut depth = 0usize;
        for (idx, byte) in input.bytes().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => depth = depth.saturating_sub(1),
                b',' if depth == 0 => {
                    parts.push(input[start..idx].trim().to_owned());
                    start = idx + 1;
                }
                _ => {}
            }
        }
        let tail = input[start..].trim();
        if !tail.is_empty() {
            parts.push(tail.to_owned());
        }
        parts
    }

    fn identifier_after_keyword(statement: &str, keyword: &str) -> Option<String> {
        let lower = statement.to_ascii_lowercase();
        let keyword_pos = lower.find(keyword)?;
        let mut remainder = statement[keyword_pos + keyword.len()..].trim_start();
        for prefix in ["if not exists", "if exists", "only"] {
            if remainder.to_ascii_lowercase().starts_with(prefix) {
                remainder = remainder[prefix.len()..].trim_start();
            }
        }

        let identifier = remainder
            .split(|ch: char| ch.is_whitespace() || ch == '(')
            .next()?
            .trim_matches('"')
            .rsplit('.')
            .next()?
            .trim_matches('"')
            .to_ascii_lowercase();
        (!identifier.is_empty()).then_some(identifier)
    }

    fn first_parenthesized_columns(input: &str) -> Vec<String> {
        let Some(open) = input.find('(') else {
            return Vec::new();
        };
        let Some(close) = find_matching_paren(input, open) else {
            return Vec::new();
        };

        split_top_level_csv(&input[open + 1..close])
            .into_iter()
            .filter_map(|column| {
                let name = column
                    .trim()
                    .trim_matches('"')
                    .split_whitespace()
                    .next()?
                    .trim_matches('"')
                    .to_ascii_lowercase();
                (!name.is_empty()).then_some(name)
            })
            .collect()
    }

    fn column_definition_name(definition: &str) -> Option<String> {
        let trimmed = definition.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("constraint ")
            || lower.starts_with("primary key")
            || lower.starts_with("foreign key")
            || lower.starts_with("unique")
            || lower.starts_with("check ")
            || lower.starts_with("exclude ")
        {
            return None;
        }

        let name = trimmed
            .split_whitespace()
            .next()?
            .trim_matches('"')
            .to_ascii_lowercase();
        (!name.is_empty()).then_some(name)
    }

    fn create_table_body(statement: &str) -> Option<(String, Vec<String>)> {
        let table = identifier_after_keyword(statement, "create table")?;
        let open = statement.find('(')?;
        let close = find_matching_paren(statement, open)?;
        Some((table, split_top_level_csv(&statement[open + 1..close])))
    }

    fn create_table_definitions(sql: &str) -> Vec<(String, Vec<String>)> {
        split_sql_statements(sql)
            .into_iter()
            .filter_map(|statement| {
                let normalized = statement.trim_start().to_ascii_lowercase();
                if !normalized.starts_with("create table") || normalized.contains(" partition of ")
                {
                    return None;
                }
                create_table_body(&statement)
            })
            .collect()
    }

    fn create_tables(sql: &str) -> BTreeSet<String> {
        create_table_definitions(sql)
            .into_iter()
            .map(|(table, _)| table)
            .collect()
    }

    fn table_has_not_null_community_id(definitions: &[String]) -> bool {
        definitions.iter().any(|definition| {
            column_definition_name(definition).as_deref() == Some("community_id")
                && normalize_sql(definition).contains("not null")
        })
    }

    fn operator_global_tables(sql: &str) -> BTreeSet<String> {
        let mut globals = BTreeSet::new();
        let normalized = normalize_sql(sql);
        let Some(insert_pos) = normalized.find("insert into _operator_global_tables") else {
            return globals;
        };

        for value in [
            "communities",
            "rate_limit_violations",
            "_operator_global_tables",
            "push_gateway_challenges",
            "push_gateway_installations",
            "push_gateway_delegations",
            "push_gateway_endpoint_quotas",
            "push_gateway_delivery_auth_replays",
            "push_gateway_delivery_request_replays",
            "product_feedback",
            "replica_heartbeat",
        ] {
            if normalized[insert_pos..].contains(&format!("'{value}'")) {
                globals.insert(value.to_owned());
            }
        }

        globals
    }

    fn scoped_tables(sql: &str) -> BTreeSet<String> {
        let globals = operator_global_tables(sql);
        create_tables(sql)
            .into_iter()
            .filter(|table| !globals.contains(table))
            .collect()
    }

    fn constraint_lint_for_definition(table: &str, definition: &str) -> Option<ConstraintLint> {
        let normalized = normalize_sql(definition);
        let definition_without_name = if normalized.starts_with("constraint ") {
            let after_constraint = definition
                .trim_start()
                .splitn(3, char::is_whitespace)
                .nth(2)
                .unwrap_or("");
            normalize_sql(after_constraint)
        } else {
            normalized.clone()
        };

        if definition_without_name.starts_with("primary key") {
            Some(ConstraintLint {
                table: table.to_owned(),
                kind: ConstraintKind::PrimaryKey,
                description: definition.to_owned(),
                columns: first_parenthesized_columns(&definition_without_name),
            })
        } else if definition_without_name.starts_with("unique") {
            Some(ConstraintLint {
                table: table.to_owned(),
                kind: ConstraintKind::Unique,
                description: definition.to_owned(),
                columns: first_parenthesized_columns(&definition_without_name),
            })
        } else if definition_without_name.starts_with("foreign key") {
            Some(ConstraintLint {
                table: table.to_owned(),
                kind: ConstraintKind::ForeignKey,
                description: definition.to_owned(),
                columns: first_parenthesized_columns(&definition_without_name),
            })
        } else if normalized.contains(" primary key") {
            column_definition_name(definition).map(|column| ConstraintLint {
                table: table.to_owned(),
                kind: ConstraintKind::PrimaryKey,
                description: definition.to_owned(),
                columns: vec![column],
            })
        } else if normalized.contains(" references ") {
            column_definition_name(definition).map(|column| ConstraintLint {
                table: table.to_owned(),
                kind: ConstraintKind::ForeignKey,
                description: definition.to_owned(),
                columns: vec![column],
            })
        } else if normalized.contains(" unique") {
            column_definition_name(definition).map(|column| ConstraintLint {
                table: table.to_owned(),
                kind: ConstraintKind::Unique,
                description: definition.to_owned(),
                columns: vec![column],
            })
        } else {
            None
        }
    }

    fn table_constraints(sql: &str, scoped_tables: &BTreeSet<String>) -> Vec<ConstraintLint> {
        create_table_definitions(sql)
            .into_iter()
            .filter(|(table, _)| scoped_tables.contains(table))
            .flat_map(|(table, definitions)| {
                definitions.into_iter().filter_map(move |definition| {
                    constraint_lint_for_definition(&table, &definition)
                })
            })
            .collect()
    }

    fn alter_table_constraints(sql: &str, scoped_tables: &BTreeSet<String>) -> Vec<ConstraintLint> {
        split_sql_statements(sql)
            .into_iter()
            .filter_map(|statement| {
                let normalized = normalize_sql(&statement);
                if !normalized.starts_with("alter table") {
                    return None;
                }

                let table = identifier_after_keyword(&statement, "alter table")?;
                if !scoped_tables.contains(&table) {
                    return None;
                }

                let add_pos = normalized.find(" add ")?;
                let definition = normalized[add_pos + " add ".len()..].trim();
                constraint_lint_for_definition(&table, definition)
            })
            .collect()
    }

    fn unique_indexes(sql: &str, scoped_tables: &BTreeSet<String>) -> Vec<ConstraintLint> {
        split_sql_statements(sql)
            .into_iter()
            .filter_map(|statement| {
                let normalized = normalize_sql(&statement);
                if !normalized.starts_with("create unique index") {
                    return None;
                }

                let lower_statement = statement.to_ascii_lowercase();
                let on_pos = lower_statement.find(" on ")?;
                let table = statement[on_pos + " on ".len()..]
                    .trim_start()
                    .split(|ch: char| ch.is_whitespace() || ch == '(')
                    .next()?
                    .trim_matches('"')
                    .rsplit('.')
                    .next()?
                    .trim_matches('"')
                    .to_ascii_lowercase();

                scoped_tables.contains(&table).then(|| ConstraintLint {
                    table,
                    kind: ConstraintKind::Unique,
                    description: statement.clone(),
                    columns: first_parenthesized_columns(&statement[on_pos + " on ".len()..]),
                })
            })
            .collect()
    }

    fn scoped_constraint_lints(sql: &str, scoped_tables: &BTreeSet<String>) -> Vec<ConstraintLint> {
        let mut constraints = table_constraints(sql, scoped_tables);
        constraints.extend(alter_table_constraints(sql, scoped_tables));
        constraints.extend(unique_indexes(sql, scoped_tables));
        constraints
    }

    fn is_allowed_partition_primary_key_exception(constraint: &ConstraintLint) -> bool {
        constraint.table == "delivery_log"
            && constraint.kind == ConstraintKind::PrimaryKey
            && constraint.columns == ["delivered_at", "id"]
    }

    fn scoped_constraint_violations(sql: &str) -> Vec<ConstraintLint> {
        let scoped_tables = scoped_tables(sql);
        scoped_constraint_lints(sql, &scoped_tables)
            .into_iter()
            .filter(|constraint| {
                if is_allowed_partition_primary_key_exception(constraint) {
                    return false;
                }
                constraint.columns.first().map(String::as_str) != Some("community_id")
            })
            .collect()
    }

    const CORE_MONTH1_TABLES: &[&str] = &[
        "core_identity_bindings",
        "connector_accounts",
        "approved_source_scopes",
        "connector_delta_cursors",
        "embedding_versions",
        "source_items",
        "source_chunks",
        "source_item_acls",
        "assistant_insights",
        "insight_daily_budgets",
        "external_action_proposals",
        "external_action_proposal_items",
        "external_action_attempts",
        "external_action_receipts",
        "learning_revisions",
        "learning_feedback",
        "learning_heads",
        "core_audit_outbox",
        "core_audit_checkpoints",
    ];

    fn core_month1_definitions(sql: &str) -> Vec<(String, Vec<String>)> {
        create_table_definitions(sql)
            .into_iter()
            .filter(|(table, _)| CORE_MONTH1_TABLES.contains(&table.as_str()))
            .collect()
    }

    fn forbidden_secret_columns(sql: &str) -> Vec<String> {
        const DENIED_COLUMN_FRAGMENTS: &[&str] = &[
            "access_token",
            "refresh_token",
            "client_secret",
            "openai_key",
            "service_credential",
            "private_key",
            "signing_key",
            "windows_key",
            "delta_url",
            "cursor_url",
        ];

        core_month1_definitions(sql)
            .into_iter()
            .flat_map(|(table, definitions)| {
                definitions.into_iter().filter_map(move |definition| {
                    let column = column_definition_name(&definition)?;
                    DENIED_COLUMN_FRAGMENTS
                        .iter()
                        .any(|fragment| column.contains(fragment))
                        .then(|| format!("{table}.{column}"))
                })
            })
            .collect()
    }

    fn forbidden_audit_payload_columns(sql: &str) -> Vec<String> {
        const DENIED_AUDIT_FRAGMENTS: &[&str] = &[
            "prompt",
            "content",
            "body",
            "chunk",
            "transcript",
            "token",
            "mnpi",
            "raw_",
        ];

        core_month1_definitions(sql)
            .into_iter()
            .filter(|(table, _)| table == "core_audit_outbox")
            .flat_map(|(table, definitions)| {
                definitions.into_iter().filter_map(move |definition| {
                    let column = column_definition_name(&definition)?;
                    DENIED_AUDIT_FRAGMENTS
                        .iter()
                        .any(|fragment| column.contains(fragment))
                        .then(|| format!("{table}.{column}"))
                })
            })
            .collect()
    }

    fn missing_required_state_checks(sql: &str) -> Vec<String> {
        const REQUIRED: &[(&str, &str)] = &[
            ("core_identity_bindings", "lifecycle_state"),
            ("connector_accounts", "status"),
            ("approved_source_scopes", "status"),
            ("assistant_insights", "status"),
            ("external_action_proposals", "status"),
            ("external_action_attempts", "outcome"),
            ("external_action_receipts", "reconciliation_state"),
            ("learning_revisions", "state"),
            ("learning_feedback", "outcome"),
            ("learning_heads", "state"),
            ("core_audit_outbox", "export_state"),
        ];

        let definitions = core_month1_definitions(sql);
        REQUIRED
            .iter()
            .filter_map(|(table, column)| {
                let checked = definitions
                    .iter()
                    .find(|(candidate, _)| candidate == table)
                    .is_some_and(|(_, definitions)| {
                        definitions.iter().any(|definition| {
                            let normalized = normalize_sql(definition);
                            normalized.contains("check") && normalized.contains(column)
                        })
                    });
                (!checked).then(|| format!("{table}.{column}"))
            })
            .collect()
    }

    fn non_composite_tenant_relationships(sql: &str) -> Vec<String> {
        let scoped = scoped_tables(sql);
        scoped_constraint_lints(sql, &scoped)
            .into_iter()
            .filter(|constraint| constraint.kind == ConstraintKind::ForeignKey)
            .filter(|constraint| CORE_MONTH1_TABLES.contains(&constraint.table.as_str()))
            .filter(|constraint| {
                constraint.columns.len() < 2
                    && !normalize_sql(&constraint.description).contains("references communities")
            })
            .map(|constraint| format!("{}.{}", constraint.table, constraint.description))
            .collect()
    }

    fn has_channels_community_id_immutability_guard(sql: &str) -> bool {
        let normalized = normalize_sql(sql);
        normalized.contains("create trigger")
            && normalized.contains("before update")
            && normalized.contains(" on channels")
            && normalized.contains("community_id")
            && normalized.contains("old.community_id")
            && normalized.contains("new.community_id")
            && normalized.contains("raise exception")
    }

    fn forbidden_channels_community_id_mutations(sql: &str) -> Vec<String> {
        split_sql_statements(sql)
            .into_iter()
            .filter(|statement| {
                let normalized = normalize_sql(statement);
                let updates_channels =
                    identifier_after_keyword(statement, "update").as_deref() == Some("channels");
                let update_assignments = normalized
                    .split_once(" set ")
                    .map(|(_, tail)| tail.split_once(" where ").map_or(tail, |(set, _)| set));
                let mutates_with_update = updates_channels
                    && update_assignments
                        .is_some_and(|assignments| assignments.contains("community_id"));
                let alters_channels = identifier_after_keyword(statement, "alter table").as_deref()
                    == Some("channels");
                let drops_channels = identifier_after_keyword(statement, "drop table").as_deref()
                    == Some("channels");
                let drops_or_rewrites_column = alters_channels
                    && (normalized.contains("drop column community_id")
                        || normalized.contains("alter column community_id")
                        || normalized.contains("rename column community_id")
                        || normalized.contains("rename community_id")
                        || normalized.contains("drop trigger")
                        || normalized.contains("disable trigger"));

                mutates_with_update || drops_or_rewrites_column || drops_channels
            })
            .collect()
    }

    #[test]
    fn embedded_migrator_contains_consolidated_initial_schema() {
        let mut migrations: Vec<_> = MIGRATOR.iter().collect();
        migrations.sort_by_key(|migration| migration.version);

        assert_eq!(migrations.len(), 29);
        assert_eq!(migrations[0].version, 1);
        assert_eq!(&*migrations[0].description, "initial schema");
        assert!(migrations[0]
            .sql
            .as_str()
            .contains("CREATE TABLE communities"));
        assert!(migrations[0].sql.as_str().contains("CREATE TABLE channels"));
        assert!(migrations[0]
            .sql
            .as_str()
            .contains("CREATE TABLE scheduled_workflow_fires"));
        assert!(migrations[0]
            .sql
            .as_str()
            .contains("CREATE TABLE audit_log"));
        assert!(migrations[0]
            .sql
            .as_str()
            .contains("CREATE TABLE _operator_global_tables"));
        assert!(migrations[0]
            .sql
            .as_str()
            .contains("search_tsv  TSVECTOR GENERATED ALWAYS"));

        // The git repo-name registry is an additive migration, never folded into
        // 0001 — folding it would change 0001's checksum and break brownfield
        // startup (sqlx VersionMismatch). It must live in its own version, and
        // 0001 must not carry it.
        assert_eq!(migrations[1].version, 2);
        assert!(migrations[1]
            .sql
            .as_str()
            .contains("CREATE TABLE git_repo_names"));
        assert!(!migrations[0].sql.as_str().contains("git_repo_names"));

        // Same additive-migration rule for the per-community workspace icon
        // (NIP-11 `icon`): its own version, never folded into 0001.
        assert_eq!(migrations[2].version, 3);
        assert!(migrations[2]
            .sql
            .as_str()
            .contains("ALTER TABLE communities ADD COLUMN icon"));
        assert!(!migrations[0].sql.as_str().contains("icon"));
        // Same additive-migration rule for the e-tag containment GIN index
        // (channel-window aux closure): its own version, never folded into 0001.
        assert_eq!(migrations[3].version, 4);
        assert!(migrations[3]
            .sql
            .as_str()
            .contains("CREATE INDEX idx_events_tags_gin"));
        assert!(!migrations[0].sql.as_str().contains("idx_events_tags_gin"));

        // NIP-AM (kind 44200) FTS exclusion: additive migration, never folded
        // into 0001 — folding would change 0001's checksum and break brownfield
        // startup. Migration 5 drops and re-adds the generated `search_tsv`
        // column with the extended kind-44200 exclusion. 0001 must NOT carry 44200.
        assert_eq!(migrations[4].version, 5);
        assert!(migrations[4].sql.as_str().contains("search_tsv"));
        assert!(migrations[4].sql.as_str().contains("44200"));
        assert!(!migrations[0].sql.as_str().contains("44200"));

        // Community moderation (reports/bans/audit): additive migration, never
        // folded into 0001 — same brownfield checksum rule as above.
        assert_eq!(migrations[5].version, 6);
        assert!(migrations[5]
            .sql
            .as_str()
            .contains("CREATE TABLE moderation_reports"));
        assert!(migrations[5]
            .sql
            .as_str()
            .contains("CREATE TABLE community_bans"));
        assert!(migrations[5]
            .sql
            .as_str()
            .contains("CREATE TABLE moderation_actions"));
        for action in crate::moderation::MODERATION_ACTION_CHECK_VOCAB {
            assert!(
                migrations[5].sql.as_str().contains(&format!("'{action}'")),
                "migration 0006 moderation_actions.action CHECK must allow {action}"
            );
        }
        assert!(!migrations[0].sql.as_str().contains("moderation_reports"));
        // NIP-RS retention is additive and boot-safe: seed replay watermarks
        // before deleting payload history, without rewriting search storage.
        assert_eq!(migrations[6].version, 7);
        assert!(migrations[6]
            .sql
            .as_str()
            .contains("LOCK TABLE events IN SHARE ROW EXCLUSIVE MODE"));
        assert!(migrations[6]
            .sql
            .as_str()
            .contains("CREATE TABLE parameterized_event_watermarks"));
        assert!(migrations[6]
            .sql
            .as_str()
            .contains("INSERT INTO parameterized_event_watermarks"));
        assert!(migrations[6]
            .sql
            .as_str()
            .contains("CREATE INDEX idx_event_mentions_community_event"));
        assert!(migrations[6]
            .sql
            .as_str()
            .contains("NIP-RS retention blocked: deleted event outranks live head"));
        assert!(migrations[6]
            .sql
            .as_str()
            .contains("DELETE FROM events old"));
        assert!(!migrations[6]
            .sql
            .as_str()
            .contains("ALTER TABLE events DROP COLUMN search_tsv"));

        // Fresh installs opt into the positive search allowlist without making
        // populated databases rewrite their events heap during relay startup.
        assert_eq!(migrations[7].version, 8);
        assert!(migrations[7]
            .sql
            .as_str()
            .contains("IF NOT EXISTS (SELECT 1 FROM events LIMIT 1)"));
        assert!(migrations[7]
            .sql
            .as_str()
            .contains("CASE WHEN kind IN (0, 9, 40002, 45001, 45003)"));
        assert!(migrations[7].sql.as_str().contains("ELSE NULL::tsvector"));

        // Mixed-version guards are additive because 0007/0008 may already be
        // recorded by a running relay and their sqlx checksums are immutable.
        assert_eq!(migrations[8].version, 9);
        assert!(migrations[8]
            .sql
            .as_str()
            .contains("CREATE TRIGGER trg_events_nip_rs_watermark"));
        assert!(migrations[8]
            .sql
            .as_str()
            .contains("stale NIP-RS event rejected by durable watermark"));
        assert!(migrations[8]
            .sql
            .as_str()
            .contains("CREATE TRIGGER trg_events_purge_soft_deleted_nip_rs"));
        assert!(migrations[8]
            .sql
            .as_str()
            .contains("CREATE TRIGGER trg_event_mentions_require_live_event"));

        assert_eq!(migrations[9].version, 10);
        assert!(migrations[9]
            .sql
            .as_str()
            .contains("CREATE OR REPLACE FUNCTION guard_nip_rs_watermark"));
        assert!(migrations[9].sql.as_str().contains("RETURN NULL"));

        assert_eq!(migrations[10].version, 11);
        assert!(migrations[10]
            .sql
            .as_str()
            .contains("CREATE OR REPLACE FUNCTION guard_nip_rs_watermark"));
        assert!(migrations[10]
            .sql
            .as_str()
            .contains("CREATE OR REPLACE FUNCTION purge_soft_deleted_nip_rs"));
        assert!(migrations[10].sql.as_str().contains("tag->>0 = 'd'"));
        assert!(migrations[10].sql.as_str().contains(") = 1"));

        // Push leases and their durable outbox are relay-owned and structurally
        // community-scoped; the public gateway remains stateless.
        assert_eq!(migrations[11].version, 12);
        assert!(migrations[11]
            .sql
            .as_str()
            .contains("CREATE TABLE push_leases"));
        assert!(migrations[11]
            .sql
            .as_str()
            .contains("CREATE TABLE push_wake_outbox"));
        assert!(migrations[11]
            .sql
            .as_str()
            .contains("PRIMARY KEY (community_id, author, installation_id)"));
        assert!(!migrations[0].sql.as_str().contains("push_leases"));

        assert_eq!(migrations[12].version, 13);
        assert!(migrations[12]
            .sql
            .as_str()
            .contains("ADD COLUMN endpoint_enabled"));

        // Kind 30350 is author-only encrypted data, so its ciphertext is never
        // indexed for NIP-50 search. Preserve the 0001 checksum and extend the
        // generated expression additively.
        assert_eq!(migrations[13].version, 14);
        assert!(migrations[13].sql.as_str().contains("30350"));
        assert!(migrations[13].sql.as_str().contains("search_tsv"));
        assert!(!migrations[0].sql.as_str().contains("30350"));

        // Public push-gateway authority is intentionally deployment-global and
        // durable: immediate revocation and hostile-relay admission cannot be
        // honestly provided by a stateless gateway.
        assert_eq!(migrations[14].version, 15);
        assert!(migrations[14]
            .sql
            .as_str()
            .contains("CREATE TABLE push_gateway_installations"));
        assert!(migrations[14]
            .sql
            .as_str()
            .contains("push_gateway_delegations"));
        assert!(migrations[14]
            .sql
            .as_str()
            .contains("_operator_global_tables"));

        // Community archival and product feedback landed concurrently. Keep
        // both additive migrations in a single, unambiguous sequence.
        assert_eq!(migrations[15].version, 16);
        assert!(migrations[15]
            .sql
            .as_str()
            .contains("ADD COLUMN archived_at"));

        // Product feedback is a deployment-private sidecar; community_id is
        // provenance, not an operator-review authorization boundary.
        assert_eq!(migrations[16].version, 17);
        assert!(migrations[16]
            .sql
            .as_str()
            .contains("CREATE TABLE product_feedback"));
        assert!(migrations[16]
            .sql
            .as_str()
            .contains("community_id UUID NOT NULL"));
        assert!(migrations[16]
            .sql
            .as_str()
            .contains("('product_feedback', 'deployment product inbox"));
        assert!(!migrations[0].sql.as_str().contains("product_feedback"));

        // Matching is driven from a parent-table trigger so all partition and
        // internal insertion paths share the same crash-safe allowlist seam.
        assert_eq!(migrations[17].version, 18);
        let matcher = migrations[17].sql.as_str();
        assert!(matcher.contains("CREATE TABLE push_match_queue"));
        assert!(matcher.contains("AFTER INSERT ON events"));
        assert!(matcher.contains("NEW.kind IN (7, 9, 1059, 40007, 46010)"));
        assert!(!migrations[0].sql.as_str().contains("push_match_queue"));

        // Mesh status is a heartbeat, not an audit stream. The additive
        // migration removes accumulated soft-deleted payloads and covers old
        // writers during rolling deploys without changing kind:30003 broadly.
        assert_eq!(migrations[18].version, 19);
        let mesh_retention = migrations[18].sql.as_str();
        assert!(mesh_retention.contains("buzz-mesh-member-status:%"));
        assert!(mesh_retention.contains("buzz-mesh-status"));
        assert!(mesh_retention
            .contains("CREATE TRIGGER trg_events_purge_soft_deleted_buzz_mesh_status"));
        assert!(!migrations[0]
            .sql
            .as_str()
            .contains("purge_soft_deleted_buzz_mesh_status"));

        // Join policy acceptances landed concurrently with mesh status retention;
        // keep both additive migrations in a single, unambiguous sequence.
        assert_eq!(migrations[19].version, 20);
        assert!(migrations[19]
            .sql
            .as_str()
            .contains("CREATE TABLE join_policy_acceptances"));

        // Replica-fence commit-time floor guard on channel-bearing events.
        assert_eq!(migrations[20].version, 21);
        assert!(migrations[20]
            .sql
            .as_str()
            .contains("events_created_at_floor_guard"));
        assert!(!migrations[0]
            .sql
            .as_str()
            .contains("join_policy_acceptances"));

        // Channel TTL refresh belongs to the event insertion transaction so a
        // concurrent permanent -> ephemeral transition cannot be missed.
        assert_eq!(migrations[21].version, 22);
        let ttl_refresh = migrations[21].sql.as_str();
        assert!(ttl_refresh.contains("CREATE CONSTRAINT TRIGGER events_refresh_channel_ttl"));
        assert!(ttl_refresh.contains("AFTER INSERT ON events"));
        assert!(ttl_refresh.contains("DEFERRABLE INITIALLY DEFERRED"));
        assert!(ttl_refresh.contains("clock_timestamp()"));
        assert!(ttl_refresh.contains("NEW.kind <> 9007"));

        // T1b push gate: the match-queue trigger only enqueues when the
        // community has an eligible lease, ordered against lease activations
        // through the shared/exclusive per-community advisory lock.
        assert_eq!(migrations[22].version, 23);
        let push_gate = migrations[22].sql.as_str();
        assert!(push_gate.contains("CREATE OR REPLACE FUNCTION enqueue_push_match_job"));
        assert!(push_gate.contains("pg_advisory_xact_lock_shared"));
        assert!(push_gate.contains("'buzz_push_gate:' || NEW.community_id::text"));
        assert!(push_gate.contains("endpoint_enabled"));

        // T1a repair: the TTL refresh trigger synchronizes on a shared
        // per-channel advisory lock instead of FOR UPDATE on the channel row,
        // so permanent-channel commits no longer serialize.
        assert_eq!(migrations[23].version, 24);
        let ttl_shared = migrations[23].sql.as_str();
        assert!(ttl_shared
            .contains("CREATE OR REPLACE FUNCTION refresh_channel_ttl_after_event_insert"));
        assert!(ttl_shared.contains("pg_advisory_xact_lock_shared"));
        assert!(ttl_shared.contains("'buzz_channel_ttl:' || NEW.community_id::text"));
        // The row read must be a bare SELECT (comments describe the removed
        // FOR UPDATE; the executable body must not reintroduce it).
        assert!(ttl_shared.contains("SELECT ttl_seconds INTO channel_ttl"));
        assert!(!strip_sql_comments(ttl_shared)
            .to_lowercase()
            .contains("for update"));
        assert!(ttl_shared.contains("NEW.kind <> 9007"));

        // Use-limited invite links: durable relay_invites table stores only
        // the SHA-256 of an opaque v2 code, scoped by community_id. Never
        // listed in _operator_global_tables — it is community-scoped.
        assert_eq!(migrations[24].version, 25);
        let relay_invites = migrations[24].sql.as_str();
        assert!(relay_invites.contains("CREATE TABLE relay_invites"));
        assert!(relay_invites
            .contains("token_hash   BYTEA       NOT NULL CHECK (length(token_hash) = 32)"));
        assert!(relay_invites.contains("PRIMARY KEY (community_id, id)"));
        assert!(relay_invites.contains("UNIQUE (community_id, token_hash)"));
        assert!(
            relay_invites.contains("max_uses     INTEGER     CHECK (max_uses BETWEEN 1 AND 10000)")
        );
        assert!(relay_invites.contains("CHECK (max_uses IS NULL OR use_count <= max_uses)"));
        assert!(relay_invites.contains("role = 'member'"));
        assert!(relay_invites
            .contains("CREATE INDEX relay_invites_expires_at_idx ON relay_invites (expires_at)"));
        assert!(!relay_invites.contains("_operator_global_tables"));

        let desired_schema = include_str!("../../../schema/schema.sql");
        assert!(
            desired_schema.contains("CREATE TABLE join_policy_acceptances"),
            "desired-state schema must include join-policy evidence used by invite claims",
        );

        // Replica heartbeat (this branch, renumbered to 0026 after
        // 0025_relay_invites landed on main): the fence's portable read-side
        // observation. A single CHECK'd row makes the token update the
        // serialization point (multi-pod commit ordering), and the epoch
        // column is what detects token resets — both are load-bearing for
        // the routing proof.
        assert_eq!(migrations[25].version, 26);
        let heartbeat = migrations[25].sql.as_str();
        assert!(heartbeat.contains("CREATE TABLE replica_heartbeat"));
        assert!(heartbeat.contains("CHECK (id = 1)"));
        assert!(heartbeat.contains("epoch"));
        assert!(heartbeat.contains("INSERT INTO replica_heartbeat (id) VALUES (1)"));
        assert!(heartbeat.contains("_operator_global_tables"));

        assert_eq!(migrations[26].version, 27);
        let core_storage = migrations[26].sql.as_str();
        assert!(core_storage.contains("CREATE EXTENSION IF NOT EXISTS vector"));
        for table in CORE_MONTH1_TABLES {
            assert!(
                core_storage.contains(&format!("CREATE TABLE {table}")),
                "migration 0027 must create {table}"
            );
        }
        for private_kind in [44_300, 44_301, 44_310, 44_311, 44_312, 44_210, 30_179] {
            assert!(
                core_storage.contains(&private_kind.to_string()),
                "migration 0027 must exclude private kind {private_kind} from events.search_tsv"
            );
        }
        assert!(core_storage.contains("existing_expression"));
        assert!(core_storage.contains("ELSE (%s) END"));

        assert_eq!(migrations[27].version, 28);
        let action_broker = migrations[27].sql.as_str();
        assert!(action_broker.contains("ADD COLUMN decision_id UUID"));
        assert!(action_broker.contains("CREATE TABLE external_action_receipt_outbox"));
        assert!(action_broker.contains("get_byte(uuid_send(decision_id), 6) >> 4"));
        assert!(action_broker.contains("get_byte(uuid_send(receipt_id), 6) >> 4"));
        assert!(!action_broker.contains("uuid_extract_version("));

        assert_eq!(migrations[28].version, 29);
        let connector_hardening = migrations[28].sql.as_str();
        assert!(connector_hardening.contains("last_page_digest"));
        assert!(connector_hardening.contains("start_char"));
        assert!(connector_hardening.contains("end_char"));
        assert!(connector_hardening.contains("resolver_hosts"));
        assert!(connector_hardening.contains("idx_embedding_versions_one_active"));
        assert!(connector_hardening.contains("trg_connector_account_purge_source_index"));
        assert!(connector_hardening.contains("trg_source_scope_purge_source_index"));
    }

    #[test]
    fn migration_lint_detects_forbidden_secret_columns() {
        let sql = r#"
            CREATE TABLE connector_accounts (
                community_id UUID NOT NULL,
                id UUID NOT NULL,
                oauth_access_token TEXT NOT NULL,
                PRIMARY KEY (community_id, id)
            );
        "#;

        assert_eq!(
            forbidden_secret_columns(sql),
            vec!["connector_accounts.oauth_access_token"]
        );
    }

    #[test]
    fn core_month1_storage_has_no_secret_or_sensitive_audit_columns() {
        let sql = migration_sql();
        assert_eq!(
            core_month1_definitions(&sql).len(),
            CORE_MONTH1_TABLES.len()
        );
        assert!(
            forbidden_secret_columns(&sql).is_empty(),
            "connector secrets must never be stored: {:?}",
            forbidden_secret_columns(&sql)
        );
        assert!(
            forbidden_audit_payload_columns(&sql).is_empty(),
            "audit outbox must contain typed metadata only: {:?}",
            forbidden_audit_payload_columns(&sql)
        );
    }

    #[test]
    fn core_month1_storage_requires_composite_tenant_relationships_and_state_checks() {
        let sql = migration_sql();
        assert!(
            non_composite_tenant_relationships(&sql).is_empty(),
            "tenant relationships must include community_id: {:?}",
            non_composite_tenant_relationships(&sql)
        );
        assert!(
            missing_required_state_checks(&sql).is_empty(),
            "state columns must be constrained: {:?}",
            missing_required_state_checks(&sql)
        );
    }

    #[test]
    fn core_month1_embeddings_use_indexed_pgvector_storage() {
        let sql = normalize_sql(&migration_sql());
        assert!(sql.contains("from pg_available_extensions where name = 'vector'"));
        assert!(sql.contains("create extension if not exists vector"));
        assert!(sql.contains("dimensions = 384"));
        assert!(sql.contains("embedding vector(384)"));
        assert!(
            sql.contains("using hnsw (embedding vector_cosine_ops)"),
            "local embeddings need a pgvector ANN index"
        );
    }

    #[test]
    fn core_month1_schema_binds_accounts_scopes_users_learning_and_actions() {
        let sql = normalize_sql(&migration_sql());
        assert!(sql.contains("'microsoft_graph', 'google_drive', 'core_crm'"));
        for relationship in [
            "foreign key (community_id, buzz_pubkey) references users (community_id, pubkey)",
            "foreign key (community_id, owner_pubkey) references users (community_id, pubkey)",
            "foreign key (community_id, account_id, scope_id) references approved_source_scopes (community_id, account_id, id)",
        ] {
            assert!(sql.contains(relationship), "missing relationship: {relationship}");
        }
        assert!(sql.contains("unique (community_id, account_id, id)"));
        assert!(sql.contains("create unique index idx_learning_revisions_personal_identity"));
        assert!(sql.contains("create unique index idx_learning_revisions_firm_identity"));
        assert!(sql.contains("create unique index idx_learning_heads_personal_identity"));
        assert!(sql.contains("create unique index idx_learning_heads_firm_identity"));
        assert!(sql.contains("unique (community_id, sequence, entry_hash)"));
        assert!(sql.contains("expires_at <= proposed_at + interval '15 minutes'"));
        assert!(sql.contains("nonce uuid not null check"));
    }

    #[test]
    fn core_month1_uuid_v4_checks_run_on_the_compose_postgres_17_baseline() {
        let sql = normalize_sql(&migration_sql());
        assert!(
            !sql.contains("uuid_extract_version("),
            "uuid_extract_version is PostgreSQL 18-only, while Compose uses PostgreSQL 17"
        );
        for value in [
            "nonce",
            "operation_id",
            "idempotency_key",
            "decision_id",
            "receipt_id",
        ] {
            assert!(
                sql.contains(&format!("get_byte(uuid_send({value}), 6) >> 4")),
                "missing UUID version-nibble check for {value}"
            );
            assert!(
                sql.contains(&format!("get_byte(uuid_send({value}), 8) & 192")),
                "missing RFC UUID variant check for {value}"
            );
        }
    }

    #[test]
    fn core_month1_actions_audit_and_relationships_are_closed_and_non_spliceable() {
        let sql = normalize_sql(&migration_sql());
        for operation in [
            "crm/add_note",
            "crm/log_activity",
            "crm/create_contact",
            "crm/update_contact",
            "crm/create_company",
            "crm/update_company",
            "crm/create_manual_task",
            "crm/update_manual_task",
            "crm/complete_manual_task",
            "crm/create_project",
            "crm/update_project",
            "crm/add_tag",
            "crm/link_granola_record",
            "outlook/create_draft",
            "outlook/update_buzz_owned_draft",
            "outlook/attach_existing_file",
            "outlook/attach_drive_link",
            "google/create_doc",
            "google/create_sheet",
            "google/create_simple_slides",
            "google/edit_doc",
            "google/edit_sheet_range",
            "google/replace_slides_text",
        ] {
            assert!(
                sql.contains(&format!("'{operation}'")),
                "missing operation {operation}"
            );
        }
        for relationship in [
            "foreign key (community_id, connector_account_id, buzz_pubkey) references connector_accounts (community_id, id, owner_pubkey)",
            "foreign key (community_id, account_id, connector, owner_pubkey) references connector_accounts (community_id, id, provider, owner_pubkey)",
            "foreign key (community_id, proposal_id, item_index, attempt_id) references external_action_attempts (community_id, proposal_id, item_index, id)",
            "foreign key (community_id, active_revision_id, layer, owner_discriminator, domain, base_policy_version)",
            "foreign key (community_id, rollback_revision_id, layer, owner_discriminator, domain, base_policy_version)",
        ] {
            assert!(sql.contains(relationship), "missing anti-splicing relationship: {relationship}");
        }
        assert!(sql.contains("object_version ~ '^[a-za-z0-9][a-za-z0-9._:-]{0,127}$'"));
        assert!(sql.contains("signing_state = 'signed' and signer_identifier is not null"));
        assert!(sql.contains("octet_length(signature) = 64"));
        assert!(sql.contains("export_state = 'exported'"));
        assert!(sql.contains("and exported_at is not null"));
        assert!(sql.contains("export_state in ('pending', 'retry')"));
    }

    #[test]
    fn core_identity_binding_keeps_history_with_one_live_entra_binding() {
        let sql = normalize_sql(&migration_sql());
        assert!(!sql.contains("unique (community_id, entra_object_id)"));
        assert!(sql.contains("create unique index idx_core_identity_bindings_live_entra"));
        assert!(sql.contains("on core_identity_bindings (community_id, entra_object_id)"));
        assert!(sql.contains("where lifecycle_state in ('challenged', 'active')"));
        assert!(sql.contains("unique (community_id, buzz_pubkey)"));
        assert!(sql.contains(
            "foreign key (community_id, revoked_by_pubkey) references users (community_id, pubkey)"
        ));
    }

    #[test]
    fn external_actions_bind_owner_private_channel_decision_and_attempt_claim() {
        let sql = normalize_sql(&migration_sql());
        for relationship in [
            "foreign key (community_id, account_id, connector, owner_pubkey)",
            "references connector_accounts (community_id, id, provider, owner_pubkey)",
            "foreign key (community_id, channel_id, channel_visibility)",
            "references channels (community_id, id, visibility)",
            "foreign key (community_id, channel_id, owner_pubkey) references channel_members (community_id, channel_id, pubkey)",
            "foreign key (community_id, proposal_id, claim_id) references external_action_proposals (community_id, id, execution_claim_id)",
        ] {
            assert!(sql.contains(relationship), "missing action binding: {relationship}");
        }
        assert!(sql.contains("channel_visibility = 'private'"));
        assert!(sql.contains("decision_event_hash"));
        assert!(sql.contains("signer_pubkey = owner_pubkey"));
    }

    #[test]
    fn external_action_bundles_are_normalized_and_bind_per_item_outcomes() {
        let sql = normalize_sql(&migration_sql());
        for contract in [
            "create table external_action_proposal_items",
            "canonical_proposal bytea not null check (octet_length(canonical_proposal) between 1 and 65535)",
            "operation_hash bytea not null check (octet_length(operation_hash) = 32)",
            "ordered_members_hash bytea not null check (octet_length(ordered_members_hash) = 32)",
            "member_count smallint not null check (member_count between 1 and 10)",
            "primary key (community_id, proposal_id, item_index)",
            "unique (community_id, proposal_id, member_hash)",
            "foreign key (community_id, proposal_id, owner_pubkey) references external_action_proposals (community_id, id, owner_pubkey)",
            "foreign key (community_id, account_id, connector, owner_pubkey) references connector_accounts (community_id, id, provider, owner_pubkey)",
            "foreign key (community_id, account_id, scope_id) references approved_source_scopes (community_id, account_id, id)",
            "foreign key (community_id, proposal_id, item_index) references external_action_proposal_items (community_id, proposal_id, item_index)",
            "foreign key (community_id, proposal_id, item_index, member_hash, operation_id) references external_action_proposal_items (community_id, proposal_id, item_index, member_hash, operation_id)",
            "foreign key (community_id, proposal_id, item_index, attempt_id) references external_action_attempts (community_id, proposal_id, item_index, id)",
        ] {
            assert!(sql.contains(contract), "missing bundle binding: {contract}");
        }
        for field in [
            "item_index smallint not null",
            "operation_id uuid not null",
            "account_id uuid not null",
            "scope_id uuid not null",
            "target_hash bytea not null",
            "canonical_operation bytea not null",
            "canonical_operation_hash bytea not null",
            "before_hash bytea",
            "after_hash bytea",
            "expected_remote_version text",
            "idempotency_key uuid not null",
            "member_hash bytea not null",
        ] {
            assert!(sql.contains(field), "missing bundle member field: {field}");
        }
        assert!(sql.contains("item_index between 0 and 9"));
        assert!(sql.contains("after_hash bytea not null check (octet_length(after_hash) = 32)"));
        assert!(sql.contains("get_byte(uuid_send(idempotency_key), 6) >> 4"));
        assert!(sql.contains("default 'proposed'"));
        assert!(sql.contains(
            "status in ('proposed', 'approved', 'denied', 'executing', 'succeeded', 'failed', 'reconciliation_required')"
        ));
    }

    #[test]
    fn external_action_decisions_bind_owner_broker_and_private_channel() {
        let sql = normalize_sql(&migration_sql());
        for contract in [
            "broker_pubkey bytea not null check (octet_length(broker_pubkey) = 32)",
            "decision_broker_pubkey bytea",
            "foreign key (community_id, broker_pubkey) references users (community_id, pubkey)",
            "foreign key (community_id, channel_id, broker_pubkey) references channel_members (community_id, channel_id, pubkey)",
            "decision_broker_pubkey = broker_pubkey",
        ] {
            assert!(sql.contains(contract), "missing broker binding: {contract}");
        }
        assert!(sql.contains("proposed_at timestamptz not null"));
        assert!(sql.contains("expires_at > proposed_at"));
        assert!(sql.contains("expires_at <= proposed_at + interval '15 minutes'"));
        assert!(!sql.contains("expires_at > created_at and expires_at <= created_at"));
    }

    #[test]
    fn external_action_proposal_hashes_canonical_context_separately_from_ordered_members() {
        let sql = normalize_sql(&migration_sql());
        for contract in [
            "canonical_proposal bytea not null",
            "octet_length(canonical_proposal) between 1 and 65535",
            "canonical_operation_hash bytea not null check (octet_length(canonical_operation_hash) = 32)",
            "ordered_members_hash bytea not null check (octet_length(ordered_members_hash) = 32)",
            "canonical_operation_hash bytea not null check (octet_length(canonical_operation_hash) = 32)",
            "octet_length(canonical_operation) between 1 and 65535",
            "operation_id uuid not null check",
            "unique (community_id, proposal_id, operation_id)",
        ] {
            assert!(sql.contains(contract), "missing canonical action contract: {contract}");
        }
    }

    #[test]
    fn writable_source_scopes_always_require_read_authority() {
        let sql = normalize_sql(&migration_sql());
        assert!(sql.contains("check (not can_write or can_read)"));
    }

    #[test]
    fn action_receipts_use_protocol_reconciliation_states_and_bind_operation_id() {
        let sql = normalize_sql(&migration_sql());
        assert!(sql.contains(
            "outcome text not null check (outcome in ('succeeded', 'failed', 'reconciliation_required'))"
        ));
        assert!(sql.contains(
            "reconciliation_state in ('not_required', 'pending', 'reconciled', 'manual_review')"
        ));
        assert!(sql.contains(
            "foreign key (community_id, proposal_id, item_index, member_hash, operation_id) references external_action_proposal_items"
        ));
        assert!(sql.contains("(reconciliation_state = 'reconciled') = (reconciled_at is not null)"));
    }

    #[test]
    fn learning_domains_are_closed_to_the_protocol_set() {
        let sql = normalize_sql(&migration_sql());
        let definitions = create_table_definitions(&sql);
        let learning_sql = definitions
            .into_iter()
            .filter(|(table, _)| matches!(table.as_str(), "learning_revisions" | "learning_heads"))
            .flat_map(|(_, definitions)| definitions)
            .collect::<Vec<_>>()
            .join(" ");
        for domain in [
            "ranking_within_policy_tier",
            "timing_within_allowed_feed_window",
            "card_presentation_preference",
            "writing_style_traits",
            "relationship_priority_hints",
            "source_quality_weights",
            "buyer_selection_heuristics",
            "research_heuristics",
            "bounded_workflow_ordering",
        ] {
            assert!(learning_sql.matches(&format!("'{domain}'")).count() >= 2);
        }
        assert!(!learning_sql.contains("'permissions'"));
        assert!(!learning_sql.contains("'unknown'"));
    }

    #[test]
    fn migration_lint_detects_tables_missing_community_id_by_default() {
        let sql = r#"
            CREATE TABLE communities (id UUID PRIMARY KEY);
            CREATE TABLE widgets (id UUID PRIMARY KEY);
            CREATE TABLE _operator_global_tables (table_name TEXT PRIMARY KEY, reason TEXT NOT NULL);
            INSERT INTO _operator_global_tables (table_name, reason) VALUES
                ('communities', 'tenant registry'),
                ('_operator_global_tables', 'registry');
        "#;

        let definitions = create_table_definitions(sql);
        let scoped = scoped_tables(sql);
        let missing = definitions
            .into_iter()
            .filter(|(table, _)| scoped.contains(table))
            .filter(|(_, definitions)| !table_has_not_null_community_id(definitions))
            .map(|(table, _)| table)
            .collect::<Vec<_>>();

        assert_eq!(missing, vec!["widgets"]);
    }

    #[test]
    fn migration_lint_detects_scoped_key_constraints_not_led_by_community_id() {
        let sql = r#"
            CREATE TABLE widgets (
                community_id UUID NOT NULL,
                id UUID PRIMARY KEY,
                channel_id UUID REFERENCES channels(id),
                slug TEXT,
                CONSTRAINT widgets_name_unique UNIQUE (slug),
                CONSTRAINT widgets_parent_fk FOREIGN KEY (channel_id) REFERENCES channels(id)
            );
            CREATE UNIQUE INDEX idx_widgets_slug ON widgets (slug);
            ALTER TABLE widgets ADD CONSTRAINT widgets_alter_slug_unique UNIQUE (slug);
            ALTER TABLE widgets ADD CONSTRAINT widgets_alter_parent_fk FOREIGN KEY (channel_id) REFERENCES channels(id);
            CREATE TABLE _operator_global_tables (table_name TEXT PRIMARY KEY, reason TEXT NOT NULL);
            INSERT INTO _operator_global_tables (table_name, reason) VALUES
                ('_operator_global_tables', 'registry');
        "#;

        let violations = scoped_constraint_violations(sql);

        assert!(violations
            .iter()
            .any(|violation| violation.kind == ConstraintKind::PrimaryKey));
        assert_eq!(
            violations
                .iter()
                .filter(|violation| violation.kind == ConstraintKind::ForeignKey)
                .count(),
            3
        );
        assert_eq!(
            violations
                .iter()
                .filter(|violation| violation.kind == ConstraintKind::Unique)
                .count(),
            3
        );
    }

    #[test]
    fn migration_lint_accepts_scoped_key_constraints_led_by_community_id() {
        let sql = r#"
            CREATE TABLE widgets (
                community_id UUID NOT NULL,
                id UUID NOT NULL,
                channel_id UUID NOT NULL,
                slug TEXT NOT NULL,
                PRIMARY KEY (community_id, id),
                UNIQUE (community_id, slug),
                FOREIGN KEY (community_id, channel_id) REFERENCES channels(community_id, id)
            );
            CREATE UNIQUE INDEX idx_widgets_slug ON widgets (community_id, slug);
            ALTER TABLE widgets ADD CONSTRAINT widgets_alter_slug_unique UNIQUE (community_id, slug);
            ALTER TABLE widgets ADD CONSTRAINT widgets_alter_parent_fk FOREIGN KEY (community_id, channel_id) REFERENCES channels(community_id, id);
            CREATE TABLE _operator_global_tables (table_name TEXT PRIMARY KEY, reason TEXT NOT NULL);
            INSERT INTO _operator_global_tables (table_name, reason) VALUES
                ('_operator_global_tables', 'registry');
        "#;

        assert!(scoped_constraint_violations(sql).is_empty());
    }

    #[test]
    fn all_non_operator_global_tables_have_not_null_community_id() {
        let sql = migration_sql();
        let sql = sql.as_str();
        let scoped = scoped_tables(sql);
        let missing = create_table_definitions(sql)
            .into_iter()
            .filter(|(table, _)| scoped.contains(table))
            .filter(|(_, definitions)| !table_has_not_null_community_id(definitions))
            .map(|(table, _)| table)
            .collect::<Vec<_>>();

        assert!(
            missing.is_empty(),
            "every table not listed in _operator_global_tables must carry NOT NULL community_id; missing: {}",
            missing.join(", ")
        );
    }

    #[test]
    fn scoped_primary_key_unique_and_foreign_key_constraints_lead_with_community_id() {
        let sql = migration_sql();
        let sql = sql.as_str();
        let violations = scoped_constraint_violations(sql)
            .into_iter()
            .map(|constraint| {
                format!(
                    "{}. {:?} constraint must lead with community_id: {}",
                    constraint.table, constraint.kind, constraint.description
                )
            })
            .collect::<Vec<_>>();

        assert!(
            violations.is_empty(),
            "tenant-scoped tables are all tables not listed in _operator_global_tables; primary key, unique/FK constraints, and unique indexes on those tables must lead with community_id:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn channels_community_id_is_immutable_after_insert() {
        let sql = migration_sql();
        let sql = sql.as_str();
        let forbidden_mutations = forbidden_channels_community_id_mutations(sql);

        assert!(
            forbidden_mutations.is_empty(),
            "channels.community_id must not be re-tenanted after insert; forbidden migration statements:\n{}",
            forbidden_mutations.join("\n---\n")
        );
        assert!(
            has_channels_community_id_immutability_guard(sql),
            "migrations define channels.community_id but no BEFORE UPDATE trigger/function guard that rejects OLD.community_id <> NEW.community_id was found"
        );
    }

    async fn connect_test_pool() -> PgPool {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_owned());

        PgPool::connect(&database_url)
            .await
            .expect("connect to test DB")
    }

    async fn reset_public_schema(pool: &PgPool) {
        sqlx::query("DROP SCHEMA IF EXISTS public CASCADE")
            .execute(pool)
            .await
            .expect("drop public schema");
        sqlx::query("CREATE SCHEMA IF NOT EXISTS public")
            .execute(pool)
            .await
            .expect("create public schema");
    }

    async fn applied_versions(pool: &PgPool) -> Vec<i64> {
        sqlx::query_scalar::<_, i64>(
            "SELECT version FROM _sqlx_migrations WHERE success ORDER BY version",
        )
        .fetch_all(pool)
        .await
        .expect("read applied migrations")
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn pre_0007_ambiguous_nip_rs_data_blocks_without_mutation_and_allows_retry() {
        let pool = connect_test_pool().await;
        reset_public_schema(&pool).await;
        MIGRATOR
            .run_to(6, &pool)
            .await
            .expect("apply migrations 1-6");

        let community_id = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
            .bind(community_id)
            .bind(format!("pre-0007-{}.example", community_id.simple()))
            .execute(&pool)
            .await
            .expect("insert community");
        let event_id = vec![1_u8; 32];
        let pubkey = vec![2_u8; 32];
        let d_tag = format!("read-state:{}", "a".repeat(32));
        let ambiguous_tags = serde_json::json!([["d", d_tag], ["d", "other"], ["t", "read-state"]]);
        sqlx::query(
            "INSERT INTO events \
             (community_id, id, pubkey, created_at, kind, tags, content, sig, received_at, d_tag) \
             VALUES ($1, $2, $3, NOW(), 30078, $4, 'ambiguous', $5, NOW(), $6)",
        )
        .bind(community_id)
        .bind(&event_id)
        .bind(&pubkey)
        .bind(&ambiguous_tags)
        .bind(vec![3_u8; 64])
        .bind(&d_tag)
        .execute(&pool)
        .await
        .expect("insert ambiguous NIP-RS row");

        let before_versions = applied_versions(&pool).await;
        let before_row: (serde_json::Value, String) =
            sqlx::query_as("SELECT tags, content FROM events WHERE community_id=$1 AND id=$2")
                .bind(community_id)
                .bind(&event_id)
                .fetch_one(&pool)
                .await
                .expect("read ambiguous row before blocked migration");
        let blocked = run_migrations(&pool).await;
        assert!(blocked.is_err(), "ambiguous pre-0007 data must fail closed");
        assert_eq!(applied_versions(&pool).await, before_versions);
        let after_row: (serde_json::Value, String) =
            sqlx::query_as("SELECT tags, content FROM events WHERE community_id=$1 AND id=$2")
                .bind(community_id)
                .bind(&event_id)
                .fetch_one(&pool)
                .await
                .expect("blocked migration must preserve source row");
        assert_eq!(after_row, before_row);

        let repaired_tags = serde_json::json!([["d", d_tag], ["t", "read-state"]]);
        sqlx::query("UPDATE events SET tags=$1 WHERE community_id=$2 AND id=$3")
            .bind(repaired_tags)
            .bind(community_id)
            .bind(&event_id)
            .execute(&pool)
            .await
            .expect("repair ambiguous row");
        run_migrations(&pool)
            .await
            .expect("retry succeeds after operator repair");
        assert_eq!(applied_versions(&pool).await.last().copied(), Some(26));
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn populated_upgrade_preserves_search_policy_except_for_push_leases() {
        let pool = connect_test_pool().await;
        reset_public_schema(&pool).await;
        MIGRATOR
            .run_to(7, &pool)
            .await
            .expect("apply migrations 1-7");

        let community_id = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
            .bind(community_id)
            .bind(format!("pre-0008-{}.example", community_id.simple()))
            .execute(&pool)
            .await
            .expect("insert community");

        for (marker, kind) in [(1_u8, 1_i32), (2_u8, 30_350_i32)] {
            sqlx::query(
                "INSERT INTO events \
                 (community_id, id, pubkey, created_at, kind, tags, content, sig, received_at) \
                 VALUES ($1, $2, $3, NOW(), $4, '[]'::jsonb, 'brownfield needle', $5, NOW())",
            )
            .bind(community_id)
            .bind(vec![marker; 32])
            .bind(vec![marker + 10; 32])
            .bind(kind)
            .bind(vec![marker + 20; 64])
            .execute(&pool)
            .await
            .expect("insert brownfield event");
        }

        MIGRATOR
            .run_to(11, &pool)
            .await
            .expect("apply main migrations through 11");
        let before: Vec<(i32, bool)> = sqlx::query_as(
            "SELECT kind, search_tsv @@ plainto_tsquery('simple', 'needle') \
             FROM events ORDER BY kind",
        )
        .fetch_all(&pool)
        .await
        .expect("read pre-push search behavior");
        assert_eq!(before, vec![(1, true), (30_350, true)]);

        run_migrations(&pool)
            .await
            .expect("apply push migrations to populated database");
        let after: Vec<(i32, Option<bool>)> = sqlx::query_as(
            "SELECT kind, search_tsv @@ plainto_tsquery('simple', 'needle') \
             FROM events ORDER BY kind",
        )
        .fetch_all(&pool)
        .await
        .expect("read post-push search behavior");
        assert_eq!(after, vec![(1, Some(true)), (30_350, None)]);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn run_migrations_applies_consolidated_initial_schema_on_fresh_database() {
        let pool = connect_test_pool().await;
        reset_public_schema(&pool).await;

        run_migrations(&pool).await.expect("run migrations");

        // Every embedded migration must apply, in order. Derive the expected
        // list from the MIGRATOR itself so this doesn't go stale as additive
        // migrations land (it previously hardcoded [1, 2, 3] and rotted).
        let expected: Vec<i64> = {
            let mut versions: Vec<i64> = MIGRATOR.iter().map(|m| m.version).collect();
            versions.sort_unstable();
            versions
        };
        assert_eq!(applied_versions(&pool).await, expected);
        let sql = migration_sql();
        let tables = create_tables(sql.as_str());
        for table in [
            "communities",
            "events",
            "channels",
            "scheduled_workflow_fires",
            "audit_log",
        ] {
            let exists = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1)",
            )
            .bind(table)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|err| panic!("check table {table}: {err}"));
            assert!(
                tables.contains(table),
                "migration parser should see {table}"
            );
            assert!(exists, "migration should create {table}");
        }

        let search_expression: String = sqlx::query_scalar(
            "SELECT pg_get_expr(adbin, adrelid) \
             FROM pg_attrdef \
             WHERE adrelid = 'events'::regclass \
               AND adnum = (SELECT attnum FROM pg_attribute \
                            WHERE attrelid = 'events'::regclass \
                              AND attname = 'search_tsv')",
        )
        .fetch_one(&pool)
        .await
        .expect("read fresh-install search expression");
        assert!(
            search_expression.contains("ARRAY[0, 9, 40002, 45001, 45003]"),
            "fresh-install search allowlist has the wrong kinds: {search_expression}"
        );
        assert!(
            search_expression.contains("ELSE NULL::tsvector"),
            "fresh installs must default non-allowlisted kinds to NULL: {search_expression}"
        );
        assert!(
            search_expression.contains("ARRAY[44300, 44301, 44310, 44311, 44312, 44210, 30179]"),
            "Core private persistent kinds must be storage-level FTS NULL: {search_expression}"
        );
    }
}
