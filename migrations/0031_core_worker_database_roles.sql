-- Least-privilege group roles for the optional Month-1 worker profile. Login
-- roles and passwords are provisioned by the Azure host only after migrations
-- complete. Model-facing agent-supervisor deliberately has no database role.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'core_connector_worker') THEN
        CREATE ROLE core_connector_worker NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'core_sanitizer_indexer') THEN
        CREATE ROLE core_sanitizer_indexer NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'core_signal_runner') THEN
        CREATE ROLE core_signal_runner NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'core_action_executor') THEN
        CREATE ROLE core_action_executor NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'core_learning_worker') THEN
        CREATE ROLE core_learning_worker NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'core_audit_exporter') THEN
        CREATE ROLE core_audit_exporter NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO
    core_connector_worker,
    core_sanitizer_indexer,
    core_signal_runner,
    core_action_executor,
    core_learning_worker,
    core_audit_exporter;

GRANT SELECT, INSERT, UPDATE ON
    connector_accounts,
    approved_source_scopes,
    connector_delta_cursors,
    embedding_versions,
    source_items,
    source_chunks,
    source_item_acls
TO core_connector_worker;

GRANT SELECT ON
    connector_accounts,
    approved_source_scopes,
    source_items,
    source_item_acls,
    embedding_versions
TO core_sanitizer_indexer;
GRANT SELECT, INSERT, UPDATE ON source_chunks TO core_sanitizer_indexer;

GRANT SELECT ON source_items, source_chunks, source_item_acls TO core_signal_runner;
GRANT SELECT, INSERT, UPDATE ON insight_daily_budgets, assistant_insights TO core_signal_runner;

-- The executor receives read-only authorization context. All lifecycle writes
-- remain broker-owned until narrow capability-verifying procedures are added.
GRANT SELECT ON
    external_action_proposals,
    external_action_proposal_items,
    external_action_attempts,
    external_action_receipts,
    external_action_receipt_outbox
TO core_action_executor;

GRANT SELECT ON core_identity_bindings TO core_learning_worker;
GRANT SELECT ON
    learning_revisions,
    learning_feedback,
    learning_heads
TO core_learning_worker;

-- Export state remains owned by the validated audit repository path. The
-- worker cannot claim/export rows or forge checkpoints with raw SQL.
GRANT SELECT ON core_audit_outbox, core_audit_checkpoints TO core_audit_exporter;

-- Audit writes from business workers go only to the append-only outbox. The
-- table's immutable triggers still reject UPDATE and DELETE.
GRANT INSERT ON core_audit_outbox TO
    core_connector_worker,
    core_signal_runner;
