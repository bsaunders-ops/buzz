-- Preserve deterministic Unicode-scalar offsets and make the database capable
-- of re-verifying the frozen, domain-separated source-chunk hash. Rows written
-- before these fields existed cannot be reconstructed safely, so fail closed
-- and require their connector scope to reindex them.

ALTER TABLE connector_delta_cursors
    ADD COLUMN last_page_digest BYTEA
        CHECK (last_page_digest IS NULL OR octet_length(last_page_digest) = 32);

ALTER TABLE approved_source_scopes
    ADD COLUMN resolver_hosts TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    ADD CONSTRAINT approved_source_scopes_resolver_hosts_check CHECK (
        cardinality(resolver_hosts) <= 16
        AND array_position(resolver_hosts, NULL) IS NULL
    );

ALTER TABLE source_chunks
    ADD COLUMN start_char BIGINT,
    ADD COLUMN end_char BIGINT;

UPDATE source_items item
SET status = 'unavailable',
    updated_at = NOW()
WHERE EXISTS (
    SELECT 1
    FROM source_chunks chunk
    WHERE chunk.community_id = item.community_id
      AND chunk.item_id = item.id
);

DELETE FROM source_chunks;

ALTER TABLE source_chunks
    ALTER COLUMN start_char SET NOT NULL,
    ALTER COLUMN end_char SET NOT NULL,
    ADD CONSTRAINT source_chunks_scalar_offsets_check CHECK (
        start_char >= 0
        AND end_char > start_char
        AND end_char - start_char <= 1200
    );

-- An unactivated model can never satisfy retrieval, even if an older build
-- wrote the legacy default status. Only one fully indexed model revision may
-- be active for a model family inside a tenant.
UPDATE embedding_versions
SET status = 'building'
WHERE status = 'active' AND activated_at IS NULL;

ALTER TABLE embedding_versions
    ADD CONSTRAINT embedding_versions_lifecycle_check CHECK (
        (status = 'building' AND activated_at IS NULL AND retired_at IS NULL)
        OR (status = 'active' AND activated_at IS NOT NULL AND retired_at IS NULL)
        OR (status = 'retired' AND activated_at IS NOT NULL AND retired_at IS NOT NULL)
    );

CREATE UNIQUE INDEX idx_embedding_versions_one_active
    ON embedding_versions (community_id, model_name)
    WHERE status = 'active';

-- Removing read authority also removes the active index and ACL projection in
-- the same database statement. Re-enabling an account/scope requires a fresh
-- deterministic delta page; stale indexed content is never resurrected.
CREATE OR REPLACE FUNCTION purge_source_index_for_inactive_account()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status <> 'active' AND OLD.status IS DISTINCT FROM NEW.status THEN
        DELETE FROM source_chunks chunk
        USING source_items item
        WHERE item.community_id = NEW.community_id
          AND item.account_id = NEW.id
          AND chunk.community_id = item.community_id
          AND chunk.item_id = item.id;

        DELETE FROM source_item_acls acl
        USING source_items item
        WHERE item.community_id = NEW.community_id
          AND item.account_id = NEW.id
          AND acl.community_id = item.community_id
          AND acl.item_id = item.id;

        UPDATE source_items
        SET status = CASE WHEN NEW.status = 'revoked' THEN 'revoked' ELSE 'unavailable' END,
            tombstoned_at = COALESCE(tombstoned_at, transaction_timestamp()),
            updated_at = transaction_timestamp()
        WHERE community_id = NEW.community_id
          AND account_id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_connector_account_purge_source_index
AFTER UPDATE OF status ON connector_accounts
FOR EACH ROW
EXECUTE FUNCTION purge_source_index_for_inactive_account();

CREATE OR REPLACE FUNCTION purge_source_index_for_inactive_scope()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF (NEW.status <> 'active' OR NOT NEW.can_read)
       AND (OLD.status IS DISTINCT FROM NEW.status OR OLD.can_read IS DISTINCT FROM NEW.can_read)
    THEN
        DELETE FROM source_chunks chunk
        USING source_items item
        WHERE item.community_id = NEW.community_id
          AND item.account_id = NEW.account_id
          AND item.scope_id = NEW.id
          AND chunk.community_id = item.community_id
          AND chunk.item_id = item.id;

        DELETE FROM source_item_acls acl
        USING source_items item
        WHERE item.community_id = NEW.community_id
          AND item.account_id = NEW.account_id
          AND item.scope_id = NEW.id
          AND acl.community_id = item.community_id
          AND acl.item_id = item.id;

        UPDATE source_items
        SET status = CASE WHEN NEW.status = 'revoked' THEN 'revoked' ELSE 'unavailable' END,
            tombstoned_at = COALESCE(tombstoned_at, transaction_timestamp()),
            updated_at = transaction_timestamp()
        WHERE community_id = NEW.community_id
          AND account_id = NEW.account_id
          AND scope_id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_source_scope_purge_source_index
AFTER UPDATE OF status, can_read ON approved_source_scopes
FOR EACH ROW
EXECUTE FUNCTION purge_source_index_for_inactive_scope();
