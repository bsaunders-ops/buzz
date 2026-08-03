-- Core Month-1 durable storage. Every table below is community-scoped; tenant
-- relationships are composite and all uniqueness begins with community_id.
-- Connector credentials remain in Key Vault. PostgreSQL stores only a
-- non-secret credential reference and application-encrypted opaque cursors.

CREATE TABLE connector_accounts (
    community_id          UUID NOT NULL REFERENCES communities(id),
    id                    UUID NOT NULL DEFAULT gen_random_uuid(),
    provider              TEXT NOT NULL CHECK (provider IN ('microsoft_graph', 'google_drive', 'core_crm')),
    owner_pubkey          BYTEA NOT NULL CHECK (octet_length(owner_pubkey) = 32),
    external_account_id   TEXT NOT NULL,
    credential_reference  TEXT NOT NULL CHECK (credential_reference ~ '^[A-Za-z0-9-]{1,127}$'),
    status                TEXT NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active', 'paused', 'revoked', 'error')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at            TIMESTAMPTZ,
    revocation_reason     TEXT,
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, provider, external_account_id),
    UNIQUE (community_id, id, provider),
    UNIQUE (community_id, id, owner_pubkey),
    UNIQUE (community_id, id, provider, owner_pubkey),
    FOREIGN KEY (community_id, owner_pubkey)
        REFERENCES users (community_id, pubkey),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX idx_connector_accounts_owner
    ON connector_accounts (community_id, owner_pubkey, status);

CREATE TABLE core_identity_bindings (
    community_id          UUID NOT NULL REFERENCES communities(id),
    id                    UUID NOT NULL DEFAULT gen_random_uuid(),
    entra_object_id       UUID NOT NULL,
    buzz_pubkey           BYTEA NOT NULL CHECK (octet_length(buzz_pubkey) = 32),
    lifecycle_state       TEXT NOT NULL DEFAULT 'challenged'
                          CHECK (lifecycle_state IN ('challenged', 'active', 'revoked', 'expired')),
    challenge_hash        BYTEA NOT NULL CHECK (octet_length(challenge_hash) = 32),
    challenge_created_at  TIMESTAMPTZ NOT NULL,
    challenge_expires_at  TIMESTAMPTZ NOT NULL,
    challenge_verified_at TIMESTAMPTZ,
    connector_account_id  UUID,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at            TIMESTAMPTZ,
    revoked_by_pubkey     BYTEA CHECK (revoked_by_pubkey IS NULL OR octet_length(revoked_by_pubkey) = 32),
    revocation_reason     TEXT,
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, buzz_pubkey),
    FOREIGN KEY (community_id, buzz_pubkey)
        REFERENCES users (community_id, pubkey),
    FOREIGN KEY (community_id, connector_account_id, buzz_pubkey)
        REFERENCES connector_accounts (community_id, id, owner_pubkey),
    FOREIGN KEY (community_id, revoked_by_pubkey)
        REFERENCES users (community_id, pubkey),
    CHECK (challenge_expires_at > challenge_created_at),
    CHECK (
        (lifecycle_state = 'challenged' AND challenge_verified_at IS NULL)
        OR (lifecycle_state = 'active' AND challenge_verified_at IS NOT NULL
            AND challenge_verified_at >= challenge_created_at
            AND challenge_verified_at <= challenge_expires_at)
        OR (lifecycle_state = 'revoked' AND challenge_verified_at IS NOT NULL
            AND challenge_verified_at >= challenge_created_at
            AND challenge_verified_at <= challenge_expires_at)
        OR (lifecycle_state = 'expired' AND challenge_verified_at IS NULL)
    ),
    CHECK ((lifecycle_state = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE UNIQUE INDEX idx_core_identity_bindings_live_entra
    ON core_identity_bindings (community_id, entra_object_id)
    WHERE lifecycle_state IN ('challenged', 'active');

CREATE TABLE approved_source_scopes (
    community_id          UUID NOT NULL REFERENCES communities(id),
    id                    UUID NOT NULL DEFAULT gen_random_uuid(),
    account_id            UUID NOT NULL,
    external_scope_id     TEXT NOT NULL,
    scope_type            TEXT NOT NULL,
    display_name          TEXT,
    can_read              BOOLEAN NOT NULL DEFAULT TRUE,
    can_write             BOOLEAN NOT NULL DEFAULT FALSE,
    active_deal_pinned    BOOLEAN NOT NULL DEFAULT FALSE,
    status                TEXT NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active', 'paused', 'revoked', 'error')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at            TIMESTAMPTZ,
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, account_id, external_scope_id),
    UNIQUE (community_id, account_id, id),
    FOREIGN KEY (community_id, account_id)
        REFERENCES connector_accounts (community_id, id),
    CHECK (can_read OR can_write),
    CHECK (NOT can_write OR can_read),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX idx_approved_source_scopes_active
    ON approved_source_scopes (community_id, account_id, status);

CREATE TABLE connector_delta_cursors (
    community_id          UUID NOT NULL REFERENCES communities(id),
    account_id            UUID NOT NULL,
    scope_id              UUID NOT NULL,
    stream                TEXT NOT NULL CHECK (stream ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    encrypted_cursor      BYTEA NOT NULL CHECK (octet_length(encrypted_cursor) > 0),
    cursor_integrity_hash BYTEA NOT NULL CHECK (octet_length(cursor_integrity_hash) = 32),
    cursor_key_version    INTEGER NOT NULL CHECK (cursor_key_version > 0),
    generation            BIGINT NOT NULL DEFAULT 0 CHECK (generation >= 0),
    last_success_at       TIMESTAMPTZ,
    lease_owner           UUID,
    lease_until           TIMESTAMPTZ,
    retry_count           INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    next_retry_at         TIMESTAMPTZ,
    last_error_code       TEXT,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, account_id, scope_id, stream),
    FOREIGN KEY (community_id, account_id)
        REFERENCES connector_accounts (community_id, id),
    FOREIGN KEY (community_id, account_id, scope_id)
        REFERENCES approved_source_scopes (community_id, account_id, id),
    CHECK ((lease_owner IS NULL) = (lease_until IS NULL))
);

CREATE INDEX idx_connector_delta_cursors_due
    ON connector_delta_cursors (community_id, next_retry_at, lease_until);

CREATE TABLE embedding_versions (
    community_id          UUID NOT NULL REFERENCES communities(id),
    id                    UUID NOT NULL DEFAULT gen_random_uuid(),
    model_name            TEXT NOT NULL,
    dimensions            INTEGER NOT NULL CHECK (dimensions = 384),
    version               INTEGER NOT NULL CHECK (version > 0),
    status                TEXT NOT NULL DEFAULT 'active'
                          CHECK (status IN ('building', 'active', 'retired')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at          TIMESTAMPTZ,
    retired_at            TIMESTAMPTZ,
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, model_name, version)
);

CREATE TABLE source_items (
    community_id               UUID NOT NULL REFERENCES communities(id),
    id                         UUID NOT NULL DEFAULT gen_random_uuid(),
    account_id                 UUID NOT NULL,
    scope_id                   UUID NOT NULL,
    external_item_id           TEXT NOT NULL,
    remote_version             TEXT NOT NULL,
    remote_etag                TEXT,
    title                      TEXT NOT NULL,
    source_type                TEXT NOT NULL,
    modified_at                TIMESTAMPTZ NOT NULL,
    resolvable_link            TEXT NOT NULL,
    status                     TEXT NOT NULL DEFAULT 'active'
                               CHECK (status IN ('active', 'unavailable', 'revoked')),
    tombstoned_at              TIMESTAMPTZ,
    last_authorization_check_at TIMESTAMPTZ NOT NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, account_id, scope_id, external_item_id),
    FOREIGN KEY (community_id, account_id)
        REFERENCES connector_accounts (community_id, id),
    FOREIGN KEY (community_id, account_id, scope_id)
        REFERENCES approved_source_scopes (community_id, account_id, id)
);

CREATE INDEX idx_source_items_active
    ON source_items (community_id, account_id, scope_id, modified_at DESC)
    WHERE status = 'active' AND tombstoned_at IS NULL;

CREATE TABLE source_chunks (
    community_id        UUID NOT NULL REFERENCES communities(id),
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    item_id             UUID NOT NULL,
    chunk_index         INTEGER NOT NULL CHECK (chunk_index >= 0),
    content             TEXT NOT NULL,
    content_hash        BYTEA NOT NULL CHECK (octet_length(content_hash) = 32),
    search_tsv          TSVECTOR GENERATED ALWAYS AS (to_tsvector('simple', content)) STORED,
    embedding_version_id UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, item_id, chunk_index),
    UNIQUE (community_id, item_id, content_hash),
    FOREIGN KEY (community_id, item_id)
        REFERENCES source_items (community_id, id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, embedding_version_id)
        REFERENCES embedding_versions (community_id, id)
);

CREATE INDEX idx_source_chunks_fts
    ON source_chunks USING GIN (search_tsv);

-- Core deployments install pgvector in their managed Postgres image. Keep the
-- OSS relay bootable on vanilla/external Postgres by adding vector storage only
-- when the server advertises the extension. Core retrieval fails closed if the
-- optional column is absent; it never substitutes JSON or remote embeddings.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'vector') THEN
        CREATE EXTENSION IF NOT EXISTS vector;
        EXECUTE 'ALTER TABLE source_chunks ADD COLUMN embedding VECTOR(384)';
        EXECUTE 'ALTER TABLE source_chunks ADD CONSTRAINT source_chunks_embedding_version_check CHECK ((embedding IS NULL) = (embedding_version_id IS NULL))';
        EXECUTE 'CREATE INDEX idx_source_chunks_embedding ON source_chunks USING HNSW (embedding vector_cosine_ops)';
    END IF;
END $$;

CREATE TABLE source_item_acls (
    community_id       UUID NOT NULL REFERENCES communities(id),
    id                 UUID NOT NULL DEFAULT gen_random_uuid(),
    item_id            UUID NOT NULL,
    principal_type     TEXT NOT NULL CHECK (principal_type IN ('user', 'channel')),
    principal_pubkey   BYTEA CHECK (principal_pubkey IS NULL OR octet_length(principal_pubkey) = 32),
    channel_id         UUID,
    granted_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, id),
    FOREIGN KEY (community_id, item_id)
        REFERENCES source_items (community_id, id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, channel_id)
        REFERENCES channels (community_id, id),
    FOREIGN KEY (community_id, principal_pubkey)
        REFERENCES users (community_id, pubkey),
    CHECK (
        (principal_type = 'user' AND principal_pubkey IS NOT NULL AND channel_id IS NULL)
        OR
        (principal_type = 'channel' AND principal_pubkey IS NULL AND channel_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX idx_source_item_acls_user
    ON source_item_acls (community_id, item_id, principal_pubkey)
    WHERE principal_type = 'user';
CREATE UNIQUE INDEX idx_source_item_acls_channel
    ON source_item_acls (community_id, item_id, channel_id)
    WHERE principal_type = 'channel';

CREATE TABLE insight_daily_budgets (
    community_id      UUID NOT NULL REFERENCES communities(id),
    owner_pubkey      BYTEA NOT NULL CHECK (octet_length(owner_pubkey) = 32),
    new_york_date     DATE NOT NULL,
    accepted_count    SMALLINT NOT NULL DEFAULT 0 CHECK (accepted_count BETWEEN 0 AND 10),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, owner_pubkey, new_york_date),
    FOREIGN KEY (community_id, owner_pubkey)
        REFERENCES users (community_id, pubkey)
);

ALTER TABLE channels
    ADD CONSTRAINT channels_tenant_id_visibility_unique
    UNIQUE (community_id, id, visibility);

CREATE TABLE assistant_insights (
    community_id      UUID NOT NULL REFERENCES communities(id),
    id                UUID NOT NULL DEFAULT gen_random_uuid(),
    owner_pubkey      BYTEA NOT NULL CHECK (octet_length(owner_pubkey) = 32),
    channel_id        UUID NOT NULL,
    channel_visibility channel_visibility NOT NULL DEFAULT 'private'
                       CHECK (channel_visibility = 'private'),
    new_york_date     DATE NOT NULL,
    dedupe_key        BYTEA NOT NULL CHECK (octet_length(dedupe_key) = 32),
    priority          SMALLINT NOT NULL CHECK (priority BETWEEN 0 AND 3),
    status            TEXT NOT NULL DEFAULT 'accepted'
                      CHECK (status IN ('accepted', 'published', 'dismissed', 'expired')),
    evidence_hash     BYTEA NOT NULL CHECK (octet_length(evidence_hash) = 32),
    evidence_count    INTEGER NOT NULL CHECK (evidence_count > 0),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at      TIMESTAMPTZ,
    dismissed_at      TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ,
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, owner_pubkey, new_york_date, dedupe_key),
    FOREIGN KEY (community_id, channel_id, channel_visibility)
        REFERENCES channels (community_id, id, visibility),
    FOREIGN KEY (community_id, channel_id, owner_pubkey)
        REFERENCES channel_members (community_id, channel_id, pubkey),
    FOREIGN KEY (community_id, owner_pubkey)
        REFERENCES users (community_id, pubkey),
    FOREIGN KEY (community_id, owner_pubkey, new_york_date)
        REFERENCES insight_daily_budgets (community_id, owner_pubkey, new_york_date)
);

CREATE INDEX idx_assistant_insights_feed
    ON assistant_insights (community_id, owner_pubkey, new_york_date, priority DESC, created_at);

CREATE TABLE external_action_proposals (
    community_id          UUID NOT NULL REFERENCES communities(id),
    id                    UUID NOT NULL DEFAULT gen_random_uuid(),
    owner_pubkey          BYTEA NOT NULL CHECK (octet_length(owner_pubkey) = 32),
    broker_pubkey         BYTEA NOT NULL CHECK (octet_length(broker_pubkey) = 32),
    channel_id            UUID NOT NULL,
    channel_visibility    channel_visibility NOT NULL DEFAULT 'private'
                          CHECK (channel_visibility = 'private'),
    canonical_proposal    BYTEA NOT NULL CHECK (octet_length(canonical_proposal) BETWEEN 1 AND 65535),
    operation_hash        BYTEA NOT NULL CHECK (octet_length(operation_hash) = 32),
    ordered_members_hash  BYTEA NOT NULL CHECK (octet_length(ordered_members_hash) = 32),
    member_count          SMALLINT NOT NULL CHECK (member_count BETWEEN 1 AND 10),
    nonce                 UUID NOT NULL CHECK (uuid_extract_version(nonce) = 4),
    proposed_at           TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,
    status                TEXT NOT NULL DEFAULT 'proposed'
                          CHECK (status IN ('proposed', 'approved', 'denied', 'expired', 'executing', 'succeeded', 'reconciliation_required', 'failed')),
    signer_pubkey         BYTEA CHECK (signer_pubkey IS NULL OR octet_length(signer_pubkey) = 32),
    decision_broker_pubkey BYTEA CHECK (decision_broker_pubkey IS NULL OR octet_length(decision_broker_pubkey) = 32),
    decision_event_hash   BYTEA CHECK (decision_event_hash IS NULL OR octet_length(decision_event_hash) = 32),
    decision_reason_code  TEXT,
    decided_at            TIMESTAMPTZ,
    execution_claim_id    UUID,
    execution_claimed_by  UUID,
    execution_claimed_at  TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, nonce),
    UNIQUE (community_id, id, owner_pubkey),
    UNIQUE (community_id, id, execution_claim_id),
    FOREIGN KEY (community_id, owner_pubkey)
        REFERENCES users (community_id, pubkey),
    FOREIGN KEY (community_id, broker_pubkey)
        REFERENCES users (community_id, pubkey),
    FOREIGN KEY (community_id, channel_id, channel_visibility)
        REFERENCES channels (community_id, id, visibility),
    FOREIGN KEY (community_id, channel_id, owner_pubkey)
        REFERENCES channel_members (community_id, channel_id, pubkey),
    FOREIGN KEY (community_id, channel_id, broker_pubkey)
        REFERENCES channel_members (community_id, channel_id, pubkey),
    CHECK (expires_at > proposed_at AND expires_at <= proposed_at + INTERVAL '15 minutes'),
    CHECK ((execution_claim_id IS NULL) = (execution_claimed_at IS NULL)),
    CHECK ((execution_claim_id IS NULL) = (execution_claimed_by IS NULL)),
    CHECK (
        (status = 'proposed'
         AND signer_pubkey IS NULL AND decision_broker_pubkey IS NULL
         AND decision_event_hash IS NULL AND decided_at IS NULL)
        OR (status IN ('approved', 'denied', 'executing', 'succeeded', 'reconciliation_required', 'failed')
            AND signer_pubkey = owner_pubkey
            AND decision_broker_pubkey = broker_pubkey
            AND decision_event_hash IS NOT NULL AND decided_at IS NOT NULL)
        OR (status = 'expired'
            AND (
                (signer_pubkey IS NULL AND decision_broker_pubkey IS NULL
                 AND decision_event_hash IS NULL AND decided_at IS NULL)
                OR (signer_pubkey = owner_pubkey AND decision_broker_pubkey = broker_pubkey
                    AND decision_event_hash IS NOT NULL AND decided_at IS NOT NULL)
            ))
    )
);

CREATE TABLE external_action_proposal_items (
    community_id          UUID NOT NULL REFERENCES communities(id),
    proposal_id           UUID NOT NULL,
    item_index            SMALLINT NOT NULL CHECK (item_index BETWEEN 0 AND 9),
    operation_id          UUID NOT NULL CHECK (uuid_extract_version(operation_id) = 4),
    account_id            UUID NOT NULL,
    scope_id              UUID NOT NULL,
    owner_pubkey          BYTEA NOT NULL CHECK (octet_length(owner_pubkey) = 32),
    connector             TEXT NOT NULL CHECK (connector IN ('microsoft_graph', 'google_drive', 'core_crm')),
    operation             TEXT NOT NULL CHECK (operation IN (
                              'crm/add_note',
                              'crm/log_activity',
                              'crm/create_contact',
                              'crm/update_contact',
                              'crm/create_company',
                              'crm/update_company',
                              'crm/create_manual_task',
                              'crm/update_manual_task',
                              'crm/complete_manual_task',
                              'crm/create_project',
                              'crm/update_project',
                              'crm/add_tag',
                              'crm/link_granola_record',
                              'outlook/create_draft',
                              'outlook/update_buzz_owned_draft',
                              'outlook/attach_existing_file',
                              'outlook/attach_drive_link',
                              'google/create_doc',
                              'google/create_sheet',
                              'google/create_simple_slides',
                              'google/edit_doc',
                              'google/edit_sheet_range',
                              'google/replace_slides_text'
                          )),
    target_hash           BYTEA NOT NULL CHECK (octet_length(target_hash) = 32),
    canonical_operation   BYTEA NOT NULL CHECK (octet_length(canonical_operation) BETWEEN 1 AND 65535),
    canonical_operation_hash BYTEA NOT NULL CHECK (octet_length(canonical_operation_hash) = 32),
    before_hash           BYTEA CHECK (before_hash IS NULL OR octet_length(before_hash) = 32),
    after_hash            BYTEA NOT NULL CHECK (octet_length(after_hash) = 32),
    expected_remote_version TEXT,
    idempotency_key       UUID NOT NULL CHECK (uuid_extract_version(idempotency_key) = 4),
    member_hash           BYTEA NOT NULL CHECK (octet_length(member_hash) = 32),
    status                TEXT NOT NULL DEFAULT 'proposed'
                          CHECK (status IN ('proposed', 'approved', 'denied', 'executing', 'succeeded', 'failed', 'reconciliation_required')),
    PRIMARY KEY (community_id, proposal_id, item_index),
    UNIQUE (community_id, proposal_id, member_hash),
    UNIQUE (community_id, proposal_id, operation_id),
    UNIQUE (community_id, proposal_id, item_index, member_hash),
    UNIQUE (community_id, proposal_id, item_index, member_hash, operation_id),
    UNIQUE (community_id, idempotency_key),
    FOREIGN KEY (community_id, proposal_id, owner_pubkey)
        REFERENCES external_action_proposals (community_id, id, owner_pubkey),
    FOREIGN KEY (community_id, account_id, connector, owner_pubkey)
        REFERENCES connector_accounts (community_id, id, provider, owner_pubkey),
    FOREIGN KEY (community_id, account_id, scope_id)
        REFERENCES approved_source_scopes (community_id, account_id, id),
    CHECK (
        (connector = 'core_crm' AND operation LIKE 'crm/%')
        OR (connector = 'microsoft_graph' AND operation LIKE 'outlook/%')
        OR (connector = 'google_drive' AND operation LIKE 'google/%')
    ),
    CHECK (
        (operation IN (
            'crm/create_contact',
            'crm/create_company',
            'crm/create_manual_task',
            'crm/create_project',
            'outlook/create_draft',
            'google/create_doc',
            'google/create_sheet',
            'google/create_simple_slides'
         ) AND before_hash IS NULL AND expected_remote_version IS NULL)
        OR
        (operation NOT IN (
            'crm/create_contact',
            'crm/create_company',
            'crm/create_manual_task',
            'crm/create_project',
            'outlook/create_draft',
            'google/create_doc',
            'google/create_sheet',
            'google/create_simple_slides'
         ) AND before_hash IS NOT NULL
           AND octet_length(expected_remote_version) BETWEEN 1 AND 256)
    )
);

CREATE TABLE external_action_attempts (
    community_id      UUID NOT NULL REFERENCES communities(id),
    id                UUID NOT NULL DEFAULT gen_random_uuid(),
    proposal_id       UUID NOT NULL,
    item_index        SMALLINT NOT NULL,
    claim_id          UUID NOT NULL,
    attempt_number    INTEGER NOT NULL CHECK (attempt_number > 0),
    started_at        TIMESTAMPTZ NOT NULL,
    finished_at       TIMESTAMPTZ,
    outcome           TEXT NOT NULL DEFAULT 'in_progress'
                      CHECK (outcome IN ('in_progress', 'succeeded', 'failed', 'timeout', 'remote_unknown')),
    remote_status_code INTEGER,
    remote_outcome_hash BYTEA CHECK (remote_outcome_hash IS NULL OR octet_length(remote_outcome_hash) = 32),
    error_code        TEXT,
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, proposal_id, item_index, attempt_number),
    UNIQUE (community_id, proposal_id, item_index, id),
    FOREIGN KEY (community_id, proposal_id, item_index)
        REFERENCES external_action_proposal_items (community_id, proposal_id, item_index),
    FOREIGN KEY (community_id, proposal_id, claim_id)
        REFERENCES external_action_proposals (community_id, id, execution_claim_id)
);

CREATE TABLE external_action_receipts (
    community_id          UUID NOT NULL REFERENCES communities(id),
    id                    UUID NOT NULL DEFAULT gen_random_uuid(),
    proposal_id           UUID NOT NULL,
    item_index            SMALLINT NOT NULL,
    operation_id          UUID NOT NULL CHECK (uuid_extract_version(operation_id) = 4),
    member_hash           BYTEA NOT NULL CHECK (octet_length(member_hash) = 32),
    attempt_id            UUID NOT NULL,
    remote_result_id      TEXT CHECK (
                              remote_result_id IS NULL
                              OR remote_result_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}$'
                          ),
    remote_resource_id_hash BYTEA CHECK (remote_resource_id_hash IS NULL OR octet_length(remote_resource_id_hash) = 32),
    remote_version        TEXT,
    outcome               TEXT NOT NULL CHECK (outcome IN ('succeeded', 'failed', 'reconciliation_required')),
    reconciliation_state  TEXT NOT NULL DEFAULT 'not_required'
                          CHECK (reconciliation_state IN ('not_required', 'pending', 'reconciled', 'manual_review')),
    reconciled_at         TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, proposal_id, item_index),
    FOREIGN KEY (community_id, proposal_id, item_index, member_hash, operation_id)
        REFERENCES external_action_proposal_items (community_id, proposal_id, item_index, member_hash, operation_id),
    FOREIGN KEY (community_id, proposal_id, item_index, attempt_id)
        REFERENCES external_action_attempts (community_id, proposal_id, item_index, id),
    CHECK (
        outcome <> 'succeeded'
        OR (remote_result_id IS NOT NULL AND octet_length(remote_version) BETWEEN 1 AND 256)
    ),
    CHECK (
        (outcome = 'succeeded' AND reconciliation_state IN ('not_required', 'reconciled'))
        OR (outcome = 'failed' AND reconciliation_state = 'not_required')
        OR (outcome = 'reconciliation_required'
            AND reconciliation_state IN ('pending', 'manual_review'))
    ),
    CHECK ((reconciliation_state = 'reconciled') = (reconciled_at IS NOT NULL))
);

CREATE TABLE learning_revisions (
    community_id          UUID NOT NULL REFERENCES communities(id),
    id                    UUID NOT NULL DEFAULT gen_random_uuid(),
    layer                 TEXT NOT NULL CHECK (layer IN ('personal', 'sanitized_firm')),
    owner_pubkey          BYTEA CHECK (owner_pubkey IS NULL OR octet_length(owner_pubkey) = 32),
    owner_discriminator   BYTEA GENERATED ALWAYS AS (COALESCE(owner_pubkey, ''::bytea)) STORED,
    domain                TEXT NOT NULL CHECK (domain IN (
                              'ranking_within_policy_tier',
                              'timing_within_allowed_feed_window',
                              'card_presentation_preference',
                              'writing_style_traits',
                              'relationship_priority_hints',
                              'source_quality_weights',
                              'buyer_selection_heuristics',
                              'research_heuristics',
                              'bounded_workflow_ordering'
                          )),
    version               INTEGER NOT NULL CHECK (version > 0),
    encrypted_bundle      BYTEA NOT NULL CHECK (octet_length(encrypted_bundle) > 0),
    bundle_integrity_hash BYTEA NOT NULL CHECK (octet_length(bundle_integrity_hash) = 32),
    encryption_key_version INTEGER NOT NULL CHECK (encryption_key_version > 0),
    base_policy_version   TEXT NOT NULL,
    evidence_count        INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
    positive_evidence_count INTEGER NOT NULL DEFAULT 0 CHECK (positive_evidence_count >= 0),
    negative_evidence_count INTEGER NOT NULL DEFAULT 0 CHECK (negative_evidence_count >= 0),
    canary_assignment     SMALLINT CHECK (canary_assignment BETWEEN 0 AND 99),
    canary_outcome        TEXT CHECK (canary_outcome IN ('pending', 'passed', 'failed')),
    state                 TEXT NOT NULL DEFAULT 'candidate'
                          CHECK (state IN ('candidate', 'canary', 'active', 'rolled_back', 'quarantined', 'retired')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at          TIMESTAMPTZ,
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, id, layer, owner_discriminator, domain, base_policy_version),
    FOREIGN KEY (community_id, owner_pubkey)
        REFERENCES users (community_id, pubkey),
    CHECK ((layer = 'personal') = (owner_pubkey IS NOT NULL)),
    CHECK (positive_evidence_count + negative_evidence_count <= evidence_count)
);

CREATE UNIQUE INDEX idx_learning_revisions_personal_identity
    ON learning_revisions (community_id, layer, owner_pubkey, domain, version)
    WHERE layer = 'personal';
CREATE UNIQUE INDEX idx_learning_revisions_firm_identity
    ON learning_revisions (community_id, layer, domain, version)
    WHERE layer = 'sanitized_firm';

CREATE TABLE learning_feedback (
    community_id          UUID NOT NULL REFERENCES communities(id),
    id                    UUID NOT NULL DEFAULT gen_random_uuid(),
    revision_id           UUID NOT NULL,
    evidence_id_hash      BYTEA NOT NULL CHECK (octet_length(evidence_id_hash) = 32),
    outcome               TEXT NOT NULL CHECK (outcome IN ('positive', 'negative', 'neutral', 'invalid')),
    occurred_at           TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, revision_id, evidence_id_hash),
    FOREIGN KEY (community_id, revision_id)
        REFERENCES learning_revisions (community_id, id)
);

CREATE TABLE learning_heads (
    community_id          UUID NOT NULL REFERENCES communities(id),
    id                    UUID NOT NULL DEFAULT gen_random_uuid(),
    layer                 TEXT NOT NULL CHECK (layer IN ('personal', 'sanitized_firm')),
    owner_pubkey          BYTEA CHECK (owner_pubkey IS NULL OR octet_length(owner_pubkey) = 32),
    owner_discriminator   BYTEA GENERATED ALWAYS AS (COALESCE(owner_pubkey, ''::bytea)) STORED,
    domain                TEXT NOT NULL CHECK (domain IN (
                              'ranking_within_policy_tier',
                              'timing_within_allowed_feed_window',
                              'card_presentation_preference',
                              'writing_style_traits',
                              'relationship_priority_hints',
                              'source_quality_weights',
                              'buyer_selection_heuristics',
                              'research_heuristics',
                              'bounded_workflow_ordering'
                          )),
    active_revision_id    UUID NOT NULL,
    rollback_revision_id  UUID,
    base_policy_version   TEXT NOT NULL,
    state                 TEXT NOT NULL DEFAULT 'active'
                          CHECK (state IN ('active', 'rolled_back', 'quarantined')),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, id),
    FOREIGN KEY (community_id, owner_pubkey)
        REFERENCES users (community_id, pubkey),
    FOREIGN KEY (community_id, active_revision_id, layer, owner_discriminator, domain, base_policy_version)
        REFERENCES learning_revisions (community_id, id, layer, owner_discriminator, domain, base_policy_version),
    FOREIGN KEY (community_id, rollback_revision_id, layer, owner_discriminator, domain, base_policy_version)
        REFERENCES learning_revisions (community_id, id, layer, owner_discriminator, domain, base_policy_version),
    CHECK ((layer = 'personal') = (owner_pubkey IS NOT NULL))
);

CREATE UNIQUE INDEX idx_learning_heads_personal_identity
    ON learning_heads (community_id, layer, owner_pubkey, domain)
    WHERE layer = 'personal';
CREATE UNIQUE INDEX idx_learning_heads_firm_identity
    ON learning_heads (community_id, layer, domain)
    WHERE layer = 'sanitized_firm';

CREATE TABLE core_audit_outbox (
    community_id      UUID NOT NULL REFERENCES communities(id),
    sequence          BIGINT NOT NULL CHECK (sequence > 0),
    event_type        TEXT NOT NULL CHECK (event_type IN (
                          'identity_binding_changed', 'connector_account_changed', 'source_sync',
                          'insight_claimed', 'action_proposal_decided', 'action_execution',
                          'learning_revision_changed', 'audit_export'
                      )),
    entity_type       TEXT NOT NULL CHECK (entity_type IN (
                          'identity_binding', 'connector_account', 'source_scope', 'source_item',
                          'assistant_insight', 'external_action_proposal', 'learning_revision',
                          'audit_checkpoint'
                      )),
    entity_id         UUID NOT NULL,
    object_hash       BYTEA NOT NULL CHECK (octet_length(object_hash) = 32),
    object_version    TEXT CHECK (
                          object_version IS NULL
                          OR object_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
                      ),
    occurred_at       TIMESTAMPTZ NOT NULL,
    outcome           TEXT NOT NULL CHECK (outcome IN (
                          'accepted', 'rejected', 'succeeded', 'failed', 'timeout',
                          'reconciliation_required', 'revoked', 'tombstoned', 'retried'
                      )),
    prior_entry_hash  BYTEA CHECK (prior_entry_hash IS NULL OR octet_length(prior_entry_hash) = 32),
    entry_hash        BYTEA NOT NULL CHECK (octet_length(entry_hash) = 32),
    signing_state     TEXT NOT NULL DEFAULT 'unsigned'
                      CHECK (signing_state IN ('unsigned', 'signed', 'signing_failed')),
    signer_identifier TEXT CHECK (
                          signer_identifier IS NULL
                          OR signer_identifier ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
                      ),
    signature         BYTEA,
    export_state      TEXT NOT NULL DEFAULT 'pending'
                      CHECK (export_state IN ('pending', 'claimed', 'retry', 'exported')),
    export_batch_id   UUID,
    export_claimed_by UUID,
    export_claimed_at TIMESTAMPTZ,
    export_claim_until TIMESTAMPTZ,
    retry_count       INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    next_retry_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    exported_at       TIMESTAMPTZ,
    PRIMARY KEY (community_id, sequence),
    UNIQUE (community_id, entry_hash),
    UNIQUE (community_id, sequence, entry_hash),
    CHECK ((sequence = 1) = (prior_entry_hash IS NULL)),
    CHECK (
        (signing_state = 'signed' AND signer_identifier IS NOT NULL
         AND octet_length(signature) = 64)
        OR (signing_state IN ('unsigned', 'signing_failed')
            AND signer_identifier IS NULL AND signature IS NULL)
    ),
    CHECK (
        (export_state = 'claimed'
         AND export_batch_id IS NOT NULL AND export_claimed_by IS NOT NULL
         AND export_claimed_at IS NOT NULL AND export_claim_until IS NOT NULL
         AND exported_at IS NULL)
        OR (export_state = 'exported'
            AND export_batch_id IS NULL AND export_claimed_by IS NULL
            AND export_claimed_at IS NULL AND export_claim_until IS NULL
            AND exported_at IS NOT NULL)
        OR (export_state IN ('pending', 'retry')
            AND export_batch_id IS NULL AND export_claimed_by IS NULL
            AND export_claimed_at IS NULL AND export_claim_until IS NULL
            AND exported_at IS NULL)
    ),
    CHECK (export_state NOT IN ('claimed', 'exported') OR signing_state = 'signed')
);

CREATE INDEX idx_core_audit_outbox_export
    ON core_audit_outbox (community_id, export_state, sequence);

CREATE OR REPLACE FUNCTION enforce_core_audit_outbox_insert()
RETURNS TRIGGER AS $$
DECLARE
    predecessor_sequence BIGINT;
    predecessor_hash BYTEA;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('core_audit:' || NEW.community_id::text, 0));
    SELECT sequence, entry_hash INTO predecessor_sequence, predecessor_hash
      FROM core_audit_outbox
     WHERE community_id = NEW.community_id
     ORDER BY sequence DESC
     LIMIT 1;
    IF predecessor_sequence IS NULL THEN
        IF NEW.sequence <> 1 OR NEW.prior_entry_hash IS NOT NULL THEN
            RAISE EXCEPTION 'audit chain must begin at sequence 1 without a predecessor';
        END IF;
    ELSIF NEW.sequence <> predecessor_sequence + 1
       OR NEW.prior_entry_hash IS DISTINCT FROM predecessor_hash THEN
        RAISE EXCEPTION 'audit predecessor sequence/hash continuity violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_core_audit_outbox_insert
BEFORE INSERT ON core_audit_outbox
FOR EACH ROW EXECUTE FUNCTION enforce_core_audit_outbox_insert();

CREATE OR REPLACE FUNCTION enforce_core_audit_outbox_update()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.community_id IS DISTINCT FROM OLD.community_id
       OR NEW.sequence IS DISTINCT FROM OLD.sequence
       OR NEW.event_type IS DISTINCT FROM OLD.event_type
       OR NEW.entity_type IS DISTINCT FROM OLD.entity_type
       OR NEW.entity_id IS DISTINCT FROM OLD.entity_id
       OR NEW.object_hash IS DISTINCT FROM OLD.object_hash
       OR NEW.object_version IS DISTINCT FROM OLD.object_version
       OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at
       OR NEW.outcome IS DISTINCT FROM OLD.outcome
       OR NEW.prior_entry_hash IS DISTINCT FROM OLD.prior_entry_hash
       OR NEW.entry_hash IS DISTINCT FROM OLD.entry_hash THEN
        RAISE EXCEPTION 'audit envelope and chain hashes are immutable';
    END IF;

    IF OLD.signing_state = 'signed'
       AND (NEW.signing_state IS DISTINCT FROM OLD.signing_state
            OR NEW.signer_identifier IS DISTINCT FROM OLD.signer_identifier
            OR NEW.signature IS DISTINCT FROM OLD.signature) THEN
        RAISE EXCEPTION 'signed audit signature is immutable';
    END IF;
    IF NEW.signing_state IS DISTINCT FROM OLD.signing_state
       AND NOT ((OLD.signing_state = 'unsigned' AND NEW.signing_state IN ('signed', 'signing_failed'))
                OR (OLD.signing_state = 'signing_failed' AND NEW.signing_state IN ('unsigned', 'signed'))) THEN
        RAISE EXCEPTION 'invalid audit signing transition';
    END IF;
    IF NEW.signing_state = OLD.signing_state
       AND (NEW.signer_identifier IS DISTINCT FROM OLD.signer_identifier
            OR NEW.signature IS DISTINCT FROM OLD.signature) THEN
        RAISE EXCEPTION 'audit signing fields require a signing-state transition';
    END IF;

    IF NEW.export_state IS DISTINCT FROM OLD.export_state THEN
        IF NOT ((OLD.export_state IN ('pending', 'retry') AND NEW.export_state = 'claimed')
                OR (OLD.export_state = 'claimed' AND NEW.export_state IN ('retry', 'exported'))) THEN
            RAISE EXCEPTION 'invalid audit export transition';
        END IF;
    ELSIF NEW.export_batch_id IS DISTINCT FROM OLD.export_batch_id
       OR NEW.export_claimed_by IS DISTINCT FROM OLD.export_claimed_by
       OR NEW.export_claimed_at IS DISTINCT FROM OLD.export_claimed_at
       OR NEW.export_claim_until IS DISTINCT FROM OLD.export_claim_until
       OR NEW.retry_count IS DISTINCT FROM OLD.retry_count
       OR NEW.next_retry_at IS DISTINCT FROM OLD.next_retry_at
       OR NEW.exported_at IS DISTINCT FROM OLD.exported_at THEN
        RAISE EXCEPTION 'audit export fields require an export-state transition';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_core_audit_outbox_update
BEFORE UPDATE ON core_audit_outbox
FOR EACH ROW EXECUTE FUNCTION enforce_core_audit_outbox_update();

CREATE OR REPLACE FUNCTION reject_core_audit_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'core audit history is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_core_audit_outbox_delete
BEFORE DELETE ON core_audit_outbox
FOR EACH ROW EXECUTE FUNCTION reject_core_audit_delete();

CREATE TABLE core_audit_checkpoints (
    community_id          UUID NOT NULL REFERENCES communities(id),
    last_exported_sequence BIGINT NOT NULL CHECK (last_exported_sequence > 0),
    last_entry_hash       BYTEA NOT NULL CHECK (octet_length(last_entry_hash) = 32),
    blob_object_key       TEXT NOT NULL CHECK (
                              octet_length(blob_object_key) BETWEEN 1 AND 1024
                              AND blob_object_key !~ '(^/|//|(^|/)\.\.(/|$)|://|[?#[:cntrl:]])'
                          ),
    blob_content_hash     BYTEA NOT NULL CHECK (octet_length(blob_content_hash) = 32),
    blob_etag             TEXT NOT NULL CHECK (octet_length(blob_etag) BETWEEN 1 AND 256),
    checkpointed_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, last_exported_sequence),
    UNIQUE (community_id, blob_object_key),
    UNIQUE (community_id, blob_content_hash),
    FOREIGN KEY (community_id, last_exported_sequence, last_entry_hash)
        REFERENCES core_audit_outbox (community_id, sequence, entry_hash)
);

CREATE OR REPLACE FUNCTION enforce_core_audit_checkpoint_insert()
RETURNS TRIGGER AS $$
DECLARE
    prior_checkpoint BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('core_audit:' || NEW.community_id::text, 0));
    SELECT MAX(last_exported_sequence) INTO prior_checkpoint
      FROM core_audit_checkpoints
     WHERE community_id = NEW.community_id;
    IF prior_checkpoint IS NOT NULL AND NEW.last_exported_sequence <= prior_checkpoint THEN
        RAISE EXCEPTION 'audit checkpoint history must move strictly forward';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_core_audit_checkpoints_insert
BEFORE INSERT ON core_audit_checkpoints
FOR EACH ROW EXECUTE FUNCTION enforce_core_audit_checkpoint_insert();

CREATE TRIGGER trg_core_audit_checkpoints_update
BEFORE UPDATE ON core_audit_checkpoints
FOR EACH ROW EXECUTE FUNCTION reject_core_audit_delete();

CREATE TRIGGER trg_core_audit_checkpoints_delete
BEFORE DELETE ON core_audit_checkpoints
FOR EACH ROW EXECUTE FUNCTION reject_core_audit_delete();

-- Preserve the existing fresh/brownfield search policy and every prior
-- exclusion while making persistent Core private payload kinds unsearchable.
-- Ephemeral kinds 24820-24822 never reach durable storage.
DO $$
DECLARE
    existing_expression TEXT;
BEGIN
    SELECT pg_get_expr(d.adbin, d.adrelid)
      INTO existing_expression
      FROM pg_attrdef d
      JOIN pg_attribute a
        ON a.attrelid = d.adrelid
       AND a.attnum = d.adnum
     WHERE d.adrelid = 'events'::regclass
       AND a.attname = 'search_tsv';

    IF existing_expression IS NULL THEN
        RAISE EXCEPTION 'events.search_tsv generated expression not found';
    END IF;

    ALTER TABLE events DROP COLUMN search_tsv;
    EXECUTE format(
        'ALTER TABLE events ADD COLUMN search_tsv TSVECTOR GENERATED ALWAYS AS (CASE WHEN kind IN (44300, 44301, 44310, 44311, 44312, 44210, 30179) THEN NULL::tsvector ELSE (%s) END) STORED',
        existing_expression
    );
    CREATE INDEX idx_events_search_tsv ON events USING GIN (search_tsv);
END $$;
