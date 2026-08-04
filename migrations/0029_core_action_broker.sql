-- Bind the durable owner decision identity independently from its signed
-- event hash. The broker records this only through a tenant-scoped CAS.
ALTER TABLE external_action_proposals
    ADD COLUMN decision_id UUID
        CHECK (
            decision_id IS NULL
            OR (
                (get_byte(uuid_send(decision_id), 6) >> 4) = 4
                AND (get_byte(uuid_send(decision_id), 8) & 192) = 128
            )
        ),
    ADD CONSTRAINT external_action_proposals_decision_presence_check CHECK (
        (decision_id IS NULL) = (decision_event_hash IS NULL)
    );

CREATE UNIQUE INDEX external_action_proposals_decision_id_unique
    ON external_action_proposals (community_id, decision_id)
    WHERE decision_id IS NOT NULL;

CREATE UNIQUE INDEX external_action_proposals_decision_event_unique
    ON external_action_proposals (community_id, decision_event_hash)
    WHERE decision_event_hash IS NOT NULL;

-- A deterministic pre-dispatch rejection has no provider attempt. Successful
-- and ambiguous outcomes still require a bound attempt.
ALTER TABLE external_action_receipts
    ALTER COLUMN attempt_id DROP NOT NULL,
    ADD CONSTRAINT external_action_receipts_attempt_presence_check CHECK (
        attempt_id IS NOT NULL OR outcome = 'failed'
    );

-- Durable marker claimed by the receipt signer/publisher. The exact protocol
-- payload is reconstructed only from the immutable proposal/member bindings
-- and durable receipt rows; a crash after outcome commit cannot lose the wake.
CREATE TABLE external_action_receipt_outbox (
    community_id      UUID NOT NULL REFERENCES communities(id),
    proposal_id       UUID NOT NULL,
    receipt_id        UUID NOT NULL CHECK (
                          (get_byte(uuid_send(receipt_id), 6) >> 4) = 4
                          AND (get_byte(uuid_send(receipt_id), 8) & 192) = 128
                      ),
    occurred_at       TIMESTAMPTZ NOT NULL,
    publish_state     TEXT NOT NULL DEFAULT 'pending'
                      CHECK (publish_state IN ('pending', 'claimed', 'retry', 'published')),
    publish_claim_id  UUID,
    publish_claimed_by UUID,
    publish_claimed_at TIMESTAMPTZ,
    publish_claim_until TIMESTAMPTZ,
    published_event_hash BYTEA CHECK (
                             published_event_hash IS NULL
                             OR octet_length(published_event_hash) = 32
                         ),
    published_at      TIMESTAMPTZ,
    retry_count       INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    next_retry_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, proposal_id),
    UNIQUE (community_id, receipt_id),
    FOREIGN KEY (community_id, proposal_id)
        REFERENCES external_action_proposals (community_id, id),
    CHECK (
        (publish_state = 'claimed') =
        (publish_claim_id IS NOT NULL AND publish_claimed_by IS NOT NULL
         AND publish_claimed_at IS NOT NULL AND publish_claim_until IS NOT NULL)
    ),
    CHECK (
        (publish_state = 'published') =
        (published_event_hash IS NOT NULL AND published_at IS NOT NULL)
    )
);

CREATE INDEX idx_external_action_receipt_outbox_pending
    ON external_action_receipt_outbox
       (community_id, publish_state, next_retry_at, created_at)
    WHERE publish_state IN ('pending', 'retry', 'claimed');
