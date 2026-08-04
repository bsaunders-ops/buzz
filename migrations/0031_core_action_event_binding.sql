-- A durable proposal may enter the action lifecycle only after the exact
-- broker-authored kind 44310 event has been signature-verified. Columns remain
-- nullable solely so existing pilot databases can migrate; all new insertion,
-- decision, execution, and receipt paths require a bound event.
ALTER TABLE external_action_proposals
    ADD COLUMN proposal_event_hash BYTEA
        CHECK (proposal_event_hash IS NULL OR octet_length(proposal_event_hash) = 32),
    ADD COLUMN proposal_event_created_at TIMESTAMPTZ,
    ADD CONSTRAINT external_action_proposals_event_presence_check CHECK (
        (proposal_event_hash IS NULL) = (proposal_event_created_at IS NULL)
    ),
    ADD CONSTRAINT external_action_proposals_event_time_check CHECK (
        proposal_event_created_at IS NULL OR proposal_event_created_at = proposed_at
    );

CREATE UNIQUE INDEX external_action_proposals_event_hash_unique
    ON external_action_proposals (community_id, proposal_event_hash)
    WHERE proposal_event_hash IS NOT NULL;
