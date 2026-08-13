-- Replacements and tombstones clear stale chunks and ACLs before inserting the
-- current source page. The connector worker must not delete the source item
-- itself or any connector, cursor, scope, or audit state.
GRANT DELETE ON source_chunks, source_item_acls TO core_connector_worker;
