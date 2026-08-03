# Core Buzz Month-1 Windows Desktop and Azure Pilot

## Goal

Deliver a Blake-only, MNPI-capable Windows Buzz desktop pilot backed by a
hardened single-node Azure deployment. Preserve strict data boundaries and a
direct migration path to the existing production Helm chart for later HA.

## Global Constraints

- Follow `AGENTS.md`: Hermit, no `unsafe`, no new production `unwrap()` or
  `expect()`, public API docs, repository quality gates, and `git commit -s`.
- Use strict TDD for every behavioral production change and record red/green
  commands in the task report.
- Desktop only. Do not change `mobile/`, the mobile push gateway, or web client.
- Every Core feature is opt-in and disabled by default for upstream users.
- Model processes never receive signing keys, connector credentials, raw write
  tools, shell, filesystem, arbitrary HTTP, or direct connector network access.
- A conversational response is never approval. Only an exact, signed,
  one-time decision over a canonical operation hash may execute a write.
- CRM delete/merge, Outlook send/calendar mutation/delete/move, and Drive
  delete/trash/move/share/permission/ownership/bulk operations are absent from
  the executable operation enum.
- Core CRM access uses only `https://crm.coreadvs.com/api/mcp`; never direct
  Supabase or database access.
- Raw call audio never leaves memory, never reaches disk, and never leaves the
  desktop. Only finalized NIP-44 encrypted text may traverse the relay.
- Ordinary Core Buzz records retain seven years; audit/action/learning evidence
  exports use a 2,555-day immutable policy. Logs contain no content or secrets.
- The OpenAI Responses API is stateless with `store=false`; no Conversations,
  Assistants, vector stores, background mode, or file persistence.
- Use local embeddings for connector indexing. Only minimized authorized
  excerpts may be sent to OpenAI for a user turn.
- Commit only source, tests, configuration templates, and documentation. Never
  commit credentials, tenant IDs that are secrets, private data, or MNPI.

### Task 1: Freeze Core protocol and authorization

1. Add persistent kinds 44300, 44301, 44310, 44311, 44312, and 44210;
   parameterized kind 30179; and ephemeral kinds 24820, 24821, 24822.
2. Add version-1 Rust SDK payloads for insights, dispositions, action proposals,
   decisions, receipts, learning records/bundle heads, and call events.
3. Enforce required private `h` scope and explicit `p` recipients, pair-gating
   for encrypted learning records, and correct ephemeral non-storage behavior.
4. Reject unknown schema versions, malformed hashes/nonces/UUIDs, invalid
   expiries, missing scopes, and invalid author/recipient relationships.
5. Keep all existing protocol behavior backward compatible.

### Task 2: Add tenant-scoped durable storage and audit outbox

1. Add migrations after 0026 for identity bindings, connector accounts/scopes,
   source items/chunks/ACLs/cursors/tombstones, insights/daily budgets, action
   proposals/attempts, learning revisions/feedback/heads, and audit outbox.
2. Lead every key and uniqueness constraint with `community_id`.
3. Implement atomic daily insight caps, one-time action claims, idempotency,
   expected remote versions, reconciliation states, and retryable audit export.
4. Store no OAuth tokens or connector secrets in Postgres.

### Task 3: Implement the external action broker

1. Add a connector-independent proposal -> signed decision -> receipt state
   machine with canonical JSON hashing, one-time nonce, idempotency key,
   expected ETag/version, and 15-minute expiry.
2. Implement positive write enums only for allowed CRM, Outlook draft, and
   Google content operations. Forbidden operations must be unrepresentable.
3. Re-read before execution, reject stale state, claim exactly once, and enter
   reconciliation after ambiguous remote outcomes rather than blind retry.
4. Record intent before connector I/O and result afterward using the durable
   audit outbox.

### Task 4: Build the connector index and constrained adapters

1. Add stable provider/account/drive/folder/external-ID/version records,
   source ACLs, tombstones, FTS, pgvector-ready local embeddings, and citations.
2. Filter ACLs in SQL before ranking and recheck every result before output.
3. Add constrained Core CRM MCP reads and the positive confirmed write allowlist.
4. Add Microsoft Graph delegated Outlook/calendar sync, per-folder delta,
   webhook wakeups, draft-only confirmed writes, and no send/calendar writes.
5. Add read-only selected OneDrive folder sync by stable ID.
6. Add five-ID Google Shared Drive sync using WIF and per-drive change cursors;
   allow only confirmed Google-native content edits/creates.
7. Treat all connector/web content as untrusted data and keep credentials in
   executor-only services.

### Task 5: Seal the ACP/model boundary

1. Add a Core brokered publish mode that supports one private assistant and
   allowlisted deal channels while deriving destination and tags from verified
   triggers, never model output.
2. Clear inherited child environments; keep signing in the supervisor; issue
   only short-lived channel-scoped broker tokens to the model process.
3. Remove permission bypass/automatic `allow_once` in sealed mode.
4. Expose only typed read and `propose_*` tools; reject arbitrary MCP servers,
   shell, file, raw HTTP, and connector methods.
5. Preserve upstream modes unchanged when Core mode is off.

### Task 6: Add the proactive relationship feed

1. Add a durable leased signal runner, deterministic cursoring/dedupe, New York
   daily budget, 7:30 a.m. briefing, 7 a.m.-8 p.m. event window, and hard cap 10.
2. Rank commitments/deadlines, then deal/client/meeting movement, then
   relationship/buyer opportunities. Never force filler.
3. Project insights into Home `agent_activity`, unresolved proposals into
   `needs_action`, and keep them out of desktop notification hooks.
4. Add searchable insight history, evidence expansion, optional draft, and all
   configured dispositions.

### Task 7: Add governed automatic learning

1. Add encrypted append-only learning records and typed deny-unknown personal
   and firm bundle heads without modifying personas, engrams, or safety policy.
2. Run personal evaluation nightly and firm evaluation weekly; use the locked
   signal thresholds, 20% deterministic canary, quality gates, and rollback.
3. Exclude entities, IDs, unique excerpts, amounts, dates, and MNPI from firm
   bundles; allow encrypted personal CRM references only with runtime re-read.
4. Stamp every output with safety/persona/firm/personal/model versions and
   invalidate ACP sessions when a verified active head changes.
5. Prove learned content cannot affect action policy, permissions, or scopes.

### Task 8: Add Windows live-call capture and copilot transport

1. Add Tauri commands to list devices and start/stop/query capture state.
2. Capture microphone and selected-output endpoint separately, normalize to
   mono f32, reuse local Parakeet transcription, and label self/others.
3. Add mandatory per-call consent, visible persistent capture UI, source health,
   transcript, quiet suggestions, and global Stop.
4. Publish only finalized encrypted ephemeral call events; accumulate live
   sessions without creating one ACP turn per segment; purge on end/timeout.
5. Add OS-keyring-backed local transcript recovery capped at 24 hours, purged
   when the canonical CRM/Granola record arrives.
6. Stop on exit/suspend and never record hidden in the tray.

### Task 9: Add Entra-bound identity onboarding

1. Add Entra PKCE tenant sign-in and challenge-bound Entra object ID <-> Buzz
   pubkey <-> connector-account bindings while preserving NIP-42.
2. Keep user signing keys in Windows Credential Manager with no employee escrow.
3. Add pre-provision, first-login, revoke/offboard, and lost-device replacement
   flows that restore memberships without restoring the revoked key.
4. Make every future employee receive a private assistant and personal connector
   grants without exposing Blake-private state.

### Task 10: Harden attachment handling and retention

1. Quarantine and verify extension/magic, malware scan, and parse allowed files
   in a networkless sandbox.
2. Reject executables, archives, HTML/SVG/JS, encrypted/password documents,
   macros, ActiveX, embedded packages, and unsupported formats.
3. Limit Month-1 Buzz uploads to sanitized images, PDF, TXT, and CSV.
4. Add seven-year Core content policy, redacted structured logs, daily signed
   NDJSON audit checkpoints, immutable export tooling, and restore verification.

### Task 11: Add hardened Azure deployment and delivery

1. Add Bicep for East US 2 Trusted Launch D4as_v5, P15 data disk, ACR, Key
   Vault, Front Door Standard, custom WAF/rate rules, origin NSG, DNS, Monitor,
   Backup, budgets, and immutable Blob audit storage.
2. Add production Compose overlays for relay, Postgres/pgvector, Redis, MinIO,
   agent supervisor, connectors, sanitizer/indexer, signal runner, broker,
   executor, and learning worker on constrained networks.
3. Expose only 443 through Front Door; no public SSH; support JIT/Run Command.
4. Add desktop WebSocket reconnect/keepalive for Front Door rotation/limits.
5. Add GitHub Actions OIDC to Azure for digest-pinned Linux images, SBOM,
   provenance, Windows NSIS build/signing, checksums, and Intune-ready artifacts.

### Task 12: Integration, security gates, and pilot package

1. Run focused red/green checks per task, then format, clippy, unit/integration,
   Tauri, desktop, E2E, and repository CI gates under Hermit.
2. Run cross-user/channel/deal/ACL, approval replay/stale/hash, forbidden-action,
   delta reconciliation, feed cap, learning rollback, hostile-file, secret-log,
   and no-raw-audio tests.
3. Verify RPO 24 hours/RTO four hours and immutable audit-chain restore in a
   disposable environment before locking retention.
4. Build and sign the Windows installer; produce checksum, version manifest,
   deployment/admin/user runbooks, and copy release artifacts to the approved
   `Buzz - Deploy` OneDrive folder.
5. Stop at documented Azure/Entra/Google/Intune authorization gates rather than
   weakening controls or requesting credentials in chat.

## Completion Evidence

- Per-task red/green evidence, signed commits, and independent task reviews.
- Whole-branch security and code review with no unresolved critical/important
  findings.
- Fresh build/test/format/lint output and a clean worktree.
- Azure dry-run/lint plus disposable-environment evidence for destructive cloud
  controls before any live deployment.
- Signed Windows package and verified clean-machine installation, or an exact
  external authorization gate after all deterministic work is complete.
