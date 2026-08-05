//! Production composition for the sole enabled Month-1 connector: read-only Core CRM.

use std::{collections::BTreeSet, time::Duration};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use buzz_connector_core::{
    apply::ApplyOutcome,
    core_crm::{BearerToken, CoreCrmHttpTransport, CoreCrmReadAdapter, CoreCrmReadOperation},
    core_crm_sync::CoreCrmSyncCursorV1,
    persistence::apply_postgres_change_page,
    types::{AccountId, AclPrincipal, ChangePage, ConnectorProvider, EncryptedCursor, ScopeId},
};
use buzz_core::CommunityId;
use buzz_db::core_storage::{
    claim_next_core_crm_delta_scope, fail_delta_scope, CoreCrmDeltaScopeClaim,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    connector_iteration::{
        run_connector_iteration, ConnectorBoundaryError, ConnectorIterationFailureCode,
        ConnectorIterationFuture, ConnectorIterationRunner, DueScopeClaimer, FencedFailureRecorder,
        PageApplier, ProviderPageError, TrustedConnectorClaim,
    },
    core_crm_provider::{
        CoreCrmCursorCodec, CoreCrmPageProvider, CoreCrmReadOutcome, CoreCrmSnapshotReader,
    },
};

const LEASE_DURATION: Duration = Duration::from_secs(60);
const RETRY_DELAY: Duration = Duration::from_secs(30);
const CURSOR_NONCE_BYTES: usize = 12;

fn boundary_error<T>(_error: T) -> ConnectorBoundaryError {
    ConnectorBoundaryError::new()
}

/// Production application-encryption codec for Core CRM logical cursors.
pub struct CoreCrmAesCursorCodec {
    key: Zeroizing<[u8; 32]>,
    key_version: u32,
}

impl std::fmt::Debug for CoreCrmAesCursorCodec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoreCrmAesCursorCodec")
            .field("key_version", &self.key_version)
            .field("key_redacted", &true)
            .finish()
    }
}

impl CoreCrmAesCursorCodec {
    /// Create a codec from one runtime-injected 256-bit key and positive version.
    pub fn new(key: [u8; 32], key_version: u32) -> Result<Self, ConnectorBoundaryError> {
        if key_version == 0 {
            return Err(ConnectorBoundaryError::new());
        }
        Ok(Self {
            key: Zeroizing::new(key),
            key_version,
        })
    }

    fn aad(claim: &TrustedConnectorClaim, key_version: u32) -> Vec<u8> {
        let mut aad = Vec::with_capacity(128 + claim.stream().len());
        aad.extend_from_slice(b"core-buzz:core-crm-cursor:v1\0");
        aad.extend_from_slice(claim.community_id().as_bytes());
        aad.extend_from_slice(claim.account_id().as_uuid().as_bytes());
        aad.extend_from_slice(claim.scope_id().as_uuid().as_bytes());
        aad.extend_from_slice(claim.stream().as_bytes());
        aad.push(0);
        aad.extend_from_slice(&key_version.to_be_bytes());
        aad
    }

    fn cipher(&self) -> Result<Aes256Gcm, ProviderPageError> {
        Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| ProviderPageError::InvalidResponse)
    }
}

impl CoreCrmCursorCodec for CoreCrmAesCursorCodec {
    fn decode(
        &mut self,
        claim: &TrustedConnectorClaim,
    ) -> Result<CoreCrmSyncCursorV1, ProviderPageError> {
        let encrypted = claim.current_cursor();
        if encrypted.key_version() != self.key_version {
            return Err(ProviderPageError::InvalidResponse);
        }
        let ciphertext = encrypted.ciphertext();
        let digest: [u8; 32] = Sha256::digest(ciphertext).into();
        if digest != encrypted.integrity_hash() || ciphertext.len() <= CURSOR_NONCE_BYTES {
            return Err(ProviderPageError::InvalidResponse);
        }
        let (nonce, sealed) = ciphertext.split_at(CURSOR_NONCE_BYTES);
        let mut plaintext = self
            .cipher()?
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: &Self::aad(claim, self.key_version),
                },
            )
            .map_err(|_| ProviderPageError::InvalidResponse)?;
        let decoded =
            CoreCrmSyncCursorV1::decode(&plaintext).map_err(|_| ProviderPageError::InvalidResponse);
        plaintext.zeroize();
        decoded
    }

    fn encode(
        &mut self,
        claim: &TrustedConnectorClaim,
        cursor: &CoreCrmSyncCursorV1,
    ) -> Result<EncryptedCursor, ProviderPageError> {
        let mut plaintext = cursor
            .encode()
            .map_err(|_| ProviderPageError::InvalidResponse)?;
        let mut nonce = [0_u8; CURSOR_NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| ProviderPageError::InvalidResponse)?;
        let sealed = self
            .cipher()?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &Self::aad(claim, self.key_version),
                },
            )
            .map_err(|_| ProviderPageError::InvalidResponse);
        plaintext.zeroize();
        let mut ciphertext = nonce.to_vec();
        ciphertext.extend_from_slice(&sealed?);
        let integrity_hash = Sha256::digest(&ciphertext).into();
        EncryptedCursor::new(
            ciphertext,
            integrity_hash,
            self.key_version,
            claim.lease_generation(),
        )
        .map_err(|_| ProviderPageError::InvalidResponse)
    }
}

/// Production exact-detail reader. Provider errors remain non-destructive and
/// never become tombstones without a future explicit typed missing contract.
pub struct ProductionCoreCrmReader {
    adapter: CoreCrmReadAdapter<CoreCrmHttpTransport>,
}

impl ProductionCoreCrmReader {
    /// Create the fixed-endpoint, no-redirect Core CRM reader.
    pub fn new(token: BearerToken) -> Result<Self, ConnectorBoundaryError> {
        let transport = CoreCrmHttpTransport::new(token).map_err(boundary_error)?;
        Ok(Self {
            adapter: CoreCrmReadAdapter::new(transport),
        })
    }
}

impl CoreCrmSnapshotReader for ProductionCoreCrmReader {
    async fn read(
        &mut self,
        operation: &CoreCrmReadOperation,
        acls: Vec<AclPrincipal>,
    ) -> Result<CoreCrmReadOutcome, ProviderPageError> {
        self.adapter
            .read(operation, acls)
            .await
            .map(CoreCrmReadOutcome::Snapshot)
            .map_err(|_| ProviderPageError::InvalidResponse)
    }
}

struct PostgresDueScopeClaimer {
    pool: PgPool,
    worker_id: Uuid,
}

fn trusted_claim(
    claimed: CoreCrmDeltaScopeClaim,
) -> Result<TrustedConnectorClaim, ConnectorBoundaryError> {
    let owner: [u8; 32] = claimed.owner_pubkey.try_into().map_err(boundary_error)?;
    let integrity_hash: [u8; 32] = claimed
        .lease
        .cursor_integrity_hash
        .try_into()
        .map_err(boundary_error)?;
    let generation = u64::try_from(claimed.lease.generation).map_err(boundary_error)?;
    let key_version = u32::try_from(claimed.lease.cursor_key_version).map_err(boundary_error)?;
    let current_generation = generation
        .checked_sub(1)
        .ok_or_else(ConnectorBoundaryError::new)?;
    let cursor = EncryptedCursor::new(
        claimed.lease.encrypted_cursor,
        integrity_hash,
        key_version,
        current_generation,
    )
    .map_err(boundary_error)?;
    TrustedConnectorClaim::new(
        *claimed.community_id.as_uuid(),
        AccountId::new(claimed.account_id),
        ScopeId::new(claimed.scope_id),
        ConnectorProvider::CoreCrm,
        claimed.stream,
        generation,
        cursor,
        BTreeSet::from([AclPrincipal::user(owner)]),
    )
}

impl DueScopeClaimer for PostgresDueScopeClaimer {
    async fn claim_one(&mut self) -> Result<Option<TrustedConnectorClaim>, ConnectorBoundaryError> {
        claim_next_core_crm_delta_scope(&self.pool, self.worker_id, Utc::now(), LEASE_DURATION)
            .await
            .map_err(boundary_error)?
            .map(trusted_claim)
            .transpose()
    }
}

struct PostgresPageApplier {
    pool: PgPool,
    worker_id: Uuid,
}

impl PageApplier for PostgresPageApplier {
    async fn apply_page(
        &mut self,
        claim: &TrustedConnectorClaim,
        page: &ChangePage,
    ) -> Result<ApplyOutcome, ConnectorBoundaryError> {
        let generation = i64::try_from(claim.lease_generation()).map_err(boundary_error)?;
        apply_postgres_change_page(
            &self.pool,
            CommunityId::from_uuid(claim.community_id()),
            page,
            self.worker_id,
            generation,
            Utc::now(),
        )
        .await
        .map_err(boundary_error)
    }
}

struct PostgresFailureRecorder {
    pool: PgPool,
    worker_id: Uuid,
}

impl FencedFailureRecorder for PostgresFailureRecorder {
    async fn record_failure(
        &mut self,
        claim: &TrustedConnectorClaim,
        code: ConnectorIterationFailureCode,
    ) -> Result<bool, ConnectorBoundaryError> {
        let generation = i64::try_from(claim.lease_generation()).map_err(boundary_error)?;
        fail_delta_scope(
            &self.pool,
            CommunityId::from_uuid(claim.community_id()),
            claim.account_id().as_uuid(),
            claim.scope_id().as_uuid(),
            claim.stream(),
            self.worker_id,
            generation,
            failure_code(code),
            Utc::now(),
            RETRY_DELAY,
        )
        .await
        .map_err(boundary_error)
    }
}

const fn failure_code(code: ConnectorIterationFailureCode) -> &'static str {
    match code {
        ConnectorIterationFailureCode::ProviderAuthenticationRejected => "provider.auth_rejected",
        ConnectorIterationFailureCode::ProviderRateLimited => "provider.rate_limited",
        ConnectorIterationFailureCode::ProviderNotFound => "provider.not_found",
        ConnectorIterationFailureCode::ProviderInvalidResponse => "provider.invalid_response",
        ConnectorIterationFailureCode::ProviderTimeout => "provider.timeout",
        ConnectorIterationFailureCode::PageAuthorityMismatch => "page.authority_mismatch",
        ConnectorIterationFailureCode::PageAclMismatch => "page.acl_mismatch",
        ConnectorIterationFailureCode::PageApplyRejected => "page.apply_rejected",
    }
}

/// The complete production connector registry. It intentionally contains one
/// entry only: read-only Core CRM known-record reconciliation.
pub struct CoreCrmConnectorRunner {
    claimer: PostgresDueScopeClaimer,
    provider: CoreCrmPageProvider<ProductionCoreCrmReader, CoreCrmAesCursorCodec>,
    applier: PostgresPageApplier,
    failure_recorder: PostgresFailureRecorder,
}

impl CoreCrmConnectorRunner {
    /// Build the sole production connector runner from runtime-injected secrets.
    pub fn new(
        pool: PgPool,
        worker_id: Uuid,
        token: BearerToken,
        cursor_key: [u8; 32],
        cursor_key_version: u32,
    ) -> Result<Self, ConnectorBoundaryError> {
        Ok(Self {
            claimer: PostgresDueScopeClaimer {
                pool: pool.clone(),
                worker_id,
            },
            provider: CoreCrmPageProvider::new(
                ProductionCoreCrmReader::new(token)?,
                CoreCrmAesCursorCodec::new(cursor_key, cursor_key_version)?,
            ),
            applier: PostgresPageApplier {
                pool: pool.clone(),
                worker_id,
            },
            failure_recorder: PostgresFailureRecorder { pool, worker_id },
        })
    }
}

impl ConnectorIterationRunner for CoreCrmConnectorRunner {
    fn run_once(&mut self) -> ConnectorIterationFuture<'_> {
        Box::pin(async move {
            run_connector_iteration(
                &mut self.claimer,
                &mut self.provider,
                &mut self.applier,
                &mut self.failure_recorder,
            )
            .await
        })
    }
}
