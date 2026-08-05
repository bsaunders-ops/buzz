use std::collections::BTreeSet;

use buzz_connector_core::{
    core_crm_sync::{CoreCrmSyncCursorV1, CoreCrmSyncTarget, CoreCrmTrackedTarget},
    types::{AccountId, AclPrincipal, ConnectorProvider, EncryptedCursor, ScopeId},
};
use buzz_core_worker::{
    connector_iteration::TrustedConnectorClaim, core_crm_provider::CoreCrmCursorCodec,
    postgres_core_crm::CoreCrmAesCursorCodec,
};
use uuid::Uuid;

const TENANT: Uuid = Uuid::from_u128(1);
const ACCOUNT: AccountId = AccountId::new(Uuid::from_u128(2));
const SCOPE: ScopeId = ScopeId::new(Uuid::from_u128(3));

fn claim(account: AccountId, generation: u64, cursor: EncryptedCursor) -> TrustedConnectorClaim {
    TrustedConnectorClaim::new(
        TENANT,
        account,
        SCOPE,
        ConnectorProvider::CoreCrm,
        "known-records",
        generation,
        cursor,
        BTreeSet::from([AclPrincipal::user([7; 32])]),
    )
    .expect("claim")
}

fn logical_cursor() -> CoreCrmSyncCursorV1 {
    CoreCrmSyncCursorV1::new(vec![CoreCrmTrackedTarget::new(
        CoreCrmSyncTarget::contact(
            Uuid::parse_str("11111111-1111-4111-8111-111111111111").expect("UUID"),
        ),
        Vec::new(),
    )
    .expect("target")])
    .expect("logical cursor")
}

#[test]
fn encrypted_cursor_round_trips_only_under_the_exact_authority() {
    let key = [9_u8; 32];
    let mut codec = CoreCrmAesCursorCodec::new(key, 1).expect("codec");
    let seed = claim(
        ACCOUNT,
        1,
        EncryptedCursor::new(vec![1; 32], [1; 32], 1, 0).expect("seed cursor"),
    );
    let encrypted = codec
        .encode(&seed, &logical_cursor())
        .expect("encrypt cursor");
    let next_claim = claim(ACCOUNT, 2, encrypted.clone());

    assert_eq!(
        codec
            .decode(&next_claim)
            .expect("decrypt cursor")
            .encode()
            .expect("logical bytes"),
        logical_cursor().encode().expect("expected logical bytes")
    );

    let other_account = claim(AccountId::new(Uuid::from_u128(4)), 2, encrypted);
    assert!(codec.decode(&other_account).is_err());
}

#[test]
fn cursor_integrity_and_unknown_key_versions_fail_closed() {
    let key = [9_u8; 32];
    let mut codec = CoreCrmAesCursorCodec::new(key, 1).expect("codec");
    let seed = claim(
        ACCOUNT,
        1,
        EncryptedCursor::new(vec![1; 32], [1; 32], 1, 0).expect("seed cursor"),
    );
    let encrypted = codec
        .encode(&seed, &logical_cursor())
        .expect("encrypt cursor");
    let wrong_hash = EncryptedCursor::new(
        encrypted.ciphertext().to_vec(),
        [8; 32],
        encrypted.key_version(),
        encrypted.generation(),
    )
    .expect("wrong-hash cursor");
    assert!(codec.decode(&claim(ACCOUNT, 2, wrong_hash)).is_err());

    let unknown_version = EncryptedCursor::new(
        encrypted.ciphertext().to_vec(),
        encrypted.integrity_hash(),
        2,
        encrypted.generation(),
    )
    .expect("unknown-version cursor");
    assert!(codec.decode(&claim(ACCOUNT, 2, unknown_version)).is_err());
}
