//! Provider notification validation and wake-only projection.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::{
    types::{AccountId, ConnectorProvider},
    ConnectorError, Result,
};

const MAX_NOTIFICATION_BYTES: usize = 1_048_576;

/// Validated notification reduced to a non-authoritative wake hint.
///
/// It intentionally has no source body, cursor, operation, scope target, or
/// write authority. The deterministic worker resumes from its committed cursor.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectorWakeHint {
    provider: ConnectorProvider,
    account_id: AccountId,
    received_at: DateTime<Utc>,
    dedupe_hash: [u8; 32],
}

impl std::fmt::Debug for ConnectorWakeHint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectorWakeHint")
            .field("provider", &self.provider)
            .field("received_at", &self.received_at)
            .field("account_and_dedupe_hash_redacted", &true)
            .finish()
    }
}

impl ConnectorWakeHint {
    /// Provider whose preconfigured streams should be polled.
    #[must_use]
    pub const fn provider(&self) -> ConnectorProvider {
        self.provider
    }

    /// Preconfigured connector account to wake.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Server receipt timestamp.
    #[must_use]
    pub const fn received_at(&self) -> DateTime<Utc> {
        self.received_at
    }

    /// Body digest used only to collapse duplicate wake hints.
    #[must_use]
    pub const fn dedupe_hash(&self) -> [u8; 32] {
        self.dedupe_hash
    }
}

/// Notification boundary that discards provider body content after validation.
pub struct ConnectorNotification;

impl ConnectorNotification {
    /// Validate an already constant-time-compared channel token/clientState and
    /// reduce the body to an opaque duplicate-wake digest.
    pub fn validate(
        provider: ConnectorProvider,
        account_id: AccountId,
        authentication_matches: bool,
        body: &[u8],
        received_at: DateTime<Utc>,
    ) -> Result<ConnectorWakeHint> {
        if !authentication_matches {
            return Err(ConnectorError::NotificationAuthentication);
        }
        if body.len() > MAX_NOTIFICATION_BYTES {
            return Err(ConnectorError::BoundExceeded("notification bytes"));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"core-buzz:connector-notification-wake:v1\0");
        hasher.update(provider.wire_name().as_bytes());
        hasher.update(account_id.as_uuid().as_bytes());
        hasher.update(body);
        Ok(ConnectorWakeHint {
            provider,
            account_id,
            received_at,
            dedupe_hash: hasher.finalize().into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn body_fields_cannot_be_observed_after_validation() {
        let body = br#"{"operation":"send_mail","cursor":"forged","content":"MNPI"}"#;
        let hint = ConnectorNotification::validate(
            ConnectorProvider::MicrosoftGraph,
            AccountId::new(Uuid::from_u128(1)),
            true,
            body,
            Utc::now(),
        )
        .expect("authenticated notification becomes wake hint");
        assert_eq!(hint.provider(), ConnectorProvider::MicrosoftGraph);
        assert_eq!(hint.dedupe_hash().len(), 32);
        let digest = hex::encode(hint.dedupe_hash());
        assert!(!format!("{hint:?}").contains(digest.as_str()));
    }
}
