use buzz_core::core_protocol::{
    ActionProvider, ActionSideEffect, CrmWriteOperation, GoogleWriteOperation,
    OutlookWriteOperation, PositiveWriteOperation,
};
use buzz_db::core_storage::{ExternalConnector, ExternalOperation};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    canonical::CanonicalMemberV1,
    error::BrokerError,
    proposal::{validate_request_uniqueness, ProposalRequest},
};

pub(crate) const MAX_BUNDLE_MEMBERS: usize = 10;

#[derive(Debug, Clone, Copy)]
pub(crate) struct OperationDescriptor {
    pub(crate) connector: ExternalConnector,
    pub(crate) operation: ExternalOperation,
    pub(crate) side_effect: ActionSideEffect,
    pub(crate) create: bool,
}

pub(crate) fn describe_operation(operation: &PositiveWriteOperation) -> OperationDescriptor {
    use CrmWriteOperation as Crm;
    use GoogleWriteOperation as Google;
    use OutlookWriteOperation as Outlook;

    let (connector, operation, side_effect, create) = match operation {
        PositiveWriteOperation::Crm(Crm::AddNote { .. }) => (
            ExternalConnector::CoreCrm,
            ExternalOperation::CrmAddNote,
            ActionSideEffect::UpdatesRecord,
            false,
        ),
        PositiveWriteOperation::Crm(Crm::LogActivity { .. }) => (
            ExternalConnector::CoreCrm,
            ExternalOperation::CrmLogActivity,
            ActionSideEffect::UpdatesRecord,
            false,
        ),
        PositiveWriteOperation::Crm(Crm::CreateContact { .. }) => (
            ExternalConnector::CoreCrm,
            ExternalOperation::CrmCreateContact,
            ActionSideEffect::CreatesRecord,
            true,
        ),
        PositiveWriteOperation::Crm(Crm::UpdateContact { .. }) => (
            ExternalConnector::CoreCrm,
            ExternalOperation::CrmUpdateContact,
            ActionSideEffect::UpdatesRecord,
            false,
        ),
        PositiveWriteOperation::Crm(Crm::CreateCompany { .. }) => (
            ExternalConnector::CoreCrm,
            ExternalOperation::CrmCreateCompany,
            ActionSideEffect::CreatesRecord,
            true,
        ),
        PositiveWriteOperation::Crm(Crm::UpdateCompany { .. }) => (
            ExternalConnector::CoreCrm,
            ExternalOperation::CrmUpdateCompany,
            ActionSideEffect::UpdatesRecord,
            false,
        ),
        PositiveWriteOperation::Crm(Crm::CreateManualTask { .. }) => (
            ExternalConnector::CoreCrm,
            ExternalOperation::CrmCreateManualTask,
            ActionSideEffect::CreatesRecord,
            true,
        ),
        PositiveWriteOperation::Crm(Crm::UpdateManualTask { .. }) => (
            ExternalConnector::CoreCrm,
            ExternalOperation::CrmUpdateManualTask,
            ActionSideEffect::UpdatesRecord,
            false,
        ),
        PositiveWriteOperation::Crm(Crm::CompleteManualTask { .. }) => (
            ExternalConnector::CoreCrm,
            ExternalOperation::CrmCompleteManualTask,
            ActionSideEffect::UpdatesRecord,
            false,
        ),
        PositiveWriteOperation::Crm(Crm::CreateProject { .. }) => (
            ExternalConnector::CoreCrm,
            ExternalOperation::CrmCreateProject,
            ActionSideEffect::CreatesRecord,
            true,
        ),
        PositiveWriteOperation::Crm(Crm::UpdateProject { .. }) => (
            ExternalConnector::CoreCrm,
            ExternalOperation::CrmUpdateProject,
            ActionSideEffect::UpdatesRecord,
            false,
        ),
        PositiveWriteOperation::Crm(Crm::AddTag { .. }) => (
            ExternalConnector::CoreCrm,
            ExternalOperation::CrmAddTag,
            ActionSideEffect::UpdatesRecord,
            false,
        ),
        PositiveWriteOperation::Crm(Crm::LinkGranolaRecord { .. }) => (
            ExternalConnector::CoreCrm,
            ExternalOperation::CrmLinkGranolaRecord,
            ActionSideEffect::UpdatesRecord,
            false,
        ),
        PositiveWriteOperation::Outlook(Outlook::CreateDraft { .. }) => (
            ExternalConnector::MicrosoftGraph,
            ExternalOperation::OutlookCreateDraft,
            ActionSideEffect::CreatesDraft,
            true,
        ),
        PositiveWriteOperation::Outlook(Outlook::UpdateBuzzOwnedDraft { .. }) => (
            ExternalConnector::MicrosoftGraph,
            ExternalOperation::OutlookUpdateBuzzOwnedDraft,
            ActionSideEffect::UpdatesRecord,
            false,
        ),
        PositiveWriteOperation::Outlook(Outlook::AttachExistingFile { .. }) => (
            ExternalConnector::MicrosoftGraph,
            ExternalOperation::OutlookAttachExistingFile,
            ActionSideEffect::AttachesReference,
            false,
        ),
        PositiveWriteOperation::Outlook(Outlook::AttachDriveLink { .. }) => (
            ExternalConnector::MicrosoftGraph,
            ExternalOperation::OutlookAttachDriveLink,
            ActionSideEffect::AttachesReference,
            false,
        ),
        PositiveWriteOperation::Google(Google::CreateDoc { .. }) => (
            ExternalConnector::GoogleDrive,
            ExternalOperation::GoogleCreateDoc,
            ActionSideEffect::CreatesRecord,
            true,
        ),
        PositiveWriteOperation::Google(Google::CreateSheet { .. }) => (
            ExternalConnector::GoogleDrive,
            ExternalOperation::GoogleCreateSheet,
            ActionSideEffect::CreatesRecord,
            true,
        ),
        PositiveWriteOperation::Google(Google::CreateSimpleSlides { .. }) => (
            ExternalConnector::GoogleDrive,
            ExternalOperation::GoogleCreateSimpleSlides,
            ActionSideEffect::CreatesRecord,
            true,
        ),
        PositiveWriteOperation::Google(Google::EditDoc { .. }) => (
            ExternalConnector::GoogleDrive,
            ExternalOperation::GoogleEditDoc,
            ActionSideEffect::UpdatesRecord,
            false,
        ),
        PositiveWriteOperation::Google(Google::EditSheetRange { .. }) => (
            ExternalConnector::GoogleDrive,
            ExternalOperation::GoogleEditSheetRange,
            ActionSideEffect::UpdatesRecord,
            false,
        ),
        PositiveWriteOperation::Google(Google::ReplaceSlidesText { .. }) => (
            ExternalConnector::GoogleDrive,
            ExternalOperation::GoogleReplaceSlidesText,
            ActionSideEffect::UpdatesRecord,
            false,
        ),
    };
    OperationDescriptor {
        connector,
        operation,
        side_effect,
        create,
    }
}

pub(crate) fn validate_request(request: &ProposalRequest) -> Result<(), BrokerError> {
    for (label, value) in [
        ("tenant_id", request.tenant_id),
        ("proposal_id", request.proposal_id),
        ("channel_id", request.channel_id),
        ("nonce", request.nonce),
    ] {
        validate_uuid_v4(label, value)?;
    }
    if request.owner_pubkey == request.broker_pubkey {
        return Err(BrokerError::Policy(
            "owner and broker public keys must differ".into(),
        ));
    }
    validate_timing(request.proposed_at, request.expires_at)?;
    if request.evidence.is_empty() || request.evidence.len() > 32 {
        return Err(BrokerError::Policy(
            "evidence must contain 1..=32 references".into(),
        ));
    }
    validate_request_uniqueness(request)?;
    for operation in &request.operations {
        validate_uuid_v4("operation_id", operation.operation_id)?;
        validate_uuid_v4("idempotency_key", operation.idempotency_key)?;
    }
    Ok(())
}

pub(crate) fn validate_member_policy(
    member: &CanonicalMemberV1,
    descriptor: OperationDescriptor,
) -> Result<(), BrokerError> {
    let target_provider_matches = matches!(
        (member.target.provider, descriptor.connector),
        (ActionProvider::Crm, ExternalConnector::CoreCrm)
            | (ActionProvider::Outlook, ExternalConnector::MicrosoftGraph)
            | (ActionProvider::Google, ExternalConnector::GoogleDrive)
    );
    if !target_provider_matches {
        return Err(BrokerError::Policy(
            "operation provider does not match its configured target".into(),
        ));
    }
    if member.side_effects.as_slice() != [descriptor.side_effect] {
        return Err(BrokerError::Policy(
            "declared side effects do not exactly match the typed operation".into(),
        ));
    }
    if descriptor.create {
        if member.target.object_id.is_some()
            || member.before.is_some()
            || member.expected_remote_version.is_some()
        {
            return Err(BrokerError::Policy(
                "create operation cannot bind an existing object, before state, or version".into(),
            ));
        }
    } else if member.target.object_id.is_none()
        || member.before.is_none()
        || member.expected_remote_version.is_none()
    {
        return Err(BrokerError::Policy(
            "update operation requires object, before state, and expected version".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_timing(proposed_at: i64, expires_at: i64) -> Result<(), BrokerError> {
    let lifetime = expires_at
        .checked_sub(proposed_at)
        .ok_or_else(|| BrokerError::Policy("proposal timestamps overflow".into()))?;
    if !(1..=900).contains(&lifetime) {
        return Err(BrokerError::Policy(
            "proposal lifetime must be between 1 and 900 seconds".into(),
        ));
    }
    timestamp(proposed_at)?;
    timestamp(expires_at)?;
    Ok(())
}

pub(crate) fn timestamp(value: i64) -> Result<DateTime<Utc>, BrokerError> {
    DateTime::from_timestamp(value, 0)
        .ok_or_else(|| BrokerError::Policy("proposal timestamp is out of range".into()))
}

pub(crate) fn validate_uuid_v4(label: &str, value: Uuid) -> Result<(), BrokerError> {
    if value.get_version_num() != 4 {
        return Err(BrokerError::Policy(format!("{label} must be UUIDv4")));
    }
    Ok(())
}

pub(crate) fn parse_uuid_v4(label: &str, value: &str) -> Result<Uuid, BrokerError> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| BrokerError::Policy(format!("{label} must be a canonical UUIDv4")))?;
    if parsed.get_version_num() != 4 || parsed.hyphenated().to_string() != value {
        return Err(BrokerError::Policy(format!(
            "{label} must be a canonical lowercase hyphenated UUIDv4"
        )));
    }
    Ok(parsed)
}
