//! Bounded, snapshot-only reads from the closed Core CRM MCP surface.
//!
//! Core CRM currently exposes capped list/search tools without a delta cursor or
//! an authoritative end-of-corpus signal. This adapter therefore produces
//! validated upserts, but never tombstones or a complete [`crate::types::ChangePage`].

use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    egress::{EgressRequest, ProviderEgressPolicy, RedirectMode},
    types::{
        AclPrincipal, ConnectorProvider, ExternalItemId, RemoteVersion, SourceItemUpsert,
        SourceKind, UntrustedSourceData,
    },
    ConnectorError, Result,
};

/// The sole production Core CRM MCP endpoint.
pub const CORE_CRM_MCP_URL: &str = "https://crm.coreadvs.com/api/mcp";
/// MCP protocol version implemented by the current local Core CRM server.
pub const CORE_CRM_MCP_PROTOCOL_VERSION: &str = "2025-11-25";

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Opaque, validated arguments for one closed read operation.
#[derive(Clone, PartialEq)]
pub struct CoreCrmReadArguments(Value);

impl std::fmt::Debug for CoreCrmReadArguments {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoreCrmReadArguments")
            .field("content_redacted", &true)
            .finish()
    }
}

/// Closed Core CRM operations allowed by the initial read-only adapter.
#[derive(Debug, Clone, PartialEq)]
pub enum CoreCrmReadOperation {
    /// Discover contacts through `search_contacts`.
    SearchContacts(CoreCrmReadArguments),
    /// Fetch one complete contact through `get_contact`.
    GetContact(CoreCrmReadArguments),
    /// Discover companies through `search_companies`.
    SearchCompanies(CoreCrmReadArguments),
    /// Fetch one complete company through `get_company`.
    GetCompany(CoreCrmReadArguments),
    /// Read a bounded project snapshot through `list_projects`.
    ListProjects(CoreCrmReadArguments),
    /// Fetch one complete project through `get_project`.
    GetProject(CoreCrmReadArguments),
    /// Read scoped activities, optionally including transcripts.
    ListActivities(CoreCrmReadArguments),
    /// Fetch one complete activity and its transcripts.
    GetActivity(CoreCrmReadArguments),
    /// Discover guidance documents through `list_guidance_docs`.
    ListGuidanceDocs(CoreCrmReadArguments),
    /// Fetch one complete guidance document through `get_guidance_doc`.
    GetGuidanceDoc(CoreCrmReadArguments),
}

impl CoreCrmReadOperation {
    /// Parse only a documented read tool and its exact closed argument shape.
    pub fn try_from_tool_call(name: &str, arguments: Value) -> Result<Self> {
        let arguments = match name {
            "search_contacts" => validate_arguments::<SearchContactsArgs>(arguments)?,
            "get_contact" => validate_arguments::<GetContactArgs>(arguments)?,
            "search_companies" => validate_arguments::<SearchCompaniesArgs>(arguments)?,
            "get_company" => validate_arguments::<IdArgs>(arguments)?,
            "list_projects" => validate_arguments::<ListProjectsArgs>(arguments)?,
            "get_project" => validate_arguments::<IdArgs>(arguments)?,
            "list_activities" => validate_arguments::<ListActivitiesArgs>(arguments)?,
            "get_activity" => validate_arguments::<IdArgs>(arguments)?,
            "list_guidance_docs" => validate_arguments::<Limit100Args>(arguments)?,
            "get_guidance_doc" => validate_arguments::<GuidanceArgs>(arguments)?,
            _ => {
                return Err(ConnectorError::InvalidData(
                    "Core CRM tool is not read-allowlisted",
                ))
            }
        };
        Ok(match name {
            "search_contacts" => Self::SearchContacts(arguments),
            "get_contact" => Self::GetContact(arguments),
            "search_companies" => Self::SearchCompanies(arguments),
            "get_company" => Self::GetCompany(arguments),
            "list_projects" => Self::ListProjects(arguments),
            "get_project" => Self::GetProject(arguments),
            "list_activities" => Self::ListActivities(arguments),
            "get_activity" => Self::GetActivity(arguments),
            "list_guidance_docs" => Self::ListGuidanceDocs(arguments),
            "get_guidance_doc" => Self::GetGuidanceDoc(arguments),
            _ => {
                return Err(ConnectorError::InvalidData(
                    "Core CRM tool is not read-allowlisted",
                ))
            }
        })
    }

    /// Exact deployed MCP tool name.
    #[must_use]
    pub const fn tool_name(&self) -> &'static str {
        match self {
            Self::SearchContacts(_) => "search_contacts",
            Self::GetContact(_) => "get_contact",
            Self::SearchCompanies(_) => "search_companies",
            Self::GetCompany(_) => "get_company",
            Self::ListProjects(_) => "list_projects",
            Self::GetProject(_) => "get_project",
            Self::ListActivities(_) => "list_activities",
            Self::GetActivity(_) => "get_activity",
            Self::ListGuidanceDocs(_) => "list_guidance_docs",
            Self::GetGuidanceDoc(_) => "get_guidance_doc",
        }
    }

    fn arguments(&self) -> &Value {
        match self {
            Self::SearchContacts(value)
            | Self::GetContact(value)
            | Self::SearchCompanies(value)
            | Self::GetCompany(value)
            | Self::ListProjects(value)
            | Self::GetProject(value)
            | Self::ListActivities(value)
            | Self::GetActivity(value)
            | Self::ListGuidanceDocs(value)
            | Self::GetGuidanceDoc(value) => &value.0,
        }
    }

    fn page_limit(&self) -> usize {
        self.arguments()
            .get("limit")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(50)
    }
}

fn validate_arguments<T>(arguments: Value) -> Result<CoreCrmReadArguments>
where
    T: DeserializeOwned + Serialize + ValidateArguments,
{
    let parsed: T = serde_json::from_value(arguments)
        .map_err(|_| ConnectorError::InvalidData("Core CRM arguments are invalid"))?;
    parsed.validate()?;
    serde_json::to_value(parsed)
        .map(CoreCrmReadArguments)
        .map_err(|_| ConnectorError::InvalidData("Core CRM arguments are invalid"))
}

trait ValidateArguments {
    fn validate(&self) -> Result<()>;
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SearchContactsArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relationship_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    company_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tag_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    include_dead: bool,
    #[serde(default = "default_50")]
    limit: u16,
}

impl ValidateArguments for SearchContactsArgs {
    fn validate(&self) -> Result<()> {
        validate_limit(self.limit, 100)?;
        validate_optional_uuid(self.company_id.as_deref())?;
        validate_uuids(&self.tag_ids)?;
        validate_optional_enum(
            self.relationship_type.as_deref(),
            &[
                "client",
                "prospect",
                "counterparty",
                "vendor",
                "executive",
                "referral_source",
            ],
        )?;
        validate_optional_enum(self.status.as_deref(), &["relevant", "dead"])
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GetContactArgs {
    id: String,
    #[serde(default = "default_20")]
    activity_limit: u16,
}

impl ValidateArguments for GetContactArgs {
    fn validate(&self) -> Result<()> {
        validate_uuid(&self.id)?;
        if self.activity_limit > 100 {
            return Err(ConnectorError::BoundExceeded("Core CRM activity limit"));
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SearchCompaniesArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    industry: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tag_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    include_dead: bool,
    #[serde(default = "default_50")]
    limit: u16,
}

impl ValidateArguments for SearchCompaniesArgs {
    fn validate(&self) -> Result<()> {
        validate_limit(self.limit, 100)?;
        validate_uuids(&self.tag_ids)?;
        validate_optional_enum(
            self.status.as_deref(),
            &["client", "prospect", "coverage_target", "counterparty"],
        )
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdArgs {
    id: String,
}

impl ValidateArguments for IdArgs {
    fn validate(&self) -> Result<()> {
        validate_uuid(&self.id)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ListProjectsArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    section: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    company_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    include_archived: bool,
    #[serde(default = "default_50")]
    limit: u16,
}

impl ValidateArguments for ListProjectsArgs {
    fn validate(&self) -> Result<()> {
        validate_limit(self.limit, 200)?;
        for id in [&self.owner_id, &self.contact_id, &self.company_id] {
            validate_optional_uuid(id.as_deref())?;
        }
        if self.query.as_ref().is_some_and(|value| value.len() > 255) {
            return Err(ConnectorError::BoundExceeded("Core CRM project query"));
        }
        validate_optional_enum(
            self.status.as_deref(),
            &["active", "on_hold", "completed", "archived"],
        )?;
        validate_optional_enum(
            self.section.as_deref(),
            &["live_deal", "chasing", "house_account", "dormant"],
        )
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ListActivitiesArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    company_id: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    activity_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    until: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    include_transcripts: bool,
    #[serde(default = "default_50")]
    limit: u16,
}

impl ValidateArguments for ListActivitiesArgs {
    fn validate(&self) -> Result<()> {
        if self.contact_id.is_none() && self.company_id.is_none() {
            return Err(ConnectorError::InvalidData(
                "Core CRM activity scope is required",
            ));
        }
        validate_optional_uuid(self.contact_id.as_deref())?;
        validate_optional_uuid(self.company_id.as_deref())?;
        validate_optional_timestamp(self.since.as_deref())?;
        validate_optional_timestamp(self.until.as_deref())?;
        validate_limit(self.limit, 200)?;
        validate_optional_enum(
            self.activity_type.as_deref(),
            &["email", "meeting", "call", "note"],
        )?;
        validate_optional_enum(
            self.source.as_deref(),
            &["manual", "outlook", "calendar", "granola", "voice_note"],
        )
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Limit100Args {
    #[serde(default = "default_50")]
    limit: u16,
}

impl ValidateArguments for Limit100Args {
    fn validate(&self) -> Result<()> {
        validate_limit(self.limit, 100)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GuidanceArgs {
    slug: String,
}

impl ValidateArguments for GuidanceArgs {
    fn validate(&self) -> Result<()> {
        if self.slug.is_empty()
            || self.slug.len() > 80
            || !self.slug.split('-').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
        {
            return Err(ConnectorError::InvalidData(
                "Core CRM guidance slug is invalid",
            ));
        }
        Ok(())
    }
}

const fn default_20() -> u16 {
    20
}
const fn default_50() -> u16 {
    50
}
const fn is_false(value: &bool) -> bool {
    !*value
}

fn validate_limit(value: u16, maximum: u16) -> Result<()> {
    if value == 0 || value > maximum {
        return Err(ConnectorError::BoundExceeded("Core CRM page limit"));
    }
    Ok(())
}

fn validate_uuid(value: &str) -> Result<()> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| ConnectorError::InvalidData("Core CRM identifier is invalid"))
}

fn validate_optional_uuid(value: Option<&str>) -> Result<()> {
    value.map_or(Ok(()), validate_uuid)
}

fn validate_uuids(values: &[String]) -> Result<()> {
    values.iter().try_for_each(|value| validate_uuid(value))
}

fn validate_optional_timestamp(value: Option<&str>) -> Result<()> {
    value.map_or(Ok(()), |value| parse_timestamp(value).map(|_| ()))
}

fn validate_optional_enum(value: Option<&str>, allowed: &[&str]) -> Result<()> {
    if value.is_some_and(|value| !allowed.contains(&value)) {
        return Err(ConnectorError::InvalidData(
            "Core CRM enum value is invalid",
        ));
    }
    Ok(())
}

/// OAuth bearer material that redacts debug output and zeroes memory on drop.
pub struct BearerToken(String);

impl BearerToken {
    /// Validate runtime-injected bearer material without persisting it.
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty()
            || value.len() > 8_192
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(ConnectorError::InvalidData(
                "Core CRM bearer token is invalid",
            ));
        }
        Ok(Self(value))
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BearerToken([REDACTED])")
    }
}

impl Drop for BearerToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Fixed production request builder; callers cannot add URLs or headers.
pub struct CoreCrmRequestBuilder {
    token: BearerToken,
    url: Url,
}

impl std::fmt::Debug for CoreCrmRequestBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoreCrmRequestBuilder")
            .field("authority", &"fixed_core_crm")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl CoreCrmRequestBuilder {
    /// Build a request factory fixed to the existing Core CRM egress policy.
    pub fn new(token: BearerToken) -> Result<Self> {
        let policy = ProviderEgressPolicy::for_provider(ConnectorProvider::CoreCrm);
        let validated = policy.validate(EgressRequest::new(
            CORE_CRM_MCP_URL,
            MAX_RESPONSE_BYTES as u64,
            REQUEST_TIMEOUT,
        ))?;
        Ok(Self {
            token,
            url: validated.url().clone(),
        })
    }

    /// Build one bounded JSON-RPC `tools/call` request descriptor.
    pub fn build(&self, operation: &CoreCrmReadOperation, id: u64) -> Result<CoreCrmHttpRequest> {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": operation.tool_name(), "arguments": operation.arguments()},
        }))
        .map_err(|_| ConnectorError::InvalidData("Core CRM request is invalid"))?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(ConnectorError::BoundExceeded("Core CRM request bytes"));
        }
        Ok(CoreCrmHttpRequest {
            url: self.url.clone(),
            body,
        })
    }
}

/// Immutable fixed request descriptor used by the production transport.
pub struct CoreCrmHttpRequest {
    url: Url,
    body: Vec<u8>,
}

impl std::fmt::Debug for CoreCrmHttpRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoreCrmHttpRequest")
            .field("url", &CORE_CRM_MCP_URL)
            .field("method", &"POST")
            .field("body_redacted", &true)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl CoreCrmHttpRequest {
    /// Exact destination URL.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }
    /// Exact HTTP method.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        "POST"
    }
    /// Exact MCP protocol header value.
    #[must_use]
    pub const fn protocol_version(&self) -> &'static str {
        CORE_CRM_MCP_PROTOCOL_VERSION
    }
    /// Redirects are disabled.
    #[must_use]
    pub const fn redirect_mode(&self) -> RedirectMode {
        RedirectMode::Disabled
    }
    /// Connection deadline.
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        CONNECT_TIMEOUT
    }
    /// Whole-request deadline.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        REQUEST_TIMEOUT
    }
    /// Serialized request byte ceiling.
    #[must_use]
    pub const fn max_request_bytes(&self) -> usize {
        MAX_REQUEST_BYTES
    }
    /// Streamed response byte ceiling.
    #[must_use]
    pub const fn max_response_bytes(&self) -> usize {
        MAX_RESPONSE_BYTES
    }
    /// Requests always use the injected OAuth bearer.
    #[must_use]
    pub const fn has_bearer_authorization(&self) -> bool {
        true
    }
}

/// Injected MCP transport boundary for deterministic adapter tests.
pub trait CoreCrmMcpTransport: Send + Sync {
    /// Execute one closed read and return a bounded JSON-RPC response body.
    fn call<'a>(
        &'a self,
        operation: &'a CoreCrmReadOperation,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;
}

/// Production Streamable HTTP JSON transport for the current Core CRM MCP version.
pub struct CoreCrmHttpTransport {
    client: reqwest::Client,
    builder: CoreCrmRequestBuilder,
    next_id: AtomicU64,
}

impl CoreCrmHttpTransport {
    /// Create a fixed no-redirect, deadline-bounded transport.
    pub fn new(token: BearerToken) -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| ConnectorError::EgressDenied("Core CRM HTTP client configuration"))?;
        Ok(Self {
            client,
            builder: CoreCrmRequestBuilder::new(token)?,
            next_id: AtomicU64::new(1),
        })
    }

    async fn execute(&self, operation: &CoreCrmReadOperation) -> Result<Vec<u8>> {
        let descriptor = self
            .builder
            .build(operation, self.next_id.fetch_add(1, Ordering::Relaxed))?;
        let response = self
            .client
            .post(descriptor.url.clone())
            .bearer_auth(&self.builder.token.0)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", CORE_CRM_MCP_PROTOCOL_VERSION)
            .body(descriptor.body)
            .send()
            .await
            .map_err(|_| ConnectorError::InvalidData("Core CRM request failed"))?;
        if !response.status().is_success() {
            return Err(ConnectorError::InvalidData(
                "Core CRM HTTP status is not successful",
            ));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if !content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(ConnectorError::InvalidData(
                "Core CRM response content type is invalid",
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(ConnectorError::BoundExceeded("Core CRM response bytes"));
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(|_| ConnectorError::InvalidData("Core CRM response stream failed"))?;
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(ConnectorError::BoundExceeded("Core CRM response bytes"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

impl CoreCrmMcpTransport for CoreCrmHttpTransport {
    fn call<'a>(
        &'a self,
        operation: &'a CoreCrmReadOperation,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(self.execute(operation))
    }
}

/// Adapter that separates provider transport from validation and normalization.
pub struct CoreCrmReadAdapter<T> {
    transport: T,
}

impl<T: CoreCrmMcpTransport> CoreCrmReadAdapter<T> {
    /// Inject a production or test transport.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Execute and normalize one bounded snapshot read using server ACLs only.
    pub async fn read(
        &self,
        operation: &CoreCrmReadOperation,
        acls: Vec<AclPrincipal>,
    ) -> Result<CoreCrmSnapshot> {
        let response = self.transport.call(operation).await?;
        normalize_core_crm_response(operation, &response, acls)
    }
}

/// Honest coverage marker for the current MCP surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreCrmSnapshotCoverage {
    /// Bounded initial/snapshot data only; corpus completeness is not proven.
    BoundedInitialSnapshotOnly,
}

/// Validated provider-neutral source upserts from one bounded read.
pub struct CoreCrmSnapshot {
    upserts: Vec<SourceItemUpsert>,
    coverage: CoreCrmSnapshotCoverage,
}

impl CoreCrmSnapshot {
    /// Validated current records. No destructive tombstones are inferred.
    #[must_use]
    pub fn upserts(&self) -> &[SourceItemUpsert] {
        &self.upserts
    }
    /// Snapshot-only coverage limitation.
    #[must_use]
    pub const fn coverage(&self) -> CoreCrmSnapshotCoverage {
        self.coverage
    }
    /// Fail closed because the MCP surface supplies no complete-corpus proof.
    pub fn require_complete_corpus(&self) -> Result<&[SourceItemUpsert]> {
        Err(ConnectorError::InvalidData(
            "Core CRM corpus completeness is not provable",
        ))
    }
}

/// Validate a JSON-RPC/MCP envelope and normalize only its expected tool result.
pub fn normalize_core_crm_response(
    operation: &CoreCrmReadOperation,
    response: &[u8],
    acls: Vec<AclPrincipal>,
) -> Result<CoreCrmSnapshot> {
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(ConnectorError::BoundExceeded("Core CRM response bytes"));
    }
    let envelope: McpEnvelope = serde_json::from_slice(response)
        .map_err(|_| ConnectorError::InvalidData("Core CRM JSON-RPC envelope is invalid"))?;
    if envelope.jsonrpc != "2.0" || envelope.id == 0 || envelope.result.is_error.unwrap_or(false) {
        return Err(ConnectorError::InvalidData(
            "Core CRM tool returned an error",
        ));
    }
    if envelope.result.content.len() != 1 {
        return Err(ConnectorError::InvalidData(
            "Core CRM content blocks are invalid",
        ));
    }
    let text = &envelope.result.content[0].text;
    let mut upserts = Vec::new();
    match operation {
        CoreCrmReadOperation::GetContact(_) => {
            let record: ContactRecord = parse_tool_json(text)?;
            validate_contact(&record)?;
            upserts.push(record_upsert(
                RecordSource::new(
                    "contact",
                    &record.id,
                    &record.name,
                    SourceKind::CrmRecord,
                    &record.updated_at,
                    format!("/contacts/{}", record.id),
                ),
                &record,
                &acls,
            )?);
        }
        CoreCrmReadOperation::GetCompany(_) => {
            let record: CompanyRecord = parse_tool_json(text)?;
            validate_company(&record)?;
            upserts.push(record_upsert(
                RecordSource::new(
                    "company",
                    &record.id,
                    &record.name,
                    SourceKind::CrmRecord,
                    &record.updated_at,
                    format!("/companies/{}", record.id),
                ),
                &record,
                &acls,
            )?);
        }
        CoreCrmReadOperation::GetProject(_) => {
            let record: ProjectRecord = parse_tool_json(text)?;
            validate_project(&record)?;
            upserts.push(record_upsert(
                RecordSource::new(
                    "project",
                    &record.id,
                    &record.name,
                    SourceKind::CrmRecord,
                    &record.updated_at,
                    format!("/projects/{}", record.id),
                ),
                &record,
                &acls,
            )?);
        }
        CoreCrmReadOperation::ListProjects(_) => {
            let records: Vec<ProjectRecord> = parse_tool_json(text)?;
            validate_page_len(records.len(), operation.page_limit())?;
            for record in records {
                validate_project(&record)?;
                upserts.push(record_upsert(
                    RecordSource::new(
                        "project",
                        &record.id,
                        &record.name,
                        SourceKind::CrmRecord,
                        &record.updated_at,
                        format!("/projects/{}", record.id),
                    ),
                    &record,
                    &acls,
                )?);
            }
        }
        CoreCrmReadOperation::GetActivity(_) => {
            let record: ActivityRecord = parse_tool_json(text)?;
            append_activity(&record, &acls, &mut upserts)?;
        }
        CoreCrmReadOperation::ListActivities(_) => {
            let records: Vec<ActivityRecord> = parse_tool_json(text)?;
            validate_page_len(records.len(), operation.page_limit())?;
            for record in records {
                append_activity(&record, &acls, &mut upserts)?;
            }
        }
        CoreCrmReadOperation::GetGuidanceDoc(_) => {
            let record: GuidanceRecord = parse_tool_json(text)?;
            validate_guidance(&record)?;
            upserts.push(record_upsert(
                RecordSource::new(
                    "guidance",
                    &record.id,
                    &record.title,
                    SourceKind::Document,
                    &record.updated_at,
                    "/",
                ),
                &record,
                &acls,
            )?);
        }
        CoreCrmReadOperation::SearchContacts(_) => {
            let records: Vec<ContactSummary> = parse_tool_json(text)?;
            validate_page_len(records.len(), operation.page_limit())?;
            for record in records {
                validate_contact_summary(&record)?;
            }
        }
        CoreCrmReadOperation::SearchCompanies(_) => {
            let records: Vec<CompanySummary> = parse_tool_json(text)?;
            validate_page_len(records.len(), operation.page_limit())?;
            for record in records {
                validate_company_summary(&record)?;
            }
        }
        CoreCrmReadOperation::ListGuidanceDocs(_) => {
            let records: Vec<GuidanceSummary> = parse_tool_json(text)?;
            validate_page_len(records.len(), operation.page_limit())?;
            for record in records {
                validate_guidance_summary(&record)?;
            }
        }
    }
    Ok(CoreCrmSnapshot {
        upserts,
        coverage: CoreCrmSnapshotCoverage::BoundedInitialSnapshotOnly,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpEnvelope {
    jsonrpc: String,
    id: u64,
    result: McpResult,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpResult {
    content: Vec<TextContent>,
    #[serde(rename = "isError")]
    is_error: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TextContent {
    #[serde(rename = "type")]
    _content_type: TextType,
    text: String,
}

#[derive(Deserialize, Serialize)]
enum TextType {
    #[serde(rename = "text")]
    Text,
}

fn parse_tool_json<T: DeserializeOwned>(text: &str) -> Result<T> {
    serde_json::from_str(text)
        .map_err(|_| ConnectorError::InvalidData("Core CRM tool result is invalid"))
}

fn validate_page_len(actual: usize, allowed: usize) -> Result<()> {
    if actual > allowed {
        return Err(ConnectorError::BoundExceeded("Core CRM result page"));
    }
    Ok(())
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| ConnectorError::InvalidData("Core CRM timestamp is invalid"))
}

struct RecordSource<'a> {
    entity: &'a str,
    id: &'a str,
    title: &'a str,
    source_kind: SourceKind,
    modified_at: &'a str,
    path: String,
}

impl<'a> RecordSource<'a> {
    fn new(
        entity: &'a str,
        id: &'a str,
        title: &'a str,
        source_kind: SourceKind,
        modified_at: &'a str,
        path: impl Into<String>,
    ) -> Self {
        Self {
            entity,
            id,
            title,
            source_kind,
            modified_at,
            path: path.into(),
        }
    }
}

fn record_upsert<T: Serialize>(
    source_meta: RecordSource<'_>,
    record: &T,
    acls: &[AclPrincipal],
) -> Result<SourceItemUpsert> {
    validate_uuid(source_meta.id)?;
    let canonical = serde_json::to_vec(record)
        .map_err(|_| ConnectorError::InvalidData("Core CRM canonical record is invalid"))?;
    let mut hasher = Sha256::new();
    hasher.update(b"core-buzz:core-crm-record:v1\0");
    hasher.update(&canonical);
    let version = hex::encode(hasher.finalize());
    let source = String::from_utf8(canonical)
        .map_err(|_| ConnectorError::InvalidData("Core CRM source text is invalid"))?;
    SourceItemUpsert::new(
        ExternalItemId::new(format!(
            "core-crm:{}:{}",
            source_meta.entity, source_meta.id
        ))?,
        RemoteVersion::new(version, None)?,
        source_meta.title,
        source_meta.source_kind,
        parse_timestamp(source_meta.modified_at)?,
        format!("https://crm.coreadvs.com{}", source_meta.path),
        UntrustedSourceData::new(source),
        acls.to_vec(),
    )
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Link {
    id: String,
    name: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompanyLink {
    id: String,
    name: String,
    website: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Tag {
    id: String,
    name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecentActivity {
    id: String,
    activity_date: String,
    #[serde(rename = "type")]
    activity_type: String,
    description: Option<String>,
    source: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Relationship {
    #[serde(rename = "type")]
    relationship_type: String,
    #[serde(default)]
    target: Option<Link>,
    #[serde(default)]
    source: Option<Link>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ContactRecord {
    id: String,
    name: String,
    title: Option<String>,
    company_id: Option<String>,
    relationship_type: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    linkedin_url: Option<String>,
    location: Option<String>,
    address: Option<String>,
    investment_thesis: Option<String>,
    intro_text: Option<String>,
    bio: Option<String>,
    open_followup: Option<String>,
    last_contacted: Option<String>,
    cadence: Option<String>,
    how_met: Option<String>,
    connections_made: Option<String>,
    avatar_url: Option<String>,
    status: String,
    merged_into_contact_id: Option<String>,
    notes: Option<String>,
    relationship_context_summary: Option<String>,
    relationship_context_summary_generated_at: Option<String>,
    relationship_context_summary_model: Option<String>,
    relationship_context_summary_input_hash: Option<String>,
    pause_email_logging: bool,
    last_clay_sync_at: Option<String>,
    created_at: String,
    updated_at: String,
    fts: Value,
    search_document: Value,
    companies: Option<CompanyLink>,
    tags: Vec<Tag>,
    recent_activities: Vec<RecentActivity>,
    relationships_from: Vec<Relationship>,
    relationships_to: Vec<Relationship>,
}

fn validate_contact(record: &ContactRecord) -> Result<()> {
    validate_uuid(&record.id)?;
    validate_optional_uuid(record.company_id.as_deref())?;
    validate_optional_uuid(record.merged_into_contact_id.as_deref())?;
    parse_timestamp(&record.created_at)?;
    parse_timestamp(&record.updated_at)?;
    validate_optional_timestamp(record.last_contacted.as_deref())?;
    validate_optional_timestamp(record.relationship_context_summary_generated_at.as_deref())?;
    validate_optional_timestamp(record.last_clay_sync_at.as_deref())?;
    if let Some(company) = &record.companies {
        validate_uuid(&company.id)?;
    }
    for tag in &record.tags {
        validate_uuid(&tag.id)?;
    }
    for activity in &record.recent_activities {
        validate_uuid(&activity.id)?;
        parse_timestamp(&activity.activity_date)?;
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChildCompany {
    id: String,
    name: String,
    status: Option<String>,
    industry: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompanyContact {
    id: String,
    name: String,
    title: Option<String>,
    email: Option<String>,
    relationship_type: Option<String>,
    status: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompanyRecord {
    id: String,
    name: String,
    website: Option<String>,
    industry: Option<String>,
    description: Option<String>,
    hq_location: Option<String>,
    address: Option<String>,
    ownership_type: Option<String>,
    ticker: Option<String>,
    company_size: Option<String>,
    status: Option<String>,
    business_type: Option<String>,
    category: Option<String>,
    state: Option<String>,
    parent_company_id: Option<String>,
    merged_into_company_id: Option<String>,
    normalized_domain: Option<String>,
    normalized_name: Option<String>,
    notes: Option<String>,
    created_at: String,
    updated_at: String,
    fts: Value,
    parent: Option<Link>,
    child_companies: Vec<ChildCompany>,
    contacts: Vec<CompanyContact>,
    tags: Vec<Tag>,
}

fn validate_company(record: &CompanyRecord) -> Result<()> {
    validate_uuid(&record.id)?;
    validate_optional_uuid(record.parent_company_id.as_deref())?;
    validate_optional_uuid(record.merged_into_company_id.as_deref())?;
    parse_timestamp(&record.created_at)?;
    parse_timestamp(&record.updated_at)?;
    if let Some(parent) = &record.parent {
        validate_uuid(&parent.id)?;
    }
    for child in &record.child_companies {
        validate_uuid(&child.id)?;
    }
    for contact in &record.contacts {
        validate_uuid(&contact.id)?;
    }
    for tag in &record.tags {
        validate_uuid(&tag.id)?;
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    #[serde(default)]
    id: Option<String>,
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectContactRelation {
    contact_id: String,
    contacts: Option<Link>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectCompanyRelation {
    company_id: String,
    companies: Option<Link>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectRecord {
    id: String,
    name: String,
    status: String,
    owner_id: Option<String>,
    created_by: String,
    primary_company_id: Option<String>,
    summary: Option<String>,
    context: Option<String>,
    next_step: Option<String>,
    internal_notes: Option<String>,
    completed_at: Option<String>,
    archived_at: Option<String>,
    created_at: String,
    updated_at: String,
    deleted_at: Option<String>,
    section: String,
    owner: Option<Profile>,
    creator: Option<Profile>,
    primary_company: Option<Link>,
    #[serde(default)]
    project_contacts: Vec<ProjectContactRelation>,
    #[serde(default)]
    project_companies: Vec<ProjectCompanyRelation>,
    contacts: Vec<Link>,
    companies: Vec<Link>,
}

fn validate_project(record: &ProjectRecord) -> Result<()> {
    validate_uuid(&record.id)?;
    validate_uuid(&record.created_by)?;
    validate_optional_uuid(record.owner_id.as_deref())?;
    validate_optional_uuid(record.primary_company_id.as_deref())?;
    parse_timestamp(&record.created_at)?;
    parse_timestamp(&record.updated_at)?;
    validate_optional_timestamp(record.completed_at.as_deref())?;
    validate_optional_timestamp(record.archived_at.as_deref())?;
    validate_optional_timestamp(record.deleted_at.as_deref())?;
    for link in record.contacts.iter().chain(&record.companies) {
        validate_uuid(&link.id)?;
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivityContact {
    id: String,
    name: String,
    #[serde(default)]
    company_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Transcript {
    id: String,
    content: String,
    source: String,
    #[serde(default)]
    granola_note_id: Option<String>,
    #[serde(default)]
    content_truncated: Option<bool>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivityRecord {
    id: String,
    contact_id: String,
    activity_date: String,
    #[serde(rename = "type")]
    activity_type: String,
    description: Option<String>,
    source: String,
    granola_note_id: Option<String>,
    voice_note_id: Option<String>,
    created_by: Option<String>,
    created_at: String,
    #[serde(default)]
    description_truncated: Option<bool>,
    profiles: Option<Profile>,
    contacts: ActivityContact,
    #[serde(default)]
    transcripts: Vec<Transcript>,
}

fn append_activity(
    record: &ActivityRecord,
    acls: &[AclPrincipal],
    upserts: &mut Vec<SourceItemUpsert>,
) -> Result<()> {
    validate_uuid(&record.id)?;
    validate_uuid(&record.contact_id)?;
    validate_optional_uuid(record.voice_note_id.as_deref())?;
    validate_optional_uuid(record.created_by.as_deref())?;
    parse_timestamp(&record.activity_date)?;
    parse_timestamp(&record.created_at)?;
    validate_uuid(&record.contacts.id)?;
    validate_optional_uuid(record.contacts.company_id.as_deref())?;
    let title = format!("{} activity", record.activity_type);
    upserts.push(record_upsert(
        RecordSource::new(
            "activity",
            &record.id,
            &title,
            SourceKind::CrmRecord,
            &record.created_at,
            format!("/contacts/{}", record.contact_id),
        ),
        record,
        acls,
    )?);
    for transcript in &record.transcripts {
        validate_uuid(&transcript.id)?;
        let transcript_title = format!("Transcript for {title}");
        upserts.push(record_upsert(
            RecordSource::new(
                "transcript",
                &transcript.id,
                &transcript_title,
                SourceKind::CrmTranscript,
                &record.created_at,
                format!("/contacts/{}", record.contact_id),
            ),
            transcript,
            acls,
        )?);
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GuidanceRecord {
    id: String,
    slug: String,
    title: String,
    markdown: String,
    metadata: Value,
    model: Option<String>,
    updated_by: Option<String>,
    created_at: String,
    updated_at: String,
}

fn validate_guidance(record: &GuidanceRecord) -> Result<()> {
    validate_uuid(&record.id)?;
    validate_optional_uuid(record.updated_by.as_deref())?;
    parse_timestamp(&record.created_at)?;
    parse_timestamp(&record.updated_at)?;
    if !record.metadata.is_object() {
        return Err(ConnectorError::InvalidData(
            "Core CRM guidance metadata is invalid",
        ));
    }
    GuidanceArgs {
        slug: record.slug.clone(),
    }
    .validate()
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ContactSummary {
    id: String,
    name: Option<String>,
    title: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    relationship_type: Option<String>,
    status: Option<String>,
    last_contacted: Option<String>,
    company_id: Option<String>,
    companies: Option<Link>,
    fuzzy: bool,
    #[serde(default)]
    merged_into_contact_id: Option<String>,
}
fn validate_contact_summary(record: &ContactSummary) -> Result<()> {
    validate_uuid(&record.id)?;
    validate_optional_uuid(record.company_id.as_deref())?;
    validate_optional_uuid(record.merged_into_contact_id.as_deref())?;
    validate_optional_timestamp(record.last_contacted.as_deref())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompanySummary {
    id: String,
    name: String,
    website: Option<String>,
    industry: Option<String>,
    status: Option<String>,
    business_type: Option<String>,
    category: Option<String>,
    state: Option<String>,
    parent_company_id: Option<String>,
    merged_into_company_id: Option<String>,
}
fn validate_company_summary(record: &CompanySummary) -> Result<()> {
    validate_uuid(&record.id)?;
    validate_optional_uuid(record.parent_company_id.as_deref())?;
    validate_optional_uuid(record.merged_into_company_id.as_deref())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GuidanceSummary {
    id: String,
    slug: String,
    title: String,
    metadata: Value,
    model: Option<String>,
    updated_by: Option<String>,
    created_at: String,
    updated_at: String,
}
fn validate_guidance_summary(record: &GuidanceSummary) -> Result<()> {
    validate_uuid(&record.id)?;
    validate_optional_uuid(record.updated_by.as_deref())?;
    parse_timestamp(&record.created_at)?;
    parse_timestamp(&record.updated_at)?;
    if record.title.trim().is_empty()
        || !record.metadata.is_object()
        || record.model.as_ref().is_some_and(|value| value.len() > 255)
    {
        return Err(ConnectorError::InvalidData(
            "Core CRM guidance summary is invalid",
        ));
    }
    GuidanceArgs {
        slug: record.slug.clone(),
    }
    .validate()
}
