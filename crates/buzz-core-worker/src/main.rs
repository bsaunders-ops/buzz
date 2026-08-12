use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use buzz_connector_core::core_crm::BearerToken;
use buzz_core_worker::connector_iteration::{ConnectorIterationOutcome, ConnectorIterationRunner};
use buzz_core_worker::postgres_core_crm::CoreCrmConnectorRunner;
use clap::{Parser, Subcommand, ValueEnum};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
use zeroize::Zeroizing;

const HEARTBEAT_MAX_AGE: Duration = Duration::from_secs(45);

#[derive(Debug, Parser)]
#[command(name = "buzz-core-worker")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run one hardened worker process boundary.
    Serve {
        /// Role implemented by this process.
        #[arg(long, value_enum)]
        role: WorkerRole,
    },
    /// Run exactly one read-only Core CRM claim/fetch/apply attempt, then exit.
    CoreCrmCanary,
    /// Verify the current container's worker heartbeat.
    Health,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum WorkerRole {
    AgentSupervisor,
    ConnectorWorker,
    SanitizerIndexer,
    SignalRunner,
    ActionExecutor,
    LearningWorker,
    AuditExporter,
}

impl WorkerRole {
    const fn slug(self) -> &'static str {
        match self {
            Self::AgentSupervisor => "agent-supervisor",
            Self::ConnectorWorker => "connector-worker",
            Self::SanitizerIndexer => "sanitizer-indexer",
            Self::SignalRunner => "signal-runner",
            Self::ActionExecutor => "action-executor",
            Self::LearningWorker => "learning-worker",
            Self::AuditExporter => "audit-exporter",
        }
    }

    const fn expected_database_role(self) -> Option<&'static str> {
        match self {
            Self::AgentSupervisor => None,
            Self::ConnectorWorker => Some("buzz_connector_worker"),
            Self::SanitizerIndexer => Some("buzz_sanitizer_indexer"),
            Self::SignalRunner => Some("buzz_signal_runner"),
            Self::ActionExecutor => Some("buzz_action_executor"),
            Self::LearningWorker => Some("buzz_learning_worker"),
            Self::AuditExporter => Some("buzz_audit_exporter"),
        }
    }

    const fn required_secrets(self) -> &'static [&'static str] {
        match self {
            Self::AgentSupervisor => &["OPENAI_COMPAT_API_KEY", "BUZZ_ACP_SIGNING_KEY"],
            Self::ConnectorWorker => &["CORE_CRM_CREDENTIAL_B64", "CORE_CRM_CURSOR_KEY_B64"],
            Self::SanitizerIndexer | Self::SignalRunner | Self::LearningWorker => &[],
            Self::ActionExecutor => &[
                "CORE_CRM_CREDENTIAL_B64",
                "MICROSOFT_CONNECTOR_CREDENTIAL_B64",
                "GOOGLE_CONNECTOR_CREDENTIAL_B64",
                "BUZZ_ACP_SIGNING_KEY",
            ],
            Self::AuditExporter => &["AUDIT_BLOB_CREDENTIAL_B64"],
        }
    }

    const fn forbids_model_secret(self) -> bool {
        !matches!(self, Self::AgentSupervisor)
    }
}

trait CommandExecutor {
    async fn serve(&mut self, role: WorkerRole) -> Result<()>;
    async fn core_crm_canary(&mut self) -> Result<()>;
    async fn health(&mut self) -> Result<()>;
}

struct ProductionCommandExecutor;

impl CommandExecutor for ProductionCommandExecutor {
    async fn serve(&mut self, role: WorkerRole) -> Result<()> {
        serve(role).await
    }

    async fn core_crm_canary(&mut self) -> Result<()> {
        core_crm_canary().await
    }

    async fn health(&mut self) -> Result<()> {
        health()
    }
}

async fn dispatch_command<E: CommandExecutor>(command: Command, executor: &mut E) -> Result<()> {
    match command {
        Command::Serve { role } => executor.serve(role).await,
        Command::CoreCrmCanary => executor.core_crm_canary().await,
        Command::Health => executor.health().await,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .init();

    dispatch_command(Cli::parse().command, &mut ProductionCommandExecutor).await
}

async fn core_crm_canary() -> Result<()> {
    let role = WorkerRole::ConnectorWorker;
    let mut runtime = build_worker_runtime(role, None).await?;
    let outcome = run_core_crm_canary_once(&mut runtime.connector_registry).await?;
    tracing::info!(
        role = role.slug(),
        outcome = ?outcome,
        "bounded Core CRM canary finished"
    );
    Ok(())
}

async fn serve(role: WorkerRole) -> Result<()> {
    serve_with_connector_registry(role, None).await
}

async fn serve_with_connector_registry(
    role: WorkerRole,
    connector_registry: Option<Box<dyn ConnectorIterationRunner>>,
) -> Result<()> {
    let WorkerRuntime {
        database,
        mut connector_registry,
    } = build_worker_runtime(role, connector_registry).await?;
    let health_path = health_path();

    write_heartbeat(&health_path, role)?;
    tracing::info!(role = role.slug(), "Core worker process boundary ready");

    loop {
        if matches!(role, WorkerRole::ConnectorWorker) {
            let outcome = run_connector_role_once(&mut connector_registry).await?;
            tracing::info!(
                role = role.slug(),
                outcome = ?outcome,
                "bounded connector iteration finished"
            );
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
        if let Some(pool) = &database {
            sqlx::query_scalar::<_, i32>("SELECT 1")
                .fetch_one(pool)
                .await
                .context("worker database heartbeat failed")?;
        }
        write_heartbeat(&health_path, role)?;
    }
}

struct WorkerRuntime {
    database: Option<sqlx::PgPool>,
    connector_registry: Option<Box<dyn ConnectorIterationRunner>>,
}

async fn build_worker_runtime(
    role: WorkerRole,
    mut connector_registry: Option<Box<dyn ConnectorIterationRunner>>,
) -> Result<WorkerRuntime> {
    validate_environment(role)?;
    let database = if let Some(expected_role) = role.expected_database_role() {
        let url = required_env("DATABASE_URL")?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&url)
            .await
            .context("worker database connection failed")?;
        verify_database_role(&pool, expected_role).await?;
        Some(pool)
    } else {
        None
    };
    if matches!(role, WorkerRole::ConnectorWorker) && connector_registry.is_none() {
        let pool = database
            .as_ref()
            .context("connector database is not configured")?
            .clone();
        connector_registry = Some(build_core_crm_registry(pool)?);
    }
    Ok(WorkerRuntime {
        database,
        connector_registry,
    })
}

fn decode_secret(key: &str) -> Result<Zeroizing<Vec<u8>>> {
    let encoded = Zeroizing::new(required_env(key)?);
    let decoded = STANDARD
        .decode(encoded.as_bytes())
        .with_context(|| format!("required setting {key} is invalid"))?;
    if decoded.is_empty() {
        bail!("required setting {key} is invalid");
    }
    Ok(Zeroizing::new(decoded))
}

fn build_core_crm_registry(pool: sqlx::PgPool) -> Result<Box<dyn ConnectorIterationRunner>> {
    let token_bytes = decode_secret("CORE_CRM_CREDENTIAL_B64")?;
    let token = std::str::from_utf8(&token_bytes)
        .context("Core CRM credential encoding is invalid")?
        .to_owned();
    let cursor_key = decode_secret("CORE_CRM_CURSOR_KEY_B64")?;
    let cursor_key: [u8; 32] = cursor_key
        .as_slice()
        .try_into()
        .context("Core CRM cursor key must be exactly 32 bytes")?;
    let runner = CoreCrmConnectorRunner::new(
        pool,
        Uuid::new_v4(),
        BearerToken::new(token).context("Core CRM credential is invalid")?,
        cursor_key,
        1,
    )
    .context("Core CRM provider registry configuration failed")?;
    Ok(Box::new(runner))
}

async fn run_connector_role_once(
    connector_registry: &mut Option<Box<dyn ConnectorIterationRunner>>,
) -> Result<ConnectorIterationOutcome> {
    let runner = connector_registry
        .as_mut()
        .context("connector provider registry is not configured")?;
    runner
        .run_once()
        .await
        .context("connector iteration boundary failed")
}

async fn run_core_crm_canary_once(
    connector_registry: &mut Option<Box<dyn ConnectorIterationRunner>>,
) -> Result<ConnectorIterationOutcome> {
    run_connector_role_once(connector_registry).await
}

fn validate_environment(role: WorkerRole) -> Result<()> {
    if role.forbids_model_secret() && std::env::var_os("OPENAI_COMPAT_API_KEY").is_some() {
        bail!("model credentials are forbidden for this worker role");
    }
    if role.expected_database_role().is_none() && std::env::var_os("DATABASE_URL").is_some() {
        bail!("database credentials are forbidden for this worker role");
    }
    for key in role.required_secrets() {
        let _ = required_env(key)?;
    }
    if matches!(role, WorkerRole::AgentSupervisor) {
        let _ = required_env("BUZZ_RELAY_URL")?;
    }
    Ok(())
}

async fn verify_database_role(pool: &sqlx::PgPool, expected: &str) -> Result<()> {
    let actual: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(pool)
        .await
        .context("database role verification failed")?;
    if actual != expected {
        bail!("worker database role mismatch");
    }
    Ok(())
}

fn required_env(key: &str) -> Result<String> {
    let value = std::env::var(key).with_context(|| format!("required setting {key} is missing"))?;
    if value.trim().is_empty() || value.contains(['\n', '\r']) {
        bail!("required setting {key} is invalid");
    }
    Ok(value)
}

fn health_path() -> PathBuf {
    std::env::var_os("BUZZ_WORKER_HEALTH_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/buzz-core-worker.health"))
}

fn write_heartbeat(path: &Path, role: WorkerRole) -> Result<()> {
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, role.slug()).context("write worker heartbeat")?;
    std::fs::rename(&temporary, path).context("publish worker heartbeat")?;
    Ok(())
}

fn health() -> Result<()> {
    let metadata = std::fs::metadata(health_path()).context("worker heartbeat is missing")?;
    let age = SystemTime::now()
        .duration_since(metadata.modified().context("read worker heartbeat time")?)
        .context("worker heartbeat time is in the future")?;
    if age > HEARTBEAT_MAX_AGE {
        bail!("worker heartbeat is stale");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use buzz_core_worker::connector_iteration::{
        ConnectorBoundaryError, ConnectorIterationOutcome, ConnectorIterationRunner,
    };

    use super::*;

    struct FakeConnectorRunner {
        calls: Arc<AtomicUsize>,
        result: std::result::Result<ConnectorIterationOutcome, ConnectorBoundaryError>,
    }

    impl ConnectorIterationRunner for FakeConnectorRunner {
        fn run_once(
            &mut self,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = std::result::Result<
                            ConnectorIterationOutcome,
                            ConnectorBoundaryError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self.result;
            Box::pin(async move { result })
        }
    }

    #[derive(Default)]
    struct FakeCommandExecutor {
        serve_calls: usize,
        canary_calls: usize,
        health_calls: usize,
        fail_canary: bool,
    }

    impl CommandExecutor for FakeCommandExecutor {
        async fn serve(&mut self, _role: WorkerRole) -> Result<()> {
            self.serve_calls += 1;
            Ok(())
        }

        async fn core_crm_canary(&mut self) -> Result<()> {
            self.canary_calls += 1;
            if self.fail_canary {
                bail!("synthetic canary failure");
            }
            Ok(())
        }

        async fn health(&mut self) -> Result<()> {
            self.health_calls += 1;
            Ok(())
        }
    }

    #[test]
    fn only_agent_supervisor_may_receive_model_credentials() {
        assert!(!WorkerRole::AgentSupervisor.forbids_model_secret());
        for role in [
            WorkerRole::ConnectorWorker,
            WorkerRole::SanitizerIndexer,
            WorkerRole::SignalRunner,
            WorkerRole::ActionExecutor,
            WorkerRole::LearningWorker,
            WorkerRole::AuditExporter,
        ] {
            assert!(role.forbids_model_secret());
        }
    }

    #[test]
    fn agent_supervisor_never_receives_a_database_role() {
        assert_eq!(WorkerRole::AgentSupervisor.expected_database_role(), None);
    }

    #[test]
    fn connector_worker_registers_only_core_crm_read_secrets() {
        assert_eq!(
            WorkerRole::ConnectorWorker.required_secrets(),
            &["CORE_CRM_CREDENTIAL_B64", "CORE_CRM_CURSOR_KEY_B64"]
        );
    }

    #[tokio::test]
    async fn core_crm_canary_command_dispatches_once_without_other_roles() {
        let parsed = Cli::try_parse_from(["buzz-core-worker", "core-crm-canary"])
            .expect("the bounded Core CRM canary must parse");
        let mut executor = FakeCommandExecutor::default();

        dispatch_command(parsed.command, &mut executor)
            .await
            .expect("canary dispatch");

        assert_eq!(executor.canary_calls, 1);
        assert_eq!(executor.serve_calls, 0);
        assert_eq!(executor.health_calls, 0);
    }

    #[tokio::test]
    async fn core_crm_canary_command_propagates_failure_without_retry() {
        let parsed = Cli::try_parse_from(["buzz-core-worker", "core-crm-canary"])
            .expect("the bounded Core CRM canary must parse");
        let mut executor = FakeCommandExecutor {
            fail_canary: true,
            ..FakeCommandExecutor::default()
        };

        dispatch_command(parsed.command, &mut executor)
            .await
            .expect_err("canary failure must propagate");

        assert_eq!(executor.canary_calls, 1);
        assert_eq!(executor.serve_calls, 0);
        assert_eq!(executor.health_calls, 0);
    }

    #[tokio::test]
    async fn connector_iteration_requires_an_injected_registry() {
        let mut registry = None;

        let error = run_connector_role_once(&mut registry)
            .await
            .expect_err("missing registry must fail closed");

        assert_eq!(
            error.to_string(),
            "connector provider registry is not configured"
        );
    }

    #[tokio::test]
    async fn connector_iteration_calls_the_injected_runner_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runner = FakeConnectorRunner {
            calls: Arc::clone(&calls),
            result: Ok(ConnectorIterationOutcome::Idle),
        };
        let mut registry: Option<Box<dyn ConnectorIterationRunner>> = Some(Box::new(runner));

        let outcome = run_core_crm_canary_once(&mut registry)
            .await
            .expect("injected iteration succeeds");

        assert_eq!(outcome, ConnectorIterationOutcome::Idle);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn connector_canary_does_not_retry_an_iteration_failure() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runner = FakeConnectorRunner {
            calls: Arc::clone(&calls),
            result: Err(ConnectorBoundaryError::new()),
        };
        let mut registry: Option<Box<dyn ConnectorIterationRunner>> = Some(Box::new(runner));

        run_core_crm_canary_once(&mut registry)
            .await
            .expect_err("iteration failure must propagate");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
