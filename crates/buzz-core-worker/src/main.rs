use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sqlx::postgres::PgPoolOptions;

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
            Self::ConnectorWorker => &[
                "CORE_CRM_CREDENTIAL_B64",
                "MICROSOFT_CONNECTOR_CREDENTIAL_B64",
                "GOOGLE_CONNECTOR_CREDENTIAL_B64",
            ],
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .init();

    match Cli::parse().command {
        Command::Serve { role } => serve(role).await,
        Command::Health => health(),
    }
}

async fn serve(role: WorkerRole) -> Result<()> {
    validate_environment(role)?;
    let health_path = health_path();
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

    write_heartbeat(&health_path, role)?;
    tracing::info!(role = role.slug(), "Core worker process boundary ready");

    loop {
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
    use super::*;

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
}
