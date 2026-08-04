//! Verified local-only embedding model contracts.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{types::UntrustedSourceData, ConnectorError, Result};

/// Pinned Hugging Face repository revision containing the Month-1 ONNX model.
pub const CORE_EMBEDDING_REPOSITORY_REVISION: &str = "b9db1e8a0d3a51769172ba8546f282a73f066e47";
/// Pinned repository-relative ONNX artifact path.
pub const CORE_EMBEDDING_ARTIFACT_NAME: &str = "onnx/model.onnx";
/// Pinned SHA-256 published by the upstream artifact repository.
pub const CORE_EMBEDDING_ARTIFACT_SHA256_HEX: &str =
    "6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452";
/// Upstream artifact license identifier.
pub const CORE_EMBEDDING_LICENSE: &str = "Apache-2.0";
/// Model output width stored in pgvector.
pub const CORE_EMBEDDING_DIMENSIONS: usize = 384;

/// Build/deployment-pinned local embedding artifact metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct EmbeddingManifest {
    model_name: String,
    model_version: String,
    artifact_sha256: [u8; 32],
    dimensions: usize,
    license: String,
}

impl std::fmt::Debug for EmbeddingManifest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EmbeddingManifest")
            .field("model_name", &self.model_name)
            .field("model_version", &self.model_version)
            .field("dimensions", &self.dimensions)
            .field("license", &self.license)
            .field("artifact_digest_redacted", &true)
            .finish()
    }
}

impl EmbeddingManifest {
    /// Validate an immutable artifact identity.
    pub fn new(
        model_name: impl Into<String>,
        model_version: impl Into<String>,
        artifact_sha256: [u8; 32],
        dimensions: usize,
        license: impl Into<String>,
    ) -> Result<Self> {
        let model_name = model_name.into();
        let model_version = model_version.into();
        let license = license.into();
        if model_name.is_empty()
            || model_name.len() > 256
            || model_version.is_empty()
            || model_version.len() > 128
            || dimensions != CORE_EMBEDDING_DIMENSIONS
            || license.is_empty()
            || license.len() > 128
        {
            return Err(ConnectorError::InvalidData("embedding manifest is invalid"));
        }
        Ok(Self {
            model_name,
            model_version,
            artifact_sha256,
            dimensions,
            license,
        })
    }

    /// Exact pinned model name.
    #[must_use]
    pub fn model_name(&self) -> &str {
        &self.model_name
    }

    /// Exact immutable model/repository version.
    #[must_use]
    pub fn model_version(&self) -> &str {
        &self.model_version
    }

    /// Artifact digest required before loading.
    #[must_use]
    pub const fn artifact_sha256(&self) -> [u8; 32] {
        self.artifact_sha256
    }

    /// Exact output width.
    #[must_use]
    pub const fn dimensions(&self) -> usize {
        self.dimensions
    }

    /// SPDX-compatible upstream license identifier.
    #[must_use]
    pub fn license(&self) -> &str {
        &self.license
    }

    /// Deterministic version identifier for side-by-side reindexing.
    #[must_use]
    pub fn id(&self) -> Uuid {
        let mut hasher = Sha256::new();
        hasher.update(b"core-buzz:embedding-manifest:v1\0");
        hasher.update(self.model_name.as_bytes());
        hasher.update([0]);
        hasher.update(self.model_version.as_bytes());
        hasher.update(self.artifact_sha256);
        let dimensions = u64::try_from(self.dimensions).unwrap_or(u64::MAX);
        hasher.update(dimensions.to_be_bytes());
        hasher.update(self.license.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Uuid::from_bytes(bytes)
    }

    /// Frozen Month-1 model manifest. Deployment stages this exact artifact;
    /// runtime code never downloads it.
    pub fn month_one() -> Result<Self> {
        let bytes = hex::decode(CORE_EMBEDDING_ARTIFACT_SHA256_HEX)
            .map_err(|_| ConnectorError::InvalidData("pinned embedding digest is invalid"))?;
        let digest: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ConnectorError::InvalidData("pinned embedding digest is invalid"))?;
        Self::new(
            "sentence-transformers/all-MiniLM-L6-v2",
            CORE_EMBEDDING_REPOSITORY_REVISION,
            digest,
            CORE_EMBEDDING_DIMENSIONS,
            CORE_EMBEDDING_LICENSE,
        )
    }
}

/// A local artifact that passed file-type, symlink, size, and SHA verification.
pub struct VerifiedEmbeddingArtifact {
    path: PathBuf,
    manifest: EmbeddingManifest,
}

impl std::fmt::Debug for VerifiedEmbeddingArtifact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedEmbeddingArtifact")
            .field("path_redacted", &true)
            .field("manifest", &self.manifest)
            .finish()
    }
}

impl VerifiedEmbeddingArtifact {
    /// Open and verify a pre-staged local artifact without a network fallback.
    pub fn open(path: &Path, manifest: EmbeddingManifest) -> Result<Self> {
        if !path.is_absolute() {
            return Err(ConnectorError::ArtifactVerification(
                "artifact path must be absolute",
            ));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| ConnectorError::ArtifactVerification("artifact is unavailable"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ConnectorError::ArtifactVerification(
                "artifact must be a regular non-symlink file",
            ));
        }
        if metadata.len() == 0 || metadata.len() > 2 * 1024 * 1024 * 1024 {
            return Err(ConnectorError::ArtifactVerification(
                "artifact size is outside the approved bound",
            ));
        }
        let mut file = File::open(path)
            .map_err(|_| ConnectorError::ArtifactVerification("artifact cannot be opened"))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| ConnectorError::ArtifactVerification("artifact cannot be read"))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != manifest.artifact_sha256 {
            return Err(ConnectorError::ArtifactVerification(
                "artifact digest mismatch",
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            manifest,
        })
    }

    /// Explicitly reject URL model loading. The API exists to make a network
    /// fallback impossible to accidentally substitute for `open`.
    pub fn open_url(_url: &str, _manifest: EmbeddingManifest) -> Result<Self> {
        Err(ConnectorError::ArtifactVerification(
            "network model loading is disabled",
        ))
    }

    /// Verified local file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verified immutable manifest.
    #[must_use]
    pub const fn manifest(&self) -> &EmbeddingManifest {
        &self.manifest
    }
}

/// A local embedding vector bound to one exact model version.
#[derive(Clone, PartialEq)]
pub struct LocalEmbedding {
    /// Exact manifest ID.
    pub version_id: Uuid,
    /// Finite local vector.
    pub values: Vec<f32>,
}

impl std::fmt::Debug for LocalEmbedding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalEmbedding")
            .field("version_and_values_redacted", &true)
            .field("dimensions", &self.values.len())
            .finish()
    }
}

/// Narrow CPU embedder interface. It receives no HTTP client or URL.
pub trait LocalCpuEmbedder {
    /// Exact verified model manifest.
    fn manifest(&self) -> &EmbeddingManifest;
    /// Embed bounded untrusted source text locally.
    fn embed(&mut self, source: &UntrustedSourceData) -> Result<LocalEmbedding>;
}

/// Lifecycle of one side-by-side embedding corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddingStatus {
    /// Corpus is being populated.
    Building,
    /// Exactly one version is active for new retrievals.
    Active,
    /// A previously active version remains only for rollback/cleanup.
    Retired,
}

#[derive(Clone)]
struct CatalogEntry {
    manifest: EmbeddingManifest,
    status: EmbeddingStatus,
    fully_indexed: bool,
}

impl std::fmt::Debug for CatalogEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CatalogEntry")
            .field("manifest", &self.manifest)
            .field("status", &self.status)
            .field("fully_indexed", &self.fully_indexed)
            .finish()
    }
}

/// Atomic model-version activation contract.
#[derive(Default, Clone)]
pub struct EmbeddingCatalog {
    entries: BTreeMap<Uuid, CatalogEntry>,
}

impl std::fmt::Debug for EmbeddingCatalog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EmbeddingCatalog")
            .field("entry_count", &self.entries.len())
            .field("version_identifiers_redacted", &true)
            .finish()
    }
}

impl EmbeddingCatalog {
    /// Stage a version without changing active retrieval.
    pub fn stage(&mut self, manifest: EmbeddingManifest) -> Result<Uuid> {
        let id = manifest.id();
        if let Some(existing) = self.entries.get(&id) {
            if existing.manifest != manifest {
                return Err(ConnectorError::InvalidData("embedding id collision"));
            }
            return Ok(id);
        }
        self.entries.insert(
            id,
            CatalogEntry {
                manifest,
                status: EmbeddingStatus::Building,
                fully_indexed: false,
            },
        );
        Ok(id)
    }

    /// Mark that every active authorized chunk has this model version.
    pub fn mark_fully_indexed(&mut self, id: Uuid) -> Result<()> {
        let entry = self
            .entries
            .get_mut(&id)
            .ok_or(ConnectorError::InvalidData("unknown embedding version"))?;
        if entry.status != EmbeddingStatus::Building {
            return Err(ConnectorError::InvalidData(
                "only a building embedding version can finish indexing",
            ));
        }
        entry.fully_indexed = true;
        Ok(())
    }

    /// Atomically switch active retrieval only after a complete side-by-side build.
    pub fn activate(&mut self, id: Uuid) -> Result<()> {
        let ready = self
            .entries
            .get(&id)
            .is_some_and(|entry| entry.status == EmbeddingStatus::Building && entry.fully_indexed);
        if !ready {
            return Err(ConnectorError::InvalidData(
                "embedding corpus is not ready to activate",
            ));
        }
        for entry in self.entries.values_mut() {
            if entry.status == EmbeddingStatus::Active {
                entry.status = EmbeddingStatus::Retired;
            }
        }
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.status = EmbeddingStatus::Active;
        }
        Ok(())
    }

    /// Read one version lifecycle state.
    #[must_use]
    pub fn status(&self, id: Uuid) -> Option<EmbeddingStatus> {
        self.entries.get(&id).map(|entry| entry.status)
    }

    /// Currently active model version, when one has completed activation.
    #[must_use]
    pub fn active(&self) -> Option<Uuid> {
        self.entries
            .iter()
            .find_map(|(id, entry)| (entry.status == EmbeddingStatus::Active).then_some(*id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_manifest_matches_a_real_nonzero_artifact_pin() {
        let manifest = EmbeddingManifest::month_one().expect("frozen manifest is valid");
        assert_eq!(manifest.dimensions(), 384);
        assert_eq!(manifest.license(), "Apache-2.0");
        assert_ne!(manifest.artifact_sha256(), [0; 32]);
    }
}
