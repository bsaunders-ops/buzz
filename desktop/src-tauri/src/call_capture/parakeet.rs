use std::path::Path;

use sherpa_onnx::{OfflineRecognizer, OfflineRecognizerConfig};

use super::{AudioEndpointKind, LocalTranscriber, LocalTranscript};

const PARAKEET_MODEL_VERSION: &str = "parakeet-tdt-ctc-110m-en-int8/v2";

/// Local-only Parakeet adapter. It owns no HTTP client, file writer, or provider credential.
pub(super) struct ParakeetTranscriber {
    recognizer: OfflineRecognizer,
}

impl ParakeetTranscriber {
    pub(super) fn initialize(model_dir: &Path) -> Result<Self, String> {
        let tokens_path = model_dir.join("tokens.txt");
        let model_path = model_dir.join("model.int8.onnx");
        if !tokens_path.is_file() || !model_path.is_file() {
            return Err("local Parakeet model is not installed".into());
        }

        let mut config = OfflineRecognizerConfig::default();
        config.model_config.nemo_ctc.model = Some(model_path.to_string_lossy().into_owned());
        config.model_config.tokens = Some(tokens_path.to_string_lossy().into_owned());
        config.model_config.num_threads = 1;
        config.model_config.debug = false;
        let recognizer = OfflineRecognizer::create(&config)
            .ok_or_else(|| "local Parakeet recognizer initialization failed".to_string())?;
        Ok(Self { recognizer })
    }
}

impl LocalTranscriber for ParakeetTranscriber {
    fn transcribe(
        &mut self,
        _source: AudioEndpointKind,
        samples: &[f32],
        started_at_ms: u64,
        ended_at_ms: u64,
    ) -> Result<Option<LocalTranscript>, String> {
        if samples.is_empty() {
            return Ok(None);
        }
        let stream = self.recognizer.create_stream();
        stream.accept_waveform(16_000, samples);
        self.recognizer.decode(&stream);
        let text = stream
            .get_result()
            .map(|result| result.text.trim().to_owned())
            .unwrap_or_default();
        if text.is_empty() {
            return Ok(None);
        }
        Ok(Some(LocalTranscript {
            text,
            // sherpa's Parakeet result does not expose a calibrated utterance
            // probability. Zero explicitly means "not reported", never an
            // invented confidence score.
            confidence: 0,
            started_at_ms,
            ended_at_ms,
            model_version: PARAKEET_MODEL_VERSION.to_owned(),
        }))
    }
}
