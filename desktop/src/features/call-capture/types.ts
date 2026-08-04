import type { RelayEvent } from "@/shared/api/types";

export const CALL_CONTROL_KIND = 24820;
export const CALL_TRANSCRIPT_KIND = 24821;
export const CALL_SUGGESTION_KIND = 24822;

export type CallCapturePhase = "disabled" | "idle" | "active" | "ended";
export type AudioEndpointKind = "microphone" | "output";
export type AudioSourceHealth = "healthy" | "degraded" | "unavailable";

export type CallCaptureDevice = {
  schema_version: 1;
  id: string;
  label: string;
  kind: AudioEndpointKind;
  is_default: boolean;
  sample_rate_hz: number;
  channels: number;
};

export type CallCaptureSourceState = {
  health: AudioSourceHealth;
  level_percent: number;
};

export type CallCaptureSnapshot = {
  schema_version: 1;
  phase: CallCapturePhase;
  call_id: string | null;
  selected_microphone_id: string | null;
  selected_output_id: string | null;
  microphone_source: CallCaptureSourceState;
  output_source: CallCaptureSourceState;
  degraded_reasons: string[];
  stop_reason: string | null;
  started_at_ms: number | null;
  elapsed_ms: number;
  last_segment_sequence: number;
};

export type ConsentAcknowledgement = {
  schema_version: 1;
  token: string;
  microphone_id: string;
  output_id: string;
  issued_at_ms: number;
  expires_at_ms: number;
};

export type FinalizedTranscriptSegment = {
  schema_version: 1;
  segment_id: string;
  call_id: string;
  sequence: number;
  speaker: "self" | "others";
  text: string;
  started_at_ms: number;
  ended_at_ms: number;
  confidence: number;
  model_version: string;
};

export type CopilotSuggestion = {
  schema_version: 1;
  suggestion_id: string;
  call_id: string;
  sequence: number;
  category:
    | "decision"
    | "action"
    | "private_question"
    | "missed_commitment"
    | "contradiction";
  interrupt: "quiet" | "critical";
  text: string;
  created_at: number;
  model_version: string;
  confidence: number;
  evidence_hashes: string[];
};

export type PrivateCallEventReady = {
  schema_version: 1;
  event: RelayEvent;
};

export type CallTransportScope = {
  ownerPubkey: string;
  assistantPubkey: string;
  channelId: string;
};

export const EMPTY_CALL_CAPTURE_SNAPSHOT: CallCaptureSnapshot = {
  schema_version: 1,
  phase: "disabled",
  call_id: null,
  selected_microphone_id: null,
  selected_output_id: null,
  microphone_source: { health: "unavailable", level_percent: 0 },
  output_source: { health: "unavailable", level_percent: 0 },
  degraded_reasons: [],
  stop_reason: null,
  started_at_ms: null,
  elapsed_ms: 0,
  last_segment_sequence: 0,
};
