import { invoke } from "@tauri-apps/api/core";

import type {
  CallCaptureDevice,
  CallCaptureSnapshot,
  ConsentAcknowledgement,
} from "./types";

export async function getCallCaptureState() {
  return invoke<CallCaptureSnapshot>("get_call_capture_state");
}

export async function listCallCaptureDevices() {
  return invoke<CallCaptureDevice[]>("list_call_capture_devices");
}

export async function acknowledgeCallCaptureConsent(input: {
  microphoneId: string;
  outputId: string;
}) {
  return invoke<ConsentAcknowledgement>("acknowledge_call_capture_consent", {
    request: {
      schema_version: 1,
      microphone_id: input.microphoneId,
      output_id: input.outputId,
      consent_notice_version: 1,
      consent_acknowledged: true,
    },
  });
}

export async function startCallCapture(input: {
  microphoneId: string;
  outputId: string;
  consentToken: string;
}) {
  return invoke<CallCaptureSnapshot>("start_call_capture", {
    request: {
      schema_version: 1,
      microphone_id: input.microphoneId,
      output_id: input.outputId,
      consent_token: input.consentToken,
      meeting_context: null,
    },
  });
}

export async function stopCallCapture() {
  return invoke<CallCaptureSnapshot>("stop_call_capture");
}

export async function acceptCallCopilotSuggestion(eventJson: string) {
  return invoke("accept_call_copilot_suggestion", { eventJson });
}
