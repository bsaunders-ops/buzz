import { listen } from "@tauri-apps/api/event";
import * as React from "react";

import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";

import {
  acceptCallCopilotSuggestion,
  getCallCaptureState,
  listCallCaptureDevices,
  stopCallCapture,
} from "./api";
import {
  CALL_CONTROL_KIND,
  CALL_SUGGESTION_KIND,
  CALL_TRANSCRIPT_KIND,
  EMPTY_CALL_CAPTURE_SNAPSHOT,
  type CallCaptureDevice,
  type CallCaptureSnapshot,
  type CallTransportScope,
  type CopilotSuggestion,
  type FinalizedTranscriptSegment,
  type PrivateCallEventReady,
} from "./types";

const MAX_VISIBLE_TRANSCRIPT_SEGMENTS = 200;
const MAX_VISIBLE_SUGGESTIONS = 64;

function errorMessage(error: unknown, fallback: string) {
  if (error instanceof Error && error.message.trim()) return error.message;
  if (typeof error === "string" && error.trim()) return error;
  return fallback;
}

function oneTagValue(event: RelayEvent, name: "h" | "p") {
  const values = event.tags
    .filter((tag) => tag[0] === name && typeof tag[1] === "string")
    .map((tag) => tag[1]);
  return values.length === 1 && values[0] ? values[0] : null;
}

function scopeForPrivateEvent(event: RelayEvent): CallTransportScope | null {
  if (event.kind !== CALL_CONTROL_KIND && event.kind !== CALL_TRANSCRIPT_KIND) {
    return null;
  }
  const channelId = oneTagValue(event, "h");
  const assistantPubkey = oneTagValue(event, "p");
  if (!channelId || !assistantPubkey || !event.pubkey) return null;
  return { ownerPubkey: event.pubkey, assistantPubkey, channelId };
}

function sameScope(left: CallTransportScope | null, right: CallTransportScope) {
  return (
    left?.ownerPubkey === right.ownerPubkey &&
    left.assistantPubkey === right.assistantPubkey &&
    left.channelId === right.channelId
  );
}

export function useCallCaptureSession({
  ownsRelayTransport,
}: {
  ownsRelayTransport: boolean;
}) {
  const [snapshot, setSnapshot] = React.useState<CallCaptureSnapshot>(
    EMPTY_CALL_CAPTURE_SNAPSHOT,
  );
  const [devices, setDevices] = React.useState<CallCaptureDevice[]>([]);
  const [transcript, setTranscript] = React.useState<
    FinalizedTranscriptSegment[]
  >([]);
  const [suggestions, setSuggestions] = React.useState<CopilotSuggestion[]>([]);
  const [transportScope, setTransportScope] =
    React.useState<CallTransportScope | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const callIdRef = React.useRef<string | null>(null);
  const failClosingRef = React.useRef(false);

  const updateSnapshot = React.useCallback((next: CallCaptureSnapshot) => {
    if (next.call_id && next.call_id !== callIdRef.current) {
      callIdRef.current = next.call_id;
      setTranscript([]);
      setSuggestions([]);
    }
    setSnapshot(next);
  }, []);

  const refreshDevices = React.useCallback(async () => {
    try {
      const next = await listCallCaptureDevices();
      setDevices(next);
      return next;
    } catch (nextError) {
      setError(errorMessage(nextError, "Audio devices could not be listed."));
      throw nextError;
    }
  }, []);

  const refreshState = React.useCallback(async () => {
    try {
      const next = await getCallCaptureState();
      updateSnapshot(next);
      return next;
    } catch (nextError) {
      setError(errorMessage(nextError, "Call capture state is unavailable."));
      throw nextError;
    }
  }, [updateSnapshot]);

  const failClosed = React.useCallback(async (message: string) => {
    if (failClosingRef.current) return;
    failClosingRef.current = true;
    setError(message);
    try {
      const next = await stopCallCapture();
      setSnapshot(next);
    } catch {
      // The original transport failure remains the actionable local error.
    } finally {
      failClosingRef.current = false;
    }
  }, []);

  React.useEffect(() => {
    let disposed = false;
    void refreshState().catch(() => undefined);
    const unlisteners: Array<() => void> = [];

    void Promise.all([
      listen<CallCaptureSnapshot>("call-capture-state", (event) => {
        if (!disposed) updateSnapshot(event.payload);
      }),
      listen<FinalizedTranscriptSegment>(
        "call-capture-finalized-transcript",
        (event) => {
          if (disposed || event.payload.call_id !== callIdRef.current) return;
          setTranscript((current) => {
            if (
              current.some(
                (segment) => segment.sequence === event.payload.sequence,
              )
            ) {
              return current;
            }
            return [...current, event.payload]
              .sort((left, right) => left.sequence - right.sequence)
              .slice(-MAX_VISIBLE_TRANSCRIPT_SEGMENTS);
          });
        },
      ),
      listen<CopilotSuggestion>("call-capture-suggestion", (event) => {
        if (disposed || event.payload.call_id !== callIdRef.current) return;
        setSuggestions((current) => {
          if (
            current.some(
              (suggestion) => suggestion.sequence === event.payload.sequence,
            )
          ) {
            return current;
          }
          return [...current, event.payload]
            .sort((left, right) => left.sequence - right.sequence)
            .slice(-MAX_VISIBLE_SUGGESTIONS);
        });
      }),
      ...(ownsRelayTransport
        ? [
            listen<PrivateCallEventReady>(
              "call-capture-private-event-ready",
              (event) => {
                if (disposed) return;
                const scope = scopeForPrivateEvent(event.payload.event);
                if (event.payload.schema_version !== 1 || !scope) {
                  void failClosed(
                    "Call capture stopped because its private route was invalid.",
                  );
                  return;
                }
                setTransportScope((current) =>
                  sameScope(current, scope) ? current : scope,
                );
                void (async () => {
                  await relayClient.preconnect();
                  await relayClient.publishEvent(
                    event.payload.event,
                    "Timed out publishing the private call event.",
                    "Failed to publish the private call event.",
                  );
                })().catch(() =>
                  failClosed(
                    "Call capture stopped because its encrypted relay connection failed.",
                  ),
                );
              },
            ),
          ]
        : []),
    ]).then((ready) => {
      if (disposed) {
        for (const unlisten of ready) unlisten();
      } else {
        unlisteners.push(...ready);
      }
    });

    return () => {
      disposed = true;
      for (const unlisten of unlisteners) unlisten();
    };
  }, [failClosed, ownsRelayTransport, refreshState, updateSnapshot]);

  React.useEffect(() => {
    if (snapshot.phase !== "active") return;
    const timer = window.setInterval(() => {
      void refreshState().catch(() => undefined);
    }, 500);
    return () => window.clearInterval(timer);
  }, [refreshState, snapshot.phase]);

  React.useEffect(() => {
    if (!ownsRelayTransport || snapshot.phase !== "active" || !transportScope) {
      return;
    }
    let disposed = false;
    let unsubscribe: (() => void) | null = null;
    void relayClient
      .subscribeLive(
        {
          kinds: [CALL_SUGGESTION_KIND],
          limit: 0,
          authors: [transportScope.assistantPubkey],
          "#h": [transportScope.channelId],
          "#p": [transportScope.ownerPubkey],
          since: Math.floor(Date.now() / 1_000),
        },
        (event) => {
          if (disposed) return;
          void acceptCallCopilotSuggestion(JSON.stringify(event)).catch(() => {
            // Forged, stale, replayed, or malformed suggestions fail closed in Rust
            // and are intentionally never surfaced to the call UI.
          });
        },
      )
      .then((dispose) => {
        if (disposed) {
          void dispose();
        } else {
          unsubscribe = () => void dispose();
        }
      })
      .catch(() =>
        failClosed(
          "Call capture stopped because its private suggestion channel failed.",
        ),
      );
    return () => {
      disposed = true;
      unsubscribe?.();
    };
  }, [failClosed, ownsRelayTransport, snapshot.phase, transportScope]);

  React.useEffect(() => {
    if (snapshot.phase !== "active") setTransportScope(null);
  }, [snapshot.phase]);

  return {
    devices,
    error,
    refreshDevices,
    setError,
    snapshot,
    suggestions,
    transcript,
    updateSnapshot,
  };
}
