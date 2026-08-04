import { Headphones, Mic, ShieldAlert, Square } from "lucide-react";
import type * as React from "react";

import { cn } from "@/shared/lib/cn";
import { Button } from "@/shared/ui/button";

import type {
  CallCaptureDevice,
  CallCaptureSnapshot,
  CallCaptureSourceState,
  CopilotSuggestion,
  FinalizedTranscriptSegment,
} from "./types";

function formatDuration(elapsedMs: number) {
  const totalSeconds = Math.max(0, Math.floor(elapsedMs / 1_000));
  const hours = Math.floor(totalSeconds / 3_600);
  const minutes = Math.floor((totalSeconds % 3_600) / 60);
  const seconds = totalSeconds % 60;
  return hours > 0
    ? `${hours}:${minutes.toString().padStart(2, "0")}:${seconds
        .toString()
        .padStart(2, "0")}`
    : `${minutes}:${seconds.toString().padStart(2, "0")}`;
}

function deviceLabel(
  devices: CallCaptureDevice[],
  id: string | null,
  fallback: string,
) {
  return devices.find((device) => device.id === id)?.label ?? fallback;
}

function SourceMeter({
  icon,
  label,
  source,
}: {
  icon: React.ReactNode;
  label: string;
  source: CallCaptureSourceState;
}) {
  const boundedLevel = Math.max(0, Math.min(100, source.level_percent));
  return (
    <div className="min-w-0 flex-1" data-health={source.health}>
      <div className="mb-1 flex items-center justify-between gap-2 text-xs">
        <span className="flex min-w-0 items-center gap-1.5 text-muted-foreground">
          {icon}
          <span className="truncate">{label}</span>
        </span>
        <span
          className={cn(
            "capitalize",
            source.health === "healthy"
              ? "text-emerald-600 dark:text-emerald-400"
              : "text-destructive",
          )}
        >
          {source.health}
        </span>
      </div>
      <meter
        aria-label={`${label} level`}
        className="sr-only"
        max={100}
        min={0}
        value={boundedLevel}
      />
      <div
        aria-hidden="true"
        className="h-1.5 overflow-hidden rounded-full bg-muted"
      >
        <div
          className={cn(
            "h-full rounded-full transition-[width] duration-150",
            source.health === "healthy" ? "bg-emerald-500" : "bg-destructive",
          )}
          style={{ width: `${boundedLevel}%` }}
        />
      </div>
    </div>
  );
}

function isCriticalSuggestion(suggestion: CopilotSuggestion) {
  return (
    suggestion.interrupt === "critical" &&
    (suggestion.category === "missed_commitment" ||
      suggestion.category === "contradiction") &&
    suggestion.evidence_hashes.length > 0
  );
}

function suggestionLabel(category: CopilotSuggestion["category"]) {
  switch (category) {
    case "private_question":
      return "Private question";
    case "missed_commitment":
      return "Missed commitment";
    case "contradiction":
      return "Contradiction";
    case "decision":
      return "Decision";
    case "action":
      return "Action";
  }
}

function LiveContext({
  suggestions,
  transcript,
}: {
  suggestions: CopilotSuggestion[];
  transcript: FinalizedTranscriptSegment[];
}) {
  const latestTranscript = transcript.at(-1);
  const visibleSuggestions = suggestions.slice(-2);
  return (
    <div
      className="grid min-h-0 grid-cols-2 gap-2"
      data-testid="call-live-context"
    >
      <section
        aria-label="Live transcript"
        aria-live="off"
        className="min-w-0 rounded-lg border border-border/60 bg-muted/30 px-3 py-2"
      >
        <div className="mb-1 text-xs font-medium text-muted-foreground">
          Live transcript
        </div>
        {latestTranscript ? (
          <p className="line-clamp-2 text-sm">
            <span className="mr-1 font-medium capitalize">
              {latestTranscript.speaker}:
            </span>
            {latestTranscript.text}
          </p>
        ) : (
          <p className="text-sm text-muted-foreground">
            Listening for finalized speech…
          </p>
        )}
      </section>
      <section
        aria-label="Private copilot notes"
        aria-live="off"
        className="min-w-0 space-y-1 overflow-hidden rounded-lg border border-border/60 bg-muted/30 px-3 py-2"
      >
        <div className="text-xs font-medium text-muted-foreground">
          Decisions, actions & private questions
        </div>
        {visibleSuggestions.length === 0 ? (
          <p className="text-sm text-muted-foreground">Quiet mode is active.</p>
        ) : (
          visibleSuggestions.map((suggestion) => {
            const critical = isCriticalSuggestion(suggestion);
            return (
              <div
                className={cn(
                  "truncate rounded px-1.5 py-0.5 text-sm",
                  critical &&
                    "border border-destructive/50 bg-destructive/10 text-destructive",
                )}
                data-interrupt={critical ? "critical" : "quiet"}
                key={suggestion.suggestion_id}
                role={critical ? "alert" : undefined}
              >
                <span className="mr-1 font-medium">
                  {suggestionLabel(suggestion.category)}:
                </span>
                {suggestion.text}
              </div>
            );
          })
        )}
      </section>
    </div>
  );
}

export function CallCaptureBar({
  devices,
  error,
  onStop,
  snapshot,
  standalone = false,
  stopping,
  suggestions,
  transcript,
}: {
  devices: CallCaptureDevice[];
  error: string | null;
  onStop: () => void;
  snapshot: CallCaptureSnapshot;
  standalone?: boolean;
  stopping: boolean;
  suggestions: CopilotSuggestion[];
  transcript: FinalizedTranscriptSegment[];
}) {
  const microphone = deviceLabel(
    devices,
    snapshot.selected_microphone_id,
    "Selected microphone",
  );
  const output = deviceLabel(
    devices,
    snapshot.selected_output_id,
    "Selected Windows output",
  );

  return (
    <div
      className={cn(
        "border border-border/70 bg-background/95 p-3 text-foreground shadow-2xl backdrop-blur",
        standalone
          ? "flex h-screen w-screen flex-col gap-2 overflow-hidden"
          : "fixed bottom-4 left-1/2 z-40 flex w-[min(calc(100vw-2rem),42rem)] -translate-x-1/2 flex-col gap-2 rounded-xl",
      )}
      data-testid={standalone ? "call-capture-window" : "call-capture-bar"}
    >
      <div className="flex min-w-0 items-center gap-3">
        <div className="flex shrink-0 items-center gap-2 rounded-full bg-destructive/10 px-2.5 py-1 text-xs font-semibold text-destructive">
          <span className="h-2 w-2 animate-pulse rounded-full bg-destructive" />
          CAPTURING
        </div>
        <span
          className="font-mono text-sm tabular-nums"
          data-testid="call-capture-duration"
          title={`Call duration ${formatDuration(snapshot.elapsed_ms)}`}
        >
          {formatDuration(snapshot.elapsed_ms)}
        </span>
        {snapshot.degraded_reasons.length > 0 ? (
          <div className="flex min-w-0 items-center gap-1 text-xs text-destructive">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            <span className="truncate">
              {snapshot.degraded_reasons.join(", ")}
            </span>
          </div>
        ) : (
          <span className="min-w-0 truncate text-xs text-muted-foreground">
            Raw audio stays on this PC
          </span>
        )}
        <Button
          className="ml-auto shrink-0"
          data-testid="call-capture-stop"
          disabled={stopping}
          onClick={onStop}
          size="sm"
          type="button"
          variant="destructive"
        >
          <Square className="h-3 w-3 fill-current" />
          {stopping ? "Stopping…" : "Stop"}
        </Button>
      </div>
      <div className="flex gap-4">
        <SourceMeter
          icon={<Mic className="h-3.5 w-3.5" />}
          label={microphone}
          source={snapshot.microphone_source}
        />
        <SourceMeter
          icon={<Headphones className="h-3.5 w-3.5" />}
          label={output}
          source={snapshot.output_source}
        />
      </div>
      <LiveContext suggestions={suggestions} transcript={transcript} />
      {error ? (
        <p className="truncate text-xs text-destructive" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
