import { Headphones, Mic, ShieldCheck } from "lucide-react";
import * as React from "react";

import { Button } from "@/shared/ui/button";
import { Checkbox } from "@/shared/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";

import {
  acknowledgeCallCaptureConsent,
  startCallCapture,
  stopCallCapture,
} from "./api";
import { CallCaptureBar } from "./CallCaptureBar";
import type { CallCaptureDevice } from "./types";
import { useCallCaptureSession } from "./useCallCaptureSession";

function chooseDefault(
  devices: CallCaptureDevice[],
  kind: "microphone" | "output",
) {
  const matches = devices.filter((device) => device.kind === kind);
  return (
    matches.find((device) => device.is_default)?.id ?? matches[0]?.id ?? ""
  );
}

function toMessage(error: unknown, fallback: string) {
  if (error instanceof Error && error.message.trim()) return error.message;
  if (typeof error === "string" && error.trim()) return error;
  return fallback;
}

export function CoreCallCapture() {
  const session = useCallCaptureSession({ ownsRelayTransport: true });
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [microphoneId, setMicrophoneId] = React.useState("");
  const [outputId, setOutputId] = React.useState("");
  const [consentAcknowledged, setConsentAcknowledged] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  const microphones = session.devices.filter(
    (device) => device.kind === "microphone",
  );
  const outputs = session.devices.filter((device) => device.kind === "output");

  const openDialog = React.useCallback(() => {
    session.setError(null);
    setConsentAcknowledged(false);
    setDialogOpen(true);
    void session
      .refreshDevices()
      .then((devices) => {
        setMicrophoneId(chooseDefault(devices, "microphone"));
        setOutputId(chooseDefault(devices, "output"));
      })
      .catch(() => undefined);
  }, [session.refreshDevices, session.setError]);

  const start = React.useCallback(async () => {
    if (!consentAcknowledged || !microphoneId || !outputId) return;
    session.setError(null);
    setBusy(true);
    try {
      const consent = await acknowledgeCallCaptureConsent({
        microphoneId,
        outputId,
      });
      const snapshot = await startCallCapture({
        microphoneId,
        outputId,
        consentToken: consent.token,
      });
      session.updateSnapshot(snapshot);
      setDialogOpen(false);
      setConsentAcknowledged(false);
    } catch (error) {
      session.setError(toMessage(error, "Call capture could not start."));
    } finally {
      setBusy(false);
    }
  }, [
    consentAcknowledged,
    microphoneId,
    outputId,
    session.setError,
    session.updateSnapshot,
  ]);

  const stop = React.useCallback(async () => {
    session.setError(null);
    setBusy(true);
    try {
      session.updateSnapshot(await stopCallCapture());
    } catch (error) {
      session.setError(
        toMessage(error, "Call capture could not stop cleanly."),
      );
    } finally {
      setBusy(false);
    }
  }, [session.setError, session.updateSnapshot]);

  if (session.snapshot.phase === "disabled") return null;

  return (
    <>
      {session.snapshot.phase === "active" ? (
        <CallCaptureBar
          devices={session.devices}
          error={session.error}
          onStop={() => void stop()}
          snapshot={session.snapshot}
          stopping={busy}
          suggestions={session.suggestions}
          transcript={session.transcript}
        />
      ) : (
        <Button
          className="fixed bottom-4 right-4 z-40 shadow-lg"
          data-testid="call-capture-open"
          onClick={openDialog}
          type="button"
          variant="secondary"
        >
          <Mic className="h-4 w-4" />
          Call copilot
        </Button>
      )}

      <Dialog
        onOpenChange={(open) => {
          if (!busy) {
            setDialogOpen(open);
            if (!open) setConsentAcknowledged(false);
          }
        }}
        open={dialogOpen}
      >
        <DialogContent className="max-w-lg" data-testid="call-capture-dialog">
          <DialogHeader>
            <DialogTitle>Start Core call copilot</DialogTitle>
            <DialogDescription>
              Choose the exact Windows endpoints to capture. Capture starts only
              after this call&apos;s consent acknowledgment.
            </DialogDescription>
          </DialogHeader>

          <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
            <div className="flex items-start gap-2">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-amber-700 dark:text-amber-300" />
              <p data-testid="call-capture-output-warning">
                Buzz captures your microphone and all audio playing through the
                selected Windows output endpoint. Unrelated sounds on that
                endpoint will be included. Raw audio stays in memory and is
                never written to disk.
              </p>
            </div>
          </div>

          <div className="grid gap-3">
            <label className="grid gap-1.5 text-sm" htmlFor="call-microphone">
              <span className="flex items-center gap-1.5 font-medium">
                <Mic className="h-4 w-4" />
                Microphone
              </span>
              <select
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm outline-hidden focus-visible:ring-1 focus-visible:ring-ring"
                data-testid="call-capture-microphone"
                disabled={busy}
                id="call-microphone"
                onChange={(event) => {
                  setMicrophoneId(event.target.value);
                  setConsentAcknowledged(false);
                }}
                value={microphoneId}
              >
                {microphones.map((device) => (
                  <option key={device.id} value={device.id}>
                    {device.label}
                    {device.is_default ? " (Windows default)" : ""}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1.5 text-sm" htmlFor="call-output">
              <span className="flex items-center gap-1.5 font-medium">
                <Headphones className="h-4 w-4" />
                Windows output endpoint
              </span>
              <select
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm outline-hidden focus-visible:ring-1 focus-visible:ring-ring"
                data-testid="call-capture-output"
                disabled={busy}
                id="call-output"
                onChange={(event) => {
                  setOutputId(event.target.value);
                  setConsentAcknowledged(false);
                }}
                value={outputId}
              >
                {outputs.map((device) => (
                  <option key={device.id} value={device.id}>
                    {device.label}
                    {device.is_default ? " (Windows default)" : ""}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className="flex items-start gap-2 text-sm">
            <Checkbox
              checked={consentAcknowledged}
              data-testid="call-capture-consent"
              disabled={busy}
              id="call-capture-consent"
              onCheckedChange={(checked) =>
                setConsentAcknowledged(checked === true)
              }
            />
            <label className="cursor-pointer" htmlFor="call-capture-consent">
              I confirm everyone on this call has consented to transcription,
              and I understand unrelated sounds on the selected output endpoint
              are included.
            </label>
          </div>

          {session.error ? (
            <p className="text-sm text-destructive" role="alert">
              {session.error}
            </p>
          ) : null}

          <DialogFooter>
            <Button
              disabled={busy}
              onClick={() => setDialogOpen(false)}
              type="button"
              variant="outline"
            >
              Cancel
            </Button>
            <Button
              data-testid="call-capture-start"
              disabled={
                busy ||
                !consentAcknowledged ||
                !microphoneId ||
                !outputId ||
                microphones.length === 0 ||
                outputs.length === 0
              }
              onClick={() => void start()}
              type="button"
            >
              {busy ? "Starting…" : "Start capture"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
