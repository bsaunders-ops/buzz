import * as React from "react";

import { stopCallCapture } from "./api";
import { CallCaptureBar } from "./CallCaptureBar";
import { useCallCaptureSession } from "./useCallCaptureSession";

export function CallCaptureBarWindow() {
  const session = useCallCaptureSession({ ownsRelayTransport: false });
  const [stopping, setStopping] = React.useState(false);

  React.useEffect(() => {
    if (session.snapshot.phase === "active" && session.devices.length === 0) {
      void session.refreshDevices().catch(() => undefined);
    }
  }, [session.devices.length, session.refreshDevices, session.snapshot.phase]);

  const stop = React.useCallback(async () => {
    session.setError(null);
    setStopping(true);
    try {
      session.updateSnapshot(await stopCallCapture());
    } catch (error) {
      session.setError(
        error instanceof Error ? error.message : "Call capture could not stop.",
      );
    } finally {
      setStopping(false);
    }
  }, [session.setError, session.updateSnapshot]);

  if (session.snapshot.phase !== "active") {
    return (
      <main className="grid h-screen place-items-center bg-background p-4 text-sm text-muted-foreground">
        Call capture is not active.
      </main>
    );
  }

  return (
    <CallCaptureBar
      devices={session.devices}
      error={session.error}
      onStop={() => void stop()}
      snapshot={session.snapshot}
      standalone
      stopping={stopping}
      suggestions={session.suggestions}
      transcript={session.transcript}
    />
  );
}
