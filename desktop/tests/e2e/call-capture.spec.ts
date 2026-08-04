import { expect, test } from "@playwright/test";

import { installMockBridge } from "../helpers/bridge";

test("requires fresh consent and keeps the live call copilot visible", async ({
  page,
}) => {
  await installMockBridge(page, { callCaptureEnabled: true });
  await page.goto("/");

  const openButton = page.getByTestId("call-capture-open");
  await expect(openButton).toBeVisible();
  await openButton.click();

  const dialog = page.getByTestId("call-capture-dialog");
  await expect(dialog).toBeVisible();
  await expect(page.getByTestId("call-capture-output-warning")).toContainText(
    "Unrelated sounds on that endpoint will be included",
  );
  await expect(page.getByTestId("call-capture-microphone")).toHaveValue(
    "e2e-microphone",
  );
  await expect(page.getByTestId("call-capture-output")).toHaveValue(
    "e2e-output",
  );

  const startButton = page.getByTestId("call-capture-start");
  await expect(startButton).toBeDisabled();
  await page.getByTestId("call-capture-consent").click();
  await expect(startButton).toBeEnabled();
  await startButton.click();

  const bar = page.getByTestId("call-capture-bar");
  await expect(bar).toBeVisible();
  await expect(bar).toContainText("Core USB Microphone");
  await expect(bar).toContainText("Core Office Speakers");
  await expect(
    bar.getByRole("meter", { name: /microphone level/i }),
  ).toHaveAttribute("aria-valuenow", "38");
  await expect(
    bar.getByRole("meter", { name: /office speakers level/i }),
  ).toHaveAttribute("aria-valuenow", "62");
  await expect(page.getByTestId("call-capture-stop")).toBeVisible();

  await page.evaluate(async () => {
    await window.__BUZZ_E2E_EMIT_CALL_CAPTURE_TRANSCRIPT__?.({
      text: "We will send the revised buyer list tomorrow.",
      speaker: "others",
    });
    await window.__BUZZ_E2E_EMIT_CALL_CAPTURE_SUGGESTION__?.({
      text: "Buyer list due tomorrow",
      category: "decision",
      interrupt: "quiet",
      evidenced: false,
    });
    await window.__BUZZ_E2E_EMIT_CALL_CAPTURE_SUGGESTION__?.({
      text: "The buyer-list owner was not confirmed",
      category: "missed_commitment",
      interrupt: "critical",
      evidenced: true,
    });
  });

  await expect(bar).toContainText(
    "We will send the revised buyer list tomorrow.",
  );
  const quietSuggestion = bar.locator('[data-interrupt="quiet"]');
  await expect(quietSuggestion).toContainText("Buyer list due tomorrow");
  await expect(quietSuggestion).not.toHaveAttribute("role", "alert");
  const criticalSuggestion = bar.locator('[data-interrupt="critical"]');
  await expect(criticalSuggestion).toHaveAttribute("role", "alert");
  await expect(criticalSuggestion).toContainText(
    "The buyer-list owner was not confirmed",
  );

  const notifications = await page.evaluate(
    () => window.__BUZZ_E2E_NOTIFICATIONS__ ?? [],
  );
  expect(notifications).toEqual([]);

  await page.getByTestId("call-capture-stop").click();
  await expect(bar).toBeHidden();
  await expect(openButton).toBeVisible();

  await openButton.click();
  await expect(startButton).toBeDisabled();
});
