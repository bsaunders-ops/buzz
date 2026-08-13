import { openUrl } from "@tauri-apps/plugin-opener";

import { relayClient } from "@/shared/api/relayClient";
import { invokeTauri, signRelayEvent } from "@/shared/api/tauri";
import type { RelayEvent } from "@/shared/api/types";
import {
  KIND_CORE_EVIDENCE_RESOLVE_REQUEST,
  KIND_CORE_EVIDENCE_RESOLVE_RESULT,
} from "@/shared/constants/kinds";

const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const PUBKEY = HEX_64;
const EVIDENCE_RESOLVER =
  /^evidence:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const RESULT_STATUSES = new Set(["resolved", "denied", "stale", "unavailable"]);
const SOURCE_TYPES = new Set([
  "email",
  "calendar_event",
  "document",
  "spreadsheet",
  "presentation",
  "crm_record",
  "crm_transcript",
  "buzz_event",
  "public_web",
]);
const MAX_UNIX_SECONDS = 253_402_300_799;
const REQUEST_TTL_SECONDS = 60;
const DEFAULT_UI_TIMEOUT_MS = 10_000;
const BIDI_CONTROL = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;

function decryptEvidenceResolutionEvent(
  eventJson: string,
  expectedRelayPubkey: string,
): Promise<string> {
  return invokeTauri<string>("decrypt_evidence_resolution_event", {
    eventJson,
    expectedRelayPubkey,
  });
}

type NonResolvedResult = { status: "denied" | "stale" | "unavailable" };
type ResolvedResult = {
  status: "resolved";
  title: string;
  modifiedAt: number;
  sourceType: string;
  url: string;
};
export type EvidenceResolveResult = NonResolvedResult | ResolvedResult;

export type EvidenceResolutionInput = {
  insightId: string;
  channelId: string;
  ownerPubkey: string;
  relaySelfPubkey: string;
  resolverId: string;
  sourceHash: string;
};

type EvidenceResolutionDependencies = {
  nowSeconds?: () => number;
  randomUuid?: () => string;
  randomNonceHex?: () => string;
  timeoutMs?: number;
  subscribe?: (
    filter: {
      kinds: number[];
      "#p": string[];
      "#h": string[];
      limit: number;
      since: number;
    },
    onEvent: (event: RelayEvent) => void,
  ) => Promise<() => void | Promise<void>>;
  signEvent?: typeof signRelayEvent;
  publishEvent?: (event: RelayEvent) => Promise<unknown>;
  decryptResolutionEvent?: (
    eventJson: string,
    expectedRelayPubkey: string,
  ) => Promise<string>;
  openUrl?: (url: string) => Promise<void>;
};

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]) {
  const actual = Object.keys(value);
  return (
    actual.length === keys.length && actual.every((key) => keys.includes(key))
  );
}

function isSafeText(value: unknown, maximum: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    ![...value].some((character) => {
      const point = character.codePointAt(0) ?? 0;
      return (
        point <= 0x1f ||
        (point >= 0x7f && point <= 0x9f) ||
        BIDI_CONTROL.test(character)
      );
    })
  );
}

/** Strictly parse a relay-decrypted evidence resolution result. */
export function parseEvidenceResolveResult(
  plaintext: string,
  expectedRequestId: string,
  nowSeconds: number,
): EvidenceResolveResult | null {
  let value: unknown;
  try {
    value = JSON.parse(plaintext);
  } catch {
    return null;
  }
  if (
    !isObject(value) ||
    value.schema_version !== 1 ||
    value.request_id !== expectedRequestId ||
    !UUID_V4.test(expectedRequestId) ||
    typeof value.status !== "string" ||
    !RESULT_STATUSES.has(value.status) ||
    typeof value.expires_at !== "number" ||
    !Number.isSafeInteger(value.expires_at) ||
    value.expires_at <= nowSeconds ||
    value.expires_at > MAX_UNIX_SECONDS ||
    value.expires_at > nowSeconds + REQUEST_TTL_SECONDS
  ) {
    return null;
  }

  if (value.status !== "resolved") {
    if (
      !hasExactKeys(value, [
        "schema_version",
        "request_id",
        "status",
        "expires_at",
      ])
    ) {
      return null;
    }
    return { status: value.status as NonResolvedResult["status"] };
  }

  if (
    !hasExactKeys(value, [
      "schema_version",
      "request_id",
      "status",
      "expires_at",
      "title",
      "modified_at",
      "source_type",
      "url",
    ]) ||
    !isSafeText(value.title, 256) ||
    typeof value.modified_at !== "number" ||
    !Number.isSafeInteger(value.modified_at) ||
    value.modified_at < 0 ||
    value.modified_at > MAX_UNIX_SECONDS ||
    typeof value.source_type !== "string" ||
    !SOURCE_TYPES.has(value.source_type) ||
    !isSafeText(value.url, 2048)
  ) {
    return null;
  }

  return {
    status: "resolved",
    title: value.title,
    modifiedAt: value.modified_at,
    sourceType: value.source_type,
    url: value.url,
  };
}

/** Allow only credential-free HTTPS links for the approved Month-1 providers. */
export function isAllowedEvidenceUrl(rawUrl: string) {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.port !== "" ||
    url.hash !== ""
  ) {
    return false;
  }

  const host = url.hostname.toLowerCase();
  if (
    new Set([
      "crm.coreadvs.com",
      "drive.google.com",
      "docs.google.com",
      "sheets.google.com",
      "slides.google.com",
      "outlook.office.com",
      "outlook.office365.com",
    ]).has(host)
  ) {
    return true;
  }
  const labels = host.split(".");
  return (
    labels.length === 3 &&
    labels[1] === "sharepoint" &&
    labels[2] === "com" &&
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(labels[0])
  );
}

function randomNonceHex() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hasExactPrivateTags(
  event: RelayEvent,
  channelId: string,
  ownerPubkey: string,
) {
  return (
    event.tags.length === 2 &&
    event.tags[0]?.length === 2 &&
    event.tags[0]?.[0] === "h" &&
    event.tags[0]?.[1] === channelId &&
    event.tags[1]?.length === 2 &&
    event.tags[1]?.[0] === "p" &&
    event.tags[1]?.[1]?.toLowerCase() === ownerPubkey
  );
}

/** Resolve one citation through the authenticated relay and open it on success. */
export async function resolveEvidenceSource(
  input: EvidenceResolutionInput,
  dependencies: EvidenceResolutionDependencies = {},
) {
  const ownerPubkey = input.ownerPubkey.toLowerCase();
  const relaySelfPubkey = input.relaySelfPubkey.toLowerCase();
  if (
    !UUID_V4.test(input.insightId) ||
    !UUID_V4.test(input.channelId) ||
    !PUBKEY.test(ownerPubkey) ||
    !PUBKEY.test(relaySelfPubkey) ||
    !EVIDENCE_RESOLVER.test(input.resolverId) ||
    !HEX_64.test(input.sourceHash)
  ) {
    return false;
  }

  const now = dependencies.nowSeconds?.() ?? Math.floor(Date.now() / 1_000);
  const requestId = dependencies.randomUuid?.() ?? crypto.randomUUID();
  const nonce = dependencies.randomNonceHex?.() ?? randomNonceHex();
  if (!UUID_V4.test(requestId) || !HEX_64.test(nonce)) return false;

  const subscribe =
    dependencies.subscribe ??
    ((filter, onEvent) => relayClient.subscribeLive(filter, onEvent));
  const signEvent = dependencies.signEvent ?? signRelayEvent;
  const publishEvent =
    dependencies.publishEvent ??
    ((event) =>
      relayClient.publishEvent(
        event,
        "Timed out requesting the source.",
        "Failed to request the source.",
      ));
  const decrypt =
    dependencies.decryptResolutionEvent ?? decryptEvidenceResolutionEvent;
  const opener = dependencies.openUrl ?? openUrl;

  let settle: (value: boolean) => void = () => {};
  const resolved = new Promise<boolean>((resolve) => {
    settle = resolve;
  });
  let finished = false;
  let responseClaimed = false;
  let timeout: ReturnType<typeof globalThis.setTimeout> | null = null;
  let unsubscribe: () => void | Promise<void> = () => {};
  const finish = (value: boolean) => {
    if (finished) return;
    finished = true;
    settle(value);
  };

  try {
    unsubscribe = await subscribe(
      {
        kinds: [KIND_CORE_EVIDENCE_RESOLVE_RESULT],
        "#p": [ownerPubkey],
        "#h": [input.channelId],
        limit: 0,
        since: now,
      },
      (event) => {
        if (
          finished ||
          responseClaimed ||
          event.kind !== KIND_CORE_EVIDENCE_RESOLVE_RESULT ||
          event.pubkey.toLowerCase() !== relaySelfPubkey ||
          !hasExactPrivateTags(event, input.channelId, ownerPubkey)
        ) {
          return;
        }
        void decrypt(JSON.stringify(event), relaySelfPubkey)
          .then(async (plaintext) => {
            const result = parseEvidenceResolveResult(
              plaintext,
              requestId,
              dependencies.nowSeconds?.() ?? Math.floor(Date.now() / 1_000),
            );
            if (!result || finished || responseClaimed) return;
            if (result.status !== "resolved") {
              responseClaimed = true;
              finish(false);
              return;
            }
            if (!isAllowedEvidenceUrl(result.url)) return;
            responseClaimed = true;
            if (timeout !== null) globalThis.clearTimeout(timeout);
            try {
              await opener(result.url);
              finish(true);
            } catch {
              finish(false);
            }
          })
          .catch(() => {
            // Invalid or undecryptable events are ignored until timeout.
          });
      },
    );

    timeout = globalThis.setTimeout(() => {
      if (!responseClaimed) finish(false);
    }, dependencies.timeoutMs ?? DEFAULT_UI_TIMEOUT_MS);
    const event = await signEvent({
      kind: KIND_CORE_EVIDENCE_RESOLVE_REQUEST,
      tags: [
        ["h", input.channelId],
        ["p", relaySelfPubkey],
      ],
      createdAt: now,
      content: JSON.stringify({
        schema_version: 1,
        request_id: requestId,
        insight_id: input.insightId,
        resolver_id: input.resolverId,
        expected_chunk_hash: input.sourceHash,
        nonce,
        created_at: now,
        expires_at: now + REQUEST_TTL_SECONDS,
      }),
    });
    await publishEvent(event);
    return await resolved;
  } catch {
    finish(false);
    return false;
  } finally {
    if (timeout !== null) globalThis.clearTimeout(timeout);
    try {
      await unsubscribe();
    } catch {
      // Resolution is already settled; relay teardown cannot authorize a URL.
    }
  }
}
