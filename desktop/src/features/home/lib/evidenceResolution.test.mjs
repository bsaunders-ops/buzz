import assert from "node:assert/strict";
import test from "node:test";

import {
  isAllowedEvidenceUrl,
  parseEvidenceResolveResult,
  resolveEvidenceSource,
} from "./evidenceResolution.ts";

const OWNER = "1".repeat(64);
const RELAY = "2".repeat(64);
const CHANNEL = "550e8400-e29b-41d4-a716-446655440099";
const INSIGHT_ID = "550e8400-e29b-41d4-a716-446655440000";
const REQUEST_ID = "550e8400-e29b-41d4-a716-446655440010";
const RESOLVER_ID = "evidence:550e8400-e29b-41d4-a716-446655440001";
const SOURCE_HASH = "a".repeat(64);

function resolvedPayload(overrides = {}) {
  return {
    schema_version: 1,
    request_id: REQUEST_ID,
    status: "resolved",
    expires_at: 1_700_000_050,
    title: "Acme relationship record",
    modified_at: 1_700_000_000,
    source_type: "crm_record",
    url: "https://crm.coreadvs.com/contacts/123",
    ...overrides,
  };
}

test("strictly accepts resolved and non-resolved result shapes", () => {
  assert.equal(
    parseEvidenceResolveResult(
      JSON.stringify(resolvedPayload()),
      REQUEST_ID,
      1_700_000_001,
    )?.status,
    "resolved",
  );
  assert.deepEqual(
    parseEvidenceResolveResult(
      JSON.stringify({
        schema_version: 1,
        request_id: REQUEST_ID,
        status: "denied",
        expires_at: 1_700_000_050,
      }),
      REQUEST_ID,
      1_700_000_001,
    ),
    { status: "denied" },
  );

  for (const invalid of [
    resolvedPayload({ request_id: crypto.randomUUID() }),
    resolvedPayload({ expires_at: 1_700_000_000 }),
    resolvedPayload({ expires_at: 1_700_000_062 }),
    resolvedPayload({ extra: "fail closed" }),
    { ...resolvedPayload(), status: "denied" },
    {
      schema_version: 1,
      request_id: REQUEST_ID,
      status: "resolved",
      expires_at: 1_700_000_050,
    },
  ]) {
    assert.equal(
      parseEvidenceResolveResult(
        JSON.stringify(invalid),
        REQUEST_ID,
        1_700_000_001,
      ),
      null,
    );
  }
});

test("allows only credential-free HTTPS Core provider URLs", () => {
  for (const url of [
    "https://crm.coreadvs.com/contacts/1",
    "https://drive.google.com/drive/u/0/folders/1",
    "https://docs.google.com/document/d/1",
    "https://sheets.google.com/spreadsheets/d/1",
    "https://slides.google.com/presentation/d/1",
    "https://outlook.office.com/mail/inbox/id/1",
    "https://outlook.office365.com/mail/inbox/id/1",
    "https://coreadvisors.sharepoint.com/sites/Core/file.pdf",
  ]) {
    assert.equal(isAllowedEvidenceUrl(url), true, url);
  }
  for (const url of [
    "http://crm.coreadvs.com/contacts/1",
    "https://crm.coreadvs.com:444/contacts/1",
    "https://user@crm.coreadvs.com/contacts/1",
    "https://crm.coreadvs.com/contacts/1#secret",
    "https://crm.coreadvs.com.evil.example/contacts/1",
    "https://nested.coreadvisors.sharepoint.com/",
    "https://sharepoint.com/",
  ]) {
    assert.equal(isAllowedEvidenceUrl(url), false, url);
  }
});

function responseEvent(overrides = {}) {
  return {
    id: "3".repeat(64),
    pubkey: RELAY,
    created_at: 1_700_000_001,
    kind: 24824,
    tags: [
      ["h", CHANNEL],
      ["p", OWNER],
    ],
    content: "ciphertext",
    sig: "4".repeat(128),
    ...overrides,
  };
}

function harness({
  event = responseEvent(),
  plaintext,
  emit = true,
  emitCount = 1,
  openDelayMs = 0,
  subscribeError = false,
} = {}) {
  const calls = {
    filters: [],
    signed: [],
    published: [],
    decrypted: [],
    opened: [],
  };
  let onEvent;
  const deps = {
    nowSeconds: () => 1_700_000_000,
    randomUuid: () => REQUEST_ID,
    randomNonceHex: () => "b".repeat(64),
    subscribe: async (filter, callback) => {
      if (subscribeError) throw new Error("subscription failed");
      calls.filters.push(filter);
      onEvent = callback;
      return async () => {};
    },
    signEvent: async (input) => {
      calls.signed.push(input);
      return {
        ...responseEvent(),
        id: "5".repeat(64),
        pubkey: OWNER,
        ...input,
        created_at: input.createdAt,
      };
    },
    publishEvent: async (signed) => {
      calls.published.push(signed);
      if (emit) {
        queueMicrotask(() => {
          for (let index = 0; index < emitCount; index += 1) onEvent?.(event);
        });
      }
      return signed;
    },
    decryptResolutionEvent: async (candidate, expectedRelayPubkey) => {
      calls.decrypted.push({ candidate, expectedRelayPubkey });
      return plaintext ?? JSON.stringify(resolvedPayload());
    },
    openUrl: async (url) => {
      if (openDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, openDelayMs));
      }
      calls.opened.push(url);
    },
  };
  return { calls, deps };
}

test("subscribes before publishing an exact signed request and opens only the resolved URL", async () => {
  const { calls, deps } = harness();
  const opened = await resolveEvidenceSource(
    {
      insightId: INSIGHT_ID,
      channelId: CHANNEL,
      ownerPubkey: OWNER,
      relaySelfPubkey: RELAY,
      resolverId: RESOLVER_ID,
      sourceHash: SOURCE_HASH,
    },
    deps,
  );

  assert.equal(opened, true);
  assert.deepEqual(calls.filters, [
    {
      kinds: [24824],
      "#p": [OWNER],
      "#h": [CHANNEL],
      limit: 0,
      since: 1_700_000_000,
    },
  ]);
  assert.equal(calls.signed.length, 1);
  const request = JSON.parse(calls.signed[0].content);
  assert.deepEqual(Object.keys(request).sort(), [
    "created_at",
    "expected_chunk_hash",
    "expires_at",
    "insight_id",
    "nonce",
    "request_id",
    "resolver_id",
    "schema_version",
  ]);
  assert.deepEqual(request, {
    schema_version: 1,
    request_id: REQUEST_ID,
    insight_id: INSIGHT_ID,
    resolver_id: RESOLVER_ID,
    expected_chunk_hash: SOURCE_HASH,
    nonce: "b".repeat(64),
    created_at: 1_700_000_000,
    expires_at: 1_700_000_060,
  });
  assert.deepEqual(calls.signed[0].tags, [
    ["h", CHANNEL],
    ["p", RELAY],
  ]);
  assert.equal(calls.signed[0].kind, 24823);
  assert.deepEqual(calls.decrypted[0].expectedRelayPubkey, RELAY);
  assert.deepEqual(calls.opened, ["https://crm.coreadvs.com/contacts/123"]);
});

test("claims one valid response before opening and does not race the UI timeout", async () => {
  const { calls, deps } = harness({ emitCount: 2, openDelayMs: 10 });
  const opened = await resolveEvidenceSource(
    {
      insightId: INSIGHT_ID,
      channelId: CHANNEL,
      ownerPubkey: OWNER,
      relaySelfPubkey: RELAY,
      resolverId: RESOLVER_ID,
      sourceHash: SOURCE_HASH,
    },
    { ...deps, timeoutMs: 5 },
  );

  assert.equal(opened, true);
  assert.deepEqual(calls.opened, ["https://crm.coreadvs.com/contacts/123"]);
});

test("subscription failure returns false without publishing or opening", async () => {
  const { calls, deps } = harness({ subscribeError: true });
  const opened = await resolveEvidenceSource(
    {
      insightId: INSIGHT_ID,
      channelId: CHANNEL,
      ownerPubkey: OWNER,
      relaySelfPubkey: RELAY,
      resolverId: RESOLVER_ID,
      sourceHash: SOURCE_HASH,
    },
    deps,
  );
  assert.equal(opened, false);
  assert.deepEqual(calls.published, []);
  assert.deepEqual(calls.opened, []);
});

test("invalid request context fails before subscribing", async () => {
  const invalidInputs = [
    { channelId: "not-a-channel" },
    { ownerPubkey: "not-a-pubkey" },
    { relaySelfPubkey: "not-a-pubkey" },
    { resolverId: "evidence:not-a-uuid" },
    { sourceHash: "not-a-hash" },
  ];

  for (const overrides of invalidInputs) {
    const { calls, deps } = harness();
    const opened = await resolveEvidenceSource(
      {
        insightId: INSIGHT_ID,
        channelId: CHANNEL,
        ownerPubkey: OWNER,
        relaySelfPubkey: RELAY,
        resolverId: RESOLVER_ID,
        sourceHash: SOURCE_HASH,
        ...overrides,
      },
      deps,
    );
    assert.equal(opened, false);
    assert.deepEqual(calls.filters, []);
  }
});

test("forged, mismatched, expired, denied, stale, unavailable, invalid URL, and timeout responses open nothing", async () => {
  const cases = [
    harness({ event: responseEvent({ pubkey: "9".repeat(64) }) }),
    harness({ event: responseEvent({ kind: 1 }) }),
    harness({
      event: responseEvent({
        tags: [
          ["h", "wrong"],
          ["p", OWNER],
        ],
      }),
    }),
    harness({
      event: responseEvent({
        tags: [
          ["h", CHANNEL],
          ["p", OWNER],
          ["x", "unexpected"],
        ],
      }),
    }),
    harness({
      plaintext: JSON.stringify(
        resolvedPayload({ request_id: crypto.randomUUID() }),
      ),
    }),
    harness({
      plaintext: JSON.stringify(resolvedPayload({ expires_at: 1_700_000_000 })),
    }),
    harness({
      plaintext: JSON.stringify({
        schema_version: 1,
        request_id: REQUEST_ID,
        status: "denied",
        expires_at: 1_700_000_050,
      }),
    }),
    harness({
      plaintext: JSON.stringify({
        schema_version: 1,
        request_id: REQUEST_ID,
        status: "stale",
        expires_at: 1_700_000_050,
      }),
    }),
    harness({
      plaintext: JSON.stringify({
        schema_version: 1,
        request_id: REQUEST_ID,
        status: "unavailable",
        expires_at: 1_700_000_050,
      }),
    }),
    harness({
      plaintext: JSON.stringify(
        resolvedPayload({ url: "https://evil.example/private" }),
      ),
    }),
    harness({ emit: false }),
  ];

  for (const { calls, deps } of cases) {
    const opened = await resolveEvidenceSource(
      {
        insightId: INSIGHT_ID,
        channelId: CHANNEL,
        ownerPubkey: OWNER,
        relaySelfPubkey: RELAY,
        resolverId: RESOLVER_ID,
        sourceHash: SOURCE_HASH,
      },
      { ...deps, timeoutMs: 5 },
    );
    assert.equal(opened, false);
    assert.deepEqual(calls.opened, []);
  }
});
