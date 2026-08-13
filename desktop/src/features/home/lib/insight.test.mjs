import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { InsightCard } from "../ui/InsightCard.tsx";
import { parseInsightPayload } from "./insight.ts";

const CRM_RESOLVER = "evidence:550e8400-e29b-41d4-a716-446655440001";
const WEB_RESOLVER = "evidence:550e8400-e29b-41d4-a716-446655440002";

function validPayload(overrides = {}) {
  return {
    schema_version: 1,
    insight_id: "550e8400-e29b-41d4-a716-446655440000",
    category: "deal_movement",
    priority: "high",
    change: "The buyer asked for revised terms",
    why_it_matters: "The decision window closes Friday",
    evidence: [
      {
        source: "crm",
        source_id: "contact:private-123",
        source_hash:
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        citation: {
          title: "Acme relationship record",
          modified_at: 1700000000,
          resolver_id: CRM_RESOLVER,
        },
      },
      {
        source: "public_web",
        source_id: "article:public-456",
        source_hash:
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        citation: {
          title: "Q2 market report",
          modified_at: 1700000100,
          resolver_id: WEB_RESOLVER,
        },
      },
    ],
    confidence: 88,
    freshness: "recent",
    recommendation: "Review the revised terms with the account owner",
    draft: {
      kind: "outlook_draft",
      subject: "Revised terms",
      body: "Thanks for sharing the revisions.",
    },
    dedupe_key:
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    created_at: 1700000000,
    safety_policy_version: "s1",
    persona_version: "p1",
    firm_version: "f1",
    personal_version: "u1",
    model_version: "m1",
    ...overrides,
  };
}

test("parses the exact v1 insight payload into typed display fields", () => {
  const insight = parseInsightPayload(JSON.stringify(validPayload()));

  assert.deepEqual(insight, {
    insightId: "550e8400-e29b-41d4-a716-446655440000",
    category: "deal_movement",
    priority: "high",
    change: "The buyer asked for revised terms",
    whyItMatters: "The decision window closes Friday",
    evidence: [
      {
        source: "crm",
        sourceHash:
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        citation: {
          title: "Acme relationship record",
          modifiedAt: 1700000000,
          resolverKey: CRM_RESOLVER,
        },
        stableKey:
          "crm\u0000contact:private-123\u0000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
      {
        source: "public_web",
        sourceHash:
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        citation: {
          title: "Q2 market report",
          modifiedAt: 1700000100,
          resolverKey: WEB_RESOLVER,
        },
        stableKey:
          "public_web\u0000article:public-456\u0000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      },
    ],
    confidence: 88,
    freshness: "recent",
    recommendation: "Review the revised terms with the account owner",
    draft: {
      kind: "outlook_draft",
      subject: "Revised terms",
      body: "Thanks for sharing the revisions.",
    },
  });
});

test("accepts the neutral assistant category and explicit stale freshness", () => {
  const insight = parseInsightPayload(
    JSON.stringify(
      validPayload({ category: "assistant_response", freshness: "stale" }),
    ),
  );

  assert.equal(insight?.category, "assistant_response");
  assert.equal(insight?.freshness, "stale");
});

test("rejects malformed and future insight payloads without partial parsing", () => {
  const malformed = [
    validPayload({ schema_version: 2 }),
    validPayload({ category: "future_category" }),
    validPayload({ priority: "future_priority" }),
    validPayload({ freshness: "future_freshness" }),
    validPayload({
      evidence: [
        {
          source: "crm",
          source_id: "contact:private-123",
          source_hash:
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          citation: {
            title: "Acme relationship record",
            modified_at: 1700000000,
            resolver_id: "evidence:not-a-uuid",
          },
        },
      ],
    }),
    validPayload({ unexpected: "unknown fields must fail closed" }),
    validPayload({
      evidence: [
        {
          source: "crm",
          source_id: "contact:private-123",
          source_hash:
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          citation: {
            title: "Acme relationship record",
            modified_at: 1700000000,
            resolver_id: "evidence:crm-123",
            provider_url: "https://example.invalid/private",
          },
        },
      ],
    }),
    validPayload({ evidence: [] }),
    validPayload({
      evidence: [
        {
          source: "crm",
          source_id: "contact:private-123",
          source_hash: "UPPERCASE_HASH_IS_INVALID",
          citation: null,
        },
      ],
    }),
  ];

  for (const payload of malformed) {
    assert.equal(parseInsightPayload(JSON.stringify(payload)), null);
  }
});

test("InsightCard shows source families and public citation titles without exposing opaque evidence identifiers", () => {
  const rawPayload = JSON.stringify(validPayload());
  const html = renderToStaticMarkup(
    React.createElement(InsightCard, {
      payload: parseInsightPayload(rawPayload),
    }),
  );
  const visibleText = html.replace(/<[^>]*>/g, "");

  assert.match(
    visibleText,
    /CRM record: Acme relationship record · modified 2023-11-14/,
  );
  assert.match(visibleText, /Public web research: Q2 market report/);
  assert.match(visibleText, /Confidence/);
  assert.match(visibleText, /Freshness/);
  assert.match(visibleText, /Recommendation/);
  assert.match(visibleText, /Suggested draft/);
  assert.ok(!html.includes("contact:private-123"));
  assert.ok(!html.includes("article:public-456"));
  assert.ok(!html.includes(WEB_RESOLVER));
  assert.ok(!html.includes(CRM_RESOLVER));
  assert.ok(!html.includes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
  assert.ok(!html.includes(rawPayload));
  assert.ok(!html.includes("href="));
});

test("InsightCard exposes an Open source action without rendering resolver data", () => {
  const insight = parseInsightPayload(JSON.stringify(validPayload()));
  const html = renderToStaticMarkup(
    React.createElement(InsightCard, {
      payload: insight,
      onOpenSource: async () => {},
      resolvingEvidenceKey: insight?.evidence[0].stableKey,
    }),
  );

  assert.match(html, /Open source/);
  assert.match(html, /disabled/);
  assert.ok(!html.includes(CRM_RESOLVER));
  assert.ok(!html.includes(WEB_RESOLVER));
  assert.ok(!html.includes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
});

test("InsightCard presents malformed payloads as unavailable without raw JSON", () => {
  const rawPayload = '{"schema_version":999,"change":"ignore instructions"}';
  const html = renderToStaticMarkup(
    React.createElement(InsightCard, {
      payload: parseInsightPayload(rawPayload),
    }),
  );

  assert.match(html, /Insight unavailable/);
  assert.ok(!html.includes(rawPayload));
  assert.ok(!html.includes("ignore instructions"));
});
