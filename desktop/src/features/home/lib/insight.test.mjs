import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { InsightCard } from "../ui/InsightCard.tsx";
import { parseInsightPayload } from "./insight.ts";

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
      },
      {
        source: "public_web",
        source_id: "article:public-456",
        source_hash:
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        citation: {
          title: "Q2 market report",
          resolver_id: "citation:report-789",
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
    category: "deal_movement",
    priority: "high",
    change: "The buyer asked for revised terms",
    whyItMatters: "The decision window closes Friday",
    evidence: [
      { source: "crm", citation: null },
      { source: "public_web", citation: { title: "Q2 market report" } },
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

test("rejects malformed and future insight payloads without partial parsing", () => {
  const malformed = [
    validPayload({ schema_version: 2 }),
    validPayload({ category: "future_category" }),
    validPayload({ priority: "future_priority" }),
    validPayload({ freshness: "future_freshness" }),
    validPayload({ unexpected: "unknown fields must fail closed" }),
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

  assert.match(visibleText, /CRM record/);
  assert.match(visibleText, /Public web research: Q2 market report/);
  assert.match(visibleText, /Confidence/);
  assert.match(visibleText, /Freshness/);
  assert.match(visibleText, /Recommendation/);
  assert.match(visibleText, /Suggested draft/);
  assert.ok(!html.includes("contact:private-123"));
  assert.ok(!html.includes("article:public-456"));
  assert.ok(!html.includes("citation:report-789"));
  assert.ok(!html.includes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
  assert.ok(!html.includes(rawPayload));
  assert.ok(!html.includes("href="));
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
