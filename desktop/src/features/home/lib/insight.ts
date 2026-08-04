const INSIGHT_FIELDS = [
  "schema_version",
  "insight_id",
  "category",
  "priority",
  "change",
  "why_it_matters",
  "evidence",
  "confidence",
  "freshness",
  "recommendation",
  "draft",
  "dedupe_key",
  "created_at",
  "safety_policy_version",
  "persona_version",
  "firm_version",
  "personal_version",
  "model_version",
] as const;

const INSIGHT_CATEGORIES = new Set([
  "commitment_deadline",
  "deal_movement",
  "meeting_movement",
  "relationship_opportunity",
]);
const INSIGHT_PRIORITIES = new Set(["low", "normal", "high", "urgent"]);
const INSIGHT_FRESHNESS = new Set(["realtime", "same_day", "recent"]);
const EVIDENCE_SOURCES = new Set([
  "crm",
  "outlook",
  "calendar",
  "one_drive",
  "google_drive",
  "granola",
  "buzz_event",
  "public_web",
]);
const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA_256 = /^[0-9a-f]{64}$/;
const OPAQUE_ID = /^[A-Za-z0-9._:-]{1,256}$/;
const BIDI_CONTROL = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;

export type InsightEvidence = {
  source:
    | "crm"
    | "outlook"
    | "calendar"
    | "one_drive"
    | "google_drive"
    | "granola"
    | "buzz_event"
    | "public_web";
  citation: { title: string } | null;
};

export type InsightDraft =
  | { kind: "outlook_draft"; subject: string; body: string }
  | { kind: "crm_note"; body: string }
  | { kind: "google_doc"; title: string; body: string };

export type InsightPayload = {
  category: string;
  priority: string;
  change: string;
  whyItMatters: string;
  evidence: InsightEvidence[];
  confidence: number;
  freshness: string;
  recommendation: string;
  draft: InsightDraft | null;
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

function hasOnlyKnownKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  required: readonly string[],
) {
  const actual = Object.keys(value);
  return (
    actual.every((key) => allowed.includes(key)) &&
    required.every((key) => Object.hasOwn(value, key))
  );
}

function isSafeText(value: unknown, maximum: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    ![...value].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return (
        codePoint <= 0x1f ||
        (codePoint >= 0x7f && codePoint <= 0x9f) ||
        BIDI_CONTROL.test(character)
      );
    })
  );
}

function parseCitation(value: unknown) {
  if (!isObject(value) || !hasExactKeys(value, ["title", "resolver_id"])) {
    return null;
  }
  if (
    !isSafeText(value.title, 128) ||
    !isSafeText(value.resolver_id, 256) ||
    !OPAQUE_ID.test(value.resolver_id)
  ) {
    return null;
  }
  return { title: value.title };
}

function parseEvidence(value: unknown): InsightEvidence[] | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) {
    return null;
  }

  const seen = new Set<string>();
  const evidence: InsightEvidence[] = [];
  for (const item of value) {
    if (
      !isObject(item) ||
      !hasOnlyKnownKeys(
        item,
        ["source", "source_id", "source_hash", "citation"],
        ["source", "source_id", "source_hash"],
      ) ||
      typeof item.source !== "string" ||
      !EVIDENCE_SOURCES.has(item.source) ||
      typeof item.source_id !== "string" ||
      !OPAQUE_ID.test(item.source_id) ||
      typeof item.source_hash !== "string" ||
      !SHA_256.test(item.source_hash)
    ) {
      return null;
    }
    const citation =
      item.citation === undefined || item.citation === null
        ? null
        : parseCitation(item.citation);
    if (
      item.citation !== undefined &&
      item.citation !== null &&
      citation === null
    )
      return null;
    if (item.source === "public_web" && citation === null) return null;

    const dedupeKey = `${item.source}\u0000${item.source_id}\u0000${item.source_hash}`;
    if (seen.has(dedupeKey)) return null;
    seen.add(dedupeKey);
    evidence.push({
      source: item.source as InsightEvidence["source"],
      citation,
    });
  }
  return evidence;
}

function parseDraft(value: unknown): InsightDraft | null | undefined {
  if (value === null) return null;
  if (!isObject(value) || typeof value.kind !== "string") return undefined;
  if (
    value.kind === "outlook_draft" &&
    hasExactKeys(value, ["kind", "subject", "body"]) &&
    isSafeText(value.subject, 128) &&
    isSafeText(value.body, 4096)
  ) {
    return { kind: value.kind, subject: value.subject, body: value.body };
  }
  if (
    value.kind === "crm_note" &&
    hasExactKeys(value, ["kind", "body"]) &&
    isSafeText(value.body, 4096)
  ) {
    return { kind: value.kind, body: value.body };
  }
  if (
    value.kind === "google_doc" &&
    hasExactKeys(value, ["kind", "title", "body"]) &&
    isSafeText(value.title, 128) &&
    isSafeText(value.body, 4096)
  ) {
    return { kind: value.kind, title: value.title, body: value.body };
  }
  return undefined;
}

/**
 * Strictly parses the frozen v1 Core Insight payload. Invalid or future
 * payloads intentionally return null so untrusted JSON is never displayed.
 */
export function parseInsightPayload(content: string): InsightPayload | null {
  let value: unknown;
  try {
    value = JSON.parse(content);
  } catch {
    return null;
  }
  if (
    !isObject(value) ||
    !hasOnlyKnownKeys(
      value,
      INSIGHT_FIELDS,
      INSIGHT_FIELDS.filter((field) => field !== "draft"),
    )
  ) {
    return null;
  }
  if (
    value.schema_version !== 1 ||
    typeof value.insight_id !== "string" ||
    !UUID_V4.test(value.insight_id) ||
    typeof value.category !== "string" ||
    !INSIGHT_CATEGORIES.has(value.category) ||
    typeof value.priority !== "string" ||
    !INSIGHT_PRIORITIES.has(value.priority) ||
    !isSafeText(value.change, 4096) ||
    !isSafeText(value.why_it_matters, 4096) ||
    typeof value.confidence !== "number" ||
    !Number.isInteger(value.confidence) ||
    value.confidence < 0 ||
    value.confidence > 100 ||
    typeof value.freshness !== "string" ||
    !INSIGHT_FRESHNESS.has(value.freshness) ||
    !isSafeText(value.recommendation, 4096) ||
    typeof value.dedupe_key !== "string" ||
    !SHA_256.test(value.dedupe_key) ||
    typeof value.created_at !== "number" ||
    !Number.isSafeInteger(value.created_at) ||
    !isSafeText(value.safety_policy_version, 128) ||
    !isSafeText(value.persona_version, 128) ||
    !isSafeText(value.firm_version, 128) ||
    !isSafeText(value.personal_version, 128) ||
    !isSafeText(value.model_version, 128)
  ) {
    return null;
  }

  const evidence = parseEvidence(value.evidence);
  const draft = value.draft === undefined ? null : parseDraft(value.draft);
  if (evidence === null || draft === undefined) return null;
  return {
    category: value.category,
    priority: value.priority,
    change: value.change,
    whyItMatters: value.why_it_matters,
    evidence,
    confidence: value.confidence,
    freshness: value.freshness,
    recommendation: value.recommendation,
    draft,
  };
}

export function insightCategoryLabel(category: string) {
  return (
    {
      commitment_deadline: "Commitment deadline",
      deal_movement: "Deal movement",
      meeting_movement: "Meeting movement",
      relationship_opportunity: "Relationship opportunity",
    }[category] ?? "Insight"
  );
}

export function insightFreshnessLabel(freshness: string) {
  return (
    {
      realtime: "Real-time",
      same_day: "Same day",
      recent: "Recent",
    }[freshness] ?? "Unavailable"
  );
}

export function evidenceSourceLabel(source: InsightEvidence["source"]) {
  return (
    {
      crm: "CRM record",
      outlook: "Outlook message",
      calendar: "Calendar event",
      one_drive: "OneDrive document",
      google_drive: "Google Drive document",
      granola: "Meeting notes",
      buzz_event: "Buzz event",
      public_web: "Public web research",
    }[source] ?? "Verified source"
  );
}
