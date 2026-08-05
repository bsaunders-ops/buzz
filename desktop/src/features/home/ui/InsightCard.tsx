import {
  evidenceModifiedDateLabel,
  evidenceSourceLabel,
  insightCategoryLabel,
  insightFreshnessLabel,
  type InsightEvidence,
  type InsightPayload,
} from "@/features/home/lib/insight";
import type { ReactNode } from "react";

type InsightCardProps = {
  payload: InsightPayload | null;
  onOpenSource?: (evidence: InsightEvidence) => Promise<void>;
  resolvingEvidenceKey?: string | null;
};

export function InsightCard({
  payload,
  onOpenSource,
  resolvingEvidenceKey = null,
}: InsightCardProps) {
  if (!payload) {
    return (
      <section
        className="mx-4 my-3 rounded-lg border border-muted bg-muted/30 p-4"
        data-testid="home-insight-unavailable"
      >
        <h3 className="text-base font-semibold text-foreground">
          Insight unavailable
        </h3>
        <p className="mt-1 text-sm text-muted-foreground">
          This insight could not be safely displayed.
        </p>
      </section>
    );
  }

  return (
    <article
      className="mx-4 my-3 rounded-lg border border-border bg-card p-4 text-sm shadow-sm"
      data-testid="home-insight-card"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <h3 className="text-base font-semibold text-foreground">
          {insightCategoryLabel(payload.category)}
        </h3>
        <span className="text-2xs font-medium uppercase tracking-wide text-muted-foreground">
          {payload.priority} priority
        </span>
      </div>

      <InsightSection label="Change">{payload.change}</InsightSection>
      <InsightSection label="Why it matters">
        {payload.whyItMatters}
      </InsightSection>

      <dl className="mt-4 grid grid-cols-2 gap-3 rounded-md bg-muted/50 p-3 text-sm">
        <div>
          <dt className="text-2xs font-medium uppercase tracking-wide text-muted-foreground">
            Confidence
          </dt>
          <dd className="mt-0.5 font-medium text-foreground">
            {payload.confidence}%
          </dd>
        </div>
        <div>
          <dt className="text-2xs font-medium uppercase tracking-wide text-muted-foreground">
            Freshness
          </dt>
          <dd className="mt-0.5 font-medium text-foreground">
            {insightFreshnessLabel(payload.freshness)}
          </dd>
        </div>
      </dl>

      <InsightSection label="Recommendation">
        {payload.recommendation}
      </InsightSection>

      {payload.draft ? (
        <section className="mt-4 rounded-md border border-border bg-muted/30 p-3">
          <h4 className="text-sm font-semibold text-foreground">
            Suggested draft
          </h4>
          {"subject" in payload.draft ? (
            <p className="mt-2 font-medium text-foreground">
              {payload.draft.subject}
            </p>
          ) : "title" in payload.draft ? (
            <p className="mt-2 font-medium text-foreground">
              {payload.draft.title}
            </p>
          ) : null}
          <p className="mt-1 whitespace-pre-wrap text-muted-foreground">
            {payload.draft.body}
          </p>
        </section>
      ) : null}

      <section className="mt-4">
        <h4 className="text-sm font-semibold text-foreground">Evidence</h4>
        <ul className="mt-2 space-y-1 text-muted-foreground">
          {payload.evidence.map((evidence) => (
            <li key={evidence.stableKey}>
              <span>{evidenceSourceLabel(evidence.source)}</span>
              {evidence.citation ? (
                <span>: {evidence.citation.title}</span>
              ) : null}
              {evidence.citation ? (
                <span className="text-2xs">
                  {" "}
                  · modified{" "}
                  {evidenceModifiedDateLabel(evidence.citation.modifiedAt)}
                </span>
              ) : null}
              <span className="text-2xs"> — verified reference</span>
              {evidence.citation && onOpenSource ? (
                <button
                  className="ml-2 text-xs font-medium text-primary hover:underline disabled:cursor-wait disabled:opacity-60"
                  data-testid="home-insight-open-source"
                  disabled={resolvingEvidenceKey === evidence.stableKey}
                  onClick={() => void onOpenSource(evidence)}
                  type="button"
                >
                  Open source
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      </section>
    </article>
  );
}

function InsightSection({
  children,
  label,
}: {
  children: ReactNode;
  label: string;
}) {
  return (
    <section className="mt-4">
      <h4 className="text-sm font-semibold text-foreground">{label}</h4>
      <p className="mt-1 whitespace-pre-wrap text-muted-foreground">
        {children}
      </p>
    </section>
  );
}
