use std::cmp::Ordering;
use std::collections::HashSet;

use chrono::NaiveDate;

/// Maximum number of proactive feed items allowed for one owner per New York day.
pub const DAILY_INSIGHT_HARD_CAP: usize = 10;

/// New York local date/hour/minute supplied by the scheduler.
///
/// The database remains the authority for persistent America/New_York budget
/// dates. The runner accepts local time explicitly so ranking policy stays pure
/// and deterministic in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewYorkLocalMinute {
    /// America/New_York calendar date.
    pub date: NaiveDate,
    /// Local hour in 24-hour form.
    pub hour: u8,
    /// Local minute.
    pub minute: u8,
}

impl NewYorkLocalMinute {
    /// Return whether event-driven feed delivery is allowed at this local time.
    #[must_use]
    pub const fn is_event_window(self) -> bool {
        self.hour >= 7 && self.hour < 20 && self.minute < 60
    }

    /// Return whether the daily briefing is eligible to run at this local time.
    #[must_use]
    pub const fn is_briefing_window(self) -> bool {
        self.hour == 7 && self.minute >= 30 && self.minute < 60
    }
}

/// Delivery path requesting feed selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryKind {
    /// The 7:30 a.m. New York daily briefing.
    Briefing,
    /// A change-triggered insight during the allowed business-day window.
    EventDriven,
}

/// Coarse business category used for deterministic ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalCategory {
    /// Commitments, deadlines, owner/date follow-ups, and direct action promises.
    CommitmentDeadline,
    /// Active deal/client movement and meeting preparation/follow-up.
    DealClientMeetingMovement,
    /// Relationship, warm-path, buyer, and research opportunities.
    RelationshipBuyerOpportunity,
}

impl SignalCategory {
    const fn rank(self) -> u8 {
        match self {
            Self::CommitmentDeadline => 0,
            Self::DealClientMeetingMovement => 1,
            Self::RelationshipBuyerOpportunity => 2,
        }
    }
}

/// Priority within a category bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalPriority {
    /// Low priority.
    Low,
    /// Normal priority.
    Normal,
    /// High priority.
    High,
    /// Urgent priority.
    Urgent,
}

impl SignalPriority {
    const fn rank(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Normal => 1,
            Self::High => 2,
            Self::Urgent => 3,
        }
    }
}

/// One candidate insight considered by the proactive feed runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalCandidate {
    /// Stable runner-local identifier used as the final deterministic tie-breaker.
    pub candidate_id: String,
    /// Stable content/evidence dedupe key; mirrors the DB claim key.
    pub dedupe_key: [u8; 32],
    /// Business category for top-level ranking.
    pub category: SignalCategory,
    /// Priority within the category.
    pub priority: SignalPriority,
    /// Count of supporting evidence references.
    pub evidence_count: u16,
    /// Confidence percentage, 0 through 100.
    pub confidence: u8,
    /// Age of the freshest source evidence in minutes; lower is fresher.
    pub source_freshness_minutes: u32,
    /// Whether the candidate is strong enough to show. False candidates are
    /// discarded instead of used as filler.
    pub actionable: bool,
}

/// Select deterministic feed candidates for a delivery attempt.
///
/// This function applies only pure policy. Durable claiming, owner/channel ACL
/// checks, and the authoritative daily counter remain in `buzz-db`.
#[must_use]
pub fn select_for_delivery(
    candidates: &[SignalCandidate],
    delivery_kind: DeliveryKind,
    now: NewYorkLocalMinute,
    remaining_daily_budget: usize,
) -> Vec<SignalCandidate> {
    if remaining_daily_budget == 0 || !delivery_kind.is_allowed_at(now) {
        return Vec::new();
    }

    let mut ranked: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.actionable)
        .cloned()
        .collect();
    ranked.sort_by(compare_candidates);

    let mut seen = HashSet::new();
    let cap = remaining_daily_budget.min(DAILY_INSIGHT_HARD_CAP);
    let mut selected = Vec::with_capacity(cap);
    for candidate in ranked {
        if !seen.insert(candidate.dedupe_key) {
            continue;
        }
        selected.push(candidate);
        if selected.len() == cap {
            break;
        }
    }
    selected
}

impl DeliveryKind {
    const fn is_allowed_at(self, now: NewYorkLocalMinute) -> bool {
        match self {
            Self::Briefing => now.is_briefing_window(),
            Self::EventDriven => now.is_event_window(),
        }
    }
}

fn compare_candidates(left: &SignalCandidate, right: &SignalCandidate) -> Ordering {
    left.category
        .rank()
        .cmp(&right.category.rank())
        .then_with(|| right.priority.rank().cmp(&left.priority.rank()))
        .then_with(|| right.evidence_count.cmp(&left.evidence_count))
        .then_with(|| right.confidence.cmp(&left.confidence))
        .then_with(|| {
            left.source_freshness_minutes
                .cmp(&right.source_freshness_minutes)
        })
        .then_with(|| left.candidate_id.cmp(&right.candidate_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn local(hour: u8, minute: u8) -> NewYorkLocalMinute {
        NewYorkLocalMinute {
            date: NaiveDate::from_ymd_opt(2026, 8, 4).expect("valid test date"),
            hour,
            minute,
        }
    }

    fn candidate(
        candidate_id: &str,
        dedupe_marker: u8,
        category: SignalCategory,
        priority: SignalPriority,
    ) -> SignalCandidate {
        SignalCandidate {
            candidate_id: candidate_id.to_string(),
            dedupe_key: [dedupe_marker; 32],
            category,
            priority,
            evidence_count: 1,
            confidence: 80,
            source_freshness_minutes: 30,
            actionable: true,
        }
    }

    #[test]
    fn event_driven_delivery_obeys_new_york_business_window() {
        let item = candidate(
            "deadline",
            1,
            SignalCategory::CommitmentDeadline,
            SignalPriority::Normal,
        );

        assert!(select_for_delivery(
            std::slice::from_ref(&item),
            DeliveryKind::EventDriven,
            local(6, 59),
            10
        )
        .is_empty());
        assert_eq!(
            select_for_delivery(
                std::slice::from_ref(&item),
                DeliveryKind::EventDriven,
                local(7, 0),
                10
            )
            .len(),
            1
        );
        assert_eq!(
            select_for_delivery(
                std::slice::from_ref(&item),
                DeliveryKind::EventDriven,
                local(19, 59),
                10
            )
            .len(),
            1
        );
        assert!(
            select_for_delivery(&[item], DeliveryKind::EventDriven, local(20, 0), 10).is_empty()
        );
    }

    #[test]
    fn briefing_delivery_starts_at_seven_thirty_new_york() {
        let item = candidate(
            "briefing",
            2,
            SignalCategory::DealClientMeetingMovement,
            SignalPriority::Normal,
        );

        assert!(select_for_delivery(
            std::slice::from_ref(&item),
            DeliveryKind::Briefing,
            local(7, 29),
            10
        )
        .is_empty());
        assert_eq!(
            select_for_delivery(&[item], DeliveryKind::Briefing, local(7, 30), 10).len(),
            1
        );
    }

    #[test]
    fn ranking_keeps_commitments_before_relationship_opportunities() {
        let relationship = candidate(
            "buyer-opportunity",
            3,
            SignalCategory::RelationshipBuyerOpportunity,
            SignalPriority::Urgent,
        );
        let commitment = candidate(
            "deadline",
            4,
            SignalCategory::CommitmentDeadline,
            SignalPriority::Low,
        );

        let selected = select_for_delivery(
            &[relationship, commitment],
            DeliveryKind::EventDriven,
            local(12, 0),
            10,
        );

        assert_eq!(selected[0].candidate_id, "deadline");
        assert_eq!(selected[1].candidate_id, "buyer-opportunity");
    }

    #[test]
    fn selection_dedupes_and_never_adds_non_actionable_filler() {
        let weaker_duplicate = candidate(
            "weaker-duplicate",
            5,
            SignalCategory::DealClientMeetingMovement,
            SignalPriority::Low,
        );
        let stronger_duplicate = candidate(
            "stronger-duplicate",
            5,
            SignalCategory::DealClientMeetingMovement,
            SignalPriority::High,
        );
        let mut filler = candidate(
            "filler",
            6,
            SignalCategory::RelationshipBuyerOpportunity,
            SignalPriority::Urgent,
        );
        filler.actionable = false;

        let selected = select_for_delivery(
            &[weaker_duplicate, stronger_duplicate, filler],
            DeliveryKind::EventDriven,
            local(12, 0),
            10,
        );

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].candidate_id, "stronger-duplicate");
    }

    #[test]
    fn selection_respects_remaining_budget_and_absolute_hard_cap() {
        let candidates: Vec<_> = (0_u8..20)
            .map(|marker| {
                candidate(
                    &format!("candidate-{marker:02}"),
                    marker,
                    SignalCategory::CommitmentDeadline,
                    SignalPriority::Normal,
                )
            })
            .collect();

        assert_eq!(
            select_for_delivery(&candidates, DeliveryKind::EventDriven, local(12, 0), 3).len(),
            3
        );
        assert_eq!(
            select_for_delivery(&candidates, DeliveryKind::EventDriven, local(12, 0), 99).len(),
            10
        );
        assert!(
            select_for_delivery(&candidates, DeliveryKind::EventDriven, local(12, 0), 0).is_empty()
        );
    }
}
