use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;
use sha2::{Digest, Sha256};

/// Learning layer whose contents may affect retrieval and behavior, not policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearningLayer {
    /// Owner-private learning.
    Personal,
    /// Firm-wide learning after sanitization.
    SanitizedFirm,
}

/// Signal strength considered by promotion gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalStrength {
    /// Strong positive behavioral signal.
    Strong,
    /// Weak or ambiguous signal.
    Weak,
}

/// Month-one firm promotion mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmStewardMode {
    /// Blake is the founding steward during the first month.
    FoundingSteward,
    /// Normal multi-user promotion after at least two employees have activity.
    MultiUser,
}

/// One hashed/de-identified signal considered by the evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearningSignal {
    /// Stable signal identifier; duplicates count once.
    pub signal_id: String,
    /// Signal strength.
    pub strength: SignalStrength,
    /// De-identified subject/domain key.
    pub subject_key: String,
    /// De-identified matter key, required for firm diversity checks.
    pub matter_key: Option<String>,
    /// De-identified user key.
    pub user_key: String,
    /// Local evaluation day on which the signal was observed.
    pub observed_day: NaiveDate,
    /// Whether a related disposition marked the content too sensitive.
    pub too_sensitive: bool,
    /// Whether the candidate tried to affect policy, permissions, or scopes.
    pub policy_boundary: bool,
}

/// Sanitized firm bundle text before encryption/storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmBundleCandidate {
    /// Aggregate typed rules only. Entity-specific content must be absent.
    pub body: String,
}

/// Promotion candidate evaluated before creating/activating a learning revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionCandidate {
    /// Learning layer.
    pub layer: LearningLayer,
    /// Candidate creation day.
    pub created_day: NaiveDate,
    /// Firm-steward gate mode.
    pub steward_mode: FirmStewardMode,
    /// Required sanitized firm bundle for firm learning.
    pub sanitized_firm_bundle: Option<FirmBundleCandidate>,
    /// De-identified evidence signals.
    pub signals: Vec<LearningSignal>,
}

/// Closed promotion decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionDecision {
    /// Candidate has sufficient evidence and may advance to canary or active use.
    Promote,
    /// Candidate remains below a required evidence, age, or diversity gate.
    NeedsEvidence,
    /// Candidate must be quarantined.
    Quarantine(LearningQuarantineReason),
}

/// Closed quarantine reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearningQuarantineReason {
    /// Content was marked too sensitive.
    SensitiveContent,
    /// Candidate tried to affect immutable policy/permission boundaries.
    PolicyBoundary,
    /// Sanitized-firm candidate contained entity-specific data.
    FirmSanitization,
}

/// Canary exposure and quality stats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryStats {
    /// Eligible outputs that received the candidate behavior.
    pub eligible_uses: u16,
    /// First local day on which the canary was used.
    pub first_use_day: NaiveDate,
    /// Replay-quality improvement in whole percentage points.
    pub replay_quality_improvement_pct: i16,
    /// Whether leakage was detected.
    pub leakage_detected: bool,
    /// Whether a related disposition was `too_sensitive`.
    pub too_sensitive_disposition: bool,
    /// Whether material quality regressed.
    pub material_quality_regression: bool,
}

/// Canary lifecycle decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryDecision {
    /// Continue collecting canary evidence.
    Continue,
    /// Candidate passed canary gates.
    Pass,
    /// Candidate must roll back.
    Rollback,
}

/// Evaluate whether a learning candidate can advance.
#[must_use]
pub fn evaluate_promotion(
    candidate: &PromotionCandidate,
    evaluation_day: NaiveDate,
) -> PromotionDecision {
    if candidate
        .signals
        .iter()
        .any(|signal| signal.policy_boundary)
    {
        return PromotionDecision::Quarantine(LearningQuarantineReason::PolicyBoundary);
    }
    if candidate.signals.iter().any(|signal| signal.too_sensitive) {
        return PromotionDecision::Quarantine(LearningQuarantineReason::SensitiveContent);
    }

    match candidate.layer {
        LearningLayer::Personal => evaluate_personal_promotion(candidate),
        LearningLayer::SanitizedFirm => evaluate_firm_promotion(candidate, evaluation_day),
    }
}

/// Evaluate a candidate's canary state.
#[must_use]
pub fn evaluate_canary(stats: &CanaryStats, evaluation_day: NaiveDate) -> CanaryDecision {
    if stats.leakage_detected
        || stats.too_sensitive_disposition
        || stats.material_quality_regression
    {
        return CanaryDecision::Rollback;
    }

    let canary_days = evaluation_day
        .signed_duration_since(stats.first_use_day)
        .num_days();
    let enough_exposure = stats.eligible_uses >= 10 || canary_days >= 7;
    if enough_exposure && stats.replay_quality_improvement_pct >= 10 {
        CanaryDecision::Pass
    } else {
        CanaryDecision::Continue
    }
}

/// Deterministically assign exactly the same output to a candidate's 20% canary bucket.
#[must_use]
pub fn is_canary_output(candidate_id: &str, output_id: &str) -> bool {
    canary_bucket(candidate_id, output_id) < 20
}

fn canary_bucket(candidate_id: &str, output_id: &str) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(candidate_id.as_bytes());
    hasher.update([0]);
    hasher.update(output_id.as_bytes());
    let digest = hasher.finalize();
    digest[0] % 100
}

fn evaluate_personal_promotion(candidate: &PromotionCandidate) -> PromotionDecision {
    let strong = unique_strong_signals(&candidate.signals);
    if strong.len() < 6 {
        return PromotionDecision::NeedsEvidence;
    }
    let subjects: HashSet<&str> = strong
        .iter()
        .map(|signal| signal.subject_key.as_str())
        .collect();
    let days: HashSet<NaiveDate> = strong.iter().map(|signal| signal.observed_day).collect();
    if subjects.len() >= 2 && days.len() >= 2 {
        PromotionDecision::Promote
    } else {
        PromotionDecision::NeedsEvidence
    }
}

fn evaluate_firm_promotion(
    candidate: &PromotionCandidate,
    evaluation_day: NaiveDate,
) -> PromotionDecision {
    match candidate.sanitized_firm_bundle.as_ref() {
        Some(bundle) if sanitized_firm_bundle_is_valid(bundle) => {}
        _ => return PromotionDecision::Quarantine(LearningQuarantineReason::FirmSanitization),
    }

    let strong = unique_strong_signals(&candidate.signals);
    if strong.len() < 15 {
        return PromotionDecision::NeedsEvidence;
    }
    if evaluation_day
        .signed_duration_since(candidate.created_day)
        .num_days()
        < 14
    {
        return PromotionDecision::NeedsEvidence;
    }

    let matter_counts = matter_counts(&strong);
    if matter_counts.len() < 3 {
        return PromotionDecision::NeedsEvidence;
    }
    let max_matter_count = matter_counts.values().copied().max().unwrap_or(0);
    if max_matter_count * 100 > strong.len() * 40 {
        return PromotionDecision::NeedsEvidence;
    }

    if candidate.steward_mode == FirmStewardMode::MultiUser {
        let users: HashSet<&str> = strong
            .iter()
            .map(|signal| signal.user_key.as_str())
            .collect();
        if users.len() < 2 {
            return PromotionDecision::NeedsEvidence;
        }
    }

    PromotionDecision::Promote
}

fn unique_strong_signals(signals: &[LearningSignal]) -> Vec<&LearningSignal> {
    let mut seen = HashSet::new();
    signals
        .iter()
        .filter(|signal| signal.strength == SignalStrength::Strong)
        .filter(|signal| seen.insert(signal.signal_id.as_str()))
        .collect()
}

fn matter_counts(signals: &[&LearningSignal]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for signal in signals {
        if let Some(matter_key) = &signal.matter_key {
            *counts.entry(matter_key.clone()).or_insert(0) += 1;
        }
    }
    counts
}

fn sanitized_firm_bundle_is_valid(bundle: &FirmBundleCandidate) -> bool {
    let body = bundle.body.trim();
    if body.is_empty() {
        return false;
    }
    let lower = body.to_ascii_lowercase();
    if lower.contains('@')
        || lower.contains('$')
        || lower.contains("project ")
        || lower.contains("crm")
        || lower.contains("drive")
        || lower.contains("outlook")
    {
        return false;
    }
    !contains_uuid_like_token(body) && !contains_long_hex_token(body)
}

fn contains_uuid_like_token(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_hexdigit() && character != '-')
        .any(|token| {
            token.len() == 36
                && token
                    .chars()
                    .enumerate()
                    .all(|(index, character)| match index {
                        8 | 13 | 18 | 23 => character == '-',
                        _ => character.is_ascii_hexdigit(),
                    })
        })
}

fn contains_long_hex_token(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_hexdigit())
        .any(|token| token.len() >= 32 && token.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn day(day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 8, day).expect("valid test day")
    }

    fn strong(
        signal_id: &str,
        subject_key: &str,
        matter_key: &str,
        user_key: &str,
        observed_day: NaiveDate,
    ) -> LearningSignal {
        LearningSignal {
            signal_id: signal_id.to_string(),
            strength: SignalStrength::Strong,
            subject_key: subject_key.to_string(),
            matter_key: Some(matter_key.to_string()),
            user_key: user_key.to_string(),
            observed_day,
            too_sensitive: false,
            policy_boundary: false,
        }
    }

    #[test]
    fn personal_promotion_requires_six_strong_signals_across_subjects_and_days() {
        let candidate = PromotionCandidate {
            layer: LearningLayer::Personal,
            created_day: day(1),
            steward_mode: FirmStewardMode::FoundingSteward,
            sanitized_firm_bundle: None,
            signals: vec![
                strong("s1", "emails", "deal-a", "blake", day(1)),
                strong("s2", "emails", "deal-a", "blake", day(1)),
                strong("s3", "cards", "deal-a", "blake", day(2)),
                strong("s4", "cards", "deal-a", "blake", day(2)),
                strong("s5", "cards", "deal-a", "blake", day(3)),
            ],
        };

        assert_eq!(
            evaluate_promotion(&candidate, day(4)),
            PromotionDecision::NeedsEvidence
        );

        let mut ready = candidate;
        ready
            .signals
            .push(strong("s6", "ranking", "deal-a", "blake", day(3)));
        assert_eq!(
            evaluate_promotion(&ready, day(4)),
            PromotionDecision::Promote
        );
    }

    #[test]
    fn firm_promotion_requires_matter_diversity_age_and_multi_user_when_not_month_one() {
        let mut signals = Vec::new();
        for i in 0..5 {
            signals.push(strong(
                &format!("a{i}"),
                "ranking",
                "deal-a",
                "blake",
                day(1),
            ));
            signals.push(strong(
                &format!("b{i}"),
                "ranking",
                "deal-b",
                "blake",
                day(2),
            ));
            signals.push(strong(
                &format!("c{i}"),
                "ranking",
                "deal-c",
                "blake",
                day(3),
            ));
        }
        let founding = PromotionCandidate {
            layer: LearningLayer::SanitizedFirm,
            created_day: day(1),
            steward_mode: FirmStewardMode::FoundingSteward,
            sanitized_firm_bundle: Some(FirmBundleCandidate {
                body: "Prefer concise relationship context before recommendations.".to_string(),
            }),
            signals: signals.clone(),
        };

        assert_eq!(
            evaluate_promotion(&founding, day(14)),
            PromotionDecision::NeedsEvidence,
            "firm learning needs a full 14-day observation period"
        );
        assert_eq!(
            evaluate_promotion(&founding, day(15)),
            PromotionDecision::Promote
        );

        let multi_user = PromotionCandidate {
            steward_mode: FirmStewardMode::MultiUser,
            ..founding
        };
        assert_eq!(
            evaluate_promotion(&multi_user, day(15)),
            PromotionDecision::NeedsEvidence,
            "post-month-one firm promotion needs evidence from at least two users"
        );
    }

    #[test]
    fn firm_promotion_rejects_overconcentration_and_unsanitized_bundle_content() {
        let mut concentrated = Vec::new();
        for i in 0..7 {
            concentrated.push(strong(
                &format!("a{i}"),
                "ranking",
                "deal-a",
                "blake",
                day(1),
            ));
        }
        for i in 0..4 {
            concentrated.push(strong(
                &format!("b{i}"),
                "ranking",
                "deal-b",
                "alex",
                day(2),
            ));
            concentrated.push(strong(
                &format!("c{i}"),
                "ranking",
                "deal-c",
                "alex",
                day(3),
            ));
        }

        let candidate = PromotionCandidate {
            layer: LearningLayer::SanitizedFirm,
            created_day: day(1),
            steward_mode: FirmStewardMode::MultiUser,
            sanitized_firm_bundle: Some(FirmBundleCandidate {
                body: "Use this rule for Project Falcon, contact blake@example.com, $42M."
                    .to_string(),
            }),
            signals: concentrated,
        };

        assert_eq!(
            evaluate_promotion(&candidate, day(15)),
            PromotionDecision::Quarantine(LearningQuarantineReason::FirmSanitization)
        );
    }

    #[test]
    fn canary_requires_minimum_exposure_and_quality_lift() {
        let pending = CanaryStats {
            eligible_uses: 9,
            first_use_day: day(3),
            replay_quality_improvement_pct: 25,
            leakage_detected: false,
            too_sensitive_disposition: false,
            material_quality_regression: false,
        };
        assert_eq!(evaluate_canary(&pending, day(9)), CanaryDecision::Continue);

        let passed = CanaryStats {
            eligible_uses: 10,
            ..pending
        };
        assert_eq!(evaluate_canary(&passed, day(9)), CanaryDecision::Pass);

        let aged = CanaryStats {
            eligible_uses: 9,
            first_use_day: day(1),
            ..pending
        };
        assert_eq!(evaluate_canary(&aged, day(9)), CanaryDecision::Pass);

        let weak_quality = CanaryStats {
            replay_quality_improvement_pct: 9,
            ..passed
        };
        assert_eq!(
            evaluate_canary(&weak_quality, day(9)),
            CanaryDecision::Continue
        );
    }

    #[test]
    fn canary_rolls_back_on_leakage_sensitive_disposition_or_regression() {
        let base = CanaryStats {
            eligible_uses: 10,
            first_use_day: day(1),
            replay_quality_improvement_pct: 25,
            leakage_detected: false,
            too_sensitive_disposition: false,
            material_quality_regression: false,
        };

        assert_eq!(evaluate_canary(&base, day(9)), CanaryDecision::Pass);
        assert_eq!(
            evaluate_canary(
                &CanaryStats {
                    leakage_detected: true,
                    ..base
                },
                day(9)
            ),
            CanaryDecision::Rollback
        );
        assert_eq!(
            evaluate_canary(
                &CanaryStats {
                    too_sensitive_disposition: true,
                    ..base
                },
                day(9)
            ),
            CanaryDecision::Rollback
        );
        assert_eq!(
            evaluate_canary(
                &CanaryStats {
                    material_quality_regression: true,
                    ..base
                },
                day(9)
            ),
            CanaryDecision::Rollback
        );
    }

    #[test]
    fn canary_assignment_is_deterministic_twenty_percent() {
        let mut assigned = 0;
        for index in 0..1_000 {
            if is_canary_output("candidate-a", &format!("output-{index}")) {
                assigned += 1;
            }
        }

        assert!(
            (150..=250).contains(&assigned),
            "deterministic canary assignment should stay near 20%; got {assigned}"
        );
        assert_eq!(
            is_canary_output("candidate-a", "output-17"),
            is_canary_output("candidate-a", "output-17")
        );
    }
}
