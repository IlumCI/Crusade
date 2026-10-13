//! Learning what the behavioural honeypot signals are actually worth.
//!
//! Stage 1 combines signals with a noisy-OR over weights I chose by reading
//! the literature and thinking about it. That is a defensible way to start and
//! a poor way to finish: the weights are guesses, and a guess that has been
//! shipped looks exactly like a measurement.
//!
//! This module replaces the guesses with numbers from an operator's own index,
//! by asking a question that has an answer there: **do the behavioural signals
//! predict the hosts the rule pack recognises?** The rule pack is a set of
//! exact artefacts of known honeypot software — Cowrie's default SSH banner,
//! Conpot's device identity — so a rule hit is about as close to a label as
//! scan data offers. Logistic regression is then fitted from the *non-rule*
//! features alone to that label, and scored on held-out hosts.
//!
//! What this does and does not establish is worth being exact about, because
//! the shape of the experiment limits the conclusion:
//!
//! * It **can** show that a signal carries information about being a honeypot,
//!   and how much relative to the others. If `erratic-answer-time` predicts
//!   rule-labelled honeypots on a real index, that is evidence for it.
//! * It **cannot** discover honeypots the rules miss and the signals do not
//!   predict either — nothing in the data points at those.
//! * It **will** inherit the rule pack's own blind spots. A honeypot family no
//!   rule covers contributes negative labels, which pushes the weights away
//!   from whatever makes it recognisable. The AUC is measured against the
//!   rules, not against the truth.
//!
//! So no weights ship with Crusade. There is no index to fit them on here, and
//! a weight file shipped from a synthetic population would be the same guess
//! with a more convincing filename. `crusade rescore --calibrate` fits on the
//! index it is run against, prints the measurement, and writes the weights
//! only if asked. Until then the noisy-OR stands, which is at least honest
//! about being a prior.
//!
//! No peer-reviewed classifier over scan records exists (see
//! `docs/FRONTIER.md`), so the method here is deliberately the simplest thing
//! that can be checked: a linear model whose coefficients can be read, not a
//! forest whose cannot.

use std::collections::BTreeMap;

use anyhow::Result;
use crusade_core::Host;
use serde::{Deserialize, Serialize};

/// The behavioural signals, in a fixed order so a weight vector means the same
/// thing every time it is loaded.
///
/// Rule hits are deliberately absent: they are the label, and a model given
/// its own label learns nothing.
pub const FEATURES: &[&str] = &[
    "ssh-kex-anachronism",
    "ics-multi-protocol",
    "ics-with-it-stack",
    "ics-on-cloud",
    "os-contradiction",
    "accepts-everything",
    "implausible-port-set",
    "slow-to-answer",
    "erratic-answer-time",
];

/// Fitted weights, with the measurement that produced them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Calibration {
    /// Coefficient per [`FEATURES`] entry, same order.
    pub weights: Vec<f32>,
    pub bias: f32,
    /// Hosts fitted on, and how many carried a rule hit.
    pub hosts: usize,
    pub labelled: usize,
    /// Area under the ROC curve on the held-out split. 0.5 is a coin flip.
    pub auc: f32,
}

impl Calibration {
    /// Probability this feature vector belongs to a rule-labelled honeypot.
    pub fn score(&self, features: &[f32]) -> f32 {
        let z: f32 = self
            .weights
            .iter()
            .zip(features)
            .map(|(w, x)| w * x)
            .sum::<f32>()
            + self.bias;
        1.0 / (1.0 + (-z).exp())
    }

    /// The coefficients, largest first, for reading.
    pub fn ranked(&self) -> Vec<(&'static str, f32)> {
        let mut out: Vec<(&'static str, f32)> = FEATURES
            .iter()
            .copied()
            .zip(self.weights.iter().copied())
            .collect();
        out.sort_by(|a, b| b.1.abs().total_cmp(&a.1.abs()));
        out
    }

    /// Whether this fit is worth using.
    ///
    /// An AUC near 0.5 means the signals do not predict the labels, and a fit
    /// on a handful of labelled hosts means nothing whatever its AUC. Both
    /// have to pass, and the bar is low on purpose: the point is to refuse the
    /// obviously useless, not to certify the rest.
    pub fn is_usable(&self) -> bool {
        self.labelled >= MIN_LABELLED && self.auc >= 0.60
    }
}

/// Fewer labelled honeypots than this and there is nothing to fit.
pub const MIN_LABELLED: usize = 30;

/// One host's features and label.
pub struct Sample {
    pub features: Vec<f32>,
    /// Whether the rule pack recognised this host.
    pub label: bool,
}

/// Turn a scored host into a training sample.
///
/// The host must already carry its assessment (`honeypot` on the `Host`), as
/// `HoneypotScorer::apply` leaves it.
pub fn sample(host: &Host) -> Option<Sample> {
    let assessment = host.honeypot.as_ref()?;
    let present: BTreeMap<&str, ()> = assessment
        .evidence
        .iter()
        .map(|e| (e.signal.as_str(), ()))
        .collect();
    let label = present.keys().any(|s| s.starts_with("rule:"));
    let features = FEATURES
        .iter()
        .map(|f| if present.contains_key(*f) { 1.0 } else { 0.0 })
        .collect();
    Some(Sample { features, label })
}

/// Fit weights by gradient descent, and measure on a held-out split.
///
/// The split is a hash of each host's position, not every k-th host. A fixed
/// period can align with a period in the data: writing this with "every third
/// host" against a test set whose label was also every third host put every
/// positive example in the held-out half and fitted the model on nothing. Real
/// scan data has periods too — a /24 of identical appliances, a provider's
/// address plan — so the split must not have one of its own. Hashing keeps it
/// deterministic, and therefore reproducible, without a period.
pub fn fit(samples: &[Sample]) -> Result<Calibration> {
    anyhow::ensure!(!samples.is_empty(), "no scored hosts to calibrate on");
    let n_features = FEATURES.len();
    for s in samples {
        anyhow::ensure!(
            s.features.len() == n_features,
            "a sample has {} features, expected {n_features}",
            s.features.len()
        );
    }
    let mut train: Vec<&Sample> = Vec::new();
    let mut test: Vec<&Sample> = Vec::new();
    for (i, sample) in samples.iter().enumerate() {
        if is_held_out(i) {
            test.push(sample);
        } else {
            train.push(sample);
        }
    }
    let labelled = samples.iter().filter(|s| s.label).count();

    let mut weights = vec![0.0f32; n_features];
    // Started at the prior odds of the label rather than zero, so the fit
    // begins calibrated and the coefficients only have to explain deviation
    // from the base rate.
    let rate = (labelled as f32 / samples.len() as f32).clamp(1e-4, 1.0 - 1e-4);
    let mut bias = (rate / (1.0 - rate)).ln();

    const EPOCHS: usize = 400;
    const LR: f32 = 0.3;
    // L2, because honeypot signals are rare and correlated: without it a
    // feature that fires on three hosts, all labelled, gets an unbounded
    // coefficient and the model becomes that one feature.
    const L2: f32 = 0.01;
    for _ in 0..EPOCHS {
        let mut grad = vec![0.0f32; n_features];
        let mut grad_bias = 0.0f32;
        for s in &train {
            let z: f32 = weights
                .iter()
                .zip(&s.features)
                .map(|(w, x)| w * x)
                .sum::<f32>()
                + bias;
            let p = 1.0 / (1.0 + (-z).exp());
            let err = p - if s.label { 1.0 } else { 0.0 };
            for (g, x) in grad.iter_mut().zip(&s.features) {
                *g += err * x;
            }
            grad_bias += err;
        }
        let scale = LR / train.len().max(1) as f32;
        for (w, g) in weights.iter_mut().zip(&grad) {
            *w -= scale * g + LR * L2 * *w;
        }
        bias -= scale * grad_bias;
    }

    let scored: Vec<(f32, bool)> = test
        .iter()
        .map(|s| {
            let z: f32 = weights
                .iter()
                .zip(&s.features)
                .map(|(w, x)| w * x)
                .sum::<f32>()
                + bias;
            (1.0 / (1.0 + (-z).exp()), s.label)
        })
        .collect();

    Ok(Calibration {
        weights,
        bias,
        hosts: samples.len(),
        labelled,
        auc: auc(&scored),
    })
}

/// Whether a sample at this position is held out: roughly a third, by a hash
/// so the choice has no period that could align with one in the data.
fn is_held_out(i: usize) -> bool {
    // FNV-1a over the index's bytes. Any decent avalanche would do; this one
    // is four lines and has no dependencies.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in (i as u64).to_le_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h.is_multiple_of(3)
}

/// Area under the ROC curve, by counting concordant pairs.
///
/// Exact rather than trapezoidal: the scores here take few distinct values
/// (the features are binary), so ties are the common case and a curve drawn
/// through them is misleading. Each tied pair counts a half, which is what the
/// rank-sum definition gives.
pub fn auc(scored: &[(f32, bool)]) -> f32 {
    let pos: Vec<f32> = scored.iter().filter(|(_, l)| *l).map(|(s, _)| *s).collect();
    let neg: Vec<f32> = scored
        .iter()
        .filter(|(_, l)| !*l)
        .map(|(s, _)| *s)
        .collect();
    if pos.is_empty() || neg.is_empty() {
        return 0.5;
    }
    let mut concordant = 0.0f64;
    for p in &pos {
        for n in &neg {
            concordant += match p.partial_cmp(n) {
                Some(std::cmp::Ordering::Greater) => 1.0,
                Some(std::cmp::Ordering::Equal) => 0.5,
                _ => 0.0,
            };
        }
    }
    (concordant / (pos.len() * neg.len()) as f64) as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(features: &[f32], label: bool) -> Sample {
        Sample {
            features: features.to_vec(),
            label,
        }
    }

    fn one_hot(i: usize) -> Vec<f32> {
        let mut v = vec![0.0; FEATURES.len()];
        v[i] = 1.0;
        v
    }

    /// The bug this caught in its own fixture: a split with a period can
    /// align with a period in the data and put every positive example on one
    /// side. Both halves must see both classes for any periodic label.
    #[test]
    fn the_split_has_no_period_to_align_with() {
        for period in 2..12usize {
            let (train_pos, test_pos) =
                (0..600)
                    .filter(|i| i % period == 0)
                    .fold((0, 0), |(tr, te), i| {
                        if is_held_out(i) {
                            (tr, te + 1)
                        } else {
                            (tr + 1, te)
                        }
                    });
            assert!(
                train_pos > 0 && test_pos > 0,
                "period {period}: {train_pos} train, {test_pos} held out"
            );
        }
        let held = (0..3000).filter(|i| is_held_out(*i)).count();
        assert!((800..1200).contains(&held), "{held} of 3000 held out");
    }

    #[test]
    fn auc_is_a_half_for_a_coin_flip() {
        let scored: Vec<(f32, bool)> = (0..100).map(|i| (0.5, i % 2 == 0)).collect();
        assert_eq!(auc(&scored), 0.5);
    }

    #[test]
    fn auc_is_one_for_a_perfect_ranking() {
        let scored = vec![(0.9, true), (0.8, true), (0.2, false), (0.1, false)];
        assert_eq!(auc(&scored), 1.0);
    }

    #[test]
    fn auc_handles_a_single_class() {
        assert_eq!(auc(&[(0.9, true), (0.8, true)]), 0.5);
        assert_eq!(auc(&[]), 0.5);
    }

    /// A signal that really does predict the label should come out with the
    /// largest coefficient, and the fit should beat a coin flip.
    #[test]
    fn a_predictive_signal_gets_the_largest_coefficient() {
        let predictive = 8; // erratic-answer-time
        let noise = 2;
        let mut samples = Vec::new();
        for i in 0..300 {
            // The signal fires on a third of hosts and the label follows it,
            // which is what "predictive" means.
            let label = i % 3 == 0;
            let mut f = vec![0.0; FEATURES.len()];
            if label {
                f[predictive] = 1.0;
            }
            // A feature that fires on its own schedule, carrying nothing.
            if i % 7 == 0 {
                f[noise] = 1.0;
            }
            samples.push(s(&f, label));
        }
        let c = fit(&samples).unwrap();
        assert_eq!(c.ranked()[0].0, FEATURES[predictive], "{:?}", c.ranked());
        assert!(c.auc > 0.9, "auc {}", c.auc);
        assert!(c.is_usable());
    }

    /// The result this is most likely to produce on real data, and the one it
    /// has to report honestly: features that carry nothing must not come out
    /// looking predictive.
    #[test]
    fn signals_that_carry_nothing_are_not_usable() {
        let mut samples = Vec::new();
        for i in 0..600 {
            // The label's period is coprime with the feature's, so which
            // feature fires says nothing about the label. (Written as `i % 3`
            // against `one_hot(i % 9)` it said everything, since 9 is a
            // multiple of 3 — the same aliasing trap as the split.)
            samples.push(s(&one_hot(i % FEATURES.len()), i % 11 < 4));
        }
        let c = fit(&samples).unwrap();
        assert!(c.auc < 0.65, "auc {} should be near a coin flip", c.auc);
        assert!(
            !c.is_usable(),
            "a fit this weak must not be offered for use"
        );
    }

    /// Too few labelled honeypots is not a fit, whatever the AUC says.
    #[test]
    fn a_handful_of_labels_is_not_a_calibration() {
        let mut samples = Vec::new();
        for i in 0..200 {
            let label = i < 5;
            let mut f = vec![0.0; FEATURES.len()];
            if label {
                f[0] = 1.0;
            }
            samples.push(s(&f, label));
        }
        let c = fit(&samples).unwrap();
        assert!(c.auc > 0.9, "auc {}", c.auc);
        assert!(
            !c.is_usable(),
            "{} labelled host(s) is not enough",
            c.labelled
        );
    }

    #[test]
    fn a_wrong_shaped_sample_is_refused() {
        assert!(fit(&[s(&[1.0, 0.0], true)]).is_err());
        assert!(fit(&[]).is_err());
    }

    #[test]
    fn the_score_is_a_probability() {
        let c = Calibration {
            weights: vec![2.0; FEATURES.len()],
            bias: -1.0,
            hosts: 100,
            labelled: 40,
            auc: 0.8,
        };
        let p = c.score(&vec![1.0; FEATURES.len()]);
        assert!((0.0..=1.0).contains(&p), "{p}");
        let q = c.score(&vec![0.0; FEATURES.len()]);
        assert!(q < p, "{q} should be below {p}");
    }
}
