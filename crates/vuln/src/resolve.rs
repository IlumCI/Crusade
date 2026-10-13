//! Resolving a banner's product name to a CPE that NVD actually uses.
//!
//! CVE matching is a join on `cpe:2.3:a:<vendor>:<product>:<version>`, and the
//! join only fires when the product string Crusade saw agrees with the string
//! NVD chose. It usually does not. nmap reports `Apache httpd`; NVD calls the
//! same software `apache:http_server`. nmap reports `OpenSSH`; NVD agrees, as
//! `openbsd:openssh`. Exact lookup therefore silently finds nothing for a
//! large share of real services — the gap VulCPE (arXiv:2505.13895) measures
//! as over 50% vendor-name inconsistency between CPE and CVE data.
//!
//! The fix is retrieval, not generation. A model asked to *write* a CPE
//! produces plausible strings that match no NVD row, and fuzzy string
//! matching alone mislabels anything with a non-standard name
//! (arXiv:2412.16607). So the candidate set here is always the set of
//! `(vendor, product)` pairs that appear in the indexed CVE rules: whatever
//! comes out of this module is a pair with CVEs attached, or nothing. That
//! keeps the zero-shot framing of CHRONOS (arXiv:2301.03944) without
//! inventing identifiers.
//!
//! Three tiers run in order, cheapest first, and each has to clear a bar:
//!
//! 1. **Exact** — the normalised query is a product in the vocabulary.
//! 2. **Lexical** — IDF-weighted token F1 against candidates sharing a rare
//!    token. The F1 (rather than plain overlap) is what stops `nginx` from
//!    resolving to `nginx_amplify_agent`: the extra tokens cost precision.
//! 3. **Fuzzy** — character-trigram similarity, blended with whatever token
//!    agreement there was. This is the tier that gets `httpd` to
//!    `http_server`, where no useful token is shared.
//!
//! A fourth tier, embedding retrieval over the whole vocabulary, was built and
//! then removed: measured against the real NVD vocabulary it was wrong four
//! times in five. `Microsoft IIS httpd` went to `microsoft:system.net.http`,
//! `Cowboy Erlang HTTP server` to `ibm:http_server`, and `Totally Bespoke
//! Daemon` — which should resolve to nothing — to `magzter:bespoke`. The cause
//! is structural rather than a matter of tuning: a static embedding of
//! `vendor product` is a mean over a handful of tokens, so a frequent vendor
//! word dominates the vector and the ranking answers "which pair mentions
//! Microsoft" instead of "which pair is this software". The rarity weighting
//! in tier 2 asks the better question with none of the cost, and the one case
//! retrieval got right (`Werkzeug httpd`) scored below the guard that would
//! have been needed to exclude the wrong four. Raising the bar removed the
//! win; lowering it kept the losses. So there is no embedding tier here.
//!
//! Every resolution carries the tier and score that produced it, and callers
//! report them alongside the CVE, because a resolved match is weaker evidence
//! than an exact one and should never be presented as the same thing.

use std::collections::HashMap;

/// Minimum token F1 for a lexical resolution.
const MIN_LEXICAL: f32 = 0.60;
/// A lexical resolution must share at least one token this rare. Rarity is
/// IDF divided by its maximum for the vocabulary's size, so the bar means the
/// same thing on a ten-entry test set and on NVD's hundred thousand pairs.
const MIN_RARITY: f32 = 0.35;
/// Minimum blended score for the fuzzy tier.
const MIN_FUZZY: f32 = 0.55;
/// Tokens on more than this fraction of the vocabulary are not worth walking
/// (`linux`, `server`, `windows`): they reach tens of thousands of candidates
/// and carry almost no information.
const MAX_TOKEN_SHARE: f32 = 0.02;
/// Candidates scoring within this fraction of the best are treated as fitting
/// the name comparably well, and the tie is broken by how much of NVD names
/// the pair — a maximum-a-posteriori step, where the rule count stands in for
/// the prior. `Redis key-value store` fits `redis-store:redis-store` slightly
/// better token-for-token than `redis:redis`, and is a thousand times more
/// likely to mean the latter.
const SCORE_BAND: f32 = 0.65;

/// How a product name was matched to a CPE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// The name is the CPE product, after normalisation.
    Exact,
    /// Shared rare tokens, weighted by rarity.
    Lexical,
    /// Character-level similarity, with no token in common.
    Fuzzy,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Exact => "exact",
            Tier::Lexical => "lexical",
            Tier::Fuzzy => "fuzzy",
        }
    }
}

/// One `(vendor, product)` pair that exists in the CVE index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub vendor: String,
    pub product: String,
    /// How many CVE rules name this pair, for reporting.
    pub rules: u32,
}

impl Candidate {
    /// The text this candidate is matched against: vendor and product with
    /// their underscores opened up, which is how NVD spells multi-word names.
    fn text(&self) -> String {
        format!(
            "{} {}",
            self.vendor.replace(['_', '-'], " "),
            self.product.replace(['_', '-'], " ")
        )
    }
}

/// A resolution, with the evidence that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolution {
    pub vendor: String,
    pub product: String,
    pub tier: Tier,
    pub score: f32,
}

impl Resolution {
    /// One line fit for a tag detail, so a resolved CVE never looks exact.
    pub fn explain(&self) -> String {
        format!(
            "product resolved to cpe {}:{} ({}, {:.2})",
            self.vendor,
            self.product,
            self.tier.as_str(),
            self.score
        )
    }
}

/// Split a product name into comparable tokens.
///
/// Case and punctuation are discarded, as are bare version numbers: `nginx
/// 1.18.0` and `nginx` have to reach the same tokens, since the version is
/// matched separately by the CVE rules.
pub fn tokens(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        if raw.is_empty() {
            continue;
        }
        let t = raw.to_ascii_lowercase();
        // A pure number, or a `v2`-style prefix, is version noise.
        if t.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if t.len() > 1 && t.starts_with('v') && t[1..].chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// Character trigrams of a string, for Dice similarity.
fn trigrams(text: &str) -> Vec<[u8; 3]> {
    let cleaned: Vec<u8> = text
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric())
        .map(|b| b.to_ascii_lowercase())
        .collect();
    if cleaned.len() < 3 {
        return Vec::new();
    }
    let mut out: Vec<[u8; 3]> = Vec::with_capacity(cleaned.len() - 2);
    for w in cleaned.windows(3) {
        let g = [w[0], w[1], w[2]];
        if !out.contains(&g) {
            out.push(g);
        }
    }
    out
}

/// Sørensen-Dice similarity over character trigrams, in `0.0..=1.0`.
///
/// Trigrams rather than edit distance because the differences that matter here
/// are insertions of whole words (`http_server` for `httpd`), which edit
/// distance punishes in proportion to their length.
pub fn trigram_similarity(a: &str, b: &str) -> f32 {
    let (ta, tb) = (trigrams(a), trigrams(b));
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }
    let shared = ta.iter().filter(|g| tb.contains(g)).count();
    2.0 * shared as f32 / (ta.len() + tb.len()) as f32
}

/// The `(vendor, product)` pairs in the CVE index, searchable by name.
pub struct ProductVocab {
    entries: Vec<Candidate>,
    /// token -> indices into `entries`, for tokens rare enough to be useful.
    index: HashMap<String, Vec<u32>>,
    /// Document frequency per token, including tokens dropped from `index`.
    df: HashMap<String, u32>,
    /// product name -> indices, so the exact tier needs no scan.
    by_product: HashMap<String, Vec<u32>>,
}

impl ProductVocab {
    /// Build the vocabulary from the pairs found in the CVE rules.
    pub fn new(entries: Vec<Candidate>) -> Self {
        let mut df: HashMap<String, u32> = HashMap::new();
        let mut postings: HashMap<String, Vec<u32>> = HashMap::new();
        for (i, c) in entries.iter().enumerate() {
            for t in tokens(&c.text()) {
                *df.entry(t.clone()).or_insert(0) += 1;
                postings.entry(t).or_default().push(i as u32);
            }
        }
        let cap = ((entries.len() as f32) * MAX_TOKEN_SHARE).max(64.0) as u32;
        postings.retain(|_, v| v.len() as u32 <= cap);
        let mut by_product: HashMap<String, Vec<u32>> = HashMap::new();
        for (i, c) in entries.iter().enumerate() {
            by_product
                .entry(c.product.clone())
                .or_default()
                .push(i as u32);
        }
        ProductVocab {
            entries,
            index: postings,
            df,
            by_product,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Inverse document frequency of a token, floored at zero.
    fn idf(&self, token: &str) -> f32 {
        let n = self.entries.len().max(1) as f32;
        let d = *self.df.get(token).unwrap_or(&0) as f32;
        ((n / (1.0 + d)).ln()).max(0.0)
    }

    /// How rare a token is, in `0.0..=1.0`: 1.0 names one entry only, 0.0 is
    /// on everything. Normalising by `ln(n)` keeps the thresholds independent
    /// of how large the vocabulary happens to be.
    fn rarity(&self, token: &str) -> f32 {
        let n = self.entries.len().max(2) as f32;
        (self.idf(token) / n.ln()).clamp(0.0, 1.0)
    }

    /// Candidates sharing at least one token with the query, by index.
    fn reachable(&self, q: &[String]) -> Vec<u32> {
        let mut out: Vec<u32> = Vec::new();
        for t in q {
            if let Some(ids) = self.index.get(t) {
                for &i in ids {
                    if !out.contains(&i) {
                        out.push(i);
                    }
                }
            }
        }
        out
    }

    /// IDF-weighted token F1 per reachable candidate.
    ///
    /// F1 rather than plain overlap: recall alone would let any candidate
    /// containing the query win, which is how `nginx` becomes
    /// `nginx_amplify_agent`. Requiring a rare shared token keeps the
    /// comparison off candidates joined only by a word like `server`.
    fn lexical_scores(&self, q: &[String]) -> Vec<(f32, u32)> {
        let q_weight: f32 = q.iter().map(|t| self.idf(t)).sum();
        let mut out = Vec::new();
        if q_weight <= 0.0 {
            return out;
        }
        for i in self.reachable(q) {
            let ct = tokens(&self.entries[i as usize].text());
            let shared: Vec<&String> = ct.iter().filter(|t| q.contains(t)).collect();
            if !shared.iter().any(|t| self.rarity(t) >= MIN_RARITY) {
                continue;
            }
            let overlap: f32 = shared.iter().map(|t| self.idf(t)).sum();
            let c_weight: f32 = ct.iter().map(|t| self.idf(t)).sum();
            if overlap <= 0.0 || c_weight <= 0.0 {
                continue;
            }
            let recall = overlap / q_weight;
            let precision = overlap / c_weight;
            out.push((2.0 * recall * precision / (recall + precision), i));
        }
        out
    }

    /// Character similarity blended with token agreement, per candidate.
    fn fuzzy_scores(&self, name: &str, q: &[String]) -> Vec<(f32, u32)> {
        let q_weight: f32 = q.iter().map(|t| self.idf(t)).sum();
        let mut out = Vec::new();
        for i in self.reachable(q) {
            let text = self.entries[i as usize].text();
            let sim = trigram_similarity(name, &text);
            let overlap: f32 = tokens(&text)
                .iter()
                .filter(|t| q.contains(t))
                .map(|t| self.idf(t))
                .sum();
            let token_part = if q_weight > 0.0 {
                (overlap / q_weight).min(1.0)
            } else {
                0.0
            };
            // The character signal leads here: by construction token
            // agreement already failed to clear the lexical bar, so it is
            // corroboration rather than evidence.
            out.push((0.65 * sim + 0.35 * token_part, i));
        }
        out
    }

    /// Decide between scored candidates.
    ///
    /// Nothing is returned unless the best candidate clears `min`: the prior
    /// breaks ties, it does not rescue a name that fits nothing.
    ///
    /// The prior may only promote a candidate the banner *contains* — every
    /// token of its product name appears in the query. That is the difference
    /// between the two cases this has to get right at once. `Redis key-value
    /// store` contains `redis`, so the prior is free to prefer the heavily
    /// documented `redis:redis` over the near-unknown `redis-store`. `Apache
    /// httpd` does not contain `tomcat`, so the equally well documented
    /// `apache:tomcat` cannot be promoted over `apache:http_server`, however
    /// many CVEs it carries. A candidate naming software the banner never
    /// mentioned is not a tie to break.
    fn decide(&self, scored: &[(f32, u32)], min: f32, q: &[String]) -> Option<(f32, u32)> {
        let best = scored.iter().map(|(s, _)| *s).fold(f32::MIN, f32::max);
        if !best.is_finite() || best < min {
            return None;
        }
        let floor = best * SCORE_BAND;
        scored
            .iter()
            .filter(|(s, i)| {
                *s >= best
                    || (*s >= floor && {
                        let c = &self.entries[*i as usize];
                        tokens(&c.product.replace(['_', '-'], " "))
                            .iter()
                            .all(|t| q.contains(t))
                    })
            })
            .max_by(|a, b| {
                let (ca, cb) = (&self.entries[a.1 as usize], &self.entries[b.1 as usize]);
                ca.rules
                    .cmp(&cb.rules)
                    .then(cb.product.len().cmp(&ca.product.len()))
                    .then(cb.product.cmp(&ca.product))
            })
            .copied()
    }

    /// The candidates a name scores against, best first: the audit trail
    /// behind a resolution, and the way to see what it nearly picked instead.
    pub fn rank(&self, name: &str, limit: usize) -> Vec<(Candidate, f32, Tier)> {
        let q = tokens(name);
        let mut out: Vec<(Candidate, f32, Tier)> = Vec::new();
        if q.is_empty() {
            return out;
        }
        for (score, i) in self.lexical_scores(&q) {
            out.push((self.entries[i as usize].clone(), score, Tier::Lexical));
        }
        for (score, i) in self.fuzzy_scores(name, &q) {
            out.push((self.entries[i as usize].clone(), score, Tier::Fuzzy));
        }
        out.sort_by(|a, b| b.1.total_cmp(&a.1));
        out.truncate(limit);
        out
    }

    /// Resolve a product name to a CPE pair, or nothing.
    pub fn resolve(&self, name: &str) -> Option<Resolution> {
        let q = tokens(name);
        if q.is_empty() {
            return None;
        }

        // Tier 1: the name, with separators normalised, is a product — either
        // whole, or after stripping a leading vendor the banner included.
        // Every split is tried, not the first that hits: `Apache Tomcat` is
        // the product `apache_tomcat` of a junk vendor NVD also carries, and
        // the product `tomcat` of `apache`, and only the prior separates them.
        let mut exact: Vec<(f32, u32)> = Vec::new();
        for k in 0..q.len() {
            let rest = q[k..].join("_");
            let Some(ids) = self.by_product.get(&rest) else {
                continue;
            };
            for &i in ids {
                let c = &self.entries[i as usize];
                // k == 0 is the unqualified name; beyond that the skipped
                // tokens have to be the candidate's own vendor.
                if k == 0 || tokens(&c.vendor.replace(['_', '-'], " ")) == q[..k] {
                    exact.push((1.0, i));
                }
            }
        }
        if let Some((score, i)) = self.decide(&exact, 1.0, &q) {
            let c = &self.entries[i as usize];
            return Some(Resolution {
                vendor: c.vendor.clone(),
                product: c.product.clone(),
                tier: Tier::Exact,
                score,
            });
        }

        // Tier 2: IDF-weighted token F1 over candidates sharing a token.
        if let Some((score, i)) = self.decide(&self.lexical_scores(&q), MIN_LEXICAL, &q) {
            let c = &self.entries[i as usize];
            return Some(Resolution {
                vendor: c.vendor.clone(),
                product: c.product.clone(),
                tier: Tier::Lexical,
                score,
            });
        }

        // Tier 3: character similarity among the same reachable candidates,
        // blended with whatever token agreement there was. A name that shares
        // a token but spells the rest differently lands here.
        if let Some((score, i)) = self.decide(&self.fuzzy_scores(name, &q), MIN_FUZZY, &q) {
            let c = &self.entries[i as usize];
            return Some(Resolution {
                vendor: c.vendor.clone(),
                product: c.product.clone(),
                tier: Tier::Fuzzy,
                score,
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(vendor: &str, product: &str) -> Candidate {
        Candidate {
            vendor: vendor.into(),
            product: product.into(),
            rules: 1,
        }
    }

    /// A vocabulary with the shapes that actually cause trouble: a product
    /// whose name is a prefix of a different product, a vendor-qualified
    /// name, and software NVD spells with underscores.
    fn vocab() -> ProductVocab {
        ProductVocab::new(vec![
            cand("f5", "nginx"),
            cand("nginx", "nginx_amplify_agent"),
            cand("apache", "http_server"),
            cand("apache", "tomcat"),
            cand("openbsd", "openssh"),
            cand("exim", "exim"),
            cand("postfix", "postfix"),
            cand("microsoft", "internet_information_services"),
            cand("isc", "bind"),
            cand("dovecot", "dovecot"),
        ])
    }

    #[test]
    fn exact_product_resolves_exactly() {
        let r = vocab().resolve("nginx").unwrap();
        assert_eq!(r.product, "nginx");
        assert_eq!(r.tier, Tier::Exact);
    }

    #[test]
    fn version_is_not_part_of_the_name() {
        let r = vocab().resolve("nginx 1.18.0").unwrap();
        assert_eq!(r.product, "nginx");
        assert_eq!(r.tier, Tier::Exact);
    }

    /// The failure this module exists for: a longer product containing the
    /// query as a token must not win over the product that *is* the query.
    #[test]
    fn longer_product_does_not_shadow_the_exact_one() {
        let r = vocab().resolve("nginx").unwrap();
        assert_eq!(r.product, "nginx");
        assert_ne!(r.product, "nginx_amplify_agent");
    }

    #[test]
    fn vendor_qualified_name_resolves_through_tokens() {
        let r = vocab().resolve("Apache Tomcat").unwrap();
        assert_eq!(
            (r.vendor.as_str(), r.product.as_str()),
            ("apache", "tomcat")
        );
    }

    /// `Apache httpd` shares only `apache` with `apache:http_server`, so this
    /// is the fuzzy tier's job.
    #[test]
    fn httpd_reaches_http_server() {
        let r = vocab().resolve("Apache httpd").unwrap();
        assert_eq!(
            (r.vendor.as_str(), r.product.as_str()),
            ("apache", "http_server")
        );
        assert_eq!(r.tier, Tier::Fuzzy);
    }

    #[test]
    fn unknown_software_resolves_to_nothing() {
        assert!(vocab().resolve("Totally Bespoke Daemon").is_none());
        assert!(vocab().resolve("").is_none());
        assert!(vocab().resolve("7.4").is_none());
    }

    /// The negative result the module doc records, kept as a test: a name
    /// that resembles nothing in the vocabulary must resolve to nothing
    /// rather than to its nearest neighbour.
    #[test]
    fn a_name_like_nothing_resolves_to_nothing() {
        let v = ProductVocab::new(vec![cand("magzter", "bespoke"), cand("exim", "exim")]);
        assert!(v.resolve("Totally Bespoke Daemon").is_none());
    }

    #[test]
    fn trigram_similarity_is_bounded_and_symmetric() {
        assert_eq!(trigram_similarity("nginx", "nginx"), 1.0);
        assert_eq!(trigram_similarity("nginx", "apache"), 0.0);
        let a = trigram_similarity("httpd", "http_server");
        let b = trigram_similarity("http_server", "httpd");
        assert_eq!(a, b);
        assert!(a > 0.0 && a < 1.0);
    }

    #[test]
    fn tokens_drop_version_noise_but_keep_names() {
        assert_eq!(tokens("OpenSSH 8.9p1 Ubuntu"), ["openssh", "9p1", "ubuntu"]);
        assert_eq!(tokens("nginx 1.18.0"), ["nginx"]);
        assert_eq!(tokens("Redis v7"), ["redis"]);
    }

    #[test]
    fn explanation_names_the_tier() {
        let r = vocab().resolve("Apache Tomcat").unwrap();
        let line = r.explain();
        assert!(line.contains("apache:tomcat"), "{line}");
        assert!(line.contains("lexical") || line.contains("exact"), "{line}");
    }
}
