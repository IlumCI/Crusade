//! Translating a question into a Crusade query, without a model.
//!
//! This is the baseline a language model has to beat, and the default engine
//! when no model is installed. It is a cue-phrase translator: a span of the
//! question that unambiguously names a filter becomes that filter, and
//! everything left over becomes free text — which is the right fallback,
//! because free text is searched against banners and so a word nobody mapped
//! still does something useful.
//!
//! Why bother with a baseline at all, when the plan calls for a 0.5-1.5B model
//! under a grammar? Because the question "is the model worth its 400 MB"
//! cannot be answered without one. The literature is explicit that the
//! constraint which makes small-model output *parseable* also costs semantic
//! accuracy (the "constraint tax", GenSIE 2026), and that inference-time
//! scaling does not reliably recover it at this size (arXiv:2608.25761). On a
//! domain this narrow — a few dozen fields, each with a small set of ways
//! people refer to it — a translator that never guesses may well be the better
//! instrument. Both engines are kept, both are measured against the same set
//! of questions, and the measurement is in the repository.
//!
//! What this deliberately does not do is paraphrase. `nginx servers in
//! Germany` becomes `product:nginx country:DE`; `show me something
//! interesting` becomes free text and says so. A translator that invents a
//! filter the question did not ask for is worse than one that declines.

use crate::query::{Field, FilterValue, Query};

/// A translated question, with the evidence for each filter.
#[derive(Debug, Clone, PartialEq)]
pub struct Translation {
    /// The query to run.
    pub query: Query,
    /// One line per filter: the words that produced it.
    pub because: Vec<String>,
    /// Words that mapped to nothing and became free text.
    pub residual: Vec<String>,
}

impl Translation {
    /// Whether anything structured came out. A translation that is all free
    /// text is not wrong, but the caller should say so rather than present it
    /// as an understood question.
    pub fn is_structured(&self) -> bool {
        !self.query.filters.is_empty()
    }
}

/// A cue: words that name a filter, and what to do when they appear.
struct Cue {
    /// Lower-cased phrase, matched on word boundaries.
    phrase: &'static str,
    field: Field,
    /// The value, or `None` when the cue is followed by one in the question.
    value: Option<&'static str>,
}

/// Cues that carry their own value.
///
/// Each is a phrase a question actually uses, mapped to the filter it means.
/// Nothing here is clever; the value is that it is explicit and testable, and
/// that every entry was chosen because it is unambiguous. `expired` is not
/// here, for instance, because Crusade has no expiry filter and guessing one
/// would produce a query that silently answers a different question.
const CUES: &[Cue] = &[
    // Posture and findings.
    Cue {
        phrase: "honeypot",
        field: Field::Honeypot,
        value: Some("true"),
    },
    Cue {
        phrase: "honeypots",
        field: Field::Honeypot,
        value: Some("true"),
    },
    Cue {
        phrase: "not a honeypot",
        field: Field::Honeypot,
        value: Some("false"),
    },
    Cue {
        phrase: "real hosts",
        field: Field::Honeypot,
        value: Some("false"),
    },
    Cue {
        phrase: "vulnerable",
        field: Field::HasVuln,
        value: Some("true"),
    },
    Cue {
        phrase: "with cves",
        field: Field::HasVuln,
        value: Some("true"),
    },
    Cue {
        phrase: "with a cve",
        field: Field::HasVuln,
        value: Some("true"),
    },
    Cue {
        phrase: "exploitable",
        field: Field::HasExploit,
        value: Some("true"),
    },
    Cue {
        phrase: "known exploit",
        field: Field::HasExploit,
        value: Some("true"),
    },
    Cue {
        phrase: "public exploit",
        field: Field::HasExploit,
        value: Some("true"),
    },
    Cue {
        phrase: "unauthenticated",
        field: Field::Auth,
        value: Some("open"),
    },
    Cue {
        phrase: "no authentication",
        field: Field::Auth,
        value: Some("open"),
    },
    Cue {
        phrase: "without authentication",
        field: Field::Auth,
        value: Some("open"),
    },
    Cue {
        phrase: "no auth",
        field: Field::Auth,
        value: Some("open"),
    },
    Cue {
        phrase: "open access",
        field: Field::Auth,
        value: Some("open"),
    },
    Cue {
        phrase: "requires authentication",
        field: Field::Auth,
        value: Some("required"),
    },
    // Industrial control.
    Cue {
        phrase: "ics",
        field: Field::HasIcs,
        value: Some("true"),
    },
    Cue {
        phrase: "scada",
        field: Field::HasIcs,
        value: Some("true"),
    },
    Cue {
        phrase: "industrial control",
        field: Field::HasIcs,
        value: Some("true"),
    },
    Cue {
        phrase: "operational technology",
        field: Field::HasIcs,
        value: Some("true"),
    },
    // Screenshots.
    Cue {
        phrase: "with a screenshot",
        field: Field::HasScreenshot,
        value: Some("true"),
    },
    Cue {
        phrase: "with screenshots",
        field: Field::HasScreenshot,
        value: Some("true"),
    },
    Cue {
        phrase: "screenshotted",
        field: Field::HasScreenshot,
        value: Some("true"),
    },
    // Transport.
    Cue {
        phrase: "over udp",
        field: Field::Transport,
        value: Some("udp"),
    },
    Cue {
        phrase: "udp",
        field: Field::Transport,
        value: Some("udp"),
    },
    Cue {
        phrase: "over tcp",
        field: Field::Transport,
        value: Some("tcp"),
    },
    // Cues whose value follows them in the question.
    Cue {
        phrase: "port",
        field: Field::Port,
        value: None,
    },
    Cue {
        phrase: "on port",
        field: Field::Port,
        value: None,
    },
    Cue {
        phrase: "asn",
        field: Field::Asn,
        value: None,
    },
    Cue {
        phrase: "as",
        field: Field::Asn,
        value: None,
    },
    Cue {
        phrase: "cve",
        field: Field::Vuln,
        value: None,
    },
    Cue {
        phrase: "running",
        field: Field::Product,
        value: None,
    },
    Cue {
        phrase: "serving",
        field: Field::Product,
        value: None,
    },
    Cue {
        phrase: "version",
        field: Field::Version,
        value: None,
    },
    Cue {
        phrase: "tagged",
        field: Field::Tag,
        value: None,
    },
    Cue {
        phrase: "in city",
        field: Field::City,
        value: None,
    },
    Cue {
        phrase: "cluster",
        field: Field::Cluster,
        value: None,
    },
    Cue {
        phrase: "jarm",
        field: Field::Jarm,
        value: None,
    },
    Cue {
        phrase: "hassh",
        field: Field::Hassh,
        value: None,
    },
    Cue {
        phrase: "in network",
        field: Field::Net,
        value: None,
    },
    Cue {
        phrase: "inside",
        field: Field::Net,
        value: None,
    },
];

/// Country names to ISO 3166-1 alpha-2 codes.
///
/// Only the countries a question is likely to name, and only names that are
/// unambiguous. The list is short on purpose: a wrong country code produces a
/// confidently empty result set, which is the worst kind of wrong answer.
const COUNTRIES: &[(&str, &str)] = &[
    ("germany", "DE"),
    ("german", "DE"),
    ("france", "FR"),
    ("french", "FR"),
    ("netherlands", "NL"),
    ("dutch", "NL"),
    ("united states", "US"),
    ("usa", "US"),
    ("america", "US"),
    ("united kingdom", "GB"),
    ("britain", "GB"),
    ("china", "CN"),
    ("chinese", "CN"),
    ("russia", "RU"),
    ("russian", "RU"),
    ("japan", "JP"),
    ("japanese", "JP"),
    ("india", "IN"),
    ("brazil", "BR"),
    ("canada", "CA"),
    ("australia", "AU"),
    ("italy", "IT"),
    ("spain", "ES"),
    ("poland", "PL"),
    ("sweden", "SE"),
    ("finland", "FI"),
    ("norway", "NO"),
    ("denmark", "DK"),
    ("switzerland", "CH"),
    ("austria", "AT"),
    ("belgium", "BE"),
    ("ireland", "IE"),
    ("portugal", "PT"),
    ("greece", "GR"),
    ("turkey", "TR"),
    ("ukraine", "UA"),
    ("israel", "IL"),
    ("south korea", "KR"),
    ("korea", "KR"),
    ("taiwan", "TW"),
    ("singapore", "SG"),
    ("hong kong", "HK"),
    ("mexico", "MX"),
    ("argentina", "AR"),
    ("south africa", "ZA"),
    ("egypt", "EG"),
    ("nigeria", "NG"),
    ("kenya", "KE"),
    ("vietnam", "VN"),
    ("thailand", "TH"),
    ("indonesia", "ID"),
    ("philippines", "PH"),
    ("malaysia", "MY"),
    ("new zealand", "NZ"),
    ("czechia", "CZ"),
    ("czech republic", "CZ"),
    ("romania", "RO"),
    ("hungary", "HU"),
    ("bulgaria", "BG"),
    ("estonia", "EE"),
    ("latvia", "LV"),
    ("lithuania", "LT"),
    ("iceland", "IS"),
    ("luxembourg", "LU"),
];

/// Service names a question uses that are not the product string.
///
/// `ssh servers` means port 22, not `product:ssh`; the product is OpenSSH or
/// Dropbear or something else. Mapping the service word to its port is both
/// what the asker meant and what the index can answer.
const SERVICE_PORTS: &[(&str, u16)] = &[
    ("ssh", 22),
    ("telnet", 23),
    ("smtp", 25),
    ("dns", 53),
    ("http", 80),
    ("pop3", 110),
    ("imap", 143),
    ("snmp", 161),
    ("ldap", 389),
    ("https", 443),
    ("smb", 445),
    ("rdp", 3389),
    ("mysql", 3306),
    ("postgres", 5432),
    ("postgresql", 5432),
    ("vnc", 5900),
    ("redis", 6379),
    ("elasticsearch", 9200),
    ("mongodb", 27017),
    ("memcached", 11211),
    ("rtsp", 554),
    ("mqtt", 1883),
    ("modbus", 502),
    ("bacnet", 47808),
];

/// Words that carry no information and should not become free text.
const NOISE: &[&str] = &[
    "a",
    "an",
    "the",
    "and",
    "or",
    "of",
    "in",
    "on",
    "at",
    "to",
    "with",
    "for",
    "from",
    "by",
    "show",
    "me",
    "find",
    "list",
    "get",
    "all",
    "any",
    "which",
    "what",
    "that",
    "are",
    "is",
    "hosts",
    "host",
    "servers",
    "server",
    "services",
    "service",
    "machines",
    "boxes",
    "devices",
    "device",
    "systems",
    "system",
    "please",
    "there",
    "give",
    "every",
    "some",
    "located",
    "using",
    "have",
    "has",
    "had",
    "do",
    "does",
    "it",
    "its",
    "their",
    "be",
    "been",
    "anything",
    "something",
    "everything",
    "things",
    "stuff",
];

/// Translate a question into a query.
pub fn translate(question: &str) -> Translation {
    translate_with(question, &[])
}

/// Translate a question, told which product names the index actually holds.
///
/// Without that list a bare `nginx servers in Germany` can only make `nginx`
/// free text — which does find nginx banners through the full-text index, but
/// is not the filter the asker meant. There is no way to know from the
/// sentence alone that `nginx` names a product and `interesting` does not, and
/// a built-in list of product names would be both endless and stale. The index
/// already knows: `products` comes from the products it has seen (the store's
/// own facet), so the translator learns the vocabulary of the data it is
/// searching.
pub fn translate_with(question: &str, products: &[String]) -> Translation {
    let lower = question.to_ascii_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '/' | ':')))
        .filter(|w| !w.is_empty())
        .collect();

    let mut query = Query::default();
    let mut because: Vec<String> = Vec::new();
    let mut used = vec![false; words.len()];

    // Longest phrase first, so `not a honeypot` is not eaten by `honeypot`
    // and `south korea` is not eaten by `korea`.
    let mut cues: Vec<&Cue> = CUES.iter().collect();
    cues.sort_by_key(|c| std::cmp::Reverse(c.phrase.split(' ').count()));

    let add = |query: &mut Query,
               because: &mut Vec<String>,
               field: Field,
               raw: &str,
               evidence: String| {
        // The value goes through the real parser, so a cue can never produce
        // a filter the query language would reject.
        match crate::query::parse(&format!("{}:{}", field.as_str(), quote(raw))) {
            Ok(q) if q.filters.len() == 1 => {
                let f = q.filters[0].clone();
                if !query.filters.contains(&f) {
                    query.filters.push(f);
                    because.push(evidence);
                }
                true
            }
            _ => false,
        }
    };

    for cue in cues {
        let needle: Vec<&str> = cue.phrase.split(' ').collect();
        let mut i = 0;
        while i + needle.len() <= words.len() {
            let span = i..i + needle.len();
            if used[span.clone()].iter().any(|u| *u) || words[span.clone()] != needle[..] {
                i += 1;
                continue;
            }
            match cue.value {
                Some(v) => {
                    if add(
                        &mut query,
                        &mut because,
                        cue.field,
                        v,
                        format!("\"{}\" -> {}:{}", cue.phrase, cue.field.as_str(), v),
                    ) {
                        used[span.clone()].fill(true);
                    }
                }
                None => {
                    // The value is the next unused word.
                    let at = span.end;
                    if at < words.len() && !used[at] {
                        let raw = words[at];
                        if add(
                            &mut query,
                            &mut because,
                            cue.field,
                            raw,
                            format!("\"{} {raw}\" -> {}:{raw}", cue.phrase, cue.field.as_str()),
                        ) {
                            used[span.clone()].fill(true);
                            used[at] = true;
                        }
                    }
                }
            }
            i = span.end;
        }
    }

    // Countries, longest name first.
    let mut countries: Vec<&(&str, &str)> = COUNTRIES.iter().collect();
    countries.sort_by_key(|(name, _)| std::cmp::Reverse(name.split(' ').count()));
    for (name, code) in countries {
        let needle: Vec<&str> = name.split(' ').collect();
        let mut i = 0;
        while i + needle.len() <= words.len() {
            let span = i..i + needle.len();
            if used[span.clone()].iter().any(|u| *u) || words[span.clone()] != needle[..] {
                i += 1;
                continue;
            }
            if add(
                &mut query,
                &mut because,
                Field::Country,
                code,
                format!("\"{name}\" -> country:{code}"),
            ) {
                used[span.clone()].fill(true);
            }
            i = span.end;
        }
    }

    // Service words, which mean a port rather than a product.
    for (i, w) in words.iter().enumerate() {
        if used[i] {
            continue;
        }
        if let Some((name, port)) = SERVICE_PORTS.iter().find(|(n, _)| n == w) {
            // An explicit port in the question is the answer; the service
            // word's default port would only contradict it. `ssh on port
            // 2222` means 2222, not 22 as well.
            if query.filters.iter().any(|f| f.field == Field::Port) {
                continue;
            }
            let value = port.to_string();
            if add(
                &mut query,
                &mut because,
                Field::Port,
                &value,
                format!("\"{name}\" -> port:{port}"),
            ) {
                used[i] = true;
            }
        }
    }

    // A bare CVE id is unambiguous wherever it appears.
    for (i, w) in words.iter().enumerate() {
        if used[i] || !w.starts_with("cve-") {
            continue;
        }
        let id = w.to_ascii_uppercase();
        if add(
            &mut query,
            &mut because,
            Field::Vuln,
            &id,
            format!("\"{w}\" -> vuln:{id}"),
        ) {
            used[i] = true;
        }
    }

    // A bare CIDR, likewise.
    for (i, w) in words.iter().enumerate() {
        if used[i] || !w.contains('/') || !w.contains('.') {
            continue;
        }
        if add(
            &mut query,
            &mut because,
            Field::Net,
            w,
            format!("\"{w}\" -> net:{w}"),
        ) {
            used[i] = true;
        }
    }

    // A residual word the index knows as a product becomes that filter.
    // Checked after the cues, so an explicit `running X` still wins.
    for (i, w) in words.iter().enumerate() {
        if used[i] || NOISE.contains(w) {
            continue;
        }
        if products.iter().any(|p| p.eq_ignore_ascii_case(w))
            && add(
                &mut query,
                &mut because,
                Field::Product,
                w,
                format!("\"{w}\" is a product in the index -> product:{w}"),
            )
        {
            used[i] = true;
        }
    }

    // Whatever is left and carries meaning becomes free text.
    let mut residual: Vec<String> = Vec::new();
    for (i, w) in words.iter().enumerate() {
        if used[i] || NOISE.contains(w) {
            continue;
        }
        residual.push((*w).to_string());
        query.text.push((*w).to_string());
    }

    Translation {
        query,
        because,
        residual,
    }
}

/// Quote a value that contains spaces, so the parser keeps it whole.
fn quote(raw: &str) -> String {
    if raw.contains(' ') {
        format!("\"{raw}\"")
    } else {
        raw.to_string()
    }
}

/// The questions both engines are measured on.
///
/// Kept in the crate rather than in a test file because the model engine
/// measures itself against the same set, and a benchmark that lives in one
/// engine's tests is not a benchmark. Each entry is a question and the filters
/// a correct translation must contain, as `key:value` strings; extra filters
/// are a miss, so a translator cannot score by guessing broadly.
pub const BENCHMARK: &[(&str, &[&str])] = &[
    ("nginx servers in Germany", &["product:nginx", "country:DE"]),
    ("ssh on port 2222", &["port:2222"]),
    ("telnet in China", &["port:23", "country:CN"]),
    (
        "unauthenticated redis in the netherlands",
        &["auth:open", "port:6379", "country:NL"],
    ),
    (
        "hosts running Apache in France",
        &["product:apache", "country:FR"],
    ),
    (
        "exploitable hosts in Russia",
        &["has_exploit:true", "country:RU"],
    ),
    (
        "industrial control systems in Japan",
        &["has_ics:true", "country:JP"],
    ),
    (
        "honeypots in the united states",
        &["honeypot:true", "country:US"],
    ),
    ("real hosts with cves", &["honeypot:false", "has_vuln:true"]),
    ("CVE-2021-44228", &["vuln:CVE-2021-44228"]),
    ("anything inside 10.0.0.0/8", &["net:10.0.0.0/8"]),
    (
        "rdp with a screenshot",
        &["port:3389", "has_screenshot:true"],
    ),
    ("dns over udp", &["port:53", "transport:udp"]),
    ("asn 15169", &["asn:15169"]),
    ("vulnerable mongodb", &["has_vuln:true", "port:27017"]),
    ("modbus in italy", &["port:502", "country:IT"]),
    ("tagged iot", &["tag:iot"]),
    (
        "no authentication elasticsearch",
        &["auth:open", "port:9200"],
    ),
    (
        "vnc in brazil without authentication",
        &["port:5900", "country:BR", "auth:open"],
    ),
    ("postgres in south korea", &["port:5432", "country:KR"]),
];

/// Score a translator against [`BENCHMARK`].
///
/// Returns `(exact, partial, total)`: exact is every expected filter present
/// and nothing extra, partial is every expected filter present with extras.
pub fn score<F: Fn(&str) -> Query>(translate: F) -> (usize, usize, usize) {
    let (mut exact, mut partial) = (0, 0);
    for (question, expected) in BENCHMARK {
        let q = translate(question);
        let got: Vec<String> = q.filters.iter().map(render_filter).collect();
        let all_present = expected
            .iter()
            .all(|e| got.iter().any(|g| g.eq_ignore_ascii_case(e)));
        if all_present {
            if got.len() == expected.len() {
                exact += 1;
            } else {
                partial += 1;
            }
        }
    }
    (exact, partial, BENCHMARK.len())
}

/// `key:value` for one filter, for comparison against the benchmark.
fn render_filter(f: &crate::query::Filter) -> String {
    let value = match &f.value {
        FilterValue::Int(n) => n.to_string(),
        FilterValue::Bool(b) => b.to_string(),
        FilterValue::Timestamp(t) => t.to_string(),
        FilterValue::Text(t) => t.clone(),
    };
    format!(
        "{}{}:{}",
        if f.negate { "-" } else { "" },
        f.field.as_str(),
        value
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filters(question: &str) -> Vec<String> {
        translate(question)
            .query
            .filters
            .iter()
            .map(render_filter)
            .collect()
    }

    #[test]
    fn a_country_name_becomes_its_code() {
        assert_eq!(filters("hosts in Germany"), ["country:DE"]);
        assert_eq!(filters("anything in south korea"), ["country:KR"]);
    }

    /// `korea` must not eat `south korea`, and `honeypot` must not eat
    /// `not a honeypot`: the longest phrase has to win.
    #[test]
    fn the_longest_phrase_wins() {
        assert_eq!(filters("hosts in south korea"), ["country:KR"]);
        assert_eq!(filters("not a honeypot"), ["honeypot:false"]);
    }

    #[test]
    fn a_service_word_means_its_port() {
        assert_eq!(filters("ssh servers"), ["port:22"]);
        assert_eq!(filters("redis"), ["port:6379"]);
    }

    /// An explicit port must win over the service word's default.
    #[test]
    fn an_explicit_port_is_kept() {
        let f = filters("ssh on port 2222");
        assert!(f.contains(&"port:2222".to_string()), "{f:?}");
    }

    #[test]
    fn unmapped_words_become_free_text() {
        let t = translate("show me something interesting");
        assert!(!t.is_structured());
        assert_eq!(t.residual, ["interesting"]);
        assert_eq!(t.query.text, ["interesting"]);
    }

    /// Told what the index holds, a bare product name becomes a filter
    /// instead of free text.
    #[test]
    fn a_known_product_becomes_a_filter() {
        assert_eq!(filters("nginx in Germany"), ["country:DE"]);
        let known = vec!["nginx".to_string(), "Apache httpd".to_string()];
        let t = translate_with("nginx in Germany", &known);
        let got: Vec<String> = t.query.filters.iter().map(render_filter).collect();
        assert!(got.contains(&"product:nginx".to_string()), "{got:?}");
        assert!(t.query.text.is_empty(), "{:?}", t.query.text);
    }

    /// An unknown word stays free text even with a product list: the list
    /// says what the index has, not what every word means.
    #[test]
    fn an_unknown_word_is_still_free_text() {
        let known = vec!["nginx".to_string()];
        let t = translate_with("interesting things in Germany", &known);
        assert_eq!(t.residual, ["interesting"]);
    }

    #[test]
    fn a_cve_id_is_recognised_anywhere() {
        assert_eq!(
            filters("anything with CVE-2021-44228"),
            ["vuln:CVE-2021-44228"]
        );
    }

    #[test]
    fn a_cidr_is_recognised_anywhere() {
        assert_eq!(filters("hosts inside 10.0.0.0/8"), ["net:10.0.0.0/8"]);
    }

    #[test]
    fn every_filter_carries_its_evidence() {
        let t = translate("nginx in Germany on port 8080");
        assert_eq!(t.query.filters.len(), t.because.len());
        assert!(
            t.because.iter().any(|b| b.contains("country:DE")),
            "{:?}",
            t.because
        );
    }

    /// The baseline's own score, recorded so a change to the cues cannot
    /// quietly make it worse.
    #[test]
    fn the_baseline_scores_what_it_scored() {
        let (exact, partial, total) = score(|q| translate(q).query);
        assert_eq!(total, 20);
        assert!(
            exact >= 19,
            "the cue translator got {exact} exact and {partial} partial of {total}"
        );
    }
}
