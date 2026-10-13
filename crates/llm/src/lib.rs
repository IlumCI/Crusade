//! A local language model that writes Crusade queries, under grammar
//! constraint.
//!
//! The model never emits text that has to be trusted. It emits tokens under
//! the GBNF grammar generated from the query language itself
//! ([`crusade_core::grammar`]), so whatever comes out parses — the constraint
//! masks every token that would make the prefix unextendable to a valid query.
//! That is the result NVIDIA measured as taking Qwen3-0.6B from 16.7% to 59.2%
//! on structured output, and arXiv:2608.25761 reports the same shape for
//! text-to-SQL at this size.
//!
//! Three things had to be right before the model was usable at all, and each
//! was found by measurement rather than reasoning:
//!
//! 1. **The grammar must accept a leading space.** A model completing `Query:`
//!    wants a space-prefixed token, because that is how its tokenizer
//!    represents the start of a word. Forbid it and every such piece is masked
//!    at the first position, so generation falls to whichever unprefixed key
//!    ranks highest. That put a spurious `ics:modbus` in front of seven of
//!    eight otherwise sensible queries, and no amount of prompting removed it —
//!    the cause was mechanical, not semantic.
//! 2. **The prompt must describe exactly the grammar's fields.** With a prompt
//!    listing 29 fields and a grammar allowing 18, the model aims at a field it
//!    cannot use, the token is refused, and generation lands somewhere else
//!    entirely.
//! 3. **Values must be restricted to what the index holds.** Given a free-text
//!    field, a small model will put the subject of the sentence in it:
//!    `ics:boxes`, `ics:databases`, `ics:mail` on three consecutive questions.
//!    [`crusade_core::grammar::IndexVocab`] makes that unrepresentable.
//!
//! Self-consistency is available but is not a cure. Sampling five times at
//! temperature 0.8 and keeping the filters a majority agree on does remove
//! unstable guesses, but the errors that matter here are *stable*: the model
//! returned `auth:unknown` for "nobody needs a password for" in five samples
//! out of five. Voting cannot outvote a consistent misreading, which is what
//! GenSIE 2026 calls the constraint tax and arXiv:2608.25761 finds
//! inference-time scaling does not recover at this size.
//!
//! Everything here is optional, behind the `llm` feature, because llama.cpp is
//! a C++ build and the model is hundreds of megabytes. Without it `crusade
//! ask` uses the cue translator in [`crusade_core::nlq`], which is also the
//! baseline this engine is measured against.

use crusade_core::grammar::{field_reference_for_index, IndexVocab};
use crusade_core::query::Query;

#[cfg(feature = "llm")]
mod engine;
#[cfg(feature = "llm")]
pub use engine::{Candidate, QueryModel};

/// File name of the query model inside `<data dir>/models/`.
pub const MODEL_FILE: &str = "query-model.gguf";

/// Drop filters whose value the question never mentioned.
///
/// Restricting values to the index's vocabulary stops the model inventing
/// values, but not using a real one as filler: asked about "web servers that
/// are definitely not traps" it produced `product:nginx -honeypot:true`, the
/// second half right and the first half the first product in the list. Every
/// such filler was a *free-text* field, where the value is a literal name a
/// question asking for it would contain. So a vocabulary filter survives only
/// with lexical support in the question.
///
/// This applies to free-text fields alone. Typed fields are inferred rather
/// than quoted — `country:DE` comes from the word "german", `port:3389` from
/// "remote desktop" — and requiring them to appear verbatim would discard the
/// translations worth having.
pub fn drop_unsupported_values(mut query: Query, question: &str) -> Query {
    let words: Vec<String> = crusade_core::nlq::tokens(question);
    query.filters.retain(|f| {
        if f.field.value_kind() != crusade_core::query::ValueKind::Text {
            return true;
        }
        let crusade_core::FilterValue::Text(value) = &f.value else {
            return true;
        };
        // Supported if any word of the value appears among the question's
        // words. A multi-word product ("Apache httpd") counts when the
        // question names either part.
        crusade_core::nlq::tokens(value)
            .iter()
            .any(|v| words.iter().any(|w| w == v))
    });
    query
}

/// The prompt, built from the same metadata as the grammar.
///
/// The rules are not decoration: each one is a failure that was measured and
/// then corrected. Without the negation rule the model answered `country:US`
/// to "anywhere but the united states" — the opposite of the question. Without
/// the `auth:open` rule it chose `auth:unknown` for "nobody needs a password
/// for", consistently. Without the service-port rule it looked for a product
/// called "mail".
pub fn prompt_for(question: &str, vocab: &IndexVocab) -> String {
    let reference = field_reference_for_index(vocab, true);
    format!(
        "<|im_start|>system\n\
         You translate questions into a search query for an internet-wide scan index.\n\
         Output only the query: space-separated key:value filters, nothing else.\n\
         Use only the filters the question actually asks for. Leave out anything it does \
         not mention.\n\n\
         Fields:\n{reference}\n\
         Rules:\n\
         - auth:open means no password is needed. Never use auth:unknown.\n\
         - Use ics: or has_ics: only for industrial, factory or SCADA equipment.\n\
         - \"anywhere but X\", \"not in X\" and \"except X\" mean -country:XX, with the \
         minus sign.\n\
         - A service name is a port: web/http=80, mail/smtp=25, remote desktop=3389, \
         ssh=22, database=3306.\n\n\
         Examples:\n\
         Question: nginx servers in Germany\n\
         Query: product:nginx country:DE\n\
         Question: boxes in france nobody needs a password for\n\
         Query: country:FR auth:open\n\
         Question: remote desktop anywhere but the united states\n\
         Query: port:3389 -country:US\n\
         Question: factory equipment in poland\n\
         Query: has_ics:true country:PL\n\
         Question: web servers with a known hole in them\n\
         Query: port:80 has_vuln:true<|im_end|>\n\
         <|im_start|>user\nQuestion: {question}<|im_end|>\n\
         <|im_start|>assistant\nQuery:"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crusade_core::Field;

    fn vocab() -> IndexVocab {
        IndexVocab {
            values: vec![(Field::Product, vec!["nginx".to_string()])],
        }
    }

    /// The prompt has to describe the grammar's fields and no others — the
    /// mismatch that produced a spurious filter on every answer.
    #[test]
    fn the_prompt_describes_exactly_the_grammar_fields() {
        let p = prompt_for("anything", &vocab());
        let g = crusade_core::grammar::gbnf_for_index(&vocab(), true);
        for field in Field::ALL {
            let key = format!("{}:", field.as_str());
            let in_grammar = g.contains(&format!("\"{key}\""));
            // The field reference is one line per field, at a line start.
            let described = p.lines().any(|l| l.starts_with(&key));
            assert_eq!(
                in_grammar,
                described,
                "{key} is {} the grammar but {} the prompt",
                if in_grammar { "in" } else { "not in" },
                if described { "in" } else { "not in" }
            );
        }
    }

    fn parse(q: &str) -> Query {
        crusade_core::query::parse(q).expect("valid query")
    }

    /// The filler the restricted vocabulary could not prevent.
    #[test]
    fn a_product_the_question_never_named_is_dropped() {
        let q = drop_unsupported_values(
            parse("product:nginx -honeypot:true"),
            "web servers that are definitely not traps",
        );
        assert_eq!(q.to_string(), "-honeypot:true");
    }

    #[test]
    fn a_product_the_question_did_name_is_kept() {
        let q = drop_unsupported_values(parse("product:nginx country:DE"), "nginx in germany");
        assert_eq!(q.filters.len(), 2, "{q}");
    }

    /// A multi-word product counts when the question names either part.
    #[test]
    fn half_a_product_name_is_enough_support() {
        let q = drop_unsupported_values(parse("product:\"Apache httpd\""), "apache in france");
        assert_eq!(q.filters.len(), 1, "{q}");
    }

    /// Typed fields are inferred from meaning, not quoted, so they are never
    /// held to appearing verbatim.
    #[test]
    fn inferred_typed_filters_survive() {
        let q = drop_unsupported_values(
            parse("country:DE port:3389 has_vuln:true -country:US"),
            "remote desktop in german speaking countries with holes",
        );
        assert_eq!(q.filters.len(), 4, "{q}");
    }

    #[test]
    fn the_prompt_ends_without_a_trailing_space() {
        let p = prompt_for("anything", &vocab());
        assert!(p.ends_with("Query:"), "{:?}", &p[p.len() - 24..]);
    }

    #[test]
    fn the_question_reaches_the_prompt() {
        let p = prompt_for("redis in france", &vocab());
        assert!(p.contains("Question: redis in france"), "{p}");
    }
}
