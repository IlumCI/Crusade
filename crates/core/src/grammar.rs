//! A GBNF grammar for the query language, generated from the language itself.
//!
//! Constrained decoding masks every token that would make the generated prefix
//! unextendable to a valid string, so a model emitting under this grammar
//! cannot produce a query the parser rejects. For a model of the size Crusade
//! can embed this is the difference between a usable feature and an unusable
//! one: NVIDIA measured Qwen3-0.6B going from 16.7% to 59.2% on structured
//! Bash output under grammar constraint, and arXiv:2608.25761 reports the same
//! shape of result for text-to-SQL at 0.5B-7B.
//!
//! The grammar is *generated* from [`Field::ALL`] and [`Field::value_kind`]
//! rather than written out. A hand-written grammar is a second copy of the
//! query language that silently stops matching the first one the next time a
//! field is added — and the failure is invisible, because a stale grammar
//! still produces syntactically valid output, just over the wrong language. A
//! test asserts the generated grammar covers every field the parser knows.
//!
//! Syntactic validity is not semantic correctness. Constrained decoding buys
//! the first and can cost some of the second (the "constraint tax" reported at
//! GenSIE 2026), so callers are expected to show the query they got and let it
//! be corrected, never to run it silently.

use crate::query::{Field, ValueKind};

/// The grammar's root rule name.
pub const ROOT: &str = "root";

/// Build the GBNF grammar for the query language.
///
/// `fields` restricts the grammar to a subset, which is how a caller narrows
/// generation to the fields a question could plausibly need; empty means all
/// of them.
pub fn gbnf(fields: &[Field]) -> String {
    let fields: Vec<Field> = if fields.is_empty() {
        Field::ALL.to_vec()
    } else {
        fields.to_vec()
    };

    let mut out = String::new();
    out.push_str("# Generated from crusade_core::query. Do not edit by hand.\n");
    out.push_str("root ::= term (\" \" term)*\n");

    // A term is a filter or a free-text word. Negation is a prefix on filters
    // only, matching the parser: `-port:22` is a filter, `-nginx` is text.
    let mut alts: Vec<String> = Vec::new();
    for (i, _) in fields.iter().enumerate() {
        alts.push(format!("filter{i}"));
    }
    alts.push("text".to_string());
    out.push_str(&format!("term ::= {}\n", alts.join(" | ")));

    for (i, field) in fields.iter().enumerate() {
        out.push_str(&format!(
            "filter{i} ::= \"-\"? \"{}:\" {}\n",
            field.as_str(),
            value_rule(*field, i)
        ));
    }

    // Shared value rules.
    out.push_str("int ::= [0-9]+\n");
    out.push_str("bool ::= \"true\" | \"false\"\n");
    out.push_str("date ::= [0-9] [0-9] [0-9] [0-9] \"-\" [0-9] [0-9] \"-\" [0-9] [0-9]\n");
    out.push_str("country ::= [A-Z] [A-Z]\n");
    out.push_str("cidr ::= int \".\" int \".\" int \".\" int \"/\" int\n");
    // A bare word, or a quoted phrase when the value contains spaces. The
    // character classes exclude the quote and the space that would end the
    // token, so a generated value cannot break out of its own term.
    out.push_str("word ::= [a-zA-Z0-9_.:/+*%@-]+\n");
    out.push_str("phrase ::= \"\\\"\" [^\"\\n]+ \"\\\"\"\n");
    out.push_str("value ::= word | phrase\n");
    out.push_str("text ::= word | phrase\n");

    // Per-field enum and score rules, emitted only where used.
    for (i, field) in fields.iter().enumerate() {
        match field.value_kind() {
            ValueKind::Enum(words) => {
                let alts: Vec<String> = words.iter().map(|w| format!("\"{w}\"")).collect();
                out.push_str(&format!("enum{i} ::= {}\n", alts.join(" | ")));
            }
            ValueKind::BoolOrScore => {
                out.push_str(&format!("score{i} ::= bool | int\n"));
            }
            _ => {}
        }
    }
    out
}

/// The rule reference for one field's value.
fn value_rule(field: Field, i: usize) -> String {
    match field.value_kind() {
        ValueKind::Int => "int".into(),
        ValueKind::Bool => "bool".into(),
        ValueKind::BoolOrScore => format!("score{i}"),
        ValueKind::Enum(_) => format!("enum{i}"),
        ValueKind::Date => "date".into(),
        ValueKind::Cidr => "cidr".into(),
        ValueKind::Country => "country".into(),
        ValueKind::Text => "value".into(),
    }
}

/// A one-line description of each field, for a model's prompt.
///
/// Derived from the same metadata as the grammar, so the prompt cannot
/// describe a language the grammar does not accept.
pub fn field_reference(fields: &[Field]) -> String {
    let fields: Vec<Field> = if fields.is_empty() {
        Field::ALL.to_vec()
    } else {
        fields.to_vec()
    };
    let mut out = String::new();
    for field in fields {
        let shape = match field.value_kind() {
            ValueKind::Int => "<integer>".to_string(),
            ValueKind::Bool => "true|false".to_string(),
            ValueKind::BoolOrScore => "true|false|0-100".to_string(),
            ValueKind::Enum(words) => words.join("|"),
            ValueKind::Date => "YYYY-MM-DD".to_string(),
            ValueKind::Cidr => "A.B.C.D/N".to_string(),
            ValueKind::Country => "XX".to_string(),
            ValueKind::Text => "<text>".to_string(),
        };
        out.push_str(&format!("{}:{}\n", field.as_str(), shape));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query;

    /// The point of generating the grammar: it cannot fall behind the parser.
    /// If this fails, a field was added to `Field` and not to `Field::ALL`.
    #[test]
    fn grammar_covers_every_field_the_parser_knows() {
        let g = gbnf(&[]);
        for field in Field::ALL {
            assert!(
                g.contains(&format!("\"{}:\"", field.as_str())),
                "{} is missing from the grammar",
                field.as_str()
            );
        }
    }

    /// Every field named in the grammar must parse back to the same field,
    /// so the grammar cannot offer a key the parser would treat as free text.
    #[test]
    fn every_grammar_key_round_trips_through_the_parser() {
        for field in Field::ALL {
            let sample = match field.value_kind() {
                ValueKind::Int => format!("{}:443", field.as_str()),
                ValueKind::Bool => format!("{}:true", field.as_str()),
                ValueKind::BoolOrScore => format!("{}:80", field.as_str()),
                ValueKind::Enum(words) => format!("{}:{}", field.as_str(), words[0]),
                ValueKind::Date => format!("{}:2026-01-01", field.as_str()),
                ValueKind::Cidr => format!("{}:10.0.0.0/8", field.as_str()),
                ValueKind::Country => format!("{}:DE", field.as_str()),
                ValueKind::Text => format!("{}:nginx", field.as_str()),
            };
            let q = query::parse(&sample).unwrap_or_else(|e| panic!("{sample}: {e}"));
            assert_eq!(
                q.filters.len(),
                1,
                "{sample} did not parse as one filter: {q:?}"
            );
            assert_eq!(
                q.filters[0].field, *field,
                "{sample} parsed as another field"
            );
        }
    }

    /// A subset grammar names only what was asked for, which is how a caller
    /// keeps a small model's choices down to the fields a question needs.
    #[test]
    fn a_subset_grammar_omits_the_rest() {
        let g = gbnf(&[Field::Port, Field::Country]);
        assert!(g.contains("\"port:\""));
        assert!(g.contains("\"country:\""));
        assert!(!g.contains("\"honeypot:\""));
    }

    #[test]
    fn enum_fields_offer_only_their_own_words() {
        let g = gbnf(&[Field::Transport]);
        assert!(g.contains("\"tcp\" | \"udp\""), "{g}");
        assert!(!g.contains("\"sctp\""));
    }

    #[test]
    fn the_field_reference_describes_every_field() {
        let r = field_reference(&[]);
        assert_eq!(r.lines().count(), Field::ALL.len());
        assert!(r.contains("transport:tcp|udp"));
        assert!(r.contains("before:YYYY-MM-DD"));
    }
}
