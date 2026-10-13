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
    gbnf_with(fields, true)
}

/// Build the grammar, optionally without the free-text alternative.
///
/// Free text is part of the query language — a bare word is matched against
/// banners — but including it in a grammar used for *generation* makes the
/// grammar almost vacuous: every sentence is a valid query, so the constraint
/// stops constraining and a small model is free to echo the question back.
/// Measured with Qwen2.5-0.5B, that is exactly what it does. For generation,
/// pass `free_text: false` and let the caller decide what to do with a
/// question the model could not express as filters.
pub fn gbnf_with(fields: &[Field], free_text: bool) -> String {
    let fields: Vec<Field> = if fields.is_empty() {
        Field::ALL.to_vec()
    } else {
        fields.to_vec()
    };

    let mut out = String::new();
    out.push_str("# Generated from crusade_core::query. Do not edit by hand.\n");
    // The optional leading space is not cosmetic. A model completing
    // `Query:` wants to emit a space-prefixed piece, which is how its
    // tokenizer represents the start of a word. Forbid that and every such
    // piece is masked at the first position, so generation falls to whatever
    // unprefixed key happens to rank highest — measured with Qwen2.5-1.5B,
    // that was a spurious `ics:modbus` in front of seven of eight otherwise
    // reasonable queries, which no amount of prompting removed. The parser
    // skips leading whitespace anyway.
    out.push_str("root ::= \" \"? term (\" \" term)*\n");

    // A term is a filter or a free-text word. Negation is a prefix on filters
    // only, matching the parser: `-port:22` is a filter, `-nginx` is text.
    let mut alts: Vec<String> = Vec::new();
    for (i, _) in fields.iter().enumerate() {
        alts.push(format!("filter{i}"));
    }
    if free_text {
        alts.push("text".to_string());
    }
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
    if free_text {
        out.push_str("text ::= word | phrase\n");
    }

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

/// Literal values a field may take, drawn from the index being searched.
///
/// The grammar alone cannot stop a model writing a filter whose value exists
/// nowhere: `product:nginx` and `product:boxes` are equally well formed, and a
/// small model asked to translate `boxes in the netherlands nobody needs a
/// password for` will reach for a free-text field and put `boxes` in it —
/// measured with Qwen2.5-1.5B, which produced `ics:boxes`, `ics:databases`
/// and `ics:mail` on three consecutive questions.
///
/// Restricting each free-text field to the values the index has actually seen
/// closes that off. `product:nginx` stays possible because nginx is in the
/// index; `product:boxes` becomes unrepresentable. It also changes what an
/// empty result means: a query whose every value exists somewhere in the index
/// returns nothing because no host matches the *combination*, not because the
/// translation was nonsense.
///
/// This is the same principle as CPE resolution in `crusade-vuln`: candidates
/// come from the data, never from free text.
#[derive(Debug, Clone, Default)]
pub struct IndexVocab {
    /// `(field, values)`. A field absent here keeps its generic value rule.
    pub values: Vec<(Field, Vec<String>)>,
}

impl IndexVocab {
    /// Values for one field, if any were supplied.
    fn get(&self, field: Field) -> Option<&[String]> {
        self.values
            .iter()
            .find(|(f, _)| *f == field)
            .map(|(_, v)| v.as_slice())
            .filter(|v| !v.is_empty())
    }
}

/// Build a grammar whose free-text values are restricted to what the index
/// holds (see [`IndexVocab`]).
///
/// A field with a supplied vocabulary can only take one of those values. A
/// field with none is dropped entirely when `strict`, since a field the index
/// has no values for cannot match anything anyway, and offering it only gives
/// a model somewhere wrong to put a word.
pub fn gbnf_for_index(vocab: &IndexVocab, strict: bool) -> String {
    let fields = index_fields(vocab, strict);
    let mut out = gbnf_with(&fields, false);
    for (i, field) in fields.iter().enumerate() {
        if field.value_kind() != ValueKind::Text {
            continue;
        }
        let Some(values) = vocab.get(*field) else {
            continue;
        };
        // One alternative per value, each a literal, so nothing outside the
        // list can be generated. Values are capped: a grammar with ten
        // thousand alternatives costs more to compile than it saves.
        let alts: Vec<String> = values
            .iter()
            .take(MAX_VOCAB_ALTERNATIVES)
            .map(|v| format!("\"{}\"", escape_literal(v)))
            .collect();
        if alts.is_empty() {
            continue;
        }
        out.push_str(&format!("vocab{i} ::= {}\n", alts.join(" | ")));
        out = out.replace(
            &format!("filter{i} ::= \"-\"? \"{}:\" value", field.as_str()),
            &format!("filter{i} ::= \"-\"? \"{}:\" vocab{i}", field.as_str()),
        );
    }
    out
}

/// The fields a restricted grammar will contain.
///
/// Exposed because a prompt that describes fields the grammar does not accept
/// is worse than no prompt at all: the model aims at a field it cannot use,
/// the grammar refuses the token, and generation lands on whatever the grammar
/// *does* allow next. Measured with Qwen2.5-1.5B against a prompt listing all
/// 29 fields and a grammar allowing 18, every one of eight questions came back
/// with a spurious `ics:` filter. Describing exactly the allowed fields fixed
/// it. So callers build their prompt from this, not from `Field::ALL`.
pub fn index_fields(vocab: &IndexVocab, strict: bool) -> Vec<Field> {
    Field::ALL
        .iter()
        .copied()
        .filter(|f| !strict || f.value_kind() != ValueKind::Text || vocab.get(*f).is_some())
        .collect()
}

/// A field reference describing exactly a restricted grammar's fields, with
/// each free-text field's allowed values spelled out.
pub fn field_reference_for_index(vocab: &IndexVocab, strict: bool) -> String {
    let fields = index_fields(vocab, strict);
    let mut out = String::new();
    for field in fields {
        if field.value_kind() == ValueKind::Text {
            if let Some(values) = vocab.get(field) {
                let shown: Vec<&str> = values.iter().take(12).map(|v| v.as_str()).collect();
                out.push_str(&format!("{}:{}", field.as_str(), shown.join("|")));
                if values.len() > shown.len() {
                    out.push_str(&format!("|… ({} values)", values.len()));
                }
                out.push('\n');
                continue;
            }
        }
        out.push_str(&field_reference(&[field]));
    }
    out
}

/// Values per field in a generated grammar. Beyond this the grammar takes
/// longer to compile than the generation it constrains.
pub const MAX_VOCAB_ALTERNATIVES: usize = 256;

/// Escape a value for a GBNF string literal, and reject what cannot be
/// escaped safely.
fn escape_literal(v: &str) -> String {
    v.chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '"' => "\\\"".to_string(),
            '\\' => "\\\\".to_string(),
            c => c.to_string(),
        })
        .collect()
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
    /// A model's tokenizer puts the space in front of the word, so the first
    /// position has to accept one.
    #[test]
    fn the_root_accepts_a_leading_space() {
        assert!(gbnf(&[]).contains("root ::= \" \"? term"), "{}", gbnf(&[]));
    }

    #[test]
    fn a_subset_grammar_omits_the_rest() {
        let g = gbnf(&[Field::Port, Field::Country]);
        assert!(g.contains("\"port:\""));
        assert!(g.contains("\"country:\""));
        assert!(!g.contains("\"honeypot:\""));
    }

    /// The generation grammar must not accept an arbitrary sentence, or it
    /// constrains nothing and the model echoes the question.
    #[test]
    fn without_free_text_a_sentence_is_not_a_query() {
        let g = gbnf_with(&[], false);
        assert!(!g.contains("| text"), "{g}");
        assert!(!g.contains("text ::="), "{g}");
        assert!(gbnf(&[]).contains("text ::="));
    }

    fn vocab() -> IndexVocab {
        IndexVocab {
            values: vec![
                (
                    Field::Product,
                    vec!["nginx".to_string(), "Apache httpd".to_string()],
                ),
                (Field::Tag, vec!["iot".to_string()]),
            ],
        }
    }

    /// A value the index has never seen must be unrepresentable, which is the
    /// whole point: `product:boxes` is well-formed English and a mistake.
    #[test]
    fn a_restricted_grammar_offers_only_the_values_the_index_has() {
        let g = gbnf_for_index(&vocab(), true);
        assert!(g.contains("\"nginx\""), "{g}");
        assert!(g.contains("\"Apache httpd\""), "{g}");
        assert!(!g.contains("boxes"));
        // The product filter must reference the restricted rule, not `value`.
        let line = g
            .lines()
            .find(|l| l.contains("\"product:\""))
            .unwrap_or_default();
        assert!(line.contains("vocab"), "{line}");
    }

    /// A free-text field with nothing behind it in this index is dropped: it
    /// could not match anything, and offering it only gives a model somewhere
    /// wrong to put a word.
    #[test]
    fn fields_with_no_values_are_dropped_when_strict() {
        let g = gbnf_for_index(&vocab(), true);
        assert!(g.contains("\"product:\""));
        assert!(!g.contains("\"org:\""), "{g}");
        // Typed fields are never dropped: their values do not come from the
        // index.
        assert!(g.contains("\"port:\""));
        assert!(g.contains("\"country:\""));
        assert!(g.contains("\"has_vuln:\""));
    }

    #[test]
    fn a_lenient_restricted_grammar_keeps_every_field() {
        let g = gbnf_for_index(&vocab(), false);
        assert!(g.contains("\"org:\""), "{g}");
        assert!(g.contains("\"nginx\""));
    }

    #[test]
    fn a_quote_in_a_value_cannot_break_out_of_the_literal() {
        let v = IndexVocab {
            values: vec![(Field::Product, vec!["we\"ird".to_string()])],
        };
        let g = gbnf_for_index(&v, true);
        assert!(g.contains("we\\\"ird"), "{g}");
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
