//! Dump the generated grammar or field reference, for prototyping and for
//! inspecting what a model will be constrained to.
use crusade_core::grammar::{
    field_reference, field_reference_for_index, gbnf, gbnf_for_index, IndexVocab,
};
use crusade_core::Field;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "ref" => print!("{}", field_reference(&[])),
        "strict" | "strictref" => {
            let vocab = IndexVocab {
                values: vec![
                    (
                        Field::Product,
                        [
                            "nginx",
                            "Apache httpd",
                            "OpenSSH",
                            "Microsoft IIS httpd",
                            "Postfix smtpd",
                            "MySQL",
                            "Redis",
                            "lighttpd",
                            "Jetty",
                            "Dovecot imapd",
                        ]
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                    ),
                    (
                        Field::Tag,
                        ["iot", "database", "webcam", "honeypot", "ics"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                    ),
                ],
            };
            if mode == "strictref" {
                print!("{}", field_reference_for_index(&vocab, true));
            } else {
                print!("{}", gbnf_for_index(&vocab, true));
            }
        }
        _ => print!("{}", gbnf(&[])),
    }
}
