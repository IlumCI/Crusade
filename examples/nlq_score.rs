//! Score the question translators against the benchmarks in
//! `crusade_core::nlq`.
//!
//! `cargo run --example nlq_score` measures the cue translator.
//! `cargo run --features llm --example nlq_score -- <model.gguf>` also
//! measures the grammar-constrained local model, on the same questions, so the
//! claim that one beats the other on paraphrases can be checked rather than
//! believed.
//!
//! BENCHMARK is the questions the cue phrases were written for.
//! BENCHMARK_HARD is paraphrases nobody would add a cue for, which is where a
//! model has to earn its download.

use crusade_core::nlq::{score_set, translate, BENCHMARK, BENCHMARK_HARD};
use crusade_core::Query;

fn main() {
    let model_path = std::env::args().nth(1);
    for (label, set) in [("cue phrases", BENCHMARK), ("paraphrases", BENCHMARK_HARD)] {
        println!("== {label}");
        report("cue translator", set, |q| translate(q).query);
        if let Some(path) = &model_path {
            model_report(path, set);
        }
        println!();
    }
}

fn report<F: Fn(&str) -> Query>(engine: &str, set: &[(&str, &[&str])], translate: F) {
    // Translated once and reused: with the model engine each call is seconds,
    // and scoring a question twice would double the measurement for nothing.
    let answers: Vec<Query> = set.iter().map(|(q, _)| translate(q)).collect();
    let (exact, partial, total) = score_set(set, |q| {
        set.iter()
            .position(|(s, _)| s == &q)
            .map(|i| answers[i].clone())
            .unwrap_or_default()
    });
    println!("{engine}: {exact} exact, {partial} partial, of {total}");
    for ((question, expected), got) in set.iter().zip(&answers) {
        println!(
            "   {question}\n     got  {got}\n     want {}",
            expected.join(" ")
        );
    }
}

#[cfg(feature = "llm")]
fn model_report(path: &str, set: &[(&str, &[&str])]) {
    use crusade_core::grammar::IndexVocab;
    use crusade_core::Field;

    // The vocabulary a populated index would supply, fixed here so the
    // measurement does not depend on which hosts happen to be indexed.
    let words = |list: &[&str]| -> Vec<String> { list.iter().map(|s| s.to_string()).collect() };
    let vocab = IndexVocab {
        values: vec![
            (
                Field::Product,
                words(&[
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
                ]),
            ),
            (
                Field::Tag,
                words(&["iot", "database", "webcam", "honeypot", "ics"]),
            ),
        ],
    };

    let threads = std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(4);
    let model = match crusade_llm::QueryModel::load(std::path::Path::new(path), threads) {
        Ok(m) => m,
        Err(e) => {
            println!("query model: could not load {path}: {e}");
            return;
        }
    };
    let started = std::time::Instant::now();
    report("query model", set, |q: &str| -> Query {
        model
            .translate(q, &vocab, 1, 0.0)
            .ok()
            .and_then(|c| c.first().map(|c| c.query.clone()))
            .unwrap_or_default()
    });
    println!(
        "query model: {:.1}s for {} question(s)",
        started.elapsed().as_secs_f64(),
        set.len()
    );
}

#[cfg(not(feature = "llm"))]
fn model_report(_path: &str, _set: &[(&str, &[&str])]) {
    println!("query model: this build has no model engine (rebuild with --features llm)");
}
