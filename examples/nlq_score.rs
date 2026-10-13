//! Score the question translator against the benchmark in `crusade_core::nlq`.
//!
//! Run with `cargo run --example nlq_score`. The module doc claims a number;
//! this is how the number is obtained, so it can be checked rather than
//! believed.

fn main() {
    let (exact, partial, total) =
        crusade_core::nlq::score(|q| crusade_core::nlq::translate(q).query);
    println!("cue translator: {exact} exact, {partial} partial, of {total}\n");

    for (question, expected) in crusade_core::nlq::BENCHMARK {
        let t = crusade_core::nlq::translate(question);
        let got = t.query.to_string();
        let want = expected.join(" ");
        let mark = if expected
            .iter()
            .all(|e| got.to_lowercase().contains(&e.to_lowercase()))
            && t.query.filters.len() == expected.len()
        {
            " "
        } else {
            "x"
        };
        println!("{mark} {question}\n    got  {got}\n    want {want}");
    }
}
