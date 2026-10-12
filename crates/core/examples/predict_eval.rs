//! Does port prediction earn its keep? Recall against probe budget.
//!
//! ```text
//! cargo run --release -p crusade-core --example predict_eval -- [hosts] [seed_ports] [predict_k]
//! ```
//!
//! The model is learned on one half of a synthetic population and evaluated on
//! the other, so it is never scored on hosts it was trained on. For each test
//! host: probe the seed ports, then probe the ports the model predicts from
//! whatever answered, and count how many of that host's real services were
//! found.
//!
//! The population is synthetic, so treat the numbers as a sanity check on the
//! mechanism — that evidence from one service locates the others — rather than
//! as a measurement of the real internet. GPS (arXiv:2303.00895) reports 92.5%
//! of services at 131x less bandwidth against actual IPv4.

use std::collections::BTreeSet;

use crusade_core::PortModel;

/// Host archetypes: (weight, always-open ports, sometimes-open ports).
const ARCHETYPES: &[(u32, &[u16], &[u16])] = &[
    // Plain web server.
    (30, &[80, 443], &[22, 8080]),
    // Web stack with a database and cache behind it.
    (20, &[80, 443, 3306], &[22, 6379, 9200]),
    // Mail host.
    (12, &[25, 587], &[110, 143, 993, 22]),
    // Windows estate.
    (12, &[445, 3389], &[135, 139, 1433]),
    // Industrial controller: never shares ports with the IT archetypes.
    (8, &[102, 502], &[44818, 47808]),
    // Appliance on odd ports.
    (10, &[8443, 10443], &[22, 9443]),
    // Bare SSH box.
    (8, &[22], &[]),
];

/// Deterministic pseudo-random generator, so runs are comparable.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

fn generate(count: usize, rng: &mut Rng) -> Vec<Vec<u16>> {
    let total_weight: u32 = ARCHETYPES.iter().map(|(w, _, _)| *w).sum();
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut pick = rng.below(total_weight as u64) as u32;
        let (_, always, sometimes) = ARCHETYPES
            .iter()
            .find(|(w, _, _)| {
                if pick < *w {
                    true
                } else {
                    pick -= *w;
                    false
                }
            })
            .unwrap_or(&ARCHETYPES[0]);

        let mut ports: BTreeSet<u16> = always.iter().copied().collect();
        for &p in *sometimes {
            if rng.chance(45) {
                ports.insert(p);
            }
        }
        // A little noise: an occasional service on an arbitrary high port,
        // which nothing can predict and which caps achievable recall.
        if rng.chance(12) {
            ports.insert(20_000 + rng.below(40_000) as u16);
        }
        out.push(ports.into_iter().collect());
    }
    out
}

fn main() {
    let mut args = std::env::args().skip(1);
    let hosts: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(20_000);
    let seed_count: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(8);
    let predict_k: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(16);

    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    let population = generate(hosts, &mut rng);
    let split = population.len() / 2;
    let (train, test) = population.split_at(split);

    let model = PortModel::from_port_sets(train);
    println!(
        "trained on {} hosts ({} distinct ports); evaluating on {}\n",
        model.hosts(),
        model.distinct_ports(),
        test.len()
    );

    // The seed set is learned too, not hard-coded: the most common ports.
    let seed: Vec<u16> = model
        .most_common(seed_count)
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    println!("seed ports (most common in training): {seed:?}\n");

    let total_services: usize = test.iter().map(|p| p.len()).sum();
    let mut seed_found = 0usize;
    let mut predicted_found = 0usize;
    let mut discovered_hosts = 0usize;
    let mut predict_probes = 0usize;

    for ports in test {
        let have: BTreeSet<u16> = ports.iter().copied().collect();
        let observed: Vec<u16> = seed.iter().copied().filter(|p| have.contains(p)).collect();
        seed_found += observed.len();
        if observed.is_empty() {
            // Nothing answered, so there is nothing to predict from. This is
            // the known weakness of a two-phase design.
            continue;
        }
        discovered_hosts += 1;
        let predicted: Vec<u16> = model
            .predict(&observed, predict_k)
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        predict_probes += predicted.len();
        predicted_found += predicted.iter().filter(|p| have.contains(p)).count();
    }

    let seed_probes = test.len() * seed.len();
    let exhaustive = test.len() * 65_535;
    let pct = |n: usize| 100.0 * n as f64 / total_services as f64;

    println!("{total_services} real services on {} hosts", test.len());
    println!(
        "  seed only        {:>8} probes  {:>7} services  {:>5.1}% recall",
        seed_probes,
        seed_found,
        pct(seed_found)
    );
    println!(
        "  seed + predict   {:>8} probes  {:>7} services  {:>5.1}% recall",
        seed_probes + predict_probes,
        seed_found + predicted_found,
        pct(seed_found + predicted_found)
    );
    println!(
        "  every port       {:>8} probes  {:>7} services  100.0% recall",
        exhaustive, total_services
    );
    println!(
        "\nprediction added {:.1} points of recall for {:.1}x the seed probes,\n\
         and reaches {:.1}% of exhaustive recall using {:.0}x less bandwidth.",
        pct(predicted_found),
        (seed_probes + predict_probes) as f64 / seed_probes as f64,
        pct(seed_found + predicted_found),
        exhaustive as f64 / (seed_probes + predict_probes) as f64
    );
    println!(
        "{} of {} test hosts answered on a seed port; the rest are invisible to\n\
         a two-phase scan and bound what any amount of prediction can recover.",
        discovered_hosts,
        test.len()
    );
}
