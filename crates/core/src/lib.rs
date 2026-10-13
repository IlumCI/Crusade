//! Crusade core: shared data model and the Shodan-style query language.
//!
//! This crate is deliberately free of I/O and database dependencies so it can
//! be unit-tested in isolation and reused by every other crate.

pub mod anomaly;
pub mod grammar;
pub mod graph;
pub mod lifecycle;
pub mod model;
pub mod nlq;
pub mod pivot;
pub mod ports;
pub mod query;
pub mod revisit;
pub mod schedule;

pub use anomaly::{Anomaly, Population};
pub use graph::{Cluster, Identifier, LinkKind, Linker};
pub use model::{
    AuthState, HoneypotAssessment, HoneypotEvidence, Host, HttpInfo, IcsInfo, Latency, Service,
    SshInfo, Tag, TlsCert, Transport,
};
pub use ports::PortModel;
pub use query::{parse, Field, Filter, FilterValue, ParseError, Query};
pub use schedule::{cloud_asn, PortPermutation, Tier, TierBudget};
