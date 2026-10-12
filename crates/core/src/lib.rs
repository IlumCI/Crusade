//! Crusade core: shared data model and the Shodan-style query language.
//!
//! This crate is deliberately free of I/O and database dependencies so it can
//! be unit-tested in isolation and reused by every other crate.

pub mod lifecycle;
pub mod model;
pub mod query;

pub use model::{
    AuthState, HoneypotAssessment, HoneypotEvidence, Host, HttpInfo, IcsInfo, Service, SshInfo,
    Tag, TlsCert, Transport,
};
pub use query::{parse, Field, Filter, FilterValue, ParseError, Query};
