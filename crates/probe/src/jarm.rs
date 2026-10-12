//! JARM — an active TLS server fingerprint.
//!
//! JARM (Althouse/Smart/Nunaly/Brady, Salesforce, 2020) probes a TLS server
//! with ten carefully varied `ClientHello` messages — different TLS versions,
//! cipher orderings, GREASE, ALPN sets and extension orders — and records how
//! the server responds: which cipher and version it selects and which
//! extensions it echoes. The ten responses are distilled into a 62-character
//! fingerprint (30 characters of a per-hello fuzzy hash over cipher+version,
//! then the first 32 characters of a SHA-256 over the concatenated ALPN and
//! extension data). Two servers running the same stack, configured the same
//! way, yield the same JARM — a strong pivot and a crisp anomaly signal.
//!
//! This is a faithful port of the public reference implementation
//! (`github.com/salesforce/jarm`, BSD-3-Clause). We send only standards-shaped
//! `ClientHello` records as raw bytes over TCP and read a single ServerHello
//! back — no handshake is completed, nothing beyond the hello is ever written.
//! The 32 "random" bytes a `ClientHello` carries do not influence the result,
//! so the packet builder takes a pluggable [`Entropy`] source, which keeps it
//! deterministic under test.

use std::net::IpAddr;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The canonical "nothing responded" fingerprint: 62 zeros.
pub const EMPTY_JARM: &str = "00000000000000000000000000000000000000000000000000000000000000";

/// The pre-hash string produced when every one of the ten probes failed.
const ALL_EMPTY_RAW: &str = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||";

/// Valid GREASE placeholder values (RFC 8701), as 2-byte pairs.
const GREASE_VALUES: [[u8; 2]; 16] = [
    [0x0a, 0x0a],
    [0x1a, 0x1a],
    [0x2a, 0x2a],
    [0x3a, 0x3a],
    [0x4a, 0x4a],
    [0x5a, 0x5a],
    [0x6a, 0x6a],
    [0x7a, 0x7a],
    [0x8a, 0x8a],
    [0x9a, 0x9a],
    [0xaa, 0xaa],
    [0xba, 0xba],
    [0xca, 0xca],
    [0xda, 0xda],
    [0xea, 0xea],
    [0xfa, 0xfa],
];

/// Source of the (hash-irrelevant) random bytes and GREASE values a JARM
/// `ClientHello` carries. Abstracted so the packet builder is deterministic
/// and unit-testable.
pub trait Entropy {
    /// Fill `buf` with bytes (cryptographic quality is not required).
    fn fill(&mut self, buf: &mut [u8]);
    /// Return a GREASE value.
    fn grease(&mut self) -> [u8; 2];
}

/// A tiny non-cryptographic PRNG (xorshift64) used in production. The bytes it
/// produces never affect the fingerprint; they only need to vary.
pub struct Xorshift(u64);

impl Xorshift {
    /// Seed the generator (any non-zero seed works; zero is coerced).
    pub fn new(seed: u64) -> Self {
        Xorshift(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

impl Entropy for Xorshift {
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            for (b, v) in chunk.iter_mut().zip(bytes) {
                *b = v;
            }
        }
    }

    fn grease(&mut self) -> [u8; 2] {
        GREASE_VALUES[(self.next_u64() as usize) % GREASE_VALUES.len()]
    }
}

/// TLS version a probe advertises at the record/hello layer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Version {
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

/// Which cipher list a probe offers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CipherList {
    All,
    No13,
}

/// Ordering transform applied to ciphers, ALPN entries and versions.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Order {
    Forward,
    Reverse,
    TopHalf,
    BottomHalf,
    MiddleOut,
}

/// ALPN set a probe offers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Alpn {
    Std,
    Rare,
}

/// `supported_versions` extension behaviour for a probe.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Support {
    V12,
    None,
    V13,
}

/// One of the ten JARM probe specifications.
struct Probe {
    version: Version,
    ciphers: CipherList,
    cipher_order: Order,
    grease: bool,
    alpn: Alpn,
    support: Support,
    ext_order: Order,
}

/// The ten probes, in the canonical JARM order.
fn probes() -> [Probe; 10] {
    use Alpn::*;
    use CipherList::*;
    use Order::*;
    use Support::*;
    use Version::*;
    [
        // tls1_2_forward
        Probe {
            version: Tls1_2,
            ciphers: All,
            cipher_order: Forward,
            grease: false,
            alpn: Std,
            support: V12,
            ext_order: Reverse,
        },
        // tls1_2_reverse
        Probe {
            version: Tls1_2,
            ciphers: All,
            cipher_order: Reverse,
            grease: false,
            alpn: Std,
            support: V12,
            ext_order: Forward,
        },
        // tls1_2_top_half
        Probe {
            version: Tls1_2,
            ciphers: All,
            cipher_order: TopHalf,
            grease: false,
            alpn: Std,
            support: None,
            ext_order: Forward,
        },
        // tls1_2_bottom_half
        Probe {
            version: Tls1_2,
            ciphers: All,
            cipher_order: BottomHalf,
            grease: false,
            alpn: Rare,
            support: None,
            ext_order: Forward,
        },
        // tls1_2_middle_out
        Probe {
            version: Tls1_2,
            ciphers: All,
            cipher_order: MiddleOut,
            grease: true,
            alpn: Rare,
            support: None,
            ext_order: Reverse,
        },
        // tls1_1_middle_out (name is historical; order is FORWARD)
        Probe {
            version: Tls1_1,
            ciphers: All,
            cipher_order: Forward,
            grease: false,
            alpn: Std,
            support: None,
            ext_order: Forward,
        },
        // tls1_3_forward
        Probe {
            version: Tls1_3,
            ciphers: All,
            cipher_order: Forward,
            grease: false,
            alpn: Std,
            support: V13,
            ext_order: Reverse,
        },
        // tls1_3_reverse
        Probe {
            version: Tls1_3,
            ciphers: All,
            cipher_order: Reverse,
            grease: false,
            alpn: Std,
            support: V13,
            ext_order: Forward,
        },
        // tls1_3_invalid
        Probe {
            version: Tls1_3,
            ciphers: No13,
            cipher_order: Forward,
            grease: false,
            alpn: Std,
            support: V13,
            ext_order: Forward,
        },
        // tls1_3_middle_out
        Probe {
            version: Tls1_3,
            ciphers: All,
            cipher_order: MiddleOut,
            grease: true,
            alpn: Std,
            support: V13,
            ext_order: Reverse,
        },
    ]
}

/// The full cipher offering (`ALL`), in JARM's order.
const CIPHERS_ALL: &[[u8; 2]] = &[
    [0x00, 0x16],
    [0x00, 0x33],
    [0x00, 0x67],
    [0xc0, 0x9e],
    [0xc0, 0xa2],
    [0x00, 0x9e],
    [0x00, 0x39],
    [0x00, 0x6b],
    [0xc0, 0x9f],
    [0xc0, 0xa3],
    [0x00, 0x9f],
    [0x00, 0x45],
    [0x00, 0xbe],
    [0x00, 0x88],
    [0x00, 0xc4],
    [0x00, 0x9a],
    [0xc0, 0x08],
    [0xc0, 0x09],
    [0xc0, 0x23],
    [0xc0, 0xac],
    [0xc0, 0xae],
    [0xc0, 0x2b],
    [0xc0, 0x0a],
    [0xc0, 0x24],
    [0xc0, 0xad],
    [0xc0, 0xaf],
    [0xc0, 0x2c],
    [0xc0, 0x72],
    [0xc0, 0x73],
    [0xcc, 0xa9],
    [0x13, 0x02],
    [0x13, 0x01],
    [0xcc, 0x14],
    [0xc0, 0x07],
    [0xc0, 0x12],
    [0xc0, 0x13],
    [0xc0, 0x27],
    [0xc0, 0x2f],
    [0xc0, 0x14],
    [0xc0, 0x28],
    [0xc0, 0x30],
    [0xc0, 0x60],
    [0xc0, 0x61],
    [0xc0, 0x76],
    [0xc0, 0x77],
    [0xcc, 0xa8],
    [0x13, 0x05],
    [0x13, 0x04],
    [0x13, 0x03],
    [0xcc, 0x13],
    [0xc0, 0x11],
    [0x00, 0x0a],
    [0x00, 0x2f],
    [0x00, 0x3c],
    [0xc0, 0x9c],
    [0xc0, 0xa0],
    [0x00, 0x9c],
    [0x00, 0x35],
    [0x00, 0x3d],
    [0xc0, 0x9d],
    [0xc0, 0xa1],
    [0x00, 0x9d],
    [0x00, 0x41],
    [0x00, 0xba],
    [0x00, 0x84],
    [0x00, 0xc0],
    [0x00, 0x07],
    [0x00, 0x04],
    [0x00, 0x05],
];

/// The `NO1.3` cipher offering (TLS 1.3 suites removed), in JARM's order.
const CIPHERS_NO13: &[[u8; 2]] = &[
    [0x00, 0x16],
    [0x00, 0x33],
    [0x00, 0x67],
    [0xc0, 0x9e],
    [0xc0, 0xa2],
    [0x00, 0x9e],
    [0x00, 0x39],
    [0x00, 0x6b],
    [0xc0, 0x9f],
    [0xc0, 0xa3],
    [0x00, 0x9f],
    [0x00, 0x45],
    [0x00, 0xbe],
    [0x00, 0x88],
    [0x00, 0xc4],
    [0x00, 0x9a],
    [0xc0, 0x08],
    [0xc0, 0x09],
    [0xc0, 0x23],
    [0xc0, 0xac],
    [0xc0, 0xae],
    [0xc0, 0x2b],
    [0xc0, 0x0a],
    [0xc0, 0x24],
    [0xc0, 0xad],
    [0xc0, 0xaf],
    [0xc0, 0x2c],
    [0xc0, 0x72],
    [0xc0, 0x73],
    [0xcc, 0xa9],
    [0xcc, 0x14],
    [0xc0, 0x07],
    [0xc0, 0x12],
    [0xc0, 0x13],
    [0xc0, 0x27],
    [0xc0, 0x2f],
    [0xc0, 0x14],
    [0xc0, 0x28],
    [0xc0, 0x30],
    [0xc0, 0x60],
    [0xc0, 0x61],
    [0xc0, 0x76],
    [0xc0, 0x77],
    [0xcc, 0xa8],
    [0xcc, 0x13],
    [0xc0, 0x11],
    [0x00, 0x0a],
    [0x00, 0x2f],
    [0x00, 0x3c],
    [0xc0, 0x9c],
    [0xc0, 0xa0],
    [0x00, 0x9c],
    [0x00, 0x35],
    [0x00, 0x3d],
    [0xc0, 0x9d],
    [0xc0, 0xa1],
    [0x00, 0x9d],
    [0x00, 0x41],
    [0x00, 0xba],
    [0x00, 0x84],
    [0x00, 0xc0],
    [0x00, 0x07],
    [0x00, 0x04],
    [0x00, 0x05],
];

/// Cipher list used by the fuzzy hash. The index (1-based) of the server's
/// selected cipher in *this* list becomes two hex characters.
const CIPHER_INDEX: &[[u8; 2]] = &[
    [0x00, 0x04],
    [0x00, 0x05],
    [0x00, 0x07],
    [0x00, 0x0a],
    [0x00, 0x16],
    [0x00, 0x2f],
    [0x00, 0x33],
    [0x00, 0x35],
    [0x00, 0x39],
    [0x00, 0x3c],
    [0x00, 0x3d],
    [0x00, 0x41],
    [0x00, 0x45],
    [0x00, 0x67],
    [0x00, 0x6b],
    [0x00, 0x84],
    [0x00, 0x88],
    [0x00, 0x9a],
    [0x00, 0x9c],
    [0x00, 0x9d],
    [0x00, 0x9e],
    [0x00, 0x9f],
    [0x00, 0xba],
    [0x00, 0xbe],
    [0x00, 0xc0],
    [0x00, 0xc4],
    [0xc0, 0x07],
    [0xc0, 0x08],
    [0xc0, 0x09],
    [0xc0, 0x0a],
    [0xc0, 0x11],
    [0xc0, 0x12],
    [0xc0, 0x13],
    [0xc0, 0x14],
    [0xc0, 0x23],
    [0xc0, 0x24],
    [0xc0, 0x27],
    [0xc0, 0x28],
    [0xc0, 0x2b],
    [0xc0, 0x2c],
    [0xc0, 0x2f],
    [0xc0, 0x30],
    [0xc0, 0x60],
    [0xc0, 0x61],
    [0xc0, 0x72],
    [0xc0, 0x73],
    [0xc0, 0x76],
    [0xc0, 0x77],
    [0xc0, 0x9c],
    [0xc0, 0x9d],
    [0xc0, 0x9e],
    [0xc0, 0x9f],
    [0xc0, 0xa0],
    [0xc0, 0xa1],
    [0xc0, 0xa2],
    [0xc0, 0xa3],
    [0xc0, 0xac],
    [0xc0, 0xad],
    [0xc0, 0xae],
    [0xc0, 0xaf],
    [0xcc, 0x13],
    [0xcc, 0x14],
    [0xcc, 0xa8],
    [0xcc, 0xa9],
    [0x13, 0x01],
    [0x13, 0x02],
    [0x13, 0x03],
    [0x13, 0x04],
    [0x13, 0x05],
];

/// The fixed `signature_algorithms` extension body.
const SIGNATURE_ALGORITHMS: &[u8] = &[
    0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05,
    0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
];

fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Reorder `items` per `order`, a faithful port of the reference `cipher_mung`.
fn mung<T: Clone>(items: &[T], order: Order) -> Vec<T> {
    let n = items.len();
    match order {
        Order::Forward => items.to_vec(),
        Order::Reverse => items.iter().rev().cloned().collect(),
        Order::BottomHalf => {
            if n % 2 == 1 {
                items[n / 2 + 1..].to_vec()
            } else {
                items[n / 2..].to_vec()
            }
        }
        Order::TopHalf => {
            let mut out = Vec::new();
            if n % 2 == 1 {
                out.push(items[n / 2].clone());
            }
            let rev = mung(items, Order::Reverse);
            out.extend(mung(&rev, Order::BottomHalf));
            out
        }
        Order::MiddleOut => {
            let mut out = Vec::new();
            let middle = n / 2;
            if n % 2 == 1 {
                out.push(items[middle].clone());
                for i in 1..=middle {
                    out.push(items[middle + i].clone());
                    out.push(items[middle - i].clone());
                }
            } else {
                for i in 1..=middle {
                    out.push(items[middle - 1 + i].clone());
                    out.push(items[middle - i].clone());
                }
            }
            out
        }
    }
}

/// Build the cipher-suites block for a probe.
fn get_ciphers(p: &Probe, e: &mut dyn Entropy) -> Vec<u8> {
    let base = match p.ciphers {
        CipherList::All => CIPHERS_ALL,
        CipherList::No13 => CIPHERS_NO13,
    };
    let mut list: Vec<[u8; 2]> = base.to_vec();
    if p.cipher_order != Order::Forward {
        list = mung(&list, p.cipher_order);
    }
    if p.grease {
        list.insert(0, e.grease());
    }
    list.into_iter().flatten().collect()
}

/// `server_name` extension for `host`.
fn extension_server_name(host: &str) -> Vec<u8> {
    let host = host.as_bytes();
    let mut ext = vec![0x00, 0x00];
    push_u16(&mut ext, (host.len() + 5) as u16);
    push_u16(&mut ext, (host.len() + 3) as u16);
    ext.push(0x00);
    push_u16(&mut ext, host.len() as u16);
    ext.extend_from_slice(host);
    ext
}

/// One ALPN protocol, length-prefixed as it appears on the wire.
fn alpn_entry(proto: &str) -> Vec<u8> {
    let mut v = vec![proto.len() as u8];
    v.extend_from_slice(proto.as_bytes());
    v
}

/// `application_layer_protocol_negotiation` extension for a probe.
fn app_layer_proto_negotiation(p: &Probe) -> Vec<u8> {
    let protos: &[&str] = match p.alpn {
        Alpn::Rare => &[
            "http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "hq",
        ],
        Alpn::Std => &[
            "http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "h2", "h2c", "hq",
        ],
    };
    let mut entries: Vec<Vec<u8>> = protos.iter().map(|s| alpn_entry(s)).collect();
    if p.ext_order != Order::Forward {
        entries = mung(&entries, p.ext_order);
    }
    let all: Vec<u8> = entries.into_iter().flatten().collect();

    let mut ext = vec![0x00, 0x10];
    push_u16(&mut ext, (all.len() + 2) as u16);
    push_u16(&mut ext, all.len() as u16);
    ext.extend_from_slice(&all);
    ext
}

/// `key_share` extension (a single x25519 share, optionally GREASE-prefixed).
fn key_share(grease: Option<[u8; 2]>, e: &mut dyn Entropy) -> Vec<u8> {
    let mut share = Vec::new();
    if let Some(g) = grease {
        share.extend_from_slice(&g);
        share.extend_from_slice(&[0x00, 0x01, 0x00]);
    }
    share.extend_from_slice(&[0x00, 0x1d]); // group x25519
    share.extend_from_slice(&[0x00, 0x20]); // key length 32
    let mut key = [0u8; 32];
    e.fill(&mut key);
    share.extend_from_slice(&key);

    let mut ext = vec![0x00, 0x33];
    push_u16(&mut ext, (share.len() + 2) as u16);
    push_u16(&mut ext, share.len() as u16);
    ext.extend_from_slice(&share);
    ext
}

/// `supported_versions` extension for a probe.
fn supported_versions(p: &Probe, grease: Option<[u8; 2]>) -> Vec<u8> {
    let mut tls: Vec<[u8; 2]> = if p.support == Support::V12 {
        vec![[0x03, 0x01], [0x03, 0x02], [0x03, 0x03]]
    } else {
        vec![[0x03, 0x01], [0x03, 0x02], [0x03, 0x03], [0x03, 0x04]]
    };
    if p.ext_order != Order::Forward {
        tls = mung(&tls, p.ext_order);
    }
    let mut versions = Vec::new();
    if let Some(g) = grease {
        versions.extend_from_slice(&g);
    }
    for v in &tls {
        versions.extend_from_slice(v);
    }

    let mut ext = vec![0x00, 0x2b];
    push_u16(&mut ext, (versions.len() + 1) as u16);
    ext.push(versions.len() as u8);
    ext.extend_from_slice(&versions);
    ext
}

/// Assemble the extensions block for a probe.
fn get_extensions(p: &Probe, host: &str, e: &mut dyn Entropy) -> Vec<u8> {
    let mut all = Vec::new();
    let greased = p.grease;
    if greased {
        all.extend_from_slice(&e.grease());
        all.extend_from_slice(&[0x00, 0x00]);
    }
    all.extend_from_slice(&extension_server_name(host));
    all.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // extended_master_secret
    all.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x01]); // max_fragment_length
    all.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]); // renegotiation_info
    all.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
    ]); // supported_groups
    all.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]); // ec_point_formats
    all.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]); // session_ticket
    all.extend_from_slice(&app_layer_proto_negotiation(p));
    all.extend_from_slice(SIGNATURE_ALGORITHMS);
    all.extend_from_slice(&key_share(if greased { Some(e.grease()) } else { None }, e));
    all.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]); // psk_key_exchange_modes
    if p.version == Version::Tls1_3 || p.support == Support::V12 {
        all.extend_from_slice(&supported_versions(
            p,
            if greased { Some(e.grease()) } else { None },
        ));
    }

    let mut ext = Vec::new();
    push_u16(&mut ext, all.len() as u16);
    ext.extend_from_slice(&all);
    ext
}

/// Build a complete JARM `ClientHello` record for a probe.
fn build_packet(p: &Probe, host: &str, e: &mut dyn Entropy) -> Vec<u8> {
    let (record_ver, hello_ver): ([u8; 2], [u8; 2]) = match p.version {
        Version::Tls1_3 => ([0x03, 0x01], [0x03, 0x03]),
        Version::Tls1_1 => ([0x03, 0x02], [0x03, 0x02]),
        Version::Tls1_2 => ([0x03, 0x03], [0x03, 0x03]),
    };

    let mut hello = Vec::new();
    hello.extend_from_slice(&hello_ver);
    let mut random = [0u8; 32];
    e.fill(&mut random);
    hello.extend_from_slice(&random);
    let mut session_id = [0u8; 32];
    e.fill(&mut session_id);
    hello.push(session_id.len() as u8);
    hello.extend_from_slice(&session_id);

    let ciphers = get_ciphers(p, e);
    push_u16(&mut hello, ciphers.len() as u16);
    hello.extend_from_slice(&ciphers);
    hello.push(0x01); // compression methods length
    hello.push(0x00); // null compression
    hello.extend_from_slice(&get_extensions(p, host, e));

    // Handshake header: type(1) + length(3) + body.
    let mut handshake = vec![0x01, 0x00];
    push_u16(&mut handshake, hello.len() as u16);
    handshake.extend_from_slice(&hello);

    // TLS record: type(1) + version(2) + length(2) + handshake.
    let mut payload = vec![0x16];
    payload.extend_from_slice(&record_ver);
    push_u16(&mut payload, handshake.len() as u16);
    payload.extend_from_slice(&handshake);
    payload
}

/// Interpret a server's reply into the `cipher|version|alpn|exts` record.
///
/// A faithful port of the reference `read_packet`/`extract_extension_info`:
/// any failure to parse yields the empty record `"|||"`.
fn read_packet(data: &[u8]) -> String {
    const FAIL: &str = "|||";
    // Alert, or too short, or not a handshake ServerHello.
    if data.len() < 6 {
        return FAIL.to_string();
    }
    if data[0] == 21 {
        return FAIL.to_string();
    }
    if data[0] != 22 || data[5] != 2 {
        return FAIL.to_string();
    }

    let get2 = |i: usize| -> Option<u16> {
        if i + 1 < data.len() {
            Some(u16::from_be_bytes([data[i], data[i + 1]]))
        } else {
            None
        }
    };

    let Some(server_hello_length) = get2(3) else {
        return FAIL.to_string();
    };
    let server_hello_length = server_hello_length as usize;
    let Some(&counter) = data.get(43) else {
        return FAIL.to_string();
    };
    let counter = counter as usize;

    let Some(selected_cipher) = data.get(counter + 44..counter + 46) else {
        return FAIL.to_string();
    };
    let Some(version) = data.get(9..11) else {
        return FAIL.to_string();
    };

    let mut jarm = String::new();
    jarm.push_str(&hex_lower(selected_cipher));
    jarm.push('|');
    jarm.push_str(&hex_lower(version));
    jarm.push('|');
    jarm.push_str(&extract_extension_info(data, counter, server_hello_length));
    jarm
}

/// Lowercase hex of `bytes`.
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Extract `"alpn|type-type-..."` from a ServerHello's extensions.
fn extract_extension_info(data: &[u8], counter: usize, server_hello_length: usize) -> String {
    const FAIL: &str = "|";
    let get = |i: usize| data.get(i).copied();

    // Reference guard conditions.
    if get(counter + 47) == Some(11) {
        return FAIL.to_string();
    }
    if data.get(counter + 50..counter + 53) == Some(&[0x0e, 0xac, 0x0b][..])
        || data.get(82..85) == Some(&[0x0f, 0xf0, 0x0b][..])
    {
        return FAIL.to_string();
    }
    if counter + 42 >= server_hello_length {
        return FAIL.to_string();
    }

    let count_start = 49 + counter;
    let Some(len_bytes) = data.get(counter + 47..counter + 49) else {
        return FAIL.to_string();
    };
    let length = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
    let maximum = length + (count_start - 1);

    let mut types: Vec<[u8; 2]> = Vec::new();
    let mut values: Vec<Vec<u8>> = Vec::new();
    let mut count = count_start;
    while count < maximum {
        let Some(t) = data.get(count..count + 2) else {
            return FAIL.to_string();
        };
        types.push([t[0], t[1]]);
        let Some(lb) = data.get(count + 2..count + 4) else {
            return FAIL.to_string();
        };
        let ext_length = u16::from_be_bytes([lb[0], lb[1]]) as usize;
        if ext_length == 0 {
            count += 4;
            values.push(Vec::new());
        } else {
            let Some(v) = data.get(count + 4..count + 4 + ext_length) else {
                return FAIL.to_string();
            };
            values.push(v.to_vec());
            count += ext_length + 4;
        }
    }

    let mut result = String::new();
    // ALPN value, ASCII, skipping its 2-byte list length + 1-byte proto length.
    for (t, v) in types.iter().zip(&values) {
        if t == &[0x00, 0x10] {
            if v.len() > 3 {
                result.push_str(&String::from_utf8_lossy(&v[3..]));
            }
            break;
        }
    }
    result.push('|');
    for (i, t) in types.iter().enumerate() {
        result.push_str(&hex_lower(t));
        if i + 1 != types.len() {
            result.push('-');
        }
    }
    result
}

/// Assemble the 62-character JARM hash from the ten raw per-probe records.
pub fn jarm_hash(raw: &str) -> String {
    if raw == ALL_EMPTY_RAW {
        return EMPTY_JARM.to_string();
    }
    let mut fuzzy = String::new();
    let mut alpns_and_ext = String::new();
    for handshake in raw.split(',') {
        let components: Vec<&str> = handshake.split('|').collect();
        let cipher = components.first().copied().unwrap_or("");
        let version = components.get(1).copied().unwrap_or("");
        fuzzy.push_str(&cipher_byte(cipher));
        fuzzy.push_str(version_byte(version));
        alpns_and_ext.push_str(components.get(2).copied().unwrap_or(""));
        alpns_and_ext.push_str(components.get(3).copied().unwrap_or(""));
    }
    let mut hasher = Sha256::new();
    hasher.update(alpns_and_ext.as_bytes());
    let sha = hex_lower(&hasher.finalize());
    fuzzy.push_str(&sha[0..32]);
    fuzzy
}

/// Two-hex-character fuzzy code for a cipher: its 1-based index in
/// [`CIPHER_INDEX`], or `"00"` for none.
fn cipher_byte(cipher: &str) -> String {
    if cipher.is_empty() {
        return "00".to_string();
    }
    let mut count = 1usize;
    for bytes in CIPHER_INDEX {
        if hex_lower(bytes) == cipher {
            break;
        }
        count += 1;
    }
    let hexvalue = format!("{count:x}");
    if hexvalue.len() < 2 {
        format!("0{hexvalue}")
    } else {
        hexvalue
    }
}

/// Single fuzzy character for a negotiated version, from its last nibble.
fn version_byte(version: &str) -> &'static str {
    if version.is_empty() {
        return "0";
    }
    const OPTIONS: [&str; 6] = ["a", "b", "c", "d", "e", "f"];
    // The 4th hex character of the version (e.g. "0303" -> '3').
    match version.as_bytes().get(3).map(|c| (*c as char).to_digit(10)) {
        Some(Some(d)) if (d as usize) < OPTIONS.len() => OPTIONS[d as usize],
        _ => "0",
    }
}

/// Send one probe and return its raw per-probe record (`"|||"` on any failure).
async fn send_probe(ip: IpAddr, port: u16, packet: &[u8], timeout: Duration) -> String {
    const FAIL: &str = "|||";
    let fut = async {
        let mut stream = TcpStream::connect((ip, port)).await.ok()?;
        stream.write_all(packet).await.ok()?;
        read_server_hello(&mut stream).await
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(Some(data)) if !data.is_empty() => read_packet(&data),
        _ => FAIL.to_string(),
    }
}

/// Read the first TLS record (the ServerHello flight) from `stream`.
async fn read_server_hello(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(1484);
    let mut chunk = [0u8; 1484];
    loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        // Stop once we hold the complete first record (header is 5 bytes).
        if buf.len() >= 5 {
            let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize + 5;
            if buf.len() >= record_len || buf.len() >= 1484 {
                break;
            }
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

/// Fingerprint the TLS service at `ip:port` with JARM.
///
/// Sends the ten JARM `ClientHello` probes (each on its own short-lived TCP
/// connection) and returns the 62-character fingerprint. Returns `None` when
/// no probe elicited a ServerHello (the all-zero fingerprint), since that
/// records nothing worth storing; any genuine TLS stack yields `Some`.
pub async fn jarm(ip: IpAddr, port: u16, timeout: Duration) -> Option<String> {
    let host = ip.to_string();
    let mut e = Xorshift::new(seed_for(ip, port));
    let mut records: Vec<String> = Vec::with_capacity(10);
    for p in probes().iter() {
        let packet = build_packet(p, &host, &mut e);
        records.push(send_probe(ip, port, &packet, timeout).await);
    }
    let raw = records.join(",");
    let hash = jarm_hash(&raw);
    if hash == EMPTY_JARM {
        None
    } else {
        Some(hash)
    }
}

/// A best-effort, hash-irrelevant PRNG seed derived from the target and clock.
fn seed_for(ip: IpAddr, port: u16) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    let ip_mix = match ip {
        IpAddr::V4(v4) => u32::from(v4) as u64,
        IpAddr::V6(v6) => u128::from(v6) as u64,
    };
    nanos ^ ip_mix.rotate_left(16) ^ ((port as u64) << 48)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic entropy for reproducible packet-builder assertions.
    struct Fixed(u8);
    impl Entropy for Fixed {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
            }
        }
        fn grease(&mut self) -> [u8; 2] {
            [0x0a, 0x0a]
        }
    }

    #[test]
    fn all_empty_raw_hashes_to_canonical_zeros() {
        assert_eq!(jarm_hash(ALL_EMPTY_RAW), EMPTY_JARM);
        assert_eq!(EMPTY_JARM.len(), 62);
    }

    #[test]
    fn hash_is_62_chars_and_structured() {
        // A plausible (fabricated) raw string of ten records.
        let one = "002f|0303|h2|0000-ff01-0017";
        let raw = [one; 10].join(",");
        let h = jarm_hash(&raw);
        assert_eq!(h.len(), 62);
        // First 30 chars are the fuzzy cipher/version codes (3 per record).
        // 0x002f is index 6 in CIPHER_INDEX -> "06"; version last nibble 3 -> "d".
        assert!(h.starts_with("06d06d06d06d06d06d06d06d06d06d"));
        assert!(h[0..30].chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(h[30..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn cipher_and_version_bytes() {
        assert_eq!(cipher_byte(""), "00");
        assert_eq!(cipher_byte("0004"), "01"); // first entry
        assert_eq!(cipher_byte("1305"), "45"); // last entry, index 69 == 0x45
        assert_eq!(version_byte(""), "0");
        assert_eq!(version_byte("0303"), "d");
        assert_eq!(version_byte("0304"), "e");
    }

    #[test]
    fn build_packet_is_deterministic_and_well_formed() {
        let p = &probes()[0]; // tls1_2_forward
        let a = build_packet(p, "example.com", &mut Fixed(0x00));
        let b = build_packet(p, "example.com", &mut Fixed(0x00));
        assert_eq!(a, b, "builder must be deterministic given fixed entropy");

        // Record header: handshake content type, TLS 1.2 record version.
        assert_eq!(a[0], 0x16);
        assert_eq!(&a[1..3], &[0x03, 0x03]);
        // Declared record length matches the remaining bytes.
        let record_len = u16::from_be_bytes([a[3], a[4]]) as usize;
        assert_eq!(record_len, a.len() - 5);
        // Handshake type = ClientHello.
        assert_eq!(a[5], 0x01);
        // Handshake length (3 bytes) matches the rest of the record.
        let hs_len = u32::from_be_bytes([0, a[6], a[7], a[8]]) as usize;
        assert_eq!(hs_len, a.len() - 9);
        // ClientHello legacy version is TLS 1.2.
        assert_eq!(&a[9..11], &[0x03, 0x03]);
    }

    #[test]
    fn all_probes_build_as_valid_records() {
        // Every one of the ten probes must assemble into a self-consistent TLS
        // record without panicking, GREASE variants included.
        for p in probes().iter() {
            let pkt = build_packet(p, "example.com", &mut Fixed(0x11));
            assert!(pkt.len() > 5);
            assert_eq!(pkt[0], 0x16); // handshake record
            let record_len = u16::from_be_bytes([pkt[3], pkt[4]]) as usize;
            assert_eq!(record_len, pkt.len() - 5);
            assert_eq!(pkt[5], 0x01); // ClientHello
        }
        // A GREASE probe must carry a GREASE value (our fixed entropy -> 0a0a).
        let greased = build_packet(&probes()[4], "example.com", &mut Fixed(0x11));
        assert!(greased.windows(2).any(|w| w == [0x0a, 0x0a]));
    }

    #[test]
    fn read_packet_rejects_non_serverhello() {
        assert_eq!(read_packet(&[21, 3, 3, 0, 2, 2]), "|||"); // alert
        assert_eq!(read_packet(&[22, 3, 3, 0, 40, 1]), "|||"); // not hello(2)
        assert_eq!(read_packet(&[]), "|||");
    }
}
