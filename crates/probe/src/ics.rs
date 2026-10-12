//! Industrial-control-system / OT device identification.
//!
//! Many ICS/SCADA devices speak purpose-built protocols that, when asked the
//! right *identification* question, happily describe themselves — vendor,
//! model, firmware revision, serial number. This module catalogues such devices
//! exactly the way a passive asset-inventory tool (or Shodan) does.
//!
//! # Strictly connect-and-read
//!
//! Every request here is the protocol's own *read-only identification /
//! read-description* request and nothing else. We **never**:
//!
//! * write a coil, register, data point, variable or file;
//! * change device state, mode, time or configuration;
//! * issue a control / start / stop / reset-output command;
//! * attempt authentication or a login of any kind.
//!
//! Where a protocol's only identification path would require a write, we skip
//! it and fall back to merely *confirming* the protocol from a benign read:
//!
//! | Protocol      | Port(s)              | Identification request (read-only)                |
//! |---------------|----------------------|---------------------------------------------------|
//! | Modbus/TCP    | 502/tcp              | FC 43/14 "Read Device Identification"             |
//! | Siemens S7    | 102/tcp              | COTP CR + S7 "Read SZL" (system status list)      |
//! | EtherNet/IP   | 44818/tcp, 44818/udp | encapsulation `ListIdentity` (0x0063)             |
//! | BACnet/IP     | 47808/udp            | confirmed `ReadProperty` of the Device object     |
//! | DNP3          | 20000/tcp            | data-link "Request Link Status" (status only)     |
//!
//! Notes on read-only-ness of the chosen requests:
//!
//! * **Modbus** FC 43/14 reads the device-identification object group only; we
//!   never fall back to reading coils/registers. An exception reply still
//!   confirms a Modbus speaker via a valid MBAP echo.
//! * **S7** "Setup Communication" (function 0xF0) only *negotiates* the PDU
//!   size — it does not touch the process image — and the subsequent SZL reads
//!   fetch the CPU's own module/component identification system-status lists.
//! * **BACnet** uses a confirmed `ReadProperty` of the Device object's own
//!   descriptive properties (Object-Name, Vendor-Identifier, Model-Name,
//!   Application-Software-Version). A `Who-Is` would also only confirm presence.
//! * **DNP3** "Request Link Status" is a data-link keep-alive that asks the
//!   outstation whether its link is up; it reads no data points. If anything is
//!   uncertain we only confirm the protocol from the `0x05 0x64` start octets.
//!
//! Parsers are pure functions over byte buffers (unit-tested without a socket);
//! the socket wrappers are thin, time-bounded and never panic.

use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crusade_core::{IcsInfo, Service, Transport};

/// TCP ports we probe for an ICS identity.
pub fn ics_ports_tcp() -> &'static [u16] {
    &[502, 102, 44818, 20000]
}

/// UDP ports we probe for an ICS identity.
pub fn ics_ports_udp() -> &'static [u16] {
    &[47808, 44818]
}

/// Probe one `(ip, port)` for an ICS device identity.
///
/// Maps the port to its protocol, runs that protocol's read-only identification
/// exchange and returns a [`Service`] with the correct `transport`, `ics` set,
/// and `service`/`product`/`version` mirrored where sensible. Returns `None`
/// when the port does not respond as that protocol (or is not an ICS port).
pub async fn probe_ics_service(ip: IpAddr, port: u16, timeout: Duration) -> Option<Service> {
    match port {
        502 => probe_modbus(ip, port, timeout).await,
        102 => probe_s7(ip, port, timeout).await,
        20000 => probe_dnp3(ip, port, timeout).await,
        // EtherNet/IP is reachable over both transports on the same port; try
        // TCP first (its primary classification), then connectionless UDP.
        44818 => probe_enip(ip, port, timeout).await,
        47808 => probe_bacnet(ip, port, timeout).await,
        _ => None,
    }
}

/// Assemble a [`Service`] from a protocol identity, mirroring product/version.
fn ics_service(port: u16, transport: Transport, info: IcsInfo, service: &str) -> Service {
    let mut svc = Service::new(port, transport);
    svc.service = Some(service.to_string());
    svc.product = info.product.clone().or_else(|| info.vendor.clone());
    svc.version = info.version.clone();
    svc.ics = Some(info);
    svc
}

// ---------------------------------------------------------------------------
// Shared socket helpers (time-bounded, best-effort, never panic).
// ---------------------------------------------------------------------------

/// Upper bound on bytes we buffer from any single ICS exchange.
const MAX_ICS_REPLY: usize = 16 * 1024;

/// Connect, write `payload`, and read a framed reply whose total length is
/// reported by `expected` once enough header bytes have arrived.
async fn tcp_exchange<F>(
    ip: IpAddr,
    port: u16,
    payload: &[u8],
    timeout: Duration,
    expected: F,
) -> Option<Vec<u8>>
where
    F: Fn(&[u8]) -> Option<usize>,
{
    let connect = TcpStream::connect((ip, port));
    let mut stream = tokio::time::timeout(timeout, connect).await.ok()?.ok()?;
    tokio::time::timeout(timeout, stream.write_all(payload))
        .await
        .ok()?
        .ok()?;
    read_framed(&mut stream, timeout, expected).await
}

/// Read from `stream` until `expected(&buf)` says we have the whole frame, the
/// deadline passes, or the peer closes. Returns `None` only on an empty read.
async fn read_framed<F>(stream: &mut TcpStream, timeout: Duration, expected: F) -> Option<Vec<u8>>
where
    F: Fn(&[u8]) -> Option<usize>,
{
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        if let Some(total) = expected(&buf) {
            if buf.len() >= total {
                buf.truncate(total);
                break;
            }
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => break,
            Err(_) => break,
        }
        if buf.len() >= MAX_ICS_REPLY {
            break;
        }
    }

    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

/// Trim a fixed-width ASCII field (NUL / space padded) into a tidy `String`.
fn ascii_trim(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .trim_matches(|c: char| c == ' ' || c == '\0' || c == '\t')
        .trim()
        .to_string()
}

/// `None` for empty strings, `Some` otherwise.
fn non_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Read up to four big-endian bytes as a `u32`.
fn be_uint(bytes: &[u8]) -> u32 {
    let mut v = 0u32;
    for &b in bytes.iter().take(4) {
        v = (v << 8) | b as u32;
    }
    v
}

// ===========================================================================
// Modbus/TCP (port 502) — FC 43 / MEI 14 "Read Device Identification".
// ===========================================================================

/// Modbus function code 0x2B (Encapsulated Interface Transport).
const MODBUS_FC_MEI: u8 = 0x2B;
/// MEI type 0x0E (Read Device Identification).
const MODBUS_MEI_DEVID: u8 = 0x0E;

/// Build an MBAP-framed "Read Device Identification" request (FC 43/14, read
/// device-id code 0x01 "basic", starting at object id 0x00). This is the only
/// Modbus request we ever send; it reads the device's self-description and
/// cannot alter any coil or register.
pub fn build_modbus_devid_request() -> Vec<u8> {
    // PDU: FC, MEI type, Read Device ID code (basic), object id.
    let pdu = [MODBUS_FC_MEI, MODBUS_MEI_DEVID, 0x01, 0x00];
    let mut out = Vec::with_capacity(7 + pdu.len());
    out.extend_from_slice(&[0x00, 0x01]); // transaction id
    out.extend_from_slice(&[0x00, 0x00]); // protocol id (0 = Modbus)
    let length = (1 + pdu.len()) as u16; // unit id + PDU
    out.extend_from_slice(&length.to_be_bytes());
    out.push(0x00); // unit id
    out.extend_from_slice(&pdu);
    out
}

/// Parse a Modbus "Read Device Identification" reply (or an exception to it).
///
/// Returns `Some` whenever the bytes are a valid MBAP frame for our request —
/// including an exception reply, which still confirms a Modbus speaker — and
/// `None` if the buffer is not a plausible response to our request.
pub fn parse_modbus_devid(resp: &[u8]) -> Option<IcsInfo> {
    if resp.len() < 8 {
        return None;
    }
    // Protocol id must be 0 for Modbus.
    if u16::from_be_bytes([resp[2], resp[3]]) != 0 {
        return None;
    }
    let unit = resp[6];
    let func = resp[7];

    let mut info = IcsInfo::new("modbus");
    info.extra.push(("unit_id".into(), unit.to_string()));

    // Exception reply to our function: 0x2B | 0x80.
    if func == MODBUS_FC_MEI | 0x80 {
        let code = resp.get(8).copied().unwrap_or(0);
        info.extra
            .push(("exception".into(), format!("0x{code:02x}")));
        return Some(info);
    }
    // Only accept our own function code; never infer Modbus from anything else.
    if func != MODBUS_FC_MEI {
        return None;
    }

    // Successful Read Device Identification response.
    if resp.get(8).copied() == Some(MODBUS_MEI_DEVID) {
        // [8]=MEI, [9]=readdevid code, [10]=conformity, [11]=more follows,
        // [12]=next object id, [13]=number of objects, then objects.
        let num_objects = resp.get(13).copied().unwrap_or(0) as usize;
        let mut off = 14;
        for _ in 0..num_objects {
            let obj_id = match resp.get(off) {
                Some(b) => *b,
                None => break,
            };
            let obj_len = match resp.get(off + 1) {
                Some(b) => *b as usize,
                None => break,
            };
            let val = match resp.get(off + 2..off + 2 + obj_len) {
                Some(v) => v,
                None => break,
            };
            let s = ascii_trim(val);
            match obj_id {
                0x00 => info.vendor = non_empty(s),
                0x01 => info.product = non_empty(s),
                0x02 => info.version = non_empty(s),
                0x03 => info.extra.push(("vendor_url".into(), s)),
                0x04 => info.extra.push(("product_name".into(), s)),
                0x05 => info.extra.push(("model_name".into(), s)),
                0x06 => info.extra.push(("user_app_name".into(), s)),
                other => info.extra.push((format!("object_0x{other:02x}"), s)),
            }
            off += 2 + obj_len;
        }
    }

    Some(info)
}

fn modbus_expected(buf: &[u8]) -> Option<usize> {
    if buf.len() < 6 {
        return None;
    }
    Some(6 + u16::from_be_bytes([buf[4], buf[5]]) as usize)
}

async fn probe_modbus(ip: IpAddr, port: u16, timeout: Duration) -> Option<Service> {
    let resp = tcp_exchange(ip, port, &build_modbus_devid_request(), timeout, modbus_expected).await?;
    let info = parse_modbus_devid(&resp)?;
    Some(ics_service(port, Transport::Tcp, info, "modbus"))
}

// ===========================================================================
// Siemens S7comm (port 102) — COTP CR + S7 "Read SZL".
// ===========================================================================

/// Wrap `payload` in a TPKT (RFC 1006) header.
fn tpkt(payload: &[u8]) -> Vec<u8> {
    let total = 4 + payload.len();
    let mut out = Vec::with_capacity(total);
    out.push(0x03); // version
    out.push(0x00); // reserved
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Wrap an S7 payload in a COTP Data (DT) packet inside a TPKT.
fn cotp_dt(s7: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + s7.len());
    v.extend_from_slice(&[0x02, 0xf0, 0x80]); // COTP DT, EOT
    v.extend_from_slice(s7);
    tpkt(&v)
}

/// Build the TPKT+COTP Connection Request (CR) that opens an S7 session
/// (source/destination TSAP for rack 0 / slot 2). Purely a transport handshake.
pub fn build_s7_cotp_cr() -> Vec<u8> {
    let cotp: [u8; 18] = [
        0x11, // length indicator
        0xe0, // CR (connection request)
        0x00, 0x00, // dst reference
        0x00, 0x01, // src reference
        0x00, // class / option
        0xc0, 0x01, 0x0a, // tpdu size = 1024
        0xc1, 0x02, 0x01, 0x00, // src TSAP
        0xc2, 0x02, 0x01, 0x02, // dst TSAP (rack 0, slot 2)
    ];
    tpkt(&cotp)
}

/// Build an S7 "Setup Communication" job (function 0xF0). This only negotiates
/// the maximum PDU length / outstanding request counts — it reads and writes no
/// process data — and is a prerequisite for the SZL reads that follow.
pub fn build_s7_setup_comm() -> Vec<u8> {
    let params: [u8; 8] = [0xf0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xe0];
    let mut s7 = Vec::new();
    s7.push(0x32); // protocol id
    s7.push(0x01); // ROSCTR = Job
    s7.extend_from_slice(&[0x00, 0x00]); // redundancy id
    s7.extend_from_slice(&[0x00, 0x00]); // pdu reference
    s7.extend_from_slice(&(params.len() as u16).to_be_bytes()); // param length
    s7.extend_from_slice(&[0x00, 0x00]); // data length
    s7.extend_from_slice(&params);
    cotp_dt(&s7)
}

/// Build an S7 "Read SZL" (read system status list) UserData request for the
/// given SZL id / index. SZL reads expose the CPU's own identification lists
/// (module id 0x0011, component id 0x001C) and never touch the process image.
pub fn build_s7_szl_request(szl_id: u16, szl_index: u16) -> Vec<u8> {
    // UserData parameter block: Read SZL request.
    let params: [u8; 8] = [0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00];
    // Data block: return code 0xFF, transport size 0x09 (octet string),
    // length 4, then SZL id + index.
    let mut data = vec![0xff, 0x09, 0x00, 0x04];
    data.extend_from_slice(&szl_id.to_be_bytes());
    data.extend_from_slice(&szl_index.to_be_bytes());

    let mut s7 = Vec::new();
    s7.push(0x32); // protocol id
    s7.push(0x07); // ROSCTR = UserData
    s7.extend_from_slice(&[0x00, 0x00]); // redundancy id
    s7.extend_from_slice(&[0x00, 0x01]); // pdu reference
    s7.extend_from_slice(&(params.len() as u16).to_be_bytes());
    s7.extend_from_slice(&(data.len() as u16).to_be_bytes());
    s7.extend_from_slice(&params);
    s7.extend_from_slice(&data);
    cotp_dt(&s7)
}

/// A decoded S7 SZL (system status list) payload: its id and raw records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S7Szl {
    pub szl_id: u16,
    pub szl_index: u16,
    pub records: Vec<Vec<u8>>,
}

/// Parse an S7 "Read SZL" response (full TPKT/COTP/S7 frame) into [`S7Szl`].
///
/// Returns `None` when the frame is not a successful SZL read response.
pub fn parse_s7_szl(resp: &[u8]) -> Option<S7Szl> {
    // TPKT.
    if resp.len() < 7 || resp[0] != 0x03 {
        return None;
    }
    // COTP: skip (length-indicator byte) + its declared bytes.
    let cotp_li = *resp.get(4)? as usize;
    let s7_start = 4 + 1 + cotp_li;
    let s7 = resp.get(s7_start..)?;
    if s7.first().copied()? != 0x32 {
        return None;
    }
    let rosctr = *s7.get(1)?;
    let param_len = u16::from_be_bytes([*s7.get(6)?, *s7.get(7)?]) as usize;
    // Ack / Ack_Data headers carry two extra error bytes; Job/UserData do not.
    let header_len = if rosctr == 0x02 || rosctr == 0x03 { 12 } else { 10 };
    let data = s7.get(header_len + param_len..)?;
    // Data block: return code, transport size, length, SZL id, index,
    // record length, record count.
    if data.len() < 12 {
        return None;
    }
    if data[0] != 0xff {
        return None; // not a successful read
    }
    let szl_id = u16::from_be_bytes([data[4], data[5]]);
    let szl_index = u16::from_be_bytes([data[6], data[7]]);
    let rec_len = u16::from_be_bytes([data[8], data[9]]) as usize;
    let rec_count = u16::from_be_bytes([data[10], data[11]]) as usize;
    if rec_len == 0 {
        return Some(S7Szl { szl_id, szl_index, records: Vec::new() });
    }
    let mut records = Vec::new();
    let mut off = 12;
    for _ in 0..rec_count {
        match data.get(off..off + rec_len) {
            Some(r) => records.push(r.to_vec()),
            None => break,
        }
        off += rec_len;
    }
    Some(S7Szl { szl_id, szl_index, records })
}

/// Fold a decoded SZL list into an [`IcsInfo`] (Siemens module / component id).
pub fn apply_s7_szl(info: &mut IcsInfo, szl: &S7Szl) {
    if info.vendor.is_none() {
        info.vendor = Some("Siemens".to_string());
    }
    match szl.szl_id {
        0x0011 => {
            // Module identification: index(2) MLFB(20) BGTyp(2) Ausbg1(2) Ausbg2(2).
            for rec in &szl.records {
                if rec.len() < 28 {
                    continue;
                }
                let index = u16::from_be_bytes([rec[0], rec[1]]);
                let mlfb = ascii_trim(&rec[2..22]);
                if index == 0x0001 && !mlfb.is_empty() {
                    if info.product.is_none() {
                        info.product = Some(mlfb);
                    }
                    if info.version.is_none() {
                        info.version = Some(format!("{}.{}", rec[26], rec[27]));
                    }
                }
            }
        }
        0x001C => {
            // Component identification: index(2) + 34-byte ASCII value.
            for rec in &szl.records {
                if rec.len() < 36 {
                    continue;
                }
                let index = u16::from_be_bytes([rec[0], rec[1]]);
                let val = ascii_trim(&rec[2..36]);
                if val.is_empty() {
                    continue;
                }
                match index {
                    0x0001 => {
                        if info.device_id.is_none() {
                            info.device_id = Some(val);
                        }
                    }
                    0x0005 => {
                        info.extra.push(("serial".into(), val.clone()));
                        if info.device_id.is_none() {
                            info.device_id = Some(val);
                        }
                    }
                    0x0007 => {
                        if info.product.is_none() {
                            info.product = Some(val);
                        }
                    }
                    other => info.extra.push((format!("component_0x{other:04x}"), val)),
                }
            }
        }
        _ => {}
    }
}

async fn tpkt_exchange(
    stream: &mut TcpStream,
    timeout: Duration,
    payload: &[u8],
) -> Option<Vec<u8>> {
    tokio::time::timeout(timeout, stream.write_all(payload))
        .await
        .ok()?
        .ok()?;
    read_framed(stream, timeout, |buf| {
        if buf.len() < 4 {
            None
        } else {
            Some(u16::from_be_bytes([buf[2], buf[3]]) as usize)
        }
    })
    .await
}

async fn probe_s7(ip: IpAddr, port: u16, timeout: Duration) -> Option<Service> {
    let connect = TcpStream::connect((ip, port));
    let mut stream = tokio::time::timeout(timeout, connect).await.ok()?.ok()?;

    // COTP connection request → must be answered by a Connection Confirm (0xD0).
    let cc = tpkt_exchange(&mut stream, timeout, &build_s7_cotp_cr()).await?;
    if cc.get(5).copied() != Some(0xd0) {
        return None;
    }

    let mut info = IcsInfo::new("s7");
    info.vendor = Some("Siemens".to_string());

    // Negotiate the PDU size (read-only handshake), then read the SZL lists.
    let _ = tpkt_exchange(&mut stream, timeout, &build_s7_setup_comm()).await;
    for (szl_id, idx) in [(0x0011u16, 0x0001u16), (0x001c, 0x0001)] {
        if let Some(resp) = tpkt_exchange(&mut stream, timeout, &build_s7_szl_request(szl_id, idx)).await
        {
            if let Some(szl) = parse_s7_szl(&resp) {
                apply_s7_szl(&mut info, &szl);
            }
        }
    }

    Some(ics_service(port, Transport::Tcp, info, "s7"))
}

// ===========================================================================
// EtherNet/IP (port 44818, TCP & UDP) — encapsulation ListIdentity.
// ===========================================================================

/// Build an EtherNet/IP `ListIdentity` request (encapsulation command 0x0063).
/// A standard, read-only discovery request with an empty data section.
pub fn build_enip_list_identity() -> Vec<u8> {
    let mut v = vec![0u8; 24]; // encapsulation header, all-zero body
    v[0] = 0x63; // command 0x0063 (little-endian)
    v[1] = 0x00;
    v
}

/// Parse an EtherNet/IP `ListIdentity` reply into an [`IcsInfo`].
pub fn parse_enip_identity(resp: &[u8]) -> Option<IcsInfo> {
    if resp.len() < 24 {
        return None;
    }
    if u16::from_le_bytes([resp[0], resp[1]]) != 0x0063 {
        return None;
    }
    let data = resp.get(24..)?;
    if data.len() < 2 {
        return None;
    }
    let item_count = u16::from_le_bytes([data[0], data[1]]);
    let mut off = 2;
    for _ in 0..item_count {
        let type_id = u16::from_le_bytes([*data.get(off)?, *data.get(off + 1)?]);
        let len = u16::from_le_bytes([*data.get(off + 2)?, *data.get(off + 3)?]) as usize;
        let item = data.get(off + 4..off + 4 + len)?;
        if type_id == 0x000c {
            return parse_enip_identity_item(item);
        }
        off += 4 + len;
    }
    None
}

/// Parse the body of a CIP Identity (type 0x000C) CPF item.
fn parse_enip_identity_item(item: &[u8]) -> Option<IcsInfo> {
    // protocol version(2) + socket address(16) + vendor(2) + device type(2) +
    // product code(2) + revision(2) + status(2) + serial(4) + name len(1).
    let mut o = 2 + 16;
    let vendor_id = u16::from_le_bytes([*item.get(o)?, *item.get(o + 1)?]);
    o += 2;
    let device_type = u16::from_le_bytes([*item.get(o)?, *item.get(o + 1)?]);
    o += 2;
    let product_code = u16::from_le_bytes([*item.get(o)?, *item.get(o + 1)?]);
    o += 2;
    let rev_major = *item.get(o)?;
    let rev_minor = *item.get(o + 1)?;
    o += 2;
    let _status = u16::from_le_bytes([*item.get(o)?, *item.get(o + 1)?]);
    o += 2;
    let serial = u32::from_le_bytes([
        *item.get(o)?,
        *item.get(o + 1)?,
        *item.get(o + 2)?,
        *item.get(o + 3)?,
    ]);
    o += 4;
    let name_len = *item.get(o)? as usize;
    o += 1;
    let name = item
        .get(o..o + name_len)
        .map(ascii_trim)
        .and_then(non_empty);

    let mut info = IcsInfo::new("ethernetip");
    info.vendor = Some(enip_vendor_name(vendor_id));
    info.product = name;
    info.version = Some(format!("{rev_major}.{rev_minor:02}"));
    info.device_id = Some(format!("{serial:08X}"));
    info.extra.push(("vendor_id".into(), vendor_id.to_string()));
    info.extra.push(("device_type".into(), device_type.to_string()));
    info.extra
        .push(("product_code".into(), product_code.to_string()));
    Some(info)
}

/// Map a handful of common ODVA vendor ids to names; otherwise a generic label.
fn enip_vendor_name(id: u16) -> String {
    match id {
        1 => "Rockwell Automation/Allen-Bradley".to_string(),
        5 => "Rockwell Automation".to_string(),
        26 => "Festo".to_string(),
        47 => "Pepperl+Fuchs".to_string(),
        108 => "Schneider Electric".to_string(),
        283 => "WAGO".to_string(),
        other => format!("Vendor {other}"),
    }
}

fn enip_expected(buf: &[u8]) -> Option<usize> {
    if buf.len() < 24 {
        return None;
    }
    Some(24 + u16::from_le_bytes([buf[2], buf[3]]) as usize)
}

async fn probe_enip(ip: IpAddr, port: u16, timeout: Duration) -> Option<Service> {
    if let Some(resp) = tcp_exchange(ip, port, &build_enip_list_identity(), timeout, enip_expected).await
    {
        if let Some(info) = parse_enip_identity(&resp) {
            return Some(ics_service(port, Transport::Tcp, info, "ethernetip"));
        }
    }
    if let Some(resp) =
        crate::udp::udp_roundtrip(ip, port, &build_enip_list_identity(), timeout).await
    {
        if let Some(info) = parse_enip_identity(&resp) {
            return Some(ics_service(port, Transport::Udp, info, "ethernetip"));
        }
    }
    None
}

// ===========================================================================
// BACnet/IP (UDP port 47808) — confirmed ReadProperty of the Device object.
// ===========================================================================

/// BACnet property identifiers we read (all descriptive, read-only).
pub const BACNET_PROP_APP_SOFTWARE_VERSION: u32 = 12;
pub const BACNET_PROP_MODEL_NAME: u32 = 70;
pub const BACNET_PROP_OBJECT_NAME: u32 = 77;
pub const BACNET_PROP_VENDOR_ID: u32 = 120;

/// Encode an unsigned integer as its minimal big-endian bytes.
fn unsigned_bytes(value: u32) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let be = value.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(3);
    be[first..].to_vec()
}

/// Encode a BACnet context-tagged unsigned value (tag number < 15, len <= 4).
fn bacnet_context_unsigned(tag: u8, value: u32) -> Vec<u8> {
    let bytes = unsigned_bytes(value);
    let mut v = Vec::with_capacity(1 + bytes.len());
    v.push((tag << 4) | 0x08 | (bytes.len() as u8));
    v.extend_from_slice(&bytes);
    v
}

/// Build a BACnet/IP confirmed `ReadProperty` for the Device object's given
/// property. The Device instance is the wildcard 0x3FFFFF ("this device"). A
/// read-only request: it fetches one descriptive property and changes nothing.
pub fn build_bacnet_readprop(property_id: u32) -> Vec<u8> {
    // APDU: confirmed request, ReadProperty (service choice 12).
    let mut apdu = vec![0x00, 0x05, 0x01, 0x0c];
    // Object identifier (context tag 0, 4 bytes): device object (type 8),
    // instance 0x3FFFFF (any / this device).
    apdu.push(0x0c);
    let obj = (8u32 << 22) | 0x3f_ffff;
    apdu.extend_from_slice(&obj.to_be_bytes());
    // Property identifier (context tag 1).
    apdu.extend_from_slice(&bacnet_context_unsigned(1, property_id));

    // NPDU: version 1, control 0x04 (expecting reply).
    let npdu = [0x01u8, 0x04];

    let total = 4 + npdu.len() + apdu.len();
    let mut out = Vec::with_capacity(total);
    out.push(0x81); // BVLC type: BACnet/IP
    out.push(0x0a); // BVLC function: Original-Unicast-NPDU
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&npdu);
    out.extend_from_slice(&apdu);
    out
}

/// A BACnet property value extracted from a ReadProperty-ACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacnetProp {
    pub property_id: u32,
    pub value: String,
}

/// Read a BACnet tag header at `off`: returns
/// `(tag_number, is_context, lvt, header_len, data_len)`.
fn bacnet_tag_header(buf: &[u8], off: usize) -> Option<(u8, bool, u8, usize, usize)> {
    let b = *buf.get(off)?;
    let mut tagnum = (b >> 4) & 0x0f;
    let context = (b & 0x08) != 0;
    let lvt = b & 0x07;
    let mut p = off + 1;
    if tagnum == 0x0f {
        tagnum = *buf.get(p)?;
        p += 1;
    }
    // Opening (6) / closing (7) tags carry no data.
    if lvt == 6 || lvt == 7 {
        return Some((tagnum, context, lvt, p - off, 0));
    }
    let data_len = if lvt == 5 {
        let l = *buf.get(p)? as usize;
        p += 1;
        if l == 254 {
            let v = u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]) as usize;
            p += 2;
            v
        } else if l == 255 {
            let v = be_uint(buf.get(p..p + 4)?) as usize;
            p += 4;
            v
        } else {
            l
        }
    } else {
        lvt as usize
    };
    Some((tagnum, context, lvt, p - off, data_len))
}

/// Parse a BACnet confirmed `ReadProperty-ACK` and extract the property value.
pub fn parse_bacnet_readprop(resp: &[u8]) -> Option<BacnetProp> {
    if resp.len() < 6 || resp[0] != 0x81 {
        return None;
    }
    // Skip the 4-byte BVLC header (unicast/broadcast NPDU forms).
    let mut off = 4;
    // NPDU.
    if *resp.get(off)? != 0x01 {
        return None;
    }
    off += 1;
    let control = *resp.get(off)?;
    off += 1;
    // Optional network-layer routing fields.
    if control & 0x20 != 0 {
        off += 2; // DNET
        let dlen = *resp.get(off)? as usize;
        off += 1 + dlen;
        off += 1; // hop count
    }
    if control & 0x08 != 0 {
        off += 2; // SNET
        let slen = *resp.get(off)? as usize;
        off += 1 + slen;
    }
    // APDU: Complex-ACK (PDU type 3) for ReadProperty (service choice 12).
    let pdu_type = *resp.get(off)?;
    if pdu_type & 0xf0 != 0x30 {
        return None;
    }
    off += 1; // pdu type / flags
    off += 1; // invoke id
    if *resp.get(off)? != 0x0c {
        return None; // service ACK choice: ReadProperty
    }
    off += 1;

    // Context tag 0: object identifier (skip).
    let (t0, c0, _l0, h0, d0) = bacnet_tag_header(resp, off)?;
    if !c0 || t0 != 0 {
        return None;
    }
    off += h0 + d0;
    // Context tag 1: property identifier.
    let (t1, c1, _l1, h1, d1) = bacnet_tag_header(resp, off)?;
    if !c1 || t1 != 1 {
        return None;
    }
    let property_id = be_uint(resp.get(off + h1..off + h1 + d1)?);
    off += h1 + d1;
    // Optional context tag 2: property array index.
    if let Some((t2, c2, _l2, h2, d2)) = bacnet_tag_header(resp, off) {
        if c2 && t2 == 2 {
            off += h2 + d2;
        }
    }
    // Opening context tag 3: property value.
    let (t3, c3, l3, h3, _d3) = bacnet_tag_header(resp, off)?;
    if !(c3 && t3 == 3 && l3 == 6) {
        return None;
    }
    off += h3;
    // First application-tagged value inside the wrapper.
    let (vt, vc, _vl, vh, vd) = bacnet_tag_header(resp, off)?;
    if vc {
        return None; // expected an application tag
    }
    let vdata = resp.get(off + vh..off + vh + vd)?;
    let value = match vt {
        7 => {
            // Character string: first byte is the encoding indicator.
            if vdata.is_empty() {
                String::new()
            } else {
                ascii_trim(&vdata[1..])
            }
        }
        2 => be_uint(vdata).to_string(), // unsigned integer
        _ => ascii_trim(vdata),
    };
    Some(BacnetProp { property_id, value })
}

fn apply_bacnet_prop(info: &mut IcsInfo, bp: &BacnetProp) {
    let v = bp.value.clone();
    if v.is_empty() {
        return;
    }
    match bp.property_id {
        BACNET_PROP_OBJECT_NAME => info.device_id = Some(v),
        BACNET_PROP_VENDOR_ID => {
            info.extra.push(("vendor_id".into(), v.clone()));
            if info.vendor.is_none() {
                info.vendor = Some(format!("BACnet vendor {v}"));
            }
        }
        BACNET_PROP_MODEL_NAME => info.product = Some(v),
        BACNET_PROP_APP_SOFTWARE_VERSION => info.version = Some(v),
        other => info.extra.push((format!("property_{other}"), v)),
    }
}

async fn probe_bacnet(ip: IpAddr, port: u16, timeout: Duration) -> Option<Service> {
    let mut info = IcsInfo::new("bacnet");
    let mut responded = false;
    for pid in [
        BACNET_PROP_OBJECT_NAME,
        BACNET_PROP_VENDOR_ID,
        BACNET_PROP_MODEL_NAME,
        BACNET_PROP_APP_SOFTWARE_VERSION,
    ] {
        if let Some(resp) =
            crate::udp::udp_roundtrip(ip, port, &build_bacnet_readprop(pid), timeout).await
        {
            responded = true;
            if let Some(bp) = parse_bacnet_readprop(&resp) {
                apply_bacnet_prop(&mut info, &bp);
            }
        }
    }
    if responded {
        Some(ics_service(port, Transport::Udp, info, "bacnet"))
    } else {
        None
    }
}

// ===========================================================================
// DNP3 (port 20000) — data-link "Request Link Status".
// ===========================================================================

/// DNP3 CRC (polynomial 0x3D65, reflected as 0xA6BC, final complement).
fn dnp3_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xa6bc;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Build a DNP3 data-link "Request Link Status" frame (primary function 9).
/// This only asks whether the outstation's link layer is up; it reads no data
/// points and issues no control.
pub fn build_dnp3_link_status(dst: u16, src: u16) -> Vec<u8> {
    // Start(2) + length + control + dst(2) + src(2), then CRC over all of it.
    // Control 0xC9: DIR=1, PRM=1, FCB=0, FCV=0, function=9 (Request Link Status).
    let mut header = vec![0x05, 0x64, 0x05, 0xc9];
    header.extend_from_slice(&dst.to_le_bytes());
    header.extend_from_slice(&src.to_le_bytes());
    let crc = dnp3_crc(&header);
    header.extend_from_slice(&crc.to_le_bytes());
    header
}

/// Parse a DNP3 data-link reply, confirming the protocol from the `0x05 0x64`
/// start octets and extracting the link-layer addresses.
pub fn parse_dnp3(resp: &[u8]) -> Option<IcsInfo> {
    if resp.len() < 2 || resp[0] != 0x05 || resp[1] != 0x64 {
        return None;
    }
    let mut info = IcsInfo::new("dnp3");
    if resp.len() >= 8 {
        let control = resp[3];
        let func = control & 0x0f;
        let dst = u16::from_le_bytes([resp[4], resp[5]]);
        let src = u16::from_le_bytes([resp[6], resp[7]]);
        info.device_id = Some(src.to_string());
        info.extra.push(("source_addr".into(), src.to_string()));
        info.extra.push(("dest_addr".into(), dst.to_string()));
        info.extra.push(("link_function".into(), func.to_string()));
    }
    Some(info)
}

fn dnp3_expected(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 {
        return None;
    }
    if buf[0] != 0x05 || buf[1] != 0x64 {
        // Not DNP3 — stop reading with whatever we have.
        return Some(buf.len());
    }
    // Data-link header + its CRC is 10 bytes; enough to confirm and read addrs.
    Some(10)
}

async fn probe_dnp3(ip: IpAddr, port: u16, timeout: Duration) -> Option<Service> {
    let resp = tcp_exchange(ip, port, &build_dnp3_link_status(1, 1024), timeout, dnp3_expected).await?;
    let info = parse_dnp3(&resp)?;
    Some(ics_service(port, Transport::Tcp, info, "dnp3"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Modbus ------------------------------------------------------------

    fn modbus_devid_response() -> Vec<u8> {
        // PDU after MBAP: FC, MEI, readdevid code, conformity, more, next, count.
        let mut pdu = vec![MODBUS_FC_MEI, MODBUS_MEI_DEVID, 0x01, 0x83, 0x00, 0x00, 0x03];
        let objects: [(u8, &[u8]); 3] = [
            (0x00, b"Acme"),     // VendorName
            (0x01, b"PLC-X"),    // ProductCode
            (0x02, b"1.2"),      // MajorMinorRevision
        ];
        for (id, val) in objects {
            pdu.push(id);
            pdu.push(val.len() as u8);
            pdu.extend_from_slice(val);
        }
        let mut frame = vec![0x00, 0x01, 0x00, 0x00];
        let length = (1 + pdu.len()) as u16;
        frame.extend_from_slice(&length.to_be_bytes());
        frame.push(0x00); // unit id
        frame.extend_from_slice(&pdu);
        frame
    }

    #[test]
    fn modbus_request_framing() {
        let req = build_modbus_devid_request();
        assert_eq!(&req[0..2], &[0x00, 0x01]); // transaction id
        assert_eq!(&req[2..4], &[0x00, 0x00]); // protocol id
        assert_eq!(&req[4..6], &[0x00, 0x05]); // length = unit + 4-byte PDU
        assert_eq!(req[6], 0x00); // unit id
        assert_eq!(&req[7..], &[0x2b, 0x0e, 0x01, 0x00]); // FC 43/14 basic obj 0
    }

    #[test]
    fn modbus_parses_vendor_product_version() {
        let info = parse_modbus_devid(&modbus_devid_response()).expect("modbus");
        assert_eq!(info.protocol, "modbus");
        assert_eq!(info.vendor.as_deref(), Some("Acme"));
        assert_eq!(info.product.as_deref(), Some("PLC-X"));
        assert_eq!(info.version.as_deref(), Some("1.2"));
    }

    #[test]
    fn modbus_exception_still_confirms() {
        // MBAP + exception PDU (0x2B|0x80, code 0x01 "illegal function").
        let frame = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0xab, 0x01];
        let info = parse_modbus_devid(&frame).expect("modbus exception");
        assert_eq!(info.protocol, "modbus");
        assert!(info.vendor.is_none());
        assert!(info.extra.iter().any(|(k, _)| k == "exception"));
    }

    #[test]
    fn modbus_rejects_bad_protocol_and_short() {
        assert!(parse_modbus_devid(&[]).is_none());
        assert!(parse_modbus_devid(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x05]).is_none());
        // Non-zero protocol id → not Modbus.
        let mut bad = modbus_devid_response();
        bad[2] = 0x01;
        assert!(parse_modbus_devid(&bad).is_none());
        // Truncated mid-objects must not panic and still confirms Modbus.
        let full = modbus_devid_response();
        let info = parse_modbus_devid(&full[..16]).expect("still modbus");
        assert_eq!(info.protocol, "modbus");
    }

    // --- EtherNet/IP -------------------------------------------------------

    fn enip_identity_response() -> Vec<u8> {
        let name = b"1756-L61/B";
        let mut item = Vec::new();
        item.extend_from_slice(&[0x01, 0x00]); // encapsulation protocol version
        item.extend_from_slice(&[0u8; 16]); // socket address
        item.extend_from_slice(&1u16.to_le_bytes()); // vendor id = 1 (Rockwell)
        item.extend_from_slice(&12u16.to_le_bytes()); // device type
        item.extend_from_slice(&42u16.to_le_bytes()); // product code
        item.push(0x01); // revision major
        item.push(0x05); // revision minor
        item.extend_from_slice(&0x0030u16.to_le_bytes()); // status
        item.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // serial
        item.push(name.len() as u8);
        item.extend_from_slice(name);
        item.push(0xff); // state

        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_le_bytes()); // item count
        data.extend_from_slice(&0x000cu16.to_le_bytes()); // item type: identity
        data.extend_from_slice(&(item.len() as u16).to_le_bytes());
        data.extend_from_slice(&item);

        let mut frame = vec![0u8; 24];
        frame[0] = 0x63; // command 0x0063
        frame[2..4].copy_from_slice(&(data.len() as u16).to_le_bytes());
        frame.extend_from_slice(&data);
        frame
    }

    #[test]
    fn enip_request_framing() {
        let req = build_enip_list_identity();
        assert_eq!(req.len(), 24);
        assert_eq!(u16::from_le_bytes([req[0], req[1]]), 0x0063);
        assert!(req[2..].iter().all(|&b| b == 0)); // empty header body
    }

    #[test]
    fn enip_parses_identity() {
        let info = parse_enip_identity(&enip_identity_response()).expect("enip");
        assert_eq!(info.protocol, "ethernetip");
        assert_eq!(info.vendor.as_deref(), Some("Rockwell Automation/Allen-Bradley"));
        assert_eq!(info.product.as_deref(), Some("1756-L61/B"));
        assert_eq!(info.version.as_deref(), Some("1.05"));
        assert_eq!(info.device_id.as_deref(), Some("12345678"));
        assert!(info
            .extra
            .iter()
            .any(|(k, v)| k == "product_code" && v == "42"));
    }

    #[test]
    fn enip_rejects_short_and_wrong_command() {
        assert!(parse_enip_identity(&[0u8; 10]).is_none());
        assert!(parse_enip_identity(&[0u8; 24]).is_none()); // command 0, no items
        let mut bad = enip_identity_response();
        bad[0] = 0x64; // wrong command
        assert!(parse_enip_identity(&bad).is_none());
        // Truncated item body must not panic.
        let full = enip_identity_response();
        assert!(parse_enip_identity(&full[..30]).is_none());
    }

    // --- Siemens S7 --------------------------------------------------------

    fn s7_szl_module_id_response() -> Vec<u8> {
        // One SZL 0x0011 record (28 bytes).
        let mlfb = b"6ES7 315-2EH14-0AB0"; // 19 bytes, padded to 20
        let mut rec = Vec::new();
        rec.extend_from_slice(&0x0001u16.to_be_bytes()); // index
        rec.extend_from_slice(mlfb);
        rec.push(b' '); // pad MLFB to 20
        rec.extend_from_slice(&0x0001u16.to_be_bytes()); // BGTyp
        rec.extend_from_slice(&0x0001u16.to_be_bytes()); // Ausbg1
        rec.push(0x05); // Ausbg2 major
        rec.push(0x06); // Ausbg2 minor
        assert_eq!(rec.len(), 28);

        let mut szl_block = Vec::new();
        szl_block.extend_from_slice(&0x0011u16.to_be_bytes()); // SZL id
        szl_block.extend_from_slice(&0x0001u16.to_be_bytes()); // SZL index
        szl_block.extend_from_slice(&0x001cu16.to_be_bytes()); // record length
        szl_block.extend_from_slice(&0x0001u16.to_be_bytes()); // record count
        szl_block.extend_from_slice(&rec);

        let mut data = vec![0xff, 0x09];
        data.extend_from_slice(&(szl_block.len() as u16).to_be_bytes());
        data.extend_from_slice(&szl_block);

        let params: [u8; 8] = [0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x00];
        let mut s7 = Vec::new();
        s7.push(0x32); // protocol id
        s7.push(0x07); // ROSCTR = UserData
        s7.extend_from_slice(&[0x00, 0x00]); // redundancy
        s7.extend_from_slice(&[0x00, 0x01]); // pdu reference
        s7.extend_from_slice(&(params.len() as u16).to_be_bytes());
        s7.extend_from_slice(&(data.len() as u16).to_be_bytes());
        s7.extend_from_slice(&params);
        s7.extend_from_slice(&data);
        cotp_dt(&s7)
    }

    #[test]
    fn s7_cotp_cr_framing() {
        let cr = build_s7_cotp_cr();
        assert_eq!(&cr[0..2], &[0x03, 0x00]); // TPKT version/reserved
        assert_eq!(u16::from_be_bytes([cr[2], cr[3]]) as usize, cr.len());
        assert_eq!(cr[5], 0xe0); // COTP Connection Request
    }

    #[test]
    fn s7_szl_request_framing() {
        let req = build_s7_szl_request(0x0011, 0x0001);
        assert_eq!(&req[0..2], &[0x03, 0x00]); // TPKT
        // COTP DT header inside.
        assert_eq!(&req[4..7], &[0x02, 0xf0, 0x80]);
        assert_eq!(req[7], 0x32); // S7 protocol id
        assert_eq!(req[8], 0x07); // ROSCTR = UserData
    }

    #[test]
    fn s7_parses_module_identification() {
        let szl = parse_s7_szl(&s7_szl_module_id_response()).expect("szl");
        assert_eq!(szl.szl_id, 0x0011);
        assert_eq!(szl.records.len(), 1);

        let mut info = IcsInfo::new("s7");
        apply_s7_szl(&mut info, &szl);
        assert_eq!(info.vendor.as_deref(), Some("Siemens"));
        assert_eq!(info.product.as_deref(), Some("6ES7 315-2EH14-0AB0"));
        assert_eq!(info.version.as_deref(), Some("5.6"));
    }

    #[test]
    fn s7_rejects_short_and_non_s7() {
        assert!(parse_s7_szl(&[0x03, 0x00]).is_none());
        assert!(parse_s7_szl(&[]).is_none());
        // Valid TPKT/COTP but S7 protocol id wrong.
        let mut bad = s7_szl_module_id_response();
        bad[7] = 0x00;
        assert!(parse_s7_szl(&bad).is_none());
        // Truncated frame must not panic.
        let full = s7_szl_module_id_response();
        assert!(parse_s7_szl(&full[..20]).is_none());
    }

    // --- BACnet ------------------------------------------------------------

    fn bacnet_readprop_ack_object_name() -> Vec<u8> {
        let name = b"Device-5";
        let mut apdu = vec![0x30, 0x01, 0x0c]; // complex ack, invoke 1, ReadProperty
        // object identifier (context tag 0): device object, instance 5.
        apdu.push(0x0c);
        apdu.extend_from_slice(&((8u32 << 22) | 5).to_be_bytes());
        // property identifier (context tag 1): object-name (77).
        apdu.push(0x19);
        apdu.push(77);
        // opening tag 3.
        apdu.push(0x3e);
        // character string (application tag 7): encoding byte + text.
        apdu.push(0x75);
        apdu.push((name.len() + 1) as u8);
        apdu.push(0x00); // ANSI/UTF-8
        apdu.extend_from_slice(name);
        // closing tag 3.
        apdu.push(0x3f);

        let npdu = [0x01u8, 0x00];
        let total = 4 + npdu.len() + apdu.len();
        let mut out = vec![0x81, 0x0a];
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(&npdu);
        out.extend_from_slice(&apdu);
        out
    }

    fn bacnet_readprop_ack_vendor_id() -> Vec<u8> {
        let mut apdu = vec![0x30, 0x02, 0x0c];
        apdu.push(0x0c);
        apdu.extend_from_slice(&((8u32 << 22) | 5).to_be_bytes());
        apdu.push(0x19);
        apdu.push(120); // vendor-identifier
        apdu.push(0x3e);
        // unsigned (application tag 2), value 260.
        apdu.push(0x22);
        apdu.extend_from_slice(&260u16.to_be_bytes());
        apdu.push(0x3f);

        let npdu = [0x01u8, 0x00];
        let total = 4 + npdu.len() + apdu.len();
        let mut out = vec![0x81, 0x0a];
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(&npdu);
        out.extend_from_slice(&apdu);
        out
    }

    #[test]
    fn bacnet_request_framing() {
        let req = build_bacnet_readprop(BACNET_PROP_OBJECT_NAME);
        assert_eq!(&req[0..2], &[0x81, 0x0a]); // BVLC type/function
        assert_eq!(u16::from_be_bytes([req[2], req[3]]) as usize, req.len());
        assert_eq!(&req[4..6], &[0x01, 0x04]); // NPDU version/control
        assert_eq!(&req[6..8], &[0x00, 0x05]); // confirmed req, max apdu
        assert_eq!(req[9], 0x0c); // service choice: ReadProperty
        assert!(req.contains(&77)); // property id object-name
    }

    #[test]
    fn bacnet_parses_character_string_value() {
        let bp = parse_bacnet_readprop(&bacnet_readprop_ack_object_name()).expect("bacnet");
        assert_eq!(bp.property_id, 77);
        assert_eq!(bp.value, "Device-5");

        let mut info = IcsInfo::new("bacnet");
        apply_bacnet_prop(&mut info, &bp);
        assert_eq!(info.device_id.as_deref(), Some("Device-5"));
    }

    #[test]
    fn bacnet_parses_unsigned_value() {
        let bp = parse_bacnet_readprop(&bacnet_readprop_ack_vendor_id()).expect("bacnet");
        assert_eq!(bp.property_id, 120);
        assert_eq!(bp.value, "260");
    }

    #[test]
    fn bacnet_rejects_short_and_non_bacnet() {
        assert!(parse_bacnet_readprop(&[0x81]).is_none());
        assert!(parse_bacnet_readprop(&[0x00; 12]).is_none());
        // Truncated ACK must not panic.
        let full = bacnet_readprop_ack_object_name();
        assert!(parse_bacnet_readprop(&full[..10]).is_none());
    }

    // --- DNP3 --------------------------------------------------------------

    #[test]
    fn dnp3_crc_matches_known_vector() {
        // Documented reset-link header → CRC bytes E9 21 (low byte first).
        let header = [0x05, 0x64, 0x05, 0xc0, 0x01, 0x00, 0x00, 0x04];
        assert_eq!(dnp3_crc(&header), 0x21e9);
    }

    #[test]
    fn dnp3_request_framing_and_crc() {
        let frame = build_dnp3_link_status(1, 1024);
        assert_eq!(&frame[0..2], &[0x05, 0x64]); // start octets
        assert_eq!(frame[2], 0x05); // length
        assert_eq!(frame[3], 0xc9); // control: request link status
        assert_eq!(frame.len(), 10);
        // Appended CRC must validate over the 8-byte header.
        let crc = u16::from_le_bytes([frame[8], frame[9]]);
        assert_eq!(crc, dnp3_crc(&frame[..8]));
    }

    #[test]
    fn dnp3_parses_link_status_reply() {
        // Link-status reply: control 0x0b (function 11), src 1024, dst 1.
        let mut frame = vec![0x05, 0x64, 0x05, 0x0b];
        frame.extend_from_slice(&1u16.to_le_bytes()); // dst
        frame.extend_from_slice(&1024u16.to_le_bytes()); // src
        frame.extend_from_slice(&dnp3_crc(&frame).to_le_bytes());
        let info = parse_dnp3(&frame).expect("dnp3");
        assert_eq!(info.protocol, "dnp3");
        assert_eq!(info.device_id.as_deref(), Some("1024"));
        assert!(info
            .extra
            .iter()
            .any(|(k, v)| k == "link_function" && v == "11"));
    }

    #[test]
    fn dnp3_rejects_non_dnp3() {
        assert!(parse_dnp3(&[0x00, 0x01]).is_none());
        assert!(parse_dnp3(&[]).is_none());
        // Start octets alone still confirm (addresses unknown).
        let info = parse_dnp3(&[0x05, 0x64]).expect("confirmed");
        assert_eq!(info.protocol, "dnp3");
        assert!(info.device_id.is_none());
    }

    // --- Port tables -------------------------------------------------------

    #[test]
    fn port_tables() {
        assert_eq!(ics_ports_tcp(), &[502, 102, 44818, 20000]);
        assert_eq!(ics_ports_udp(), &[47808, 44818]);
    }
}
