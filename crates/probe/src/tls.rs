//! TLS certificate collection.
//!
//! We connect with `tokio-rustls` using a client configuration whose
//! certificate verifier **accepts every certificate**. This is deliberate: the
//! scanner is cataloguing what services present, not establishing a trusted
//! channel, so self-signed, expired, or hostname-mismatched certs must all be
//! captured rather than rejected. The handshake itself is the only data sent.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, ProtocolVersion, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crusade_core::TlsCert;

/// A certificate verifier that accepts anything. Cataloguing, not trusting.
#[derive(Debug)]
struct AcceptAll {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Complete a TLS handshake to `ip:port` and return the live stream.
///
/// `sni` sets the Server Name Indication; when `None`, the IP is used. The
/// certificate verifier accepts anything (see [`AcceptAll`]). Returns `None` on
/// any connect/handshake failure or timeout.
pub async fn connect(
    ip: IpAddr,
    port: u16,
    sni: Option<&str>,
    timeout: Duration,
) -> Option<TlsStream<TcpStream>> {
    let provider = Arc::new(ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll { provider }))
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let server_name: ServerName<'static> = match sni {
        Some(s) => ServerName::try_from(s.to_owned()).unwrap_or(ServerName::IpAddress(ip.into())),
        None => ServerName::IpAddress(ip.into()),
    };

    let tcp = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    let tls = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .ok()?
        .ok()?;
    Some(tls)
}

/// Connect over TLS and return the peer's end-entity certificate, parsed, with
/// the negotiated protocol version and cipher suite filled in.
///
/// `sni` sets the Server Name Indication; when `None`, the IP is used. Returns
/// `None` on any connect/handshake failure or timeout, or if the peer presents
/// no certificate.
pub async fn grab_cert(
    ip: IpAddr,
    port: u16,
    sni: Option<&str>,
    timeout: Duration,
) -> Option<TlsCert> {
    let tls = connect(ip, port, sni, timeout).await?;

    let (_, conn) = tls.get_ref();
    let version = conn.protocol_version().map(version_string);
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()));

    let certs = conn.peer_certificates()?;
    let ee = certs.first()?;
    let mut cert = parse_cert(ee.as_ref())?;
    cert.version = version;
    cert.cipher = cipher;
    Some(cert)
}

/// Map a rustls [`ProtocolVersion`] to a human label (e.g. "TLS 1.3").
fn version_string(v: ProtocolVersion) -> String {
    match v {
        ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
        ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
        ProtocolVersion::TLSv1_1 => "TLS 1.1".to_string(),
        ProtocolVersion::TLSv1_0 => "TLS 1.0".to_string(),
        ProtocolVersion::SSLv3 => "SSL 3.0".to_string(),
        other => format!("{other:?}"),
    }
}

/// Parse a DER-encoded end-entity certificate into a [`TlsCert`].
pub fn parse_cert(der: &[u8]) -> Option<TlsCert> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let subject_cn = first_cn(cert.subject());
    let issuer_cn = first_cn(cert.issuer());

    let mut san: Vec<String> = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(s) => san.push((*s).to_string()),
                GeneralName::IPAddress(bytes) => san.push(format_ip(bytes)),
                GeneralName::RFC822Name(s) => san.push((*s).to_string()),
                GeneralName::URI(s) => san.push((*s).to_string()),
                _ => {}
            }
        }
    }

    let not_before = Some(cert.validity().not_before.to_datetime());
    let not_after = Some(cert.validity().not_after.to_datetime());

    let self_signed = cert.subject() == cert.issuer();
    let fingerprint_sha256 = Some(fingerprint_der(der));

    Some(TlsCert {
        subject_cn,
        issuer_cn,
        san,
        not_before,
        not_after,
        self_signed,
        fingerprint_sha256,
        // Negotiated transport parameters are filled in by `grab_cert`, which
        // has access to the live connection; `parse_cert` sees only the DER.
        version: None,
        cipher: None,
    })
}

/// Lowercase hex SHA-256 of DER bytes.
pub fn fingerprint_der(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    hex::encode(hasher.finalize())
}

fn first_cn(name: &x509_parser::x509::X509Name<'_>) -> Option<String> {
    name.iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => {
            let mut parts = Vec::with_capacity(8);
            for chunk in bytes.chunks(2) {
                parts.push(format!("{:x}", ((chunk[0] as u16) << 8) | chunk[1] as u16));
            }
            parts.join(":")
        }
        _ => hex::encode(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_lowercase_and_known() {
        // SHA-256 of the empty input is a well-known constant.
        let empty = fingerprint_der(b"");
        assert_eq!(
            empty,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // SHA-256("abc").
        let abc = fingerprint_der(b"abc");
        assert_eq!(
            abc,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(abc, abc.to_lowercase());
    }

    #[test]
    fn self_signed_logic() {
        // Minimal direct check of the self-signed predicate via name equality
        // is exercised through parse_cert in integration; here we assert the
        // fingerprint length/charset contract.
        let fp = fingerprint_der(&[0u8; 32]);
        assert_eq!(fp.len(), 64);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }
}
