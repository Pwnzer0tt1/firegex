//! TLS, terminated by the engine itself.
//!
//! The TLS module does this with nginx today: one listener terminates the public
//! connection and forwards plaintext to a second loopback port, which re-encrypts and
//! forwards to the real service. A filter engine attaches to the leg in between. It
//! works, and it costs an nginx config generated per stream, a pair of ports derived
//! from a hash, and one hop where the traffic is in the clear.
//!
//! Terminating here removes all three: the engine decrypts, the rules see plaintext
//! that never leaves the process, and it re-encrypts on the way out.

use std::io;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Certificate and key for the connection the engine terminates.
pub fn server_config(cert_pem: &str, key_pem: &str) -> Result<Arc<ServerConfig>, String> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("cannot read the certificate: {e}"))?;
    if certs.is_empty() {
        return Err("the certificate is empty".to_string());
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("cannot read the private key: {e}"))?
        .ok_or_else(|| "the private key is empty".to_string())?;

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map(Arc::new)
        .map_err(|e| format!("certificate and key do not go together: {e}"))
}

/// Accepts whatever the protected service presents.
///
/// This mirrors nginx's `proxy_ssl_verify off`, which is what the TLS module already
/// configures, and it is the right call here rather than laziness: the service being
/// protected is on the other side of a loopback or a private link, it is the thing
/// firegex is defending, and in a competition it is invariably self-signed. Verifying
/// it would only ever refuse to protect it.
#[derive(Debug)]
struct AcceptAnyServer(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Re-encrypting towards the service.
pub fn client_config() -> Result<Arc<ClientConfig>, String> {
    let provider = provider();
    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("cannot configure TLS: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer(provider)))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The process-wide crypto provider, installed once.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    if let Some(installed) = rustls::crypto::CryptoProvider::get_default() {
        return Arc::clone(installed);
    }
    let provider = rustls::crypto::ring::default_provider();
    // Losing the race is fine: whoever won installed the same thing.
    let _ = provider.clone().install_default();
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(provider))
}

/// The upstream config, offering the protocols the client asked for.
///
/// Cloned per connection rather than kept in a table: the list comes from the client, so
/// there is no fixed set to precompute, and a config clone is nothing beside the
/// handshake it is about to do. An empty list means the client offered none, and then
/// neither do we — offering something on its behalf would be answering a question it did
/// not ask.
pub fn with_alpn(config: &Arc<ClientConfig>, wanted: &[Vec<u8>]) -> Arc<ClientConfig> {
    if wanted.is_empty() {
        return Arc::clone(config);
    }
    let mut copy = (**config).clone();
    copy.alpn_protocols = wanted.to_vec();
    Arc::new(copy)
}

/// The server config, advertising the one protocol the service agreed to.
///
/// One, not a list: the service has already chosen, and offering the client anything else
/// would let it pick something the other side of this proxy cannot speak. `None` means
/// the service chose nothing, so the client is told nothing and both ends fall back
/// together.
pub fn answering_with(config: &Arc<ServerConfig>, agreed: Option<&[u8]>) -> Arc<ServerConfig> {
    match agreed {
        Some(protocol) => {
            let mut copy = (**config).clone();
            copy.alpn_protocols = vec![protocol.to_vec()];
            Arc::new(copy)
        }
        None => Arc::clone(config),
    }
}

pub fn acceptor(config: Arc<ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(config)
}

pub fn connector(config: Arc<ClientConfig>) -> TlsConnector {
    TlsConnector::from(config)
}

/// The name to present upstream. Nothing verifies it here, but rustls needs one.
pub fn server_name(host: &str) -> Result<ServerName<'static>, io::Error> {
    ServerName::try_from(host.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad server name: {e}")))
}
