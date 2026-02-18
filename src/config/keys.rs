use std::fs;
use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};

/// Node TLS identity: certificate + private key stored as raw DER bytes.
pub struct NodeIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl NodeIdentity {
    /// Load existing identity from disk, or generate a new self-signed one.
    pub fn load_or_generate(
        cert_path: &Path,
        key_path: &Path,
        node_name: &str,
    ) -> anyhow::Result<Self> {
        if cert_path.exists() && key_path.exists() {
            Ok(Self {
                cert_der: fs::read(cert_path)?,
                key_der: fs::read(key_path)?,
            })
        } else {
            let certified_key = rcgen::generate_simple_self_signed(
                vec![node_name.to_string(), "localhost".to_string()],
            )?;
            let cert_der = certified_key.cert.der().to_vec();
            let key_der = certified_key.key_pair.serialize_der();

            fs::write(cert_path, &cert_der)?;
            fs::write(key_path, &key_der)?;

            Ok(Self { cert_der, key_der })
        }
    }

    fn cert(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert_der.clone())
    }

    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }

    /// Build a quinn ServerConfig for accepting incoming QUIC connections.
    pub fn build_server_config(&self) -> anyhow::Result<quinn::ServerConfig> {
        let client_verifier = Arc::new(AcceptAnyClientCert);
        let mut server_crypto = rustls::ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![self.cert()], self.key())?;
        server_crypto.alpn_protocols = vec![b"netfuse/1".to_vec()];

        let quic_server_config =
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?;
        Ok(quinn::ServerConfig::with_crypto(Arc::new(
            quic_server_config,
        )))
    }

    /// Build a rustls ServerConfig for HTTPS (web interface).
    /// Requests client certs but accepts any (app-layer auth via PeerAuth).
    pub fn build_https_config(&self) -> anyhow::Result<rustls::ServerConfig> {
        let client_verifier = Arc::new(AcceptAnyClientCert);
        let mut server_crypto = rustls::ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![self.cert()], self.key())?;
        server_crypto.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(server_crypto)
    }

    /// Generate a new client certificate + key pair for web client enrollment.
    /// Returns `(cert_der, key_der)`.
    pub fn generate_client_identity(name: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let certified_key = rcgen::generate_simple_self_signed(vec![name.to_string()])?;
        let cert_der = certified_key.cert.der().to_vec();
        let key_der = certified_key.key_pair.serialize_der();
        Ok((cert_der, key_der))
    }

    /// Build a quinn ClientConfig for connecting to peers.
    /// Accepts any server certificate (self-signed); trust is verified at
    /// the application layer after Hello exchange.
    pub fn build_client_config(&self) -> anyhow::Result<quinn::ClientConfig> {
        let mut client_crypto = rustls::ClientConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_client_auth_cert(vec![self.cert()], self.key())?;
        client_crypto.alpn_protocols = vec![b"netfuse/1".to_vec()];

        let quic_client_config =
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?;
        Ok(quinn::ClientConfig::new(Arc::new(quic_client_config)))
    }
}

fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Client certificate verifier that accepts any client certificate.
/// Actual trust is enforced at the application layer via PeerAuth.
#[derive(Debug)]
struct AcceptAnyClientCert;

impl ClientCertVerifier for AcceptAnyClientCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Certificate verifier that accepts any server certificate.
/// We use self-signed certs, so standard verification would always fail.
/// Trust is enforced at the application layer via the peer whitelist.
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
