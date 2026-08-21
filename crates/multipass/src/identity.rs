use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use noq::{ClientConfig, TransportConfig};
use noq_proto::crypto::rustls::QuicClientConfig;
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
    UnixTime,
};
use rustls::sign::CertifiedKey;

use crate::ALPN;
use crate::config::SecureFileKind;

const PUBLIC_KEY_PREFIX: &str = "ed25519:";
const ED25519_PUBLIC_KEY_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; ED25519_PUBLIC_KEY_LEN]);

impl PublicKey {
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        let encoded = value
            .strip_prefix(PUBLIC_KEY_PREFIX)
            .ok_or(IdentityError::InvalidPublicKey)?;
        let bytes = STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        let bytes = <[u8; ED25519_PUBLIC_KEY_LEN]>::try_from(bytes)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        Ok(Self(bytes))
    }

    pub fn from_raw(bytes: [u8; ED25519_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_raw(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.0
    }

    pub fn to_config_string(self) -> String {
        format!("{PUBLIC_KEY_PREFIX}{}", STANDARD_NO_PAD.encode(self.0))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey")
            .field(&self.to_config_string())
            .finish()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_config_string())
    }
}

pub struct ClientIdentity {
    private_key: PrivatePkcs8KeyDer<'static>,
    public_key: PublicKey,
}

impl ClientIdentity {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        load_identity(path)
    }

    pub fn from_secure_bytes(bytes: Vec<u8>) -> Result<Self, IdentityError> {
        parse_identity(bytes)
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("public_key", &self.public_key)
            .field("private_key", &"[secret key elided]")
            .finish()
    }
}

#[derive(Debug)]
pub enum IdentityError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Validation(crate::config::ConfigValidationError),
    InvalidPrivateKey,
    InvalidPublicKey,
    Tls(rustls::Error),
    Quic(noq_proto::crypto::rustls::NoInitialCipherSuite),
}

pub fn load_client_identity(path: impl AsRef<Path>) -> Result<ClientIdentity, IdentityError> {
    ClientIdentity::load(path)
}

pub fn client_config(
    identity: &ClientIdentity,
    pinned_server: PublicKey,
    transport: Arc<TransportConfig>,
) -> Result<ClientConfig, IdentityError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(identity.private_key.clone_key()))
        .map_err(IdentityError::Tls)?;
    if signing_key.algorithm() != rustls::SignatureAlgorithm::ED25519 {
        return Err(IdentityError::InvalidPrivateKey);
    }
    let public_spki = signing_key
        .public_key()
        .ok_or(IdentityError::InvalidPrivateKey)?;
    if public_key_from_spki(public_spki.as_ref())? != identity.public_key {
        return Err(IdentityError::InvalidPrivateKey);
    }
    let certified_key = Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(public_spki.as_ref().to_vec())],
        signing_key,
    ));
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(IdentityError::Tls)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier {
            pinned: pinned_server,
            provider: provider.into(),
        }))
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
            certified_key,
        )));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = QuicClientConfig::try_from(tls).map_err(IdentityError::Quic)?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport);
    Ok(config)
}

fn load_identity(path: impl AsRef<Path>) -> Result<ClientIdentity, IdentityError> {
    let path = path.as_ref();
    let bytes = crate::config::read_secure_file(
        path,
        "client.private_key_file",
        SecureFileKind::PrivateKey,
    )
    .map_err(IdentityError::Validation)?;
    parse_identity(bytes)
}

fn parse_identity(bytes: Vec<u8>) -> Result<ClientIdentity, IdentityError> {
    let private_key = if bytes.starts_with(b"-----BEGIN") {
        use rustls::pki_types::pem::PemObject as _;
        PrivatePkcs8KeyDer::from_pem_slice(&bytes).map_err(|_| IdentityError::InvalidPrivateKey)?
    } else {
        PrivatePkcs8KeyDer::from(bytes)
    };
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(private_key.clone_key()))
        .map_err(|_| IdentityError::InvalidPrivateKey)?;
    if signing_key.algorithm() != rustls::SignatureAlgorithm::ED25519 {
        return Err(IdentityError::InvalidPrivateKey);
    }
    let spki = signing_key
        .public_key()
        .ok_or(IdentityError::InvalidPrivateKey)?;
    let public_key = public_key_from_spki(spki.as_ref())?;
    Ok(ClientIdentity {
        private_key,
        public_key,
    })
}

pub fn public_key_from_spki(spki: &[u8]) -> Result<PublicKey, IdentityError> {
    const ED25519_SPKI_PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let raw = spki
        .strip_prefix(ED25519_SPKI_PREFIX)
        .ok_or(IdentityError::InvalidPublicKey)?;
    PublicKey::try_from(raw)
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = IdentityError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes = value
            .try_into()
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        Ok(Self(bytes))
    }
}

#[derive(Debug)]
struct PinnedServerVerifier {
    pinned: PublicKey,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty()
            || public_key_from_spki(end_entity.as_ref()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })? != self.pinned
        {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is disabled".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
        verify_tls13_signature_with_raw_key(
            message,
            &spki,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "read identity {}: {source}", path.display()),
            Self::Validation(error) => write!(f, "identity file security: {error}"),
            Self::InvalidPrivateKey => f.write_str("invalid Ed25519 private key"),
            Self::InvalidPublicKey => f.write_str("invalid Ed25519 public key"),
            Self::Tls(error) => write!(f, "TLS identity configuration: {error}"),
            Self::Quic(error) => write!(f, "QUIC identity configuration: {error}"),
        }
    }
}

impl std::error::Error for IdentityError {}
