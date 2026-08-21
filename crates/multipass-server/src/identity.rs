use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use multipass_proto::ClientId;
use noq::{Connection, ServerConfig, TransportConfig};
use noq_proto::crypto::rustls::QuicServerConfig;
use rustls::DistinguishedName;
use rustls::crypto::{CryptoProvider, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;

use crate::config::AuthorizedClient;

const PUBLIC_KEY_PREFIX: &str = "ed25519:";
const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; ED25519_PUBLIC_KEY_LEN]);

impl PublicKey {
    pub fn parse(value: &str) -> Result<Self, PublicKeyError> {
        let encoded = value
            .strip_prefix(PUBLIC_KEY_PREFIX)
            .ok_or(PublicKeyError)?;
        let bytes = STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| PublicKeyError)?;
        Self::try_from(bytes.as_slice())
    }

    #[cfg(test)]
    pub fn from_raw(bytes: [u8; ED25519_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn to_config_string(self) -> String {
        format!("{PUBLIC_KEY_PREFIX}{}", STANDARD_NO_PAD.encode(self.0))
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = PublicKeyError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes = value.try_into().map_err(|_| PublicKeyError)?;
        Ok(Self(bytes))
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKeyError;

impl fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid Ed25519 public key")
    }
}

impl std::error::Error for PublicKeyError {}

fn public_key_from_spki(spki: &[u8]) -> Result<PublicKey, PublicKeyError> {
    let raw = spki
        .strip_prefix(ED25519_SPKI_PREFIX)
        .ok_or(PublicKeyError)?;
    PublicKey::try_from(raw)
}

pub struct ServerIdentity {
    private_key: PrivatePkcs8KeyDer<'static>,
    public_key: PublicKey,
}

impl ServerIdentity {
    pub fn from_secure_bytes(bytes: Vec<u8>) -> Result<Self, ServerIdentityError> {
        let private_key = if bytes.starts_with(b"-----BEGIN") {
            use rustls::pki_types::pem::PemObject as _;
            PrivatePkcs8KeyDer::from_pem_slice(&bytes)
                .map_err(|_| ServerIdentityError::InvalidPrivateKey)?
        } else {
            PrivatePkcs8KeyDer::from(bytes)
        };
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(private_key.clone_key()))
            .map_err(|_| ServerIdentityError::InvalidPrivateKey)?;
        if signing_key.algorithm() != rustls::SignatureAlgorithm::ED25519 {
            return Err(ServerIdentityError::InvalidPrivateKey);
        }
        let spki = signing_key
            .public_key()
            .ok_or(ServerIdentityError::InvalidPrivateKey)?;
        let public_key = public_key_from_spki(spki.as_ref())?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }
}

impl fmt::Debug for ServerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerIdentity")
            .field("public_key", &self.public_key)
            .field("private_key", &"[secret key elided]")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct AuthorizedClients {
    by_key: HashMap<PublicKey, ClientId>,
}

impl AuthorizedClients {
    pub fn new(clients: &[AuthorizedClient]) -> Self {
        Self {
            by_key: clients
                .iter()
                .map(|client| (client.public_key, client.id.clone()))
                .collect(),
        }
    }

    pub fn client_id_for_connection(
        &self,
        connection: &Connection,
    ) -> Result<ClientId, PeerIdentityError> {
        let identity = connection
            .peer_identity()
            .ok_or(PeerIdentityError::Missing)?
            .downcast::<Vec<CertificateDer<'static>>>()
            .map_err(|_| PeerIdentityError::WrongType)?;
        let [presented] = identity.as_slice() else {
            return Err(PeerIdentityError::WrongCertificateCount);
        };
        let public_key = public_key_from_spki(presented.as_ref())
            .map_err(|_| PeerIdentityError::InvalidPublicKey)?;
        self.by_key
            .get(&public_key)
            .cloned()
            .ok_or(PeerIdentityError::Unauthorized)
    }
}

pub fn server_config(
    identity: &ServerIdentity,
    authorized_clients: AuthorizedClients,
    transport: Arc<TransportConfig>,
) -> Result<ServerConfig, ServerIdentityError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(identity.private_key.clone_key()))
        .map_err(ServerIdentityError::Tls)?;
    let public_spki = signing_key
        .public_key()
        .ok_or(ServerIdentityError::InvalidPrivateKey)?;
    if public_key_from_spki(public_spki.as_ref())? != identity.public_key {
        return Err(ServerIdentityError::InvalidPrivateKey);
    }
    let certified_key = Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(public_spki.as_ref().to_vec())],
        signing_key,
    ));
    let verifier = Arc::new(AuthorizedClientVerifier {
        authorized: authorized_clients.by_key,
        provider: provider.clone().into(),
        hints: Vec::new(),
    });
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(ServerIdentityError::Tls)?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
            certified_key,
        )));
    tls.alpn_protocols = vec![multipass_proto::ALPN.to_vec()];
    let crypto = QuicServerConfig::try_from(tls).map_err(ServerIdentityError::Quic)?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport);
    Ok(config)
}

#[derive(Debug)]
struct AuthorizedClientVerifier {
    authorized: HashMap<PublicKey, ClientId>,
    provider: Arc<CryptoProvider>,
    hints: Vec<DistinguishedName>,
}

impl ClientCertVerifier for AuthorizedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        let public_key = public_key_from_spki(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if !self.authorized.contains_key(&public_key) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is disabled".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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

#[derive(Debug)]
pub enum ServerIdentityError {
    InvalidPrivateKey,
    InvalidPublicKey,
    Tls(rustls::Error),
    Quic(noq_proto::crypto::rustls::NoInitialCipherSuite),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerIdentityError {
    Missing,
    WrongType,
    WrongCertificateCount,
    InvalidPublicKey,
    Unauthorized,
}

impl From<PublicKeyError> for ServerIdentityError {
    fn from(_: PublicKeyError) -> Self {
        Self::InvalidPublicKey
    }
}

impl fmt::Display for ServerIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrivateKey => f.write_str("invalid Ed25519 private key"),
            Self::InvalidPublicKey => f.write_str("invalid Ed25519 public key"),
            Self::Tls(error) => write!(f, "TLS identity configuration: {error}"),
            Self::Quic(error) => write!(f, "QUIC identity configuration: {error}"),
        }
    }
}

impl std::error::Error for ServerIdentityError {}

impl fmt::Display for PeerIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Missing => "authenticated peer identity is missing",
            Self::WrongType => "authenticated peer identity has an unexpected type",
            Self::WrongCertificateCount => {
                "authenticated peer identity must contain one raw public key"
            }
            Self::InvalidPublicKey => "authenticated peer public key is invalid",
            Self::Unauthorized => "authenticated peer public key is not authorized",
        };
        f.write_str(message)
    }
}

impl std::error::Error for PeerIdentityError {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use noq::Endpoint;
    use rcgen::{KeyPair, PublicKeyData as _};
    use rustls::client::AlwaysResolvesClientRawPublicKeys;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

    use super::*;

    const SERVER_NAME: &str = "multipass";

    struct TestClientIdentity {
        private_key: PrivatePkcs8KeyDer<'static>,
        public_key: PublicKey,
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
            _server_name: &rustls::pki_types::ServerName<'_>,
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

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    struct TestIdentityFile {
        path: PathBuf,
        private_key: Vec<u8>,
        public_key: PublicKey,
    }

    impl TestIdentityFile {
        fn new() -> Self {
            let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let private_key = key.serialize_der();
            let public_key = public_key_from_spki(&key.subject_public_key_info()).unwrap();
            let unique = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "multipass-auth-{}-{unique}.key",
                std::process::id()
            ));
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(&private_key).unwrap();
            Self {
                path,
                private_key,
                public_key,
            }
        }

        fn client_identity(&self) -> TestClientIdentity {
            TestClientIdentity {
                private_key: PrivatePkcs8KeyDer::from(self.private_key.clone()),
                public_key: self.public_key,
            }
        }

        fn load_identity(&self) -> ServerIdentity {
            ServerIdentity::from_secure_bytes(fs::read(&self.path).unwrap()).unwrap()
        }
    }

    impl Drop for TestIdentityFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    async fn handshake(
        server_config: ServerConfig,
        client_config: noq::ClientConfig,
    ) -> (
        Option<Result<Connection, noq::ConnectionError>>,
        Option<Result<Connection, noq::ConnectionError>>,
    ) {
        let server = Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        client.set_default_client_config(client_config);
        let connecting = client.connect(server_addr, SERVER_NAME).unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await?;
            Some(incoming.await)
        });
        let client = tokio::time::timeout(Duration::from_secs(3), connecting)
            .await
            .ok();
        let server = tokio::time::timeout(Duration::from_secs(3), server_task)
            .await
            .ok()
            .and_then(|result| result.ok())
            .flatten();
        (server, client)
    }

    fn test_transport() -> Arc<TransportConfig> {
        Arc::new(TransportConfig::default())
    }

    fn client_config(identity: &TestClientIdentity, pinned_server: PublicKey) -> noq::ClientConfig {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(identity.private_key.clone_key()))
            .unwrap();
        let public_spki = signing_key.public_key().unwrap();
        assert_eq!(
            public_key_from_spki(public_spki.as_ref()).unwrap(),
            identity.public_key
        );
        let certified_key = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(public_spki.as_ref().to_vec())],
            signing_key,
        ));
        let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier {
                pinned: pinned_server,
                provider: provider.into(),
            }))
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
                certified_key,
            )));
        tls.alpn_protocols = vec![multipass_proto::ALPN.to_vec()];
        let crypto = noq_proto::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut config = noq::ClientConfig::new(Arc::new(crypto));
        config.transport_config(test_transport());
        config
    }

    fn configs(
        server_identity: &ServerIdentity,
        client_identity: &TestClientIdentity,
        authorized_key: PublicKey,
        pin: PublicKey,
    ) -> (ServerConfig, noq::ClientConfig) {
        let authorized = AuthorizedClient {
            id: ClientId::new("scooter").unwrap(),
            public_key: authorized_key,
        };
        let server = server_config(
            server_identity,
            AuthorizedClients::new(&[authorized]),
            test_transport(),
        )
        .unwrap();
        let client = client_config(client_identity, pin);
        (server, client)
    }

    #[tokio::test]
    async fn authorized_client_with_pinned_server_completes_real_quic_handshake() {
        let server_file = TestIdentityFile::new();
        let client_file = TestIdentityFile::new();
        let server_identity = server_file.load_identity();
        let client_identity = client_file.client_identity();
        let (server, client) = configs(
            &server_identity,
            &client_identity,
            client_identity.public_key,
            server_identity.public_key(),
        );

        let (server, client) = handshake(server, client).await;
        assert!(server.is_some_and(|result| result.is_ok()));
        assert!(client.is_some_and(|result| result.is_ok()));
    }

    #[tokio::test]
    async fn wrong_server_key_fails_real_quic_handshake() {
        let server_file = TestIdentityFile::new();
        let client_file = TestIdentityFile::new();
        let wrong_server_file = TestIdentityFile::new();
        let server_identity = server_file.load_identity();
        let wrong_server_identity = wrong_server_file.load_identity();
        let client_identity = client_file.client_identity();
        let (server, client) = configs(
            &server_identity,
            &client_identity,
            client_identity.public_key,
            wrong_server_identity.public_key(),
        );

        let (_, client) = handshake(server, client).await;
        assert!(client.is_some_and(|result| result.is_err()));
    }

    #[tokio::test]
    async fn unauthorized_client_fails_real_quic_handshake() {
        let server_file = TestIdentityFile::new();
        let authorized_file = TestIdentityFile::new();
        let unauthorized_file = TestIdentityFile::new();
        let server_identity = server_file.load_identity();
        let authorized_identity = authorized_file.client_identity();
        let unauthorized_identity = unauthorized_file.client_identity();
        let (server, client) = configs(
            &server_identity,
            &unauthorized_identity,
            authorized_identity.public_key,
            server_identity.public_key(),
        );

        let (server, _) = handshake(server, client).await;
        assert!(server.is_some_and(|result| result.is_err()));
    }

    #[test]
    fn loading_identity_is_persistent_and_debug_redacts_private_material() {
        let file = TestIdentityFile::new();
        let before = fs::read(&file.path).unwrap();
        let first = file.load_identity();
        let second = file.load_identity();
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(fs::read(&file.path).unwrap(), before);
        assert!(format!("{first:?}").contains("[secret key elided]"));
    }
}
