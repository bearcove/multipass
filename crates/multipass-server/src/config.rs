use std::collections::HashSet;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use facet::Facet;
use multipass_proto::ClientId;

use crate::identity::PublicKey;

#[derive(Clone, Debug, Facet)]
pub struct ServerConfigFile {
    pub private_key_file: PathBuf,
    pub bind: SocketAddr,
    pub routed_ipv6_prefix: String,
    pub authorized_clients: Vec<AuthorizedClientConfigFile>,
}

#[derive(Clone, Debug, Facet)]
pub struct AuthorizedClientConfigFile {
    pub id: String,
    pub public_key: String,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub private_key_file: PathBuf,
    pub bind: SocketAddr,
    pub routed_ipv6_prefix: Ipv6Addr,
    pub authorized_clients: Vec<AuthorizedClient>,
}

#[derive(Clone, Debug)]
pub struct AuthorizedClient {
    pub id: ClientId,
    pub public_key: PublicKey,
}

pub struct ServerRuntimeConfig {
    pub config: ServerConfig,
    pub identity: crate::identity::ServerIdentity,
}

impl fmt::Debug for ServerRuntimeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerRuntimeConfig")
            .field("config", &self.config)
            .field("identity", &self.identity)
            .finish()
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: Box<facet_json::DeserializeError>,
    },
    Identity(crate::identity::ServerIdentityError),
    Validation(ConfigValidationError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigValidationError {
    pub path: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SecureFileKind {
    Config,
    PrivateKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SecureFileMetadata {
    is_regular_file: bool,
    uid: u32,
    mode: u32,
    nlink: u64,
}

fn validate_secure_file_metadata(
    path: impl Into<String>,
    kind: SecureFileKind,
    metadata: SecureFileMetadata,
) -> Result<(), ConfigValidationError> {
    let path = path.into();
    if !metadata.is_regular_file {
        return Err(validation(
            path,
            "must be a regular file opened without following symlinks",
        ));
    }
    if metadata.nlink != 1 {
        return Err(validation(path, "must have exactly one hard link"));
    }
    if metadata.uid != 0 {
        return Err(validation(path, "must be owned by root"));
    }
    let permissions = metadata.mode & 0o7777;
    match kind {
        SecureFileKind::Config if permissions & 0o022 != 0 => {
            Err(validation(path, "must not be group or world writable"))
        }
        SecureFileKind::PrivateKey if permissions & !0o600 != 0 => {
            Err(validation(path, "permissions must be 0600 or stricter"))
        }
        _ => Ok(()),
    }
}

fn open_secure_file(
    path: &Path,
    logical_path: &str,
    kind: SecureFileKind,
) -> Result<File, ConfigValidationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| validation(logical_path, format!("cannot securely open: {error}")))?;
        let metadata = file.metadata().map_err(|error| {
            validation(logical_path, format!("cannot inspect opened file: {error}"))
        })?;
        validate_secure_file_metadata(
            logical_path,
            kind,
            SecureFileMetadata {
                is_regular_file: metadata.is_file(),
                uid: metadata.uid(),
                mode: metadata.mode(),
                nlink: metadata.nlink(),
            },
        )?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, kind);
        Err(validation(
            logical_path,
            "secure no-follow file validation is unsupported on this platform",
        ))
    }
}

pub(crate) fn read_secure_file(
    path: &Path,
    logical_path: &str,
    kind: SecureFileKind,
) -> Result<Vec<u8>, ConfigValidationError> {
    let mut file = open_secure_file(path, logical_path, kind)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| validation(logical_path, format!("cannot read opened file: {error}")))?;
    Ok(bytes)
}

impl ServerConfigFile {
    pub fn from_json(input: &str) -> Result<Self, facet_json::DeserializeError> {
        facet_json::from_str(input)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let bytes = read_secure_file(path, "config_file", SecureFileKind::Config)
            .map_err(ConfigError::Validation)?;
        let input = String::from_utf8(bytes).map_err(|error| ConfigError::Read {
            path: path.to_owned(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        })?;
        Self::from_json(&input).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source: Box::new(source),
        })
    }

    pub fn validate(self) -> Result<ServerConfig, ConfigValidationError> {
        if self.private_key_file.as_os_str().is_empty() || !self.private_key_file.is_absolute() {
            return Err(validation(
                "private_key_file",
                "must be an absolute non-empty path",
            ));
        }
        let prefix = parse_prefix(&self.routed_ipv6_prefix)?;
        if self.authorized_clients.is_empty() {
            return Err(validation(
                "authorized_clients",
                "must contain at least one authorized client",
            ));
        }
        let mut ids = HashSet::with_capacity(self.authorized_clients.len());
        let mut keys = HashSet::with_capacity(self.authorized_clients.len());
        let mut authorized_clients = Vec::with_capacity(self.authorized_clients.len());
        for (index, client) in self.authorized_clients.into_iter().enumerate() {
            let id = ClientId::new(&client.id).map_err(|_| {
                validation(
                    format!("authorized_clients[{index}].id"),
                    "must be a non-empty bounded stable ID",
                )
            })?;
            if !ids.insert(id.clone()) {
                return Err(validation(
                    format!("authorized_clients[{index}].id"),
                    "duplicates an earlier client ID",
                ));
            }
            let public_key = PublicKey::parse(&client.public_key).map_err(|error| {
                validation(
                    format!("authorized_clients[{index}].public_key"),
                    error.to_string(),
                )
            })?;
            if !keys.insert(public_key) {
                return Err(validation(
                    format!("authorized_clients[{index}].public_key"),
                    "duplicates an earlier authorized public key",
                ));
            }
            authorized_clients.push(AuthorizedClient { id, public_key });
        }
        Ok(ServerConfig {
            private_key_file: self.private_key_file,
            bind: self.bind,
            routed_ipv6_prefix: prefix,
            authorized_clients,
        })
    }

    pub fn load_validated_runtime(
        path: impl AsRef<Path>,
    ) -> Result<ServerRuntimeConfig, ConfigError> {
        let config = Self::load(path)?
            .validate()
            .map_err(ConfigError::Validation)?;
        let key_bytes = read_secure_file(
            &config.private_key_file,
            "private_key_file",
            SecureFileKind::PrivateKey,
        )
        .map_err(ConfigError::Validation)?;
        let identity = crate::identity::ServerIdentity::from_secure_bytes(key_bytes)
            .map_err(ConfigError::Identity)?;
        Ok(ServerRuntimeConfig { config, identity })
    }
}

fn parse_prefix(value: &str) -> Result<Ipv6Addr, ConfigValidationError> {
    let (address, length) = value
        .split_once('/')
        .ok_or_else(|| validation("routed_ipv6_prefix", "must include /64"))?;
    if length != "64" {
        return Err(validation("routed_ipv6_prefix", "must use /64"));
    }
    let address = address.parse::<Ipv6Addr>().map_err(|error| {
        validation(
            "routed_ipv6_prefix",
            format!("invalid IPv6 address: {error}"),
        )
    })?;
    if u128::from(address) & u64::MAX as u128 != 0 {
        return Err(validation(
            "routed_ipv6_prefix",
            "must not contain host bits",
        ));
    }
    Ok(address)
}

fn validation(path: impl Into<String>, message: impl Into<String>) -> ConfigValidationError {
    ConfigValidationError {
        path: path.into(),
        message: message.into(),
    }
}

impl fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for ConfigValidationError {}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "read {}: {source}", path.display()),
            Self::Parse { path, source } => write!(f, "parse {}: {source}", path.display()),
            Self::Identity(error) => write!(f, "load identity: {error}"),
            Self::Validation(error) => write!(f, "validate config: {error}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Identity(source) => Some(source),
            Self::Validation(source) => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_file_metadata_policy_rejects_ownership_modes_links_and_non_files() {
        let secure_config = SecureFileMetadata {
            is_regular_file: true,
            uid: 0,
            mode: 0o100644,
            nlink: 1,
        };
        assert!(
            validate_secure_file_metadata("config_file", SecureFileKind::Config, secure_config)
                .is_ok()
        );
        assert!(
            validate_secure_file_metadata(
                "private_key_file",
                SecureFileKind::PrivateKey,
                SecureFileMetadata {
                    mode: 0o100600,
                    ..secure_config
                },
            )
            .is_ok()
        );

        for metadata in [
            SecureFileMetadata {
                uid: 501,
                ..secure_config
            },
            SecureFileMetadata {
                mode: 0o100666,
                ..secure_config
            },
            SecureFileMetadata {
                nlink: 2,
                ..secure_config
            },
            SecureFileMetadata {
                is_regular_file: false,
                ..secure_config
            },
        ] {
            assert!(
                validate_secure_file_metadata("config_file", SecureFileKind::Config, metadata)
                    .is_err()
            );
        }
        for mode in [0o100640, 0o100604, 0o100700, 0o100660] {
            assert!(
                validate_secure_file_metadata(
                    "private_key_file",
                    SecureFileKind::PrivateKey,
                    SecureFileMetadata {
                        mode,
                        ..secure_config
                    },
                )
                .is_err()
            );
        }
    }

    fn key(byte: u8) -> String {
        PublicKey::from_raw([byte; 32]).to_config_string()
    }

    fn json(clients: &str, prefix: &str) -> String {
        format!(
            r#"{{"private_key_file":"/tmp/server.key","bind":"[::]:51823","routed_ipv6_prefix":"{prefix}","authorized_clients":{clients}}}"#
        )
    }

    #[test]
    fn authorized_clients_and_network_fields_validate() {
        let clients = format!(r#"[{{"id":"scooter","public_key":"{}"}}]"#, key(1));
        let config = ServerConfigFile::from_json(&json(&clients, "2001:db8::/64"))
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(config.bind, "[::]:51823".parse().unwrap());
        assert_eq!(
            config.routed_ipv6_prefix,
            "2001:db8::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(config.authorized_clients[0].id.as_str(), "scooter");
    }

    #[test]
    fn duplicate_ids_and_keys_are_rejected_with_paths() {
        let duplicate_ids = format!(
            r#"[{{"id":"scooter","public_key":"{}"}},{{"id":"scooter","public_key":"{}"}}]"#,
            key(1),
            key(2)
        );
        let error = ServerConfigFile::from_json(&json(&duplicate_ids, "2001:db8::/64"))
            .unwrap()
            .validate()
            .unwrap_err();
        assert_eq!(error.path, "authorized_clients[1].id");

        let duplicate_keys = format!(
            r#"[{{"id":"scooter","public_key":"{}"}},{{"id":"laptop","public_key":"{}"}}]"#,
            key(1),
            key(1)
        );
        let error = ServerConfigFile::from_json(&json(&duplicate_keys, "2001:db8::/64"))
            .unwrap()
            .validate()
            .unwrap_err();
        assert_eq!(error.path, "authorized_clients[1].public_key");
    }

    #[test]
    fn invalid_keys_prefixes_paths_and_empty_allowlist_are_rejected() {
        let invalid_key = r#"[{"id":"scooter","public_key":"bad"}]"#;
        assert_eq!(
            ServerConfigFile::from_json(&json(invalid_key, "2001:db8::/64"))
                .unwrap()
                .validate()
                .unwrap_err()
                .path,
            "authorized_clients[0].public_key"
        );
        assert_eq!(
            ServerConfigFile::from_json(&json("[]", "2001:db8::/64"))
                .unwrap()
                .validate()
                .unwrap_err()
                .path,
            "authorized_clients"
        );
        let clients = format!(r#"[{{"id":"scooter","public_key":"{}"}}]"#, key(1));
        assert_eq!(
            ServerConfigFile::from_json(&json(&clients, "2001:db8::1/64"))
                .unwrap()
                .validate()
                .unwrap_err()
                .path,
            "routed_ipv6_prefix"
        );
        let mut relative = ServerConfigFile::from_json(&json(&clients, "2001:db8::/64")).unwrap();
        relative.private_key_file = "server.key".into();
        assert_eq!(relative.validate().unwrap_err().path, "private_key_file");
    }
}
