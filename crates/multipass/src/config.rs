use std::collections::HashSet;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use facet::Facet;
use multipass_proto::{ClientId, UplinkId};

use crate::identity::PublicKey;

#[derive(Clone, Debug, Facet)]
pub struct ClientConfigFile {
    pub gateway: GatewayConfigFile,
    pub client: ClientIdentityConfigFile,
    pub uplinks: Vec<UplinkConfigFile>,
    pub ipc_socket: PathBuf,
}

#[derive(Clone, Debug, Facet)]
pub struct GatewayConfigFile {
    pub id: String,
    pub server_public_key: String,
    pub endpoints: Vec<GatewayEndpoint>,
}

#[derive(Clone, Debug, Facet)]
pub struct GatewayEndpoint {
    pub address: SocketAddr,
    #[facet(default)]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Facet)]
pub struct ClientIdentityConfigFile {
    pub id: String,
    pub private_key_file: PathBuf,
}

#[derive(Clone, Debug, Facet)]
pub struct UplinkConfigFile {
    pub id: String,
    pub display_name: String,
    pub interface: String,
    pub enabled: bool,
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub gateway: GatewayConfig,
    pub client: ClientIdentityConfig,
    pub uplinks: Vec<UplinkConfig>,
    pub ipc_socket: PathBuf,
}

#[derive(Clone, Debug)]
pub struct GatewayConfig {
    pub id: String,
    pub server_public_key: PublicKey,
    pub endpoints: Vec<GatewayEndpoint>,
}

#[derive(Clone, Debug)]
pub struct ClientIdentityConfig {
    pub id: ClientId,
    pub private_key_file: PathBuf,
}

#[derive(Clone, Debug)]
pub struct UplinkConfig {
    pub id: UplinkId,
    pub display_name: String,
    pub interface: String,
    pub enabled: bool,
}

pub struct ClientRuntimeConfig {
    pub config: ClientConfig,
    pub identity: crate::identity::ClientIdentity,
}

impl fmt::Debug for ClientRuntimeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRuntimeConfig")
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
    Identity(crate::identity::IdentityError),
    Validation(ConfigValidationError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigValidationError {
    pub path: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureFileKind {
    Config,
    PrivateKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecureFileMetadata {
    pub is_regular_file: bool,
    pub uid: u32,
    pub mode: u32,
    pub nlink: u64,
}

pub fn validate_secure_file_metadata(
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

pub fn open_secure_file(
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

pub fn read_secure_file(
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

impl ClientConfigFile {
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

    pub fn validate(self) -> Result<ClientConfig, ConfigValidationError> {
        validate_stable_id("gateway.id", &self.gateway.id)?;
        if self.gateway.endpoints.is_empty() {
            return Err(validation(
                "gateway.endpoints",
                "must contain at least one endpoint",
            ));
        }
        let mut endpoints = HashSet::with_capacity(self.gateway.endpoints.len());
        for (index, endpoint) in self.gateway.endpoints.iter().enumerate() {
            if !endpoints.insert(endpoint.address) {
                return Err(validation(
                    format!("gateway.endpoints[{index}].address"),
                    "duplicates an earlier endpoint",
                ));
            }
        }
        let server_public_key = PublicKey::parse(&self.gateway.server_public_key)
            .map_err(|error| validation("gateway.server_public_key", error.to_string()))?;
        let client_id = ClientId::new(&self.client.id)
            .map_err(|_| validation("client.id", "must be a non-empty bounded stable ID"))?;
        validate_path("client.private_key_file", &self.client.private_key_file)?;
        validate_path("ipc_socket", &self.ipc_socket)?;

        let mut uplink_ids = HashSet::with_capacity(self.uplinks.len());
        let mut uplinks = Vec::with_capacity(self.uplinks.len());
        for (index, uplink) in self.uplinks.into_iter().enumerate() {
            let id = UplinkId::new(&uplink.id).map_err(|_| {
                validation(
                    format!("uplinks[{index}].id"),
                    "must be a non-empty bounded stable ID",
                )
            })?;
            if !uplink_ids.insert(id.clone()) {
                return Err(validation(
                    format!("uplinks[{index}].id"),
                    "duplicates an earlier uplink ID",
                ));
            }
            if uplink.display_name.trim().is_empty() {
                return Err(validation(
                    format!("uplinks[{index}].display_name"),
                    "must not be empty",
                ));
            }
            validate_interface(index, &uplink.interface)?;
            uplinks.push(UplinkConfig {
                id,
                display_name: uplink.display_name,
                interface: uplink.interface,
                enabled: uplink.enabled,
            });
        }

        Ok(ClientConfig {
            gateway: GatewayConfig {
                id: self.gateway.id,
                server_public_key,
                endpoints: self.gateway.endpoints,
            },
            client: ClientIdentityConfig {
                id: client_id,
                private_key_file: self.client.private_key_file,
            },
            uplinks,
            ipc_socket: self.ipc_socket,
        })
    }

    pub fn load_validated(path: impl AsRef<Path>) -> Result<ClientConfig, ConfigError> {
        Self::load(path)?
            .validate()
            .map_err(ConfigError::Validation)
    }

    pub fn load_validated_runtime(
        path: impl AsRef<Path>,
    ) -> Result<ClientRuntimeConfig, ConfigError> {
        let config = Self::load(path)?
            .validate()
            .map_err(ConfigError::Validation)?;
        let key_bytes = read_secure_file(
            &config.client.private_key_file,
            "client.private_key_file",
            SecureFileKind::PrivateKey,
        )
        .map_err(ConfigError::Validation)?;
        let identity = crate::identity::ClientIdentity::from_secure_bytes(key_bytes)
            .map_err(ConfigError::Identity)?;
        Ok(ClientRuntimeConfig { config, identity })
    }
}

fn validate_stable_id(path: &str, value: &str) -> Result<(), ConfigValidationError> {
    if value.is_empty()
        || value.len() > ClientId::MAX_LEN
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(validation(path, "must be a non-empty bounded stable ID"));
    }
    Ok(())
}

fn validate_interface(index: usize, value: &str) -> Result<(), ConfigValidationError> {
    if value.is_empty()
        || value.len() > 15
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        return Err(validation(
            format!("uplinks[{index}].interface"),
            "must be a valid interface name",
        ));
    }
    Ok(())
}

fn validate_path(path: &str, value: &Path) -> Result<(), ConfigValidationError> {
    if value.as_os_str().is_empty() || !value.is_absolute() {
        return Err(validation(path, "must be an absolute non-empty path"));
    }
    Ok(())
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
                "client.private_key_file",
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
                    "client.private_key_file",
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

    fn json(uplinks: &str, endpoints: &str, key: &str) -> String {
        format!(
            r#"{{"gateway":{{"id":"jax","server_public_key":"{key}","endpoints":{endpoints}}},"client":{{"id":"scooter","private_key_file":"/tmp/client.key"}},"uplinks":{uplinks},"ipc_socket":"/tmp/multipass.sock"}}"#
        )
    }

    fn key(byte: u8) -> String {
        PublicKey::from_raw([byte; 32]).to_config_string()
    }

    #[test]
    fn zero_uplinks_is_valid() {
        let config =
            ClientConfigFile::from_json(&json("[]", r#"[{"address":"127.0.0.1:51823"}]"#, &key(1)))
                .unwrap()
                .validate()
                .unwrap();
        assert!(config.uplinks.is_empty());
    }

    #[test]
    fn disabled_uplinks_remain_represented() {
        let config = ClientConfigFile::from_json(&json(
            r#"[{"id":"wifi","display_name":"Wi-Fi","interface":"en0","enabled":false}]"#,
            r#"[{"address":"127.0.0.1:51823"}]"#,
            &key(1),
        ))
        .unwrap()
        .validate()
        .unwrap();
        assert_eq!(config.uplinks.len(), 1);
        assert!(!config.uplinks[0].enabled);
    }

    #[test]
    fn duplicate_uplink_ids_and_endpoints_are_path_aware() {
        let duplicate_uplink = ClientConfigFile::from_json(&json(
            r#"[{"id":"wifi","display_name":"Wi-Fi","interface":"en0","enabled":true},{"id":"wifi","display_name":"Other","interface":"en1","enabled":true}]"#,
            r#"[{"address":"127.0.0.1:51823"}]"#,
            &key(1),
        ))
        .unwrap()
        .validate()
        .unwrap_err();
        assert_eq!(duplicate_uplink.path, "uplinks[1].id");

        let duplicate_endpoint = ClientConfigFile::from_json(&json(
            "[]",
            r#"[{"address":"127.0.0.1:51823"},{"address":"127.0.0.1:51823"}]"#,
            &key(1),
        ))
        .unwrap()
        .validate()
        .unwrap_err();
        assert_eq!(duplicate_endpoint.path, "gateway.endpoints[1].address");
    }

    #[test]
    fn invalid_ids_keys_interfaces_and_paths_are_rejected() {
        let invalid_key = ClientConfigFile::from_json(&json(
            "[]",
            r#"[{"address":"127.0.0.1:51823"}]"#,
            "not-a-key",
        ))
        .unwrap()
        .validate()
        .unwrap_err();
        assert_eq!(invalid_key.path, "gateway.server_public_key");

        let invalid_interface = ClientConfigFile::from_json(&json(
            r#"[{"id":"wifi","display_name":"Wi-Fi","interface":"en 0","enabled":true}]"#,
            r#"[{"address":"127.0.0.1:51823"}]"#,
            &key(1),
        ))
        .unwrap()
        .validate()
        .unwrap_err();
        assert_eq!(invalid_interface.path, "uplinks[0].interface");

        let mut relative =
            ClientConfigFile::from_json(&json("[]", r#"[{"address":"127.0.0.1:51823"}]"#, &key(1)))
                .unwrap();
        relative.ipc_socket = "relative.sock".into();
        assert_eq!(relative.validate().unwrap_err().path, "ipc_socket");
    }
}
