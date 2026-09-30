//! Record payloads and their encryption.
//!
//! This is the only module allowed to serialize secret values, and it does so
//! straight into a buffer that is encrypted and zeroized.

use crate::crypto::aead::{self, Sealed};
use crate::crypto::kdf;
use crate::crypto::{CryptoError, SecretBytes};
use crate::ids::Id;
use crate::storage::{RecordKind, StoredRecord};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Type of secret. Drives which broker adapter applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// Provider API key.
    ApiKey,
    /// Bearer token (PAT, bot token).
    BearerToken,
    /// HTTP Basic username and password (`fields`: `username`, `password`).
    BasicAuth,
    /// OAuth2 client (`fields`: `client_id`, `client_secret`, `refresh_token`).
    Oauth2Client,
    /// AWS credentials (`fields`: `access_key_id`, `secret_access_key`, `session_token`).
    AwsCredentials,
    /// GCP service-account JSON.
    GcpServiceAccount,
    /// Database or service connection string.
    ConnectionString,
    /// SSH private key.
    SshKey,
    /// Website or account password.
    Password,
    /// Any other secret text.
    Note,
}

impl SecretKind {
    /// All kinds, for CLI help and validation.
    pub const ALL: [SecretKind; 10] = [
        SecretKind::ApiKey,
        SecretKind::BearerToken,
        SecretKind::BasicAuth,
        SecretKind::Oauth2Client,
        SecretKind::AwsCredentials,
        SecretKind::GcpServiceAccount,
        SecretKind::ConnectionString,
        SecretKind::SshKey,
        SecretKind::Password,
        SecretKind::Note,
    ];

    /// Stable snake_case name.
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretKind::ApiKey => "api_key",
            SecretKind::BearerToken => "bearer_token",
            SecretKind::BasicAuth => "basic_auth",
            SecretKind::Oauth2Client => "oauth2_client",
            SecretKind::AwsCredentials => "aws_credentials",
            SecretKind::GcpServiceAccount => "gcp_service_account",
            SecretKind::ConnectionString => "connection_string",
            SecretKind::SshKey => "ssh_key",
            SecretKind::Password => "password",
            SecretKind::Note => "note",
        }
    }

    /// Parse the snake_case name.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.as_str() == s)
    }
}

impl fmt::Display for SecretKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A secret string inside an encrypted payload. Zeroized on drop, redacted in
/// Debug. Serializable **only** because it lives on the encryption path; it
/// must never be used outside this module's `encrypt_json`/`decrypt_json`.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretString(String);

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[secret]")
    }
}

impl SecretString {
    fn from_bytes(b: &SecretBytes) -> Self {
        // Secrets are text in practice; invalid UTF-8 is preserved losslessly as hex
        // with a marker so binary blobs round-trip.
        match core::str::from_utf8(b.expose()) {
            Ok(s) => Self(String::from(s)),
            Err(_) => {
                let mut s = String::from("hex:");
                s.push_str(&hex::encode(b.expose()));
                Self(s)
            }
        }
    }

    fn to_bytes(&self) -> SecretBytes {
        if let Some(h) = self.0.strip_prefix("hex:") {
            if let Ok(v) = hex::decode(h) {
                return SecretBytes::new(v);
            }
        }
        SecretBytes::from_slice(self.0.as_bytes())
    }
}

/// Encrypted value record contents.
#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct SecretPayload {
    /// Owning secret.
    #[zeroize(skip)]
    pub secret_id: Id,
    /// Kind, duplicated from metadata so the value record is self-describing.
    #[zeroize(skip)]
    pub kind: SecretKind,
    /// Primary value.
    pub value: SecretString,
    /// Additional named values.
    #[zeroize(skip)]
    pub fields: BTreeMap<String, SecretString>,
    /// Unix milliseconds when this version was created.
    #[zeroize(skip)]
    pub created_at: i64,
}

impl SecretPayload {
    /// Build from plaintext parts.
    pub fn new(
        secret_id: Id,
        kind: SecretKind,
        value: SecretBytes,
        fields: BTreeMap<String, SecretBytes>,
        created_at: i64,
    ) -> Self {
        Self {
            secret_id,
            kind,
            value: SecretString::from_bytes(&value),
            fields: fields
                .iter()
                .map(|(k, v)| (k.clone(), SecretString::from_bytes(v)))
                .collect(),
            created_at,
        }
    }

    /// Convert to the caller-facing revealed form.
    pub fn into_revealed(self) -> super::Revealed {
        super::Revealed {
            value: self.value.to_bytes(),
            fields: self
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), v.to_bytes()))
                .collect(),
        }
    }
}

/// Encrypted metadata record contents. Contains no secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMeta {
    /// Owning secret.
    pub secret_id: Id,
    /// Unique name.
    pub name: String,
    /// Kind.
    pub kind: SecretKind,
    /// Provider preset id.
    pub provider: Option<String>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Hosts this secret may be injected into requests for.
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Notes.
    pub notes: Option<String>,
    /// Exclude this value from response scrubbing (false positives).
    #[serde(default)]
    pub no_scrub: bool,
    /// Allow `usk run` env injection for this secret.
    #[serde(default)]
    pub allow_injection: bool,
    /// Unix milliseconds of creation.
    pub created_at: i64,
    /// Unix milliseconds of last metadata or value change.
    pub updated_at: i64,
    /// Current version of the value record.
    pub value_version: u64,
}

/// The metadata record id for a secret.
pub fn meta_record_id(secret_id: &Id) -> Id {
    Id::derived("usk/meta-record/v1", secret_id)
}

fn dek(vk: &SecretBytes, record_id: &Id, version: u64) -> SecretBytes {
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(b"usk/dek/v1/");
    info.extend_from_slice(record_id.as_bytes());
    info.push(b'/');
    info.extend_from_slice(&version.to_be_bytes());
    kdf::subkey(vk, &info)
}

fn aad(vault_id: &Id, record_id: &Id, version: u64, kind: RecordKind) -> Vec<u8> {
    let mut a = Vec::with_capacity(64);
    a.extend_from_slice(vault_id.as_bytes());
    a.extend_from_slice(record_id.as_bytes());
    a.extend_from_slice(&version.to_be_bytes());
    a.extend_from_slice(kind.as_str().as_bytes());
    a
}

/// Serialize `payload` as JSON and encrypt it into a record.
pub fn encrypt_json<T: Serialize>(
    vk: &SecretBytes,
    vault_id: &Id,
    record_id: Id,
    kind: RecordKind,
    version: u64,
    payload: &T,
    now: i64,
) -> Result<StoredRecord, CryptoError> {
    let json = serde_json::to_vec(payload).map_err(|_| CryptoError::Length)?;
    let plaintext = SecretBytes::new(json);
    let sealed = aead::seal(
        &dek(vk, &record_id, version),
        &aad(vault_id, &record_id, version, kind),
        &plaintext,
    )?;
    Ok(StoredRecord {
        record_id,
        kind,
        version,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        updated_at: now,
        deleted: false,
    })
}

/// Decrypt a record and parse its JSON payload.
pub fn decrypt_json<T: DeserializeOwned>(
    vk: &SecretBytes,
    vault_id: &Id,
    rec: &StoredRecord,
) -> Result<T, CryptoError> {
    if rec.deleted {
        return Err(CryptoError::Decrypt);
    }
    let sealed = Sealed {
        nonce: rec.nonce,
        ciphertext: rec.ciphertext.clone(),
    };
    let plaintext = aead::open(
        &dek(vk, &rec.record_id, rec.version),
        &aad(vault_id, &rec.record_id, rec.version, rec.kind),
        &sealed,
    )?;
    serde_json::from_slice(plaintext.expose()).map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trip_and_binding() {
        let vk = SecretBytes::random(32);
        let vid = Id::new_v7(1);
        let sid = Id::new_v7(2);
        let payload = SecretPayload::new(
            sid,
            SecretKind::ApiKey,
            SecretBytes::from("sk-x"),
            BTreeMap::new(),
            5,
        );
        let rec = encrypt_json(&vk, &vid, sid, RecordKind::Secret, 1, &payload, 5).unwrap();
        let back: SecretPayload = decrypt_json(&vk, &vid, &rec).unwrap();
        assert_eq!(back.into_revealed().value, SecretBytes::from("sk-x"));

        // Same ciphertext presented as a different version, kind or vault fails.
        let mut r2 = rec.clone();
        r2.version = 2;
        assert!(decrypt_json::<SecretPayload>(&vk, &vid, &r2).is_err());
        let mut r3 = rec.clone();
        r3.kind = RecordKind::SecretMeta;
        assert!(decrypt_json::<SecretPayload>(&vk, &vid, &r3).is_err());
        assert!(decrypt_json::<SecretPayload>(&vk, &Id::new_v7(9), &rec).is_err());
    }

    #[test]
    fn binary_values_round_trip() {
        let raw = SecretBytes::new(alloc::vec![0xff, 0x00, 0xfe]);
        let s = SecretString::from_bytes(&raw);
        assert_eq!(s.to_bytes(), raw);
        let text = SecretBytes::from("hex:not-really");
        assert_eq!(SecretString::from_bytes(&text).to_bytes(), text);
    }

    #[test]
    fn secret_string_debug_redacted() {
        let s = SecretString::from_bytes(&SecretBytes::from("shh"));
        assert_eq!(alloc::format!("{s:?}"), "[secret]");
        let p = SecretPayload::new(
            Id::new_v7(1),
            SecretKind::Note,
            SecretBytes::from("shh"),
            BTreeMap::new(),
            0,
        );
        assert!(!alloc::format!("{p:?}").contains("shh"));
    }
}
