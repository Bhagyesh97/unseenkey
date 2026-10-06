//! Known-answer tests against published vectors (see `tests/vectors/README.md`).

use serde::Deserialize;
use unseenkey_core::crypto::{aead, hash, kdf, sign, SecretBytes};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in vector file")
}

#[derive(Deserialize)]
struct Argon2Vector {
    password: String,
    salt: String,
    t_cost: u32,
    m_cost_kib: u32,
    p_cost: u32,
    tag_hex: String,
}

#[derive(Deserialize)]
struct Argon2File {
    vectors: Vec<Argon2Vector>,
}

#[test]
fn argon2id_reference_vectors() {
    let file: Argon2File = serde_json::from_str(include_str!("vectors/argon2id.json")).unwrap();
    for v in file.vectors {
        let profile = kdf::Argon2Profile {
            m_cost_kib: v.m_cost_kib,
            t_cost: v.t_cost,
            p_cost: v.p_cost,
        };
        let key = kdf::derive_password_key(
            &SecretBytes::from(v.password.as_str()),
            v.salt.as_bytes(),
            profile,
        )
        .unwrap();
        assert_eq!(key.expose(), h(&v.tag_hex).as_slice(), "m={}", v.m_cost_kib);
    }
}

#[derive(Deserialize)]
struct XChaChaVector {
    plaintext: String,
    aad_hex: String,
    key_hex: String,
    nonce_hex: String,
    ciphertext_hex: String,
    tag_hex: String,
}

#[test]
fn xchacha20poly1305_ietf_vector() {
    let v: XChaChaVector =
        serde_json::from_str(include_str!("vectors/xchacha20poly1305.json")).unwrap();
    let key = SecretBytes::new(h(&v.key_hex));
    let nonce: [u8; aead::NONCE_LEN] = h(&v.nonce_hex).try_into().unwrap();
    let aad = h(&v.aad_hex);
    let sealed =
        aead::seal_with_nonce(&key, &nonce, &aad, &SecretBytes::from(v.plaintext.as_str()))
            .unwrap();
    let mut expected = h(&v.ciphertext_hex);
    expected.extend(h(&v.tag_hex));
    assert_eq!(sealed.ciphertext, expected);
    let opened = aead::open(&key, &aad, &sealed).unwrap();
    assert_eq!(opened.expose(), v.plaintext.as_bytes());
}

#[derive(Deserialize)]
struct HkdfVector {
    ikm_hex: String,
    salt_hex: String,
    info_hex: String,
    length: usize,
    okm_hex: String,
}

#[test]
fn hkdf_sha256_rfc5869_case1() {
    let v: HkdfVector = serde_json::from_str(include_str!("vectors/hkdf_sha256.json")).unwrap();
    let okm = kdf::hkdf_sha256(
        &SecretBytes::new(h(&v.ikm_hex)),
        &h(&v.salt_hex),
        &h(&v.info_hex),
        v.length,
    )
    .unwrap();
    assert_eq!(okm.expose(), h(&v.okm_hex).as_slice());
}

#[derive(Deserialize)]
struct Blake3Vector {
    input_len: usize,
    hash_hex: String,
}

#[derive(Deserialize)]
struct Blake3File {
    vectors: Vec<Blake3Vector>,
}

#[test]
fn blake3_official_vectors() {
    let file: Blake3File = serde_json::from_str(include_str!("vectors/blake3.json")).unwrap();
    for v in file.vectors {
        let input: Vec<u8> = (0..v.input_len).map(|i| (i % 251) as u8).collect();
        assert_eq!(hash::blake3(&input).as_slice(), h(&v.hash_hex).as_slice());
    }
}

#[derive(Deserialize)]
struct Ed25519Vector {
    secret_key_hex: String,
    public_key_hex: String,
    message_hex: String,
    signature_hex: String,
}

#[test]
fn ed25519_rfc8032_test1() {
    let v: Ed25519Vector = serde_json::from_str(include_str!("vectors/ed25519.json")).unwrap();
    let kp = sign::SigningKeyPair::from_seed(&SecretBytes::new(h(&v.secret_key_hex))).unwrap();
    assert_eq!(kp.public_key().as_slice(), h(&v.public_key_hex).as_slice());
    let msg = h(&v.message_hex);
    let sig = kp.sign(&msg);
    assert_eq!(sig.as_slice(), h(&v.signature_hex).as_slice());
    let pk: [u8; 32] = h(&v.public_key_hex).try_into().unwrap();
    assert!(sign::verify(&pk, &msg, &sig).is_ok());
}

#[derive(Deserialize)]
struct SigV4Vector {
    name: String,
    service: String,
    region: String,
    amz_date: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    method: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
    payload_hash: String,
    body_utf8: String,
    canonical_request: String,
    signature: String,
}

#[derive(Deserialize)]
struct SigV4File {
    generator: String,
    vectors: Vec<SigV4Vector>,
}

/// Our SigV4 signer against botocore, AWS's own (`vectors/gen_sigv4.py`).
#[test]
fn sigv4_matches_botocore() {
    use unseenkey_core::broker::sigv4;
    let file: SigV4File = serde_json::from_str(include_str!("vectors/sigv4.json")).unwrap();
    assert!(file.generator.starts_with("botocore"), "{}", file.generator);
    assert!(file.vectors.len() >= 12);
    for v in file.vectors {
        let secret = SecretBytes::from(v.secret_access_key.as_str());
        let creds = sigv4::Credentials {
            access_key_id: &v.access_key_id,
            secret_access_key: &secret,
            session_token: v.session_token.as_deref(),
        };
        // What an SDK encoded is already in wire form and must pass unchanged.
        assert_eq!(sigv4::wire_path(&v.path), v.path, "{}", v.name);
        if let Some(q) = &v.query {
            assert_eq!(&sigv4::wire_query(q), q, "{}", v.name);
        }
        assert_eq!(
            sigv4::payload_hash(v.body_utf8.as_bytes()),
            v.payload_hash,
            "{}",
            v.name
        );
        let signed = sigv4::sign(
            &creds,
            &v.region,
            &v.service,
            &v.amz_date,
            &sigv4::Request {
                method: &v.method,
                path: &v.path,
                query: v.query.as_deref(),
                headers: &v.headers,
                payload_hash: &v.payload_hash,
            },
        );
        assert_eq!(signed.canonical_request, v.canonical_request, "{}", v.name);
        assert_eq!(signed.signature, v.signature, "{}", v.name);
    }
}
