//! AWS Signature Version 4.
//!
//! AWS has no bearer credential to inject: every request is signed with the
//! secret access key over the method, path, query, selected headers and a hash
//! of the body. The broker therefore works differently for AWS than for other
//! providers. The SDK is given a handle in place of the access key id and any
//! placeholder as the secret; it signs with that placeholder. The broker takes
//! the handle and the region/service scope out of the SDK's `Authorization`
//! header, throws the SDK's signature away, and signs the request again with
//! the real key for the real host ([`sign`]).
//!
//! Everything here is pure: no clock, no I/O. Canonicalisation follows
//! botocore, the reference the test vectors in `tests/vectors/sigv4.json`
//! were generated with.

use super::BrokerError;
use crate::crypto::SecretBytes;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// The only algorithm we sign with.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// SigV4A (multi-region, ECDSA). Recognised so it can be refused clearly.
pub const ALGORITHM_V4A: &str = "AWS4-ECDSA-P256-SHA256";

/// What a client's `Authorization` header says about itself. The signature in
/// it was made with a placeholder secret and is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientScope {
    /// The access key id slot: where the SDK put the handle.
    pub access_key_id: String,
    /// Region the SDK signed for (`us-east-1`).
    pub region: String,
    /// Service signing name (`s3`, `dynamodb`, `execute-api`).
    pub service: String,
}

/// Parse `AWS4-HMAC-SHA256 Credential=<id>/<date>/<region>/<service>/aws4_request, ...`.
pub fn parse_authorization(value: &str) -> Option<ClientScope> {
    let rest = value.trim().strip_prefix(ALGORITHM)?;
    let cred = rest
        .split([',', ' '])
        .map(str::trim)
        .find_map(|p| p.strip_prefix("Credential="))?;
    let mut parts = cred.split('/');
    let access_key_id = parts.next()?.to_string();
    let _date = parts.next()?;
    let region = parts.next()?.to_string();
    let service = parts.next()?.to_string();
    if parts.next()? != "aws4_request" || parts.next().is_some() {
        return None;
    }
    if access_key_id.is_empty() || region.is_empty() || service.is_empty() {
        return None;
    }
    Some(ClientScope {
        access_key_id,
        region,
        service,
    })
}

/// True when the header announces SigV4A, which we do not implement.
pub fn is_sigv4a(value: &str) -> bool {
    value.trim().starts_with(ALGORITHM_V4A)
}

/// The real credentials, borrowed from a revealed secret.
pub struct Credentials<'a> {
    /// `AKIA…` / `ASIA…`.
    pub access_key_id: &'a str,
    /// The secret access key.
    pub secret_access_key: &'a SecretBytes,
    /// Present for temporary (STS) credentials.
    pub session_token: Option<&'a str>,
}

/// The request as it will go on the wire.
pub struct Request<'a> {
    /// HTTP method, upper case.
    pub method: &'a str,
    /// Path as sent (see [`wire_path`]).
    pub path: &'a str,
    /// Query string as sent, without `?` (see [`wire_query`]).
    pub query: Option<&'a str>,
    /// Headers to sign: `(name, value)`. Must include `host` and `x-amz-date`.
    pub headers: &'a [(String, String)],
    /// Hex SHA-256 of the body, or a literal such as `UNSIGNED-PAYLOAD`.
    pub payload_hash: &'a str,
}

/// The outcome of signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// Value for the `Authorization` header.
    pub authorization: String,
    /// Hex signature.
    pub signature: String,
    /// `host;x-amz-date;…`
    pub signed_headers: String,
    /// The canonical request (not secret; useful in tests and diagnostics).
    pub canonical_request: String,
}

const fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

fn push_pct(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push('%');
    out.push(HEX[(b >> 4) as usize] as char);
    out.push(HEX[(b & 15) as usize] as char);
}

/// Percent-encode everything except unreserved characters and the bytes in `keep`.
fn encode(s: &str, keep: &[u8]) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for &b in s.as_bytes() {
        if unreserved(b) || keep.contains(&b) {
            out.push(b as char);
        } else {
            push_pct(&mut out, b);
        }
    }
    out
}

/// Bring an already-encoded string to AWS's wire form without changing its
/// meaning: existing `%XX` escapes are kept (hex upper-cased), unreserved
/// characters and the bytes in `keep` pass through, everything else is escaped.
fn fix_encoding(s: &str, keep: &[u8]) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + 8);
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            out.push('%');
            out.push(bytes[i + 1].to_ascii_uppercase() as char);
            out.push(bytes[i + 2].to_ascii_uppercase() as char);
            i += 3;
        } else if unreserved(b) || keep.contains(&b) {
            out.push(b as char);
            i += 1;
        } else {
            push_pct(&mut out, b);
            i += 1;
        }
    }
    out
}

/// The path to send upstream: the caller's path with its encoding tidied.
/// SDK-produced paths come out unchanged.
pub fn wire_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    fix_encoding(path, b"/")
}

/// The query string to send upstream: each name and value with its encoding
/// tidied, order preserved. A `+` becomes `%2B`: AWS never treats `+` as a space.
pub fn wire_query(query: &str) -> String {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => format!("{}={}", fix_encoding(k, b""), fix_encoding(v, b"")),
            None => format!("{}=", fix_encoding(pair, b"")),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// RFC 3986 dot-segment removal, plus collapsing empty segments, as AWS does
/// for every service except S3.
fn remove_dot_segments(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let first = if path.starts_with('/') { "/" } else { "" };
    let last = if path.ends_with('/') && !out.is_empty() {
        "/"
    } else {
        ""
    };
    format!("{first}{}{last}", out.join("/"))
}

/// Canonical URI. S3 signs the path exactly as sent; every other service
/// normalises it and encodes it a second time.
fn canonical_uri(path: &str, service: &str) -> String {
    if is_s3(service) {
        return if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };
    }
    encode(&remove_dot_segments(path), b"/")
}

/// Canonical query: pairs sorted by name, then value, in their wire encoding.
fn canonical_query(query: Option<&str>) -> String {
    let Some(q) = query else {
        return String::new();
    };
    let mut pairs: Vec<(&str, &str)> = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Trim and collapse runs of whitespace, as the canonical header form requires.
fn header_value(v: &str) -> String {
    v.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// S3 and its relatives sign the path as sent.
pub fn is_s3(service: &str) -> bool {
    matches!(
        service,
        "s3" | "s3-outposts" | "s3express" | "s3-object-lambda"
    )
}

/// Hex SHA-256 of a body.
pub fn payload_hash(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

fn hmac(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// Sign `req`. `amz_date` is `YYYYMMDDTHHMMSSZ` and must equal the request's
/// `x-amz-date` header.
pub fn sign(
    creds: &Credentials<'_>,
    region: &str,
    service: &str,
    amz_date: &str,
    req: &Request<'_>,
) -> Signed {
    // Canonical headers: lower-case names, sorted, same-name values comma-joined.
    let mut names: Vec<String> = req
        .headers
        .iter()
        .map(|(n, _)| n.to_ascii_lowercase())
        .collect();
    names.sort();
    names.dedup();
    let mut canonical_headers = String::new();
    for name in &names {
        let values: Vec<String> = req
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| header_value(v))
            .collect();
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(&values.join(","));
        canonical_headers.push('\n');
    }
    let signed_headers = names.join(";");

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method,
        canonical_uri(req.path, service),
        canonical_query(req.query),
        canonical_headers,
        signed_headers,
        req.payload_hash
    );

    let date = amz_date.get(..8).unwrap_or(amz_date);
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let mut seed = Zeroizing::new(Vec::with_capacity(4 + creds.secret_access_key.len()));
    seed.extend_from_slice(b"AWS4");
    seed.extend_from_slice(creds.secret_access_key.expose());
    let k_date = hmac(&seed, date.as_bytes());
    let k_region = hmac(k_date.as_slice(), region.as_bytes());
    let k_service = hmac(k_region.as_slice(), service.as_bytes());
    let k_signing = hmac(k_service.as_slice(), b"aws4_request");
    let signature = hex::encode(hmac(k_signing.as_slice(), string_to_sign.as_bytes()).as_slice());

    let authorization = format!(
        "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id
    );
    Signed {
        authorization,
        signature,
        signed_headers,
        canonical_request,
    }
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time in milliseconds.
pub fn amz_date(unix_ms: i64) -> String {
    let secs = unix_ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since the epoch (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// A body sent with `Content-Encoding: aws-chunked`, taken apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dechunked {
    /// The payload without chunk framing.
    pub body: Vec<u8>,
    /// Trailing headers (checksums), without the trailer signature.
    pub trailers: Vec<(String, String)>,
}

fn find_crlf(data: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| from + p)
}

/// Undo `aws-chunked` framing. SDKs use it for streaming uploads and sign every
/// chunk with the (placeholder) key, so the chunk signatures are worthless to
/// us: the broker sends the plain payload with an exact hash instead, and turns
/// any trailing checksum into an ordinary header.
///
/// ```text
/// <hex size>[;chunk-signature=<sig>]\r\n<data>\r\n ... 0[;chunk-signature=<sig>]\r\n
/// [name:value\r\n]* [x-amz-trailer-signature:<sig>\r\n] \r\n
/// ```
pub fn decode_aws_chunked(data: &[u8]) -> Result<Dechunked, BrokerError> {
    let bad = || BrokerError::Malformed("aws-chunked body".into());
    let mut body = Vec::with_capacity(data.len());
    let mut i = 0;
    loop {
        let eol = find_crlf(data, i).ok_or_else(bad)?;
        let line = core::str::from_utf8(&data[i..eol]).map_err(|_| bad())?;
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| bad())?;
        i = eol + 2;
        if size == 0 {
            break;
        }
        let end = i.checked_add(size).ok_or_else(bad)?;
        if end + 2 > data.len() || &data[end..end + 2] != b"\r\n" {
            return Err(bad());
        }
        body.extend_from_slice(&data[i..end]);
        i = end + 2;
    }
    let mut trailers = Vec::new();
    while i < data.len() {
        let eol = find_crlf(data, i).unwrap_or(data.len());
        let line = core::str::from_utf8(&data[i..eol]).map_err(|_| bad())?;
        i = (eol + 2).min(data.len());
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(bad)?;
        let name = name.trim().to_ascii_lowercase();
        if name != "x-amz-trailer-signature" {
            trailers.push((name, value.trim().to_string()));
        }
    }
    Ok(Dechunked { body, trailers })
}

/// Remove the `aws-chunked` token from a `Content-Encoding` value. `None`
/// when nothing else remains.
pub fn strip_aws_chunked(content_encoding: &str) -> Option<String> {
    let rest: Vec<&str> = content_encoding
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.eq_ignore_ascii_case("aws-chunked"))
        .collect();
    (!rest.is_empty()).then(|| rest.join(", "))
}

/// Services whose endpoint has no region in it; they sign as `us-east-1`.
const GLOBAL: &[(&str, &str)] = &[
    ("iam", "iam.amazonaws.com"),
    ("route53", "route53.amazonaws.com"),
    ("cloudfront", "cloudfront.amazonaws.com"),
    ("organizations", "organizations.us-east-1.amazonaws.com"),
];

/// Signing names whose host prefix differs.
const PREFIX: &[(&str, &str)] = &[
    ("ses", "email"),
    ("ecr", "api.ecr"),
    ("sagemaker", "api.sagemaker"),
];

/// Signing names shared by several endpoints, or with per-resource hosts: the
/// host cannot be derived and must be given explicitly.
const AMBIGUOUS: &[&str] = &["bedrock", "execute-api", "es", "aoss", "lex", "iotdata"];

fn label_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The usual endpoint for a signing name and region, when there is exactly one.
/// `None` means the caller must name the host (`/p/aws/@<host>/…`).
pub fn host_for(service: &str, region: &str) -> Option<String> {
    if !label_ok(service) || !label_ok(region) || AMBIGUOUS.contains(&service) {
        return None;
    }
    if let Some((_, host)) = GLOBAL.iter().find(|(s, _)| *s == service) {
        return Some((*host).to_string());
    }
    let prefix = PREFIX
        .iter()
        .find(|(s, _)| *s == service)
        .map(|(_, p)| *p)
        .unwrap_or(service);
    let suffix = if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    };
    Some(format!("{prefix}.{region}.{suffix}"))
}

fn looks_like_region(s: &str) -> bool {
    // us-east-1, eu-central-2, ap-southeast-4, us-gov-west-1, cn-north-1
    let mut parts = s.split('-');
    let ok_first = parts
        .next()
        .is_some_and(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_lowercase()));
    let rest: Vec<&str> = parts.collect();
    ok_first
        && (2..=3).contains(&rest.len())
        && rest
            .last()
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        && rest[..rest.len() - 1]
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase()))
}

/// Work out `(service signing name, region)` from an AWS host name, for callers
/// that do not send a SigV4 scope of their own (MCP `call_api`, curl).
pub fn scope_for_host(host: &str) -> Option<(String, String)> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let stem = host
        .strip_suffix(".amazonaws.com.cn")
        .or_else(|| host.strip_suffix(".amazonaws.com"))?;
    if let Some((svc, _)) = GLOBAL.iter().find(|(_, h)| *h == host) {
        return Some(((*svc).to_string(), "us-east-1".to_string()));
    }
    let labels: Vec<&str> = stem.split('.').collect();
    if labels.iter().any(|l| l.is_empty()) {
        return None;
    }
    // S3 first: bucket names in virtual-hosted style can look like anything,
    // including a region, so only labels after the `s3` label are considered.
    if let Some(at) = labels
        .iter()
        .rposition(|l| matches!(*l, "s3" | "s3-fips" | "s3-accesspoint" | "s3-control"))
    {
        let region = labels[at + 1..]
            .iter()
            .rev()
            .find(|l| looks_like_region(l))
            .map(|l| (*l).to_string())
            .unwrap_or_else(|| "us-east-1".to_string());
        return Some(("s3".to_string(), region));
    }
    // Everything else puts the region last, or has none (global endpoints).
    let (before, region) = match labels.split_last() {
        Some((last, rest)) if !rest.is_empty() && looks_like_region(last) => {
            (rest, (*last).to_string())
        }
        _ => (&labels[..], "us-east-1".to_string()),
    };
    if before.len() == 1 && looks_like_region(before[0]) {
        return None;
    }
    let joined = before.join(".");
    if let Some((svc, _)) = PREFIX.iter().find(|(_, p)| *p == joined) {
        return Some(((*svc).to_string(), region));
    }
    // `<id>.execute-api.<region>`, `bedrock-runtime.<region>`, `runtime.sagemaker.<region>`
    let last = *before.last()?;
    let service = match last {
        "execute-api" => "execute-api",
        "sagemaker" => "sagemaker",
        l if l.starts_with("bedrock") => "bedrock",
        l => l.strip_suffix("-fips").unwrap_or(l),
    };
    Some((service.to_string(), region))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_header_parsing() {
        let h = "AWS4-HMAC-SHA256 Credential=usk_h_abc/20261007/eu-west-1/dynamodb/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef";
        assert_eq!(
            parse_authorization(h),
            Some(ClientScope {
                access_key_id: "usk_h_abc".into(),
                region: "eu-west-1".into(),
                service: "dynamodb".into(),
            })
        );
        // No space after the commas (some SDKs).
        let h2 = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request,SignedHeaders=host,Signature=00";
        assert_eq!(parse_authorization(h2).unwrap().service, "s3");
        for bad in [
            "Bearer abc",
            "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=00",
            "AWS4-HMAC-SHA256 Credential=a/b/c/d, Signature=00",
            "AWS4-HMAC-SHA256 Credential=a/20150830/us-east-1/s3/other, Signature=00",
            "AWS4-HMAC-SHA256 Credential=/20150830/us-east-1/s3/aws4_request",
            "AWS4-ECDSA-P256-SHA256 Credential=a/20150830/s3/aws4_request",
        ] {
            assert_eq!(parse_authorization(bad), None, "{bad}");
        }
        assert!(is_sigv4a(
            "AWS4-ECDSA-P256-SHA256 Credential=a/20150830/s3/aws4_request"
        ));
        assert!(!is_sigv4a(h));
    }

    #[test]
    fn wire_forms_leave_sdk_output_alone_and_tidy_the_rest() {
        assert_eq!(wire_path(""), "/");
        assert_eq!(wire_path("/bucket/a%20b/c%2Fd"), "/bucket/a%20b/c%2Fd");
        assert_eq!(wire_path("/a b/ü/%e2%82%ac"), "/a%20b/%C3%BC/%E2%82%AC");
        assert_eq!(wire_path("/100%/x"), "/100%25/x");
        assert_eq!(wire_query("b=2&a=1"), "b=2&a=1");
        assert_eq!(
            wire_query("prefix=a/b&marker=x+y&flag"),
            "prefix=a%2Fb&marker=x%2By&flag="
        );
        assert_eq!(wire_query("k=%7e%7E~"), "k=%7E%7E~");
        assert_eq!(canonical_query(Some("b=2&a=2&a=1&A=0")), "A=0&a=1&a=2&b=2");
        assert_eq!(canonical_query(None), "");
    }

    #[test]
    fn canonical_uri_differs_for_s3() {
        assert_eq!(canonical_uri("/a%20b/c", "s3"), "/a%20b/c");
        assert_eq!(canonical_uri("/a%20b/c", "execute-api"), "/a%2520b/c");
        assert_eq!(canonical_uri("/a/./b/../c//d/", "lambda"), "/a/c/d/");
        assert_eq!(canonical_uri("/a/./b/../c//d/", "s3"), "/a/./b/../c//d/");
        assert_eq!(canonical_uri("", "sts"), "/");
        assert_eq!(canonical_uri("/..", "sts"), "/");
    }

    #[test]
    fn dates() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(1_440_938_160_000), "20150830T123600Z");
        assert_eq!(amz_date(1_709_164_799_999), "20240228T235959Z");
        assert_eq!(amz_date(1_709_251_200_000), "20240301T000000Z");
        assert_eq!(amz_date(951_782_400_000), "20000229T000000Z");
        assert_eq!(amz_date(4_102_444_800_000), "21000101T000000Z");
    }

    #[test]
    fn aws_chunked() {
        let signed = b"5;chunk-signature=aa\r\nhello\r\n6;chunk-signature=bb\r\n world\r\n0;chunk-signature=cc\r\n\r\n";
        let d = decode_aws_chunked(signed).unwrap();
        assert_eq!(d.body, b"hello world");
        assert!(d.trailers.is_empty());

        let trailer = b"b\r\nhello world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\nx-amz-trailer-signature:ff\r\n\r\n";
        let d = decode_aws_chunked(trailer).unwrap();
        assert_eq!(d.body, b"hello world");
        assert_eq!(
            d.trailers,
            vec![("x-amz-checksum-crc32".to_string(), "DUoRhQ==".to_string())]
        );

        // Binary data that contains CRLF is taken by length, not by scanning.
        let bin = b"4\r\n\r\n\r\n\r\n0\r\n\r\n";
        assert_eq!(decode_aws_chunked(bin).unwrap().body, b"\r\n\r\n");

        for bad in [
            &b"zz\r\nabc\r\n0\r\n\r\n"[..],
            b"5\r\nabc\r\n0\r\n\r\n",
            b"3\r\nabcXX0\r\n\r\n",
            b"3\r\nabc\r\n",
        ] {
            assert!(decode_aws_chunked(bad).is_err());
        }
        assert_eq!(strip_aws_chunked("aws-chunked"), None);
        assert_eq!(strip_aws_chunked("gzip, aws-chunked"), Some("gzip".into()));
        assert_eq!(
            strip_aws_chunked("AWS-Chunked,gzip , br"),
            Some("gzip, br".into())
        );
    }

    #[test]
    fn hosts_and_scopes() {
        assert_eq!(
            host_for("s3", "us-east-1").as_deref(),
            Some("s3.us-east-1.amazonaws.com")
        );
        assert_eq!(
            host_for("dynamodb", "eu-west-1").as_deref(),
            Some("dynamodb.eu-west-1.amazonaws.com")
        );
        assert_eq!(
            host_for("ses", "us-west-2").as_deref(),
            Some("email.us-west-2.amazonaws.com")
        );
        assert_eq!(
            host_for("iam", "us-east-1").as_deref(),
            Some("iam.amazonaws.com")
        );
        assert_eq!(
            host_for("sts", "ap-south-1").as_deref(),
            Some("sts.ap-south-1.amazonaws.com")
        );
        assert_eq!(
            host_for("s3", "cn-north-1").as_deref(),
            Some("s3.cn-north-1.amazonaws.com.cn")
        );
        // Not derivable, or not something to build a host name from.
        assert_eq!(host_for("bedrock", "us-east-1"), None);
        assert_eq!(host_for("execute-api", "us-east-1"), None);
        assert_eq!(host_for("evil.example/", "us-east-1"), None);
        assert_eq!(host_for("s3", "x.attacker.example"), None);
        assert_eq!(host_for("", ""), None);

        let scope = |h: &str| scope_for_host(h).map(|(s, r)| format!("{s}/{r}"));
        assert_eq!(
            scope("s3.us-east-1.amazonaws.com").as_deref(),
            Some("s3/us-east-1")
        );
        assert_eq!(
            scope("my-bucket.s3.eu-central-1.amazonaws.com").as_deref(),
            Some("s3/eu-central-1")
        );
        // Bucket names that look like regions do not confuse it.
        assert_eq!(
            scope("my-bucket-1.s3.amazonaws.com").as_deref(),
            Some("s3/us-east-1")
        );
        assert_eq!(
            scope("eu-west-1.s3.us-east-2.amazonaws.com").as_deref(),
            Some("s3/us-east-2")
        );
        assert_eq!(scope("a..amazonaws.com"), None);
        assert_eq!(scope("s3.amazonaws.com").as_deref(), Some("s3/us-east-1"));
        assert_eq!(
            scope("bucket.s3.dualstack.ap-southeast-2.amazonaws.com").as_deref(),
            Some("s3/ap-southeast-2")
        );
        assert_eq!(
            scope("DynamoDB.us-west-2.amazonaws.com.").as_deref(),
            Some("dynamodb/us-west-2")
        );
        assert_eq!(
            scope("email.us-west-2.amazonaws.com").as_deref(),
            Some("ses/us-west-2")
        );
        assert_eq!(
            scope("api.ecr.us-east-1.amazonaws.com").as_deref(),
            Some("ecr/us-east-1")
        );
        assert_eq!(scope("iam.amazonaws.com").as_deref(), Some("iam/us-east-1"));
        assert_eq!(scope("sts.amazonaws.com").as_deref(), Some("sts/us-east-1"));
        assert_eq!(
            scope("abc123.execute-api.us-east-1.amazonaws.com").as_deref(),
            Some("execute-api/us-east-1")
        );
        assert_eq!(
            scope("bedrock-runtime.us-east-1.amazonaws.com").as_deref(),
            Some("bedrock/us-east-1")
        );
        assert_eq!(
            scope("runtime.sagemaker.us-east-2.amazonaws.com").as_deref(),
            Some("sagemaker/us-east-2")
        );
        assert_eq!(
            scope("kms-fips.us-gov-west-1.amazonaws.com").as_deref(),
            Some("kms/us-gov-west-1")
        );
        assert_eq!(
            scope("s3.cn-north-1.amazonaws.com.cn").as_deref(),
            Some("s3/cn-north-1")
        );
        assert_eq!(scope("example.com"), None);
        assert_eq!(scope("amazonaws.com"), None);
        assert_eq!(scope("us-east-1.amazonaws.com"), None);
        // Round trip for the derivable ones.
        for (svc, region) in [
            ("sqs", "us-east-2"),
            ("ses", "eu-west-1"),
            ("ecr", "ap-northeast-1"),
            ("lambda", "sa-east-1"),
        ] {
            let host = host_for(svc, region).unwrap();
            assert_eq!(
                scope_for_host(&host),
                Some((svc.to_string(), region.to_string())),
                "{host}"
            );
        }
    }

    /// The worked example from the AWS General Reference ("Signature Version 4
    /// signing process"): IAM ListUsers on 2015-08-30.
    #[test]
    fn documented_example() {
        let secret = SecretBytes::from("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        let creds = Credentials {
            access_key_id: "AKIDEXAMPLE",
            secret_access_key: &secret,
            session_token: None,
        };
        let headers = vec![
            (
                "content-type".to_string(),
                "application/x-www-form-urlencoded; charset=utf-8".to_string(),
            ),
            ("host".to_string(), "iam.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ];
        let s = sign(
            &creds,
            "us-east-1",
            "iam",
            "20150830T123600Z",
            &Request {
                method: "GET",
                path: "/",
                query: Some("Action=ListUsers&Version=2010-05-08"),
                headers: &headers,
                payload_hash: &payload_hash(b""),
            },
        );
        assert_eq!(
            hex::encode(Sha256::digest(s.canonical_request.as_bytes())),
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        );
        assert_eq!(
            s.signature,
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
        assert_eq!(s.signed_headers, "content-type;host;x-amz-date");
        assert_eq!(
            s.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }
}
