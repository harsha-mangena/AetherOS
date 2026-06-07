//! Canonical serialization and hashing primitives.
//!
//! AetherOS signs and hashes structured data that must be reproduced byte-for-byte
//! across the Rust core and the Python bindings. We therefore avoid relying on the
//! incidental field ordering of `serde_json` and instead emit a deterministic
//! canonical JSON form: object keys are recursively sorted lexicographically and
//! no insignificant whitespace is emitted. This is the same family of approach as
//! JCS (RFC 8785), restricted to the value space we actually use (objects, arrays,
//! strings, integers, booleans, null).
//!
//! Hashing uses SHA-256 (FIPS 180-4). We deliberately prefer a widely-audited,
//! compliance-friendly hash over a faster modern one because the evidence ledger is
//! an enterprise audit artifact that may need to stand up in regulated settings.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{CoreError, Result};

/// Serialize any `Serialize` value into canonical JSON bytes.
///
/// The value is first converted into a [`serde_json::Value`] and then emitted with
/// recursively sorted object keys and compact separators.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let v = serde_json::to_value(value).map_err(|e| CoreError::Serialization(e.to_string()))?;
    let mut out = Vec::with_capacity(256);
    write_canonical(&v, &mut out);
    Ok(out)
}

/// Compute the SHA-256 hash of a value's canonical JSON form, returned as lowercase hex.
pub fn canonical_hash_hex<T: Serialize>(value: &T) -> Result<String> {
    let bytes = to_canonical_bytes(value)?;
    Ok(sha256_hex(&bytes))
}

/// SHA-256 of raw bytes as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// SHA-256 over the concatenation of two byte slices, returned as lowercase hex.
///
/// Used by the evidence ledger to chain `prev_hash` with the canonical content of
/// the current entry.
pub fn sha256_chain_hex(prev: &[u8], current: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(current);
    hex::encode(hasher.finalize())
}

/// Recursively write a JSON value in canonical form into `out`.
fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_json_string(s, out),
        Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Collect and sort keys lexicographically by Unicode scalar value.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_json_string(k, out);
                out.push(b':');
                write_canonical(&map[*k], out);
            }
            out.push(b'}');
        }
    }
}

/// Write a JSON string with minimal, deterministic escaping.
fn write_json_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0C}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_keys_are_sorted() {
        let a = json!({"b": 1, "a": 2, "c": 3});
        let bytes = to_canonical_bytes(&a).unwrap();
        assert_eq!(bytes, br#"{"a":2,"b":1,"c":3}"#);
    }

    #[test]
    fn nested_objects_sorted_recursively() {
        let a = json!({"z": {"y": 1, "x": 2}, "a": [3, {"m": 1, "k": 2}]});
        let bytes = to_canonical_bytes(&a).unwrap();
        assert_eq!(bytes, br#"{"a":[3,{"k":2,"m":1}],"z":{"x":2,"y":1}}"#);
    }

    #[test]
    fn key_order_does_not_change_hash() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(
            canonical_hash_hex(&a).unwrap(),
            canonical_hash_hex(&b).unwrap()
        );
    }

    #[test]
    fn string_escaping_is_deterministic() {
        let v = json!({"k": "line1\nline2\t\"quoted\""});
        let bytes = to_canonical_bytes(&v).unwrap();
        assert_eq!(bytes, br#"{"k":"line1\nline2\t\"quoted\""}"#);
    }

    #[test]
    fn sha256_known_vector() {
        // SHA-256 of empty string.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
