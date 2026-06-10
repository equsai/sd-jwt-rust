// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! Shared SD-JWT disclosure unpacking.
//!
//! Resolves `_sd` object digests and array `{"...": digest}` stubs against a
//! disclosure map (`digest -> decoded disclosure`). Used by both the plain
//! [`crate::verifier::SDJWTVerifier`] and the delegation-chain
//! [`crate::delegate_verifier::DelegateVerifier`], so the core algorithm lives
//! in one place.

use std::collections::HashMap;

use log::debug;
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::{DIGEST_ALG_KEY, SD_DIGESTS_KEY, SD_LIST_PREFIX};

/// Recursively unpack disclosed claims, resolving digests against
/// `hash_to_decoded`. `seen` accumulates the digests resolved during this pass so
/// a digest used twice is rejected as a duplicate. Digests with no matching
/// disclosure are treated as decoys and skipped.
pub(crate) fn unpack_disclosed_claims(
    sd_jwt_claims: &Value,
    hash_to_decoded: &HashMap<String, Value>,
    seen: &mut Vec<String>,
) -> Result<Value> {
    match sd_jwt_claims {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            Ok(sd_jwt_claims.to_owned())
        }
        Value::Array(arr) => unpack_array(arr, hash_to_decoded, seen),
        Value::Object(obj) => unpack_object(obj, hash_to_decoded, seen),
    }
}

fn unpack_array(
    arr: &[Value],
    hash_to_decoded: &HashMap<String, Value>,
    seen: &mut Vec<String>,
) -> Result<Value> {
    if arr.is_empty() {
        return Err(Error::InvalidArrayDisclosureObject(
            "Array of disclosed claims cannot be empty".to_string(),
        ));
    }

    let mut claims = vec![];
    for value in arr {
        match value {
            // case for SD objects in arrays
            Value::Object(obj) if obj.contains_key(SD_LIST_PREFIX) => {
                if obj.len() > 1 {
                    return Err(Error::InvalidDisclosure(
                        "Disclosed claim object in an array maust contain only one key".to_string(),
                    ));
                }

                let digest = obj
                    .get(SD_LIST_PREFIX)
                    .ok_or_else(|| Error::InvalidDisclosure(SD_LIST_PREFIX.to_string()))?;
                let disclosed_claim = unpack_from_digest(digest, hash_to_decoded, seen)?;
                if let Some(disclosed_claim) = disclosed_claim {
                    claims.push(disclosed_claim);
                }
            }
            _ => {
                let claim = unpack_disclosed_claims(value, hash_to_decoded, seen)?;
                claims.push(claim);
            }
        }
    }
    Ok(Value::Array(claims))
}

fn unpack_object(
    nested_sd_jwt_claims: &Map<String, Value>,
    hash_to_decoded: &HashMap<String, Value>,
    seen: &mut Vec<String>,
) -> Result<Value> {
    let mut disclosed_claims: Map<String, Value> = serde_json::Map::new();

    for (key, value) in nested_sd_jwt_claims {
        if key != SD_DIGESTS_KEY && key != DIGEST_ALG_KEY {
            disclosed_claims.insert(
                key.to_owned(),
                unpack_disclosed_claims(value, hash_to_decoded, seen)?,
            );
        }
    }

    if let Some(Value::Array(digest_of_disclosures)) = nested_sd_jwt_claims.get(SD_DIGESTS_KEY) {
        unpack_from_digests(
            &mut disclosed_claims,
            digest_of_disclosures,
            hash_to_decoded,
            seen,
        )?;
    }

    Ok(Value::Object(disclosed_claims))
}

fn unpack_from_digests(
    pre_output: &mut Map<String, Value>,
    digests_of_disclosures: &[Value],
    hash_to_decoded: &HashMap<String, Value>,
    seen: &mut Vec<String>,
) -> Result<()> {
    for digest in digests_of_disclosures {
        let digest = digest
            .as_str()
            .ok_or(Error::ConversionError("str".to_string()))?;
        if seen.contains(&digest.to_string()) {
            return Err(Error::DuplicateDigestError(digest.to_string()));
        }
        seen.push(digest.to_string());

        if let Some(value_for_digest) = hash_to_decoded.get(digest) {
            let disclosure = value_for_digest
                .as_array()
                .ok_or(Error::InvalidArrayDisclosureObject(
                    value_for_digest.to_string(),
                ))?;
            let key = disclosure[1]
                .as_str()
                .ok_or(Error::ConversionError("str".to_string()))?
                .to_owned();
            let value = disclosure[2].clone();
            if pre_output.contains_key(&key) {
                return Err(Error::DuplicateKeyError(key.to_string()));
            }
            let unpacked_value = unpack_disclosed_claims(&value, hash_to_decoded, seen)?;
            pre_output.insert(key, unpacked_value);
        } else {
            debug!("Digest {:?} skipped as decoy", digest)
        }
    }

    Ok(())
}

fn unpack_from_digest(
    digest: &Value,
    hash_to_decoded: &HashMap<String, Value>,
    seen: &mut Vec<String>,
) -> Result<Option<Value>> {
    let digest = digest
        .as_str()
        .ok_or(Error::ConversionError("str".to_string()))?;
    if seen.contains(&digest.to_string()) {
        return Err(Error::DuplicateDigestError(digest.to_string()));
    }
    seen.push(digest.to_string());

    if let Some(value_for_digest) = hash_to_decoded.get(digest) {
        let disclosure = value_for_digest
            .as_array()
            .ok_or(Error::InvalidArrayDisclosureObject(
                value_for_digest.to_string(),
            ))?;

        let value = disclosure[1].clone();
        let unpacked_value = unpack_disclosed_claims(&value, hash_to_decoded, seen)?;
        return Ok(Some(unpacked_value));
    } else {
        debug!("Digest {:?} skipped as decoy", digest)
    }

    Ok(None)
}
