// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! Shared disclosure selection.
//!
//! Given an SD-JWT payload and a "what to reveal" map, resolve which disclosure
//! strings to put on the wire. Used by the plain [`crate::holder::SDJWTHolder`]
//! when building a presentation and by [`crate::delegate_holder::DelegateHolder`]
//! when choosing which issuer disclosures to forward on first-hop delegation.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::{SD_DIGESTS_KEY, SD_LIST_PREFIX};

/// Resolve the disclosures to reveal for `claims_to_disclose` against
/// `sd_jwt_claims`, using the disclosure maps (`digest -> decoded` and
/// `digest -> raw base64url`).
pub(crate) fn select_disclosures(
    sd_jwt_claims: &Map<String, Value>,
    claims_to_disclose: Map<String, Value>,
    hash_to_decoded: &HashMap<String, Value>,
    hash_to_raw: &HashMap<String, String>,
) -> Result<Vec<String>> {
    let mut hash_to_disclosure = Vec::new();
    let default_list = Vec::new();
    let sd_map: HashMap<&str, (&Value, &str)> = sd_jwt_claims
        .get(SD_DIGESTS_KEY)
        .and_then(Value::as_array)
        .unwrap_or(&default_list)
        .iter()
        .filter_map(|digest| {
            let digest = digest.as_str()?;
            let disclosure = hash_to_decoded.get(digest)?;
            let key = disclosure[1].as_str()?;
            Some((key, (&disclosure[2], digest)))
        })
        .collect(); //TODO split to 2 maps
    for (key_to_disclose, value_to_disclose) in claims_to_disclose {
        match value_to_disclose {
            Value::Bool(true) | Value::Number(_) | Value::String(_) => {
                /* disclose without children */
            }
            Value::Array(claims_to_disclose) => {
                if let Some(sd_jwt_claims) = sd_jwt_claims
                    .get(&key_to_disclose)
                    .and_then(Value::as_array)
                {
                    hash_to_disclosure.append(&mut select_disclosures_from_disclosed_list(
                        sd_jwt_claims,
                        &claims_to_disclose,
                        hash_to_decoded,
                        hash_to_raw,
                    )?)
                } else if let Some(sd_jwt_claims) = sd_map
                    .get(key_to_disclose.as_str())
                    .and_then(|(sd, _)| sd.as_array())
                {
                    hash_to_disclosure.append(&mut select_disclosures_from_disclosed_list(
                        sd_jwt_claims,
                        &claims_to_disclose,
                        hash_to_decoded,
                        hash_to_raw,
                    )?)
                }
            }
            Value::Object(claims_to_disclose) if (!claims_to_disclose.is_empty()) => {
                let sd_jwt_claims = if let Some(next) = sd_jwt_claims
                    .get(&key_to_disclose)
                    .and_then(Value::as_object)
                {
                    next
                } else {
                    sd_map[key_to_disclose.as_str()]
                        .0
                        .as_object()
                        .ok_or(Error::ConversionError("json object".to_string()))?
                };
                hash_to_disclosure.append(&mut select_disclosures(
                    sd_jwt_claims,
                    claims_to_disclose,
                    hash_to_decoded,
                    hash_to_raw,
                )?);
            }
            Value::Object(_) => { /* disclose without children */ }
            Value::Bool(false) | Value::Null => {
                // skip unrevealed
                continue;
            }
        }
        if sd_jwt_claims.contains_key(&key_to_disclose) {
            continue;
        } else if let Some((_, digest)) = sd_map.get(key_to_disclose.as_str()) {
            hash_to_disclosure.push(hash_to_raw[*digest].to_owned());
        } else {
            return Err(Error::InvalidState(
                "Requested claim doesn't exist".to_string(),
            ));
        }
    }

    Ok(hash_to_disclosure)
}

fn select_disclosures_from_disclosed_list(
    sd_jwt_claims: &[Value],
    claims_to_disclose: &[Value],
    hash_to_decoded: &HashMap<String, Value>,
    hash_to_raw: &HashMap<String, String>,
) -> Result<Vec<String>> {
    let mut hash_to_disclosure: Vec<String> = Vec::new();
    for (claim_to_disclose, sd_jwt_claims) in claims_to_disclose.iter().zip(sd_jwt_claims) {
        match (claim_to_disclose, sd_jwt_claims) {
            (Value::Bool(true), Value::Object(sd_jwt_claims)) => {
                if let Some(Value::String(digest)) = sd_jwt_claims.get(SD_LIST_PREFIX) {
                    hash_to_disclosure.push(hash_to_raw[digest].to_owned());
                }
            }
            (claim_to_disclose, Value::Object(sd_jwt_claims)) => {
                if let Some(Value::String(digest)) = sd_jwt_claims.get(SD_LIST_PREFIX) {
                    let disclosure = hash_to_decoded[digest]
                        .as_array()
                        .ok_or(Error::ConversionError("json array".to_string()))?;
                    match (claim_to_disclose, disclosure.get(1)) {
                        (Value::Array(claim_to_disclose), Some(Value::Array(sd_jwt_claims))) => {
                            hash_to_disclosure.push(hash_to_raw[digest].clone());
                            hash_to_disclosure.append(&mut select_disclosures_from_disclosed_list(
                                sd_jwt_claims,
                                claim_to_disclose,
                                hash_to_decoded,
                                hash_to_raw,
                            )?);
                        }
                        (Value::Object(claim_to_disclose), Some(Value::Object(sd_jwt_claims))) => {
                            hash_to_disclosure.push(hash_to_raw[digest].to_owned());
                            hash_to_disclosure.append(&mut select_disclosures(
                                sd_jwt_claims,
                                claim_to_disclose.to_owned(),
                                hash_to_decoded,
                                hash_to_raw,
                            )?);
                        }
                        _ => {}
                    }
                } else if let Some(claim_to_disclose) = claim_to_disclose.as_object() {
                    hash_to_disclosure.append(&mut select_disclosures(
                        sd_jwt_claims,
                        claim_to_disclose.to_owned(),
                        hash_to_decoded,
                        hash_to_raw,
                    )?);
                }
            }
            (Value::Array(claim_to_disclose), Value::Array(sd_jwt_claims)) => {
                hash_to_disclosure.append(&mut select_disclosures_from_disclosed_list(
                    sd_jwt_claims,
                    claim_to_disclose,
                    hash_to_decoded,
                    hash_to_raw,
                )?);
            }
            _ => {}
        }
    }

    Ok(hash_to_disclosure)
}
