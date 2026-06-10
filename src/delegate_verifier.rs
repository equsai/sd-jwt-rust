// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! Verifier for Delegate SD-JWTs (dSD-JWT / dSD-JWT+KB).
//!
//! A dSD-JWT is a chain: an issuer-signed SD-JWT at position 0 followed by one or
//! more holder-signed KB-SD-JWT links. [`DelegateVerifier`] **composes** the plain
//! [`SDJWTVerifier`] to validate position 0 (per RFC 9901 §7.1), then walks the
//! chain — verifying each link's signature against the preceding component's `cnf`,
//! its `sd_hash`/`issuer_jwt_hash` binding, its `typ`, and the `delegate_payload`
//! "exactly one disclosed" rule — and finally the trailing KB-JWT (dSD-JWT+KB).

use std::str::FromStr;

use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};

use crate::delegate::{compute_issuer_jwt_hash, compute_sd_hash, DelegationChain};
use crate::error::{Error, Result};
use crate::verifier::KeyResolver;
use crate::{
    SDJWTCommon, SDJWTSerializationFormat, SDJWTVerifier, CNF_KEY,
    COMBINED_SERIALIZATION_FORMAT_SEPARATOR, DELEGATE_PAYLOAD_KEY, ISSUER_JWT_HASH_KEY, JWK_KEY,
    KB_DIGEST_KEY, KB_JWT_TYP_HEADER, KB_SD_JWT_KB_TYP_HEADER, KB_SD_JWT_TYP_HEADER, SD_LIST_PREFIX,
};

/// Result of verifying a dSD-JWT.
#[derive(Clone, Debug)]
pub struct DelegateVerified {
    /// Issuer claims with each link's Delegate Payload layered on top (a later link
    /// overrides an earlier claim of the same name).
    pub claims: Value,
    /// The disclosed Delegate Payload of each KB-SD-JWT link, in chain order.
    pub delegate_payloads: Vec<Map<String, Value>>,
    /// The `cnf` JWK of each `kb+sd-jwt+kb` link, in chain order. The last entry is
    /// the final Delegate Holder's key (used to verify the trailing KB-JWT).
    pub chain_cnfs: Vec<Jwk>,
}

/// Verifier for delegated SD-JWTs. Use [`DelegateVerifier::verify`] for a dSD-JWT;
/// use [`SDJWTVerifier`] for a plain SD-JWT(+KB).
pub struct DelegateVerifier;

impl DelegateVerifier {
    /// Verify a Compact-form dSD-JWT / dSD-JWT+KB.
    ///
    /// # Arguments
    /// * `dsd_jwt` — the delegated SD-JWT presentation.
    /// * `cb_get_issuer_key` — resolves the issuer public key for position 0.
    /// * `expected_aud` / `expected_nonce` — when both are provided, the trailing
    ///   KB-JWT (dSD-JWT+KB) is verified against the final Delegate Holder's key;
    ///   both must be `Some` or both `None`.
    ///
    /// Returns [`DelegateVerified`]. Errors if the input is not a delegation chain
    /// (use [`SDJWTVerifier`] for plain SD-JWTs).
    pub fn verify(
        dsd_jwt: String,
        cb_get_issuer_key: Box<KeyResolver>,
        expected_aud: Option<String>,
        expected_nonce: Option<String>,
    ) -> Result<DelegateVerified> {
        let want_kb = match (&expected_aud, &expected_nonce) {
            (Some(_), Some(_)) => true,
            (None, None) => false,
            _ => {
                return Err(Error::InvalidInput(
                    "Either both expected_aud and expected_nonce must be provided or both must be None"
                        .to_string(),
                ))
            }
        };

        let chain = DelegationChain::try_parse_compact(&dsd_jwt)?.ok_or_else(|| {
            Error::InvalidInput(
                "input is not a delegated SD-JWT (dSD-JWT); use SDJWTVerifier".to_string(),
            )
        })?;
        if chain.links.is_empty() {
            return Err(Error::ChainParseError("delegation chain has no links".to_string()));
        }

        // 1. Verify the position-0 issuer SD-JWT by composing the plain verifier on
        //    `<issuer-jwt>~<forwarded disclosures>~` (no KB-JWT).
        let mut sd_jwt_0_parts: Vec<&str> = vec![chain.issuer_jwt.as_str()];
        sd_jwt_0_parts.extend(chain.issuer_disclosures.iter().map(|s| s.as_str()));
        let sd_jwt_0 = format!(
            "{}{}",
            sd_jwt_0_parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR),
            COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
        );
        let base = SDJWTVerifier::new(
            sd_jwt_0,
            cb_get_issuer_key,
            None,
            None,
            SDJWTSerializationFormat::Compact,
        )?;
        let mut claims = base
            .verified_claims
            .as_object()
            .cloned()
            .ok_or_else(|| Error::InvalidState("issuer SD-JWT claims are not an object".into()))?;

        // Initial parent cnf = issuer-signed JWT's cnf.jwk.
        let issuer_cnf_value = claims
            .get(CNF_KEY)
            .and_then(|c| c.get(JWK_KEY))
            .cloned()
            .ok_or_else(|| Error::ChainSignatureFailed {
                link: 0,
                reason: "issuer-signed JWT has no cnf.jwk for first chain link".into(),
            })?;
        let mut parent_cnf: Jwk =
            serde_json::from_value(issuer_cnf_value).map_err(|e| Error::ChainSignatureFailed {
                link: 0,
                reason: format!("issuer cnf.jwk parse: {}", e),
            })?;

        // 2. Build a disclosure map over ALL chain disclosures for link unpacking.
        let mut engine = SDJWTCommon {
            serialization_format: SDJWTSerializationFormat::Compact,
            ..Default::default()
        };
        engine.input_disclosures = chain.all_disclosures();
        engine.create_hash_mappings()?;
        let hash_to_decoded = &engine.hash_to_decoded_disclosure;

        let mut parent_jwt = chain.issuer_jwt.clone();
        let mut parent_disclosures = chain.issuer_disclosures.clone();
        let trailing_kb_jwt_present = chain.trailing_kb_jwt.is_some();

        let mut delegate_payloads: Vec<Map<String, Value>> = Vec::with_capacity(chain.links.len());
        let mut chain_cnfs: Vec<Jwk> = Vec::new();

        // 3. Walk the chain links.
        for (idx, link) in chain.links.iter().enumerate() {
            let is_last = idx + 1 == chain.links.len();

            // 3a. Verify the link signature using the preceding component's cnf.
            let alg_str = SDJWTCommon::decode_header_and_get_sign_algorithm(&link.jwt)
                .unwrap_or_else(|| crate::DEFAULT_SIGNING_ALG.to_string());
            let alg = Algorithm::from_str(&alg_str).map_err(|e| Error::ChainSignatureFailed {
                link: idx,
                reason: e.to_string(),
            })?;
            let decoding_key =
                DecodingKey::from_jwk(&parent_cnf).map_err(|e| Error::ChainSignatureFailed {
                    link: idx,
                    reason: e.to_string(),
                })?;
            let mut validation = Validation::new(alg);
            validation.set_required_spec_claims::<&str>(&[]);
            validation.validate_aud = false;
            let decoded =
                jsonwebtoken::decode::<Map<String, Value>>(&link.jwt, &decoding_key, &validation)
                    .map_err(|e| Error::ChainSignatureFailed {
                        link: idx,
                        reason: e.to_string(),
                    })?;
            let typ = decoded.header.typ.clone();
            let payload = decoded.claims;

            // 3b. typ check.
            let is_kb_only = typ.as_deref() == Some(KB_SD_JWT_TYP_HEADER);
            let is_kb_kb = typ.as_deref() == Some(KB_SD_JWT_KB_TYP_HEADER);
            if is_last && !trailing_kb_jwt_present {
                if !is_kb_only && !is_kb_kb {
                    return Err(Error::ChainTypMismatch {
                        link: idx,
                        found: typ,
                        expected: "kb+sd-jwt or kb+sd-jwt+kb",
                    });
                }
            } else if !is_kb_kb {
                // Intermediate link, OR last link of dSD-JWT+KB. Must be kb+sd-jwt+kb.
                return Err(Error::ChainTypMismatch {
                    link: idx,
                    found: typ,
                    expected: KB_SD_JWT_KB_TYP_HEADER,
                });
            }

            // 3c. Binding validation (sd_hash or issuer_jwt_hash to the predecessor).
            let sd_hash_claim = payload.get(KB_DIGEST_KEY).and_then(Value::as_str);
            let issuer_jwt_hash_claim = payload.get(ISSUER_JWT_HASH_KEY).and_then(Value::as_str);
            match (sd_hash_claim, issuer_jwt_hash_claim) {
                (Some(claimed), _) => {
                    if claimed != compute_sd_hash(&parent_jwt, &parent_disclosures) {
                        return Err(Error::InvalidChainBinding { link: idx });
                    }
                }
                (None, Some(claimed)) => {
                    if claimed != compute_issuer_jwt_hash(&parent_jwt) {
                        return Err(Error::InvalidChainBinding { link: idx });
                    }
                }
                (None, None) => return Err(Error::MissingChainBinding { link: idx }),
            }

            // 3d. Unpack the link payload against the shared disclosure map.
            let mut seen = Vec::new();
            let unpacked = crate::unpacker::unpack_disclosed_claims(
                &Value::Object(payload.clone()),
                hash_to_decoded,
                &mut seen,
            )?;
            let unpacked_obj = unpacked.as_object().cloned().ok_or_else(|| {
                Error::InvalidDelegatePayload(format!(
                    "link {}: unpacked KB-SD-JWT payload is not an object",
                    idx
                ))
            })?;

            // 3e. `delegate_payload` is mandatory; enforce the "exactly one
            // disclosed alternative" rule.
            if !payload.contains_key(DELEGATE_PAYLOAD_KEY) {
                return Err(Error::InvalidDelegatePayload(format!(
                    "link {}: KB-SD-JWT is missing the mandatory delegate_payload claim",
                    idx
                )));
            }
            enforce_delegate_payload_rule(idx, &payload, &unpacked_obj)?;

            // The single disclosed Delegate Payload is "the JWT Payload" for this link.
            let delegate_payload = disclosed_delegate_payload(idx, &unpacked_obj)?;

            // 3f. Layer the Delegate Payload's claims (link overrides issuer).
            for (k, v) in delegate_payload.iter() {
                claims.insert(k.clone(), v.clone());
            }
            delegate_payloads.push(delegate_payload.clone());

            // 3g. Extract next-hop cnf from the Delegate Payload, if applicable.
            if is_kb_kb {
                let cnf_value = delegate_payload
                    .get(CNF_KEY)
                    .and_then(|c| c.as_object())
                    .and_then(|c| c.get(JWK_KEY))
                    .cloned()
                    .ok_or_else(|| {
                        Error::InvalidDelegatePayload(format!(
                            "link {}: typ={} but cnf.jwk is missing from Delegate Payload",
                            idx, KB_SD_JWT_KB_TYP_HEADER
                        ))
                    })?;
                let next_jwk: Jwk = serde_json::from_value(cnf_value).map_err(|e| {
                    Error::InvalidDelegatePayload(format!("link {}: cnf.jwk parse: {}", idx, e))
                })?;
                chain_cnfs.push(next_jwk.clone());
                parent_cnf = next_jwk;
            }

            parent_jwt = link.jwt.clone();
            parent_disclosures = link.disclosures.clone();
        }

        // 4. dSD-JWT+KB: verify the trailing KB-JWT against the final cnf.
        if want_kb {
            let kb_jwt = chain.trailing_kb_jwt.as_ref().ok_or_else(|| {
                Error::InvalidInput(
                    "expected_aud/expected_nonce were provided but this dSD-JWT has no final KB-JWT"
                        .to_string(),
                )
            })?;
            let last_jwk = chain_cnfs.last().ok_or_else(|| {
                Error::InvalidDelegatePayload(
                    "trailing KB-JWT present but chain produced no cnf for final binding".into(),
                )
            })?;
            let expected_sd_hash = chain.final_kb_sd_hash().ok_or_else(|| {
                Error::InvalidState("delegation chain present but has no links".into())
            })?;
            verify_final_kb_jwt(
                kb_jwt,
                last_jwk,
                &expected_aud.unwrap(),
                &expected_nonce.unwrap(),
                &expected_sd_hash,
            )?;
        }

        Ok(DelegateVerified {
            claims: Value::Object(claims),
            delegate_payloads,
            chain_cnfs,
        })
    }
}

/// Verify the trailing KB-JWT of a dSD-JWT+KB against the final Delegate Holder's
/// `cnf`, checking `typ`, `aud`, `nonce`, and `sd_hash`.
fn verify_final_kb_jwt(
    kb_jwt: &str,
    holder_jwk: &Jwk,
    expected_aud: &str,
    expected_nonce: &str,
    expected_sd_hash: &str,
) -> Result<()> {
    let sign_alg = SDJWTCommon::decode_header_and_get_sign_algorithm(kb_jwt)
        .unwrap_or_else(|| crate::DEFAULT_SIGNING_ALG.to_string());
    let pubkey = DecodingKey::from_jwk(holder_jwk).map_err(|e| {
        Error::DeserializationError(format!("Cannot parse DecodingKey from final cnf: {}", e))
    })?;
    let mut validation = Validation::new(
        Algorithm::from_str(&sign_alg).map_err(|e| Error::DeserializationError(e.to_string()))?,
    );
    validation.set_audience(&[expected_aud]);
    validation.set_required_spec_claims(&["aud"]);

    let decoded = jsonwebtoken::decode::<Map<String, Value>>(kb_jwt, &pubkey, &validation)
        .map_err(|e| Error::DeserializationError(e.to_string()))?;

    if decoded.header.typ.as_deref() != Some(KB_JWT_TYP_HEADER) {
        return Err(Error::InvalidInput("Invalid header type".to_string()));
    }
    if decoded.claims.get("nonce") != Some(&Value::String(expected_nonce.to_string())) {
        return Err(Error::InvalidInput("Invalid nonce".to_string()));
    }
    if decoded.claims.get(KB_DIGEST_KEY) != Some(&Value::String(expected_sd_hash.to_string())) {
        return Err(Error::InvalidInput("Invalid digest in KB-JWT".to_string()));
    }
    Ok(())
}

/// Return the single disclosed Delegate Payload object of a link, i.e. the one
/// element of the (unpacked) `delegate_payload` array. Assumes
/// [`enforce_delegate_payload_rule`] has already validated the array.
fn disclosed_delegate_payload(
    link_idx: usize,
    unpacked_obj: &Map<String, Value>,
) -> Result<Map<String, Value>> {
    let arr = unpacked_obj
        .get(DELEGATE_PAYLOAD_KEY)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Error::InvalidDelegatePayload(format!(
                "link {}: delegate_payload is not an array after unpacking",
                link_idx
            ))
        })?;
    if arr.len() != 1 {
        return Err(Error::InvalidDelegatePayload(format!(
            "link {}: expected exactly one disclosed delegate_payload element, got {}",
            link_idx,
            arr.len()
        )));
    }
    arr[0].as_object().cloned().ok_or_else(|| {
        Error::InvalidDelegatePayload(format!(
            "link {}: disclosed delegate_payload element is not a JSON object",
            link_idx
        ))
    })
}

/// Enforce the `delegate_payload` array rules: non-empty; all-inline (single) or
/// all-digest-stubs (multi); and, when stubs are used, exactly one disclosed.
fn enforce_delegate_payload_rule(
    link_idx: usize,
    raw_payload: &Map<String, Value>,
    unpacked_payload: &Map<String, Value>,
) -> Result<()> {
    let raw_arr = raw_payload
        .get(DELEGATE_PAYLOAD_KEY)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Error::InvalidDelegatePayload(format!(
                "link {}: delegate_payload is not an array",
                link_idx
            ))
        })?;
    if raw_arr.is_empty() {
        return Err(Error::InvalidDelegatePayload(format!(
            "link {}: delegate_payload is empty",
            link_idx
        )));
    }
    // Count digest stubs vs inline elements in the (pre-unpack) array.
    let stub_count = raw_arr
        .iter()
        .filter(|v| {
            v.as_object()
                .map_or(false, |obj| obj.contains_key(SD_LIST_PREFIX) && obj.len() == 1)
        })
        .count();
    if stub_count > 0 && stub_count != raw_arr.len() {
        return Err(Error::InvalidDelegatePayload(format!(
            "link {}: delegate_payload mixes inline elements and digest stubs",
            link_idx
        )));
    }
    if stub_count == 0 && raw_arr.len() != 1 {
        // Inline alternatives are only allowed when there is a single element; a
        // multi-element disjunction MUST commit to digests so unselected
        // alternatives stay opaque.
        return Err(Error::InvalidDelegatePayload(format!(
            "link {}: multi-alternative delegate_payload must use digest stubs",
            link_idx
        )));
    }
    if stub_count > 0 {
        // After unpacking, exactly one alternative must have resolved.
        let resolved = unpacked_payload
            .get(DELEGATE_PAYLOAD_KEY)
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        if resolved != 1 {
            return Err(Error::InvalidDelegatePayload(format!(
                "link {}: delegate_payload must have exactly one disclosed alternative, got {}",
                link_idx, resolved
            )));
        }
    }
    Ok(())
}
