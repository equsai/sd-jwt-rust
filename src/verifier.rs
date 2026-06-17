// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::SDJWTSerializationFormat;
use crate::error::Error;
use crate::error::Result;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use log::debug;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::ops::Add;
use std::option::Option;
use std::str::FromStr;
use std::string::String;
use std::vec::Vec;

use crate::delegate::{compute_issuer_jwt_hash, compute_sd_hash};
use crate::resolver::KeyResolver;
use crate::utils::base64_hash;
use crate::{
    SDJWTCommon, CNF_KEY, COMBINED_SERIALIZATION_FORMAT_SEPARATOR, DEFAULT_DIGEST_ALG,
    DEFAULT_SIGNING_ALG, DELEGATE_PAYLOAD_KEY, DIGEST_ALG_KEY, ISSUER_JWT_HASH_KEY, JWK_KEY,
    KB_DIGEST_KEY, KB_JWT_TYP_HEADER, KB_SD_JWT_KB_TYP_HEADER, KB_SD_JWT_TYP_HEADER, SD_DIGESTS_KEY,
    SD_LIST_PREFIX,
};

pub struct SDJWTVerifier {
    sd_jwt_engine: SDJWTCommon,

    sd_jwt_payload: Map<String, Value>,
    _holder_public_key_payload: Option<Map<String, Value>>,

    /// Claims verified by the most recent [`SDJWTVerifier::verify_presentation`]
    /// call (also returned directly from that method).
    pub verified_claims: Value,

    /// Per-link `cnf` JWKs extracted while walking a delegation chain. Empty for a
    /// plain SD-JWT(+KB). The last entry (when present) is the final Delegate
    /// Holder's key, used to verify the trailing KB-JWT of a dSD-JWT+KB.
    pub chain_cnfs: Vec<Jwk>,

    /// The disclosed Delegate Payload of each KB-SD-JWT link, in chain order.
    /// Empty when the input is not a delegation chain.
    pub verified_delegate_payloads: Vec<Map<String, Value>>,

    issuer_key_resolver: Box<dyn KeyResolver>,
}

impl SDJWTVerifier {
    /// Creates a new `SDJWTVerifier` instance.
    ///
    /// The instance can be reused to verify multiple presentations.
    ///
    /// # Arguments
    /// * `issuer_key_resolver` - A key resolver that resolves the public key of the issuer.
    ///
    /// # Returns
    /// * `SDJWTVerifier` - The `SDJWTVerifier` instance.
    pub fn new(issuer_key_resolver: Box<dyn KeyResolver>) -> Self {
        SDJWTVerifier {
            sd_jwt_payload: Default::default(),
            _holder_public_key_payload: None,
            issuer_key_resolver,
            sd_jwt_engine: Default::default(),
            verified_claims: Value::Null,
            chain_cnfs: Vec::new(),
            verified_delegate_payloads: Vec::new(),
        }
    }

    /// Verifies an SD-JWT (or delegation chain) presentation.
    ///
    /// # Arguments
    /// * `sd_jwt_presentation` - The SD-JWT presentation to verify.
    /// * `expected_aud` - The expected audience of the SD-JWT, if any.
    /// * `expected_nonce` - The expected nonce of the SD-JWT, if any.
    /// * `serialization_format` - The serialization format of the SD-JWT, see [SDJWTSerializationFormat].
    ///
    /// # Returns
    /// * `Result<Value>` - The verified claims as a JSON value. For a delegation
    ///   chain, each link's Delegate Payload is layered onto the issuer claims, and
    ///   the per-link details are exposed via [`Self::chain_cnfs`] and
    ///   [`Self::verified_delegate_payloads`]. The same value is also stored in
    ///   [`Self::verified_claims`].
    pub async fn verify_presentation(
        &mut self,
        sd_jwt_presentation: String,
        expected_aud: Option<String>,
        expected_nonce: Option<String>,
        serialization_format: SDJWTSerializationFormat,
    ) -> Result<Value> {
        self.reset();
        self.sd_jwt_engine = SDJWTCommon {
            serialization_format,
            ..Default::default()
        };

        self.sd_jwt_engine.parse_sd_jwt(sd_jwt_presentation)?;
        self.sd_jwt_engine.create_hash_mappings()?;
        let sign_alg = self.sd_jwt_engine.sign_alg.clone();
        self.verify_sd_jwt(sign_alg.clone()).await?;
        self.verified_claims = self.extract_sd_claims()?;

        // For a delegation chain, walk the holder-signed KB-SD-JWT links, layering
        // each disclosed Delegate Payload onto `verified_claims`.
        if self.sd_jwt_engine.delegation_chain.is_some() {
            self.verify_delegation_chain()?;
        }

        if let (Some(expected_aud), Some(expected_nonce)) = (&expected_aud, &expected_nonce) {
            if let Some(chain) = self.sd_jwt_engine.delegation_chain.clone() {
                if let Some(kb_jwt) = chain.trailing_kb_jwt.as_ref() {
                    // dSD-JWT+KB: the trailing KB-JWT binds to the final link and is
                    // signed by the final Delegate Holder's key.
                    let last_jwk = self.chain_cnfs.last().ok_or_else(|| {
                        Error::InvalidDelegatePayload(
                            "trailing KB-JWT present but chain produced no cnf for final binding"
                                .into(),
                        )
                    })?;
                    let expected_sd_hash = chain.final_kb_sd_hash().ok_or_else(|| {
                        Error::InvalidState("delegation chain present but has no links".into())
                    })?;
                    verify_final_kb_jwt(
                        kb_jwt,
                        last_jwk,
                        expected_aud,
                        expected_nonce,
                        &expected_sd_hash,
                    )?;
                } else {
                    // Plain dSD-JWT (no trailing KB-JWT): the credential was delegated
                    // to this Verifier, so the final KB-SD-JWT link IS the key binding.
                    // Per the Delegate SD-JWT spec, the claims a KB-JWT would carry
                    // (`aud`, `nonce`) live in that link's Delegate Payload instead. The
                    // chain walk already signature-verified the link and captured its
                    // disclosed Delegate Payload, so validate `aud`/`nonce` there.
                    let final_payload = self.verified_delegate_payloads.last().ok_or_else(|| {
                        Error::InvalidDelegatePayload(
                            "expected_aud/expected_nonce were provided but the delegation chain \
                             produced no Delegate Payload to bind them"
                                .into(),
                        )
                    })?;
                    verify_delegate_payload_binding(final_payload, expected_aud, expected_nonce)?;
                }
            } else {
                let sign_alg = self.sd_jwt_engine.unverified_input_key_binding_jwt
                    .as_ref()
                    .and_then(|value| {
                        SDJWTCommon::decode_header_and_get_sign_algorithm(value)
                    });

                self.verify_key_binding_jwt(
                    expected_aud.to_owned(),
                    expected_nonce.to_owned(),
                    sign_alg.as_deref(),
                )?;
            }
        } else if expected_aud.is_some() || expected_nonce.is_some() {
            return Err(Error::InvalidInput(
                "Either both expected_aud and expected_nonce must be provided or both must be None"
                    .to_string(),
            ));
        }

        Ok(self.verified_claims.clone())
    }

    fn reset(&mut self) {
        self.sd_jwt_payload = Default::default();
        self._holder_public_key_payload = None;
        self.verified_claims = Value::Null;
        self.chain_cnfs = Vec::new();
        self.verified_delegate_payloads = Vec::new();
    }

    /// Walk the delegation chain. Called after `verify_sd_jwt` has verified the
    /// issuer-signed JWT (position 0) and `extract_sd_claims` has produced the
    /// initial `verified_claims`. Each KB-SD-JWT link is signature-, binding-, and
    /// `typ`-verified; its single disclosed Delegate Payload is layered onto
    /// `verified_claims` and recorded in `verified_delegate_payloads`.
    fn verify_delegation_chain(&mut self) -> Result<()> {
        let chain = self
            .sd_jwt_engine
            .delegation_chain
            .as_ref()
            .ok_or_else(|| Error::InvalidState("delegation_chain absent".into()))?
            .clone();
        if chain.links.is_empty() {
            return Ok(());
        }

        // Initial parent cnf = issuer-signed JWT's cnf.jwk.
        let issuer_cnf_value = self
            .verified_claims
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

        // The disclosure map already spans ALL chain disclosures (input_disclosures
        // was set to chain.all_disclosures() during parsing).
        let hash_to_decoded = self.sd_jwt_engine.hash_to_decoded_disclosure.clone();

        let mut parent_jwt = chain.issuer_jwt.clone();
        let mut parent_disclosures = chain.issuer_disclosures.clone();
        let trailing_kb_jwt_present = chain.trailing_kb_jwt.is_some();

        let now = now_secs()?;
        if let Some(issuer_claims) = self.verified_claims.as_object() {
            validate_lifetime(issuer_claims, "issuer-signed JWT", now)?;
        }

        for (idx, link) in chain.links.iter().enumerate() {
            let is_last = idx + 1 == chain.links.len();

            // Verify the link signature using the preceding component's cnf.
            let alg_str = SDJWTCommon::decode_header_and_get_sign_algorithm(&link.jwt)
                .unwrap_or_else(|| DEFAULT_SIGNING_ALG.to_string());
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

            // typ check.
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

            // Binding validation (sd_hash or issuer_jwt_hash to the predecessor).
            let sd_hash_claim = payload.get(KB_DIGEST_KEY).and_then(Value::as_str);
            let issuer_jwt_hash_claim = payload.get(ISSUER_JWT_HASH_KEY).and_then(Value::as_str);
            match (sd_hash_claim, issuer_jwt_hash_claim) {
                (Some(claimed), None) => {
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
                (Some(_), Some(_)) => return Err(Error::AmbiguousChainBinding { link: idx }),
            }

            // Unpack the link payload against the shared disclosure map.
            let mut seen = Vec::new();
            let unpacked =
                unpack_disclosed_claims(&Value::Object(payload.clone()), &hash_to_decoded, &mut seen)?;
            let unpacked_obj = unpacked.as_object().cloned().ok_or_else(|| {
                Error::InvalidDelegatePayload(format!(
                    "link {}: unpacked KB-SD-JWT payload is not an object",
                    idx
                ))
            })?;

            // `delegate_payload` is mandatory; enforce the "exactly one disclosed
            // alternative" rule.
            if !payload.contains_key(DELEGATE_PAYLOAD_KEY) {
                return Err(Error::InvalidDelegatePayload(format!(
                    "link {}: KB-SD-JWT is missing the mandatory delegate_payload claim",
                    idx
                )));
            }
            enforce_delegate_payload_rule(idx, &payload, &unpacked_obj)?;

            // The single disclosed Delegate Payload is "the JWT Payload" for this link.
            let delegate_payload = disclosed_delegate_payload(idx, &unpacked_obj)?;

            // Enforce this link's own lifetime (`exp`/`nbf`) before trusting it.
            validate_lifetime(&delegate_payload, &format!("chain link {}", idx), now)?;

            // Layer the Delegate Payload's claims (link overrides issuer).
            if let Value::Object(ref mut existing) = self.verified_claims {
                for (k, v) in delegate_payload.iter() {
                    existing.insert(k.clone(), v.clone());
                }
            }
            self.verified_delegate_payloads.push(delegate_payload.clone());

            // Extract next-hop cnf from the Delegate Payload, if applicable.
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
                self.chain_cnfs.push(next_jwk.clone());
                parent_cnf = next_jwk;
            }

            parent_jwt = link.jwt.clone();
            parent_disclosures = link.disclosures.clone();
        }

        Ok(())
    }

    async fn verify_sd_jwt(&mut self, sign_alg: Option<String>) -> Result<()> {
        let sd_jwt = self
            .sd_jwt_engine
            .unverified_sd_jwt
            .as_ref()
            .ok_or(Error::ConversionError("reference".to_string()))?;
        let parsed_header_sd_jwt = jsonwebtoken::decode_header(sd_jwt)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;

        let unverified_issuer = self
            .sd_jwt_engine
            .unverified_input_sd_jwt_payload
            .as_ref()
            .ok_or(Error::ConversionError("reference".to_string()))?["iss"]
            .as_str()
            .ok_or(Error::ConversionError("str".to_string()))?;
        let issuer_public_key = self
            .issuer_key_resolver
            .resolve(unverified_issuer, &parsed_header_sd_jwt)
            .await?;
        let algorithm: Algorithm = match sign_alg {
            Some(alg_str) => Algorithm::from_str(&alg_str)
                .map_err(|e| Error::DeserializationError(e.to_string()))?,
            None => Algorithm::ES256, // Default or handle as needed
        };
        let claims = jsonwebtoken::decode(
            sd_jwt,
            &issuer_public_key,
            &Validation::new(algorithm),
        )
            .map_err(|e| Error::DeserializationError(format!("Cannot decode jwt: {}", e)))?
            .claims;

        let _ = sign_alg; //FIXME check algo

        self.sd_jwt_payload = claims;
        self._holder_public_key_payload = self
            .sd_jwt_payload
            .get(CNF_KEY)
            .and_then(Value::as_object)
            .cloned();

        Ok(())
    }

    fn verify_key_binding_jwt(
        &mut self,
        expected_aud: String,
        expected_nonce: String,
        sign_alg: Option<&str>,
    ) -> Result<()> {
        let sign_alg = sign_alg.unwrap_or(DEFAULT_SIGNING_ALG);
        let holder_public_key_payload_jwk = match &self._holder_public_key_payload {
            None => {
                return Err(Error::KeyNotFound(
                    "No holder public key in SD-JWT".to_string(),
                ));
            }
            Some(payload) => {
                if let Some(jwk) = payload.get(JWK_KEY) {
                    jwk.clone()
                } else {
                    return Err(Error::InvalidInput("The holder_public_key_payload is malformed. It doesn't contain the claim jwk".to_string()));
                }
            }
        };
        let pubkey: DecodingKey = match serde_json::from_value::<Jwk>(holder_public_key_payload_jwk)
        {
            Ok(jwk) => {
                if let Ok(pubkey) = DecodingKey::from_jwk(&jwk) {
                    pubkey
                } else {
                    return Err(Error::DeserializationError(
                        "Cannot parse DecodingKey from json".to_string(),
                    ));
                }
            }
            Err(_) => {
                return Err(Error::DeserializationError(
                    "Cannot parse JWK from json".to_string(),
                ));
            }
        };
        let key_binding_jwt = match &self.sd_jwt_engine.unverified_input_key_binding_jwt {
            Some(payload) => {
                let mut validation = Validation::new(
                    Algorithm::from_str(sign_alg)
                        .map_err(|e| Error::DeserializationError(e.to_string()))?,
                );
                validation.set_audience(&[&expected_aud]);
                validation.set_required_spec_claims(&["aud"]);

                jsonwebtoken::decode::<Map<String, Value>>(&payload, &pubkey, &validation)
                    .map_err(|e| Error::DeserializationError(e.to_string()))?
            }
            None => {
                return Err(Error::InvalidState(
                    "Cannot take Key Binding JWK from String".to_string(),
                ));
            }
        };
        if key_binding_jwt.header.typ != Some(KB_JWT_TYP_HEADER.to_string()) {
            return Err(Error::InvalidInput("Invalid header type".to_string()));
        }
        if key_binding_jwt.claims.get("nonce") != Some(&Value::String(expected_nonce)) {
            return Err(Error::InvalidInput("Invalid nonce".to_string()));
        }
        if self.sd_jwt_engine.serialization_format == SDJWTSerializationFormat::Compact {
            let sd_hash = self._get_key_binding_digest_hash()?;
            if key_binding_jwt.claims.get(KB_DIGEST_KEY) != Some(&Value::String(sd_hash)) {
                return Err(Error::InvalidInput("Invalid digest in KB-JWT".to_string()));
            }
        }

        Ok(())
    }

    fn _get_key_binding_digest_hash(&mut self) -> Result<String> {
        let mut combined: Vec<&str> =
            Vec::with_capacity(self.sd_jwt_engine.input_disclosures.len() + 1);
        combined.push(
            self.sd_jwt_engine
                .unverified_sd_jwt
                .as_ref()
                .ok_or(Error::ConversionError("reference".to_string()))?
        );
        combined.extend(
            self.sd_jwt_engine
                .input_disclosures
                .iter()
                .map(|s| s.as_str()),
        );
        let combined = combined
            .join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .add(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);

        Ok(base64_hash(combined.as_bytes()))
    }

    fn extract_sd_claims(&mut self) -> Result<Value> {
        if self.sd_jwt_payload.contains_key(DIGEST_ALG_KEY)
            && self.sd_jwt_payload[DIGEST_ALG_KEY] != DEFAULT_DIGEST_ALG
        {
            return Err(Error::DeserializationError(format!(
                "Invalid hash algorithm {}",
                self.sd_jwt_payload[DIGEST_ALG_KEY]
            )));
        }

        let claims: Value = self.sd_jwt_payload.clone().into_iter().collect();
        let mut seen = Vec::new();
        unpack_disclosed_claims(
            &claims,
            &self.sd_jwt_engine.hash_to_decoded_disclosure,
            &mut seen,
        )
    }
}

/// Leeway (seconds) applied to `exp`/`nbf` checks, matching `jsonwebtoken`'s
/// default so chain-component lifetime validation is consistent with the
/// issuer-JWT validation done during `verify_sd_jwt`.
const LIFETIME_LEEWAY_SECS: i64 = 60;

/// Current time as seconds since the Unix epoch.
fn now_secs() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| Error::ConversionError(format!("system time before Unix epoch: {}", e)))
}

/// Read a NumericDate claim (`exp`/`nbf`). Accepts a JSON number (integer or
/// truncated float) or a numeric string; returns `None` if the claim is absent or
/// not a parseable timestamp.
fn claim_timestamp(claims: &Map<String, Value>, key: &str) -> Option<i64> {
    match claims.get(key) {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Some(Value::String(s)) => s.parse::<i64>().ok(),
        _ => None,
    }
}

/// Enforce a chain component's `exp`/`nbf` (if present) against `now`, with
/// [`LIFETIME_LEEWAY_SECS`] of clock skew tolerance. `component` names the source
/// (e.g. `"issuer-signed JWT"`, `"chain link 1"`) for error reporting.
fn validate_lifetime(claims: &Map<String, Value>, component: &str, now: u64) -> Result<()> {
    let now = now as i64;
    if let Some(exp) = claim_timestamp(claims, "exp") {
        if now > exp + LIFETIME_LEEWAY_SECS {
            return Err(Error::ChainExpired {
                component: component.to_string(),
                exp,
            });
        }
    }
    if let Some(nbf) = claim_timestamp(claims, "nbf") {
        if now + LIFETIME_LEEWAY_SECS < nbf {
            return Err(Error::ChainNotYetValid {
                component: component.to_string(),
                nbf,
            });
        }
    }
    Ok(())
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
        .unwrap_or_else(|| DEFAULT_SIGNING_ALG.to_string());
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

/// Validate `aud`/`nonce` against a plain dSD-JWT's final Delegate Payload.
///
/// When a dSD-JWT is presented with no trailing KB-JWT, the final KB-SD-JWT link
/// is itself the key binding to this Verifier; per the Delegate SD-JWT spec the
/// claims a KB-JWT would carry (`aud`, `nonce`) live in that link's Delegate
/// Payload. The payload's signature was already verified during the chain walk, so
/// here we only confirm the bound audience and nonce match what the Verifier
/// expects. `aud` may be a single string or an array containing the expected value.
fn verify_delegate_payload_binding(
    delegate_payload: &Map<String, Value>,
    expected_aud: &str,
    expected_nonce: &str,
) -> Result<()> {
    let aud_ok = match delegate_payload.get("aud") {
        Some(Value::String(aud)) => aud == expected_aud,
        Some(Value::Array(auds)) => auds.iter().any(|v| v.as_str() == Some(expected_aud)),
        _ => false,
    };
    if !aud_ok {
        return Err(Error::InvalidInput(
            "Invalid or missing aud in final Delegate Payload".to_string(),
        ));
    }
    if delegate_payload.get("nonce") != Some(&Value::String(expected_nonce.to_string())) {
        return Err(Error::InvalidInput(
            "Invalid or missing nonce in final Delegate Payload".to_string(),
        ));
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

/// Recursively unpack disclosed claims, resolving digests against
/// `hash_to_decoded`. `seen` accumulates the digests resolved during this pass so
/// a digest used twice is rejected as a duplicate. Digests with no matching
/// disclosure are treated as decoys and skipped.
pub fn unpack_disclosed_claims(
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

#[cfg(test)]
mod tests {
    use async_std_test::async_test;
    use crate::issuer::ClaimsForSelectiveDisclosureStrategy;
    use crate::{SDJWTHolder, SDJWTIssuer, SDJWTVerifier, SDJWTSerializationFormat};
    use jsonwebtoken::{DecodingKey, EncodingKey};
    use serde_json::{json, Value};
    use crate::key::{ SDJWTKey, SDJWTPubKey };

    const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
    const PUBLIC_ISSUER_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb28d4MwZMjw8+00CG4xfnn9SLMVM\nM19SlqZpVb/uNtRe/nNbC6hpOB1LqFXjfIjqAHBOeO6SYVBCcn+QLHOqTw==\n-----END PUBLIC KEY-----\n";
    const PRIVATE_ISSUER_ED25519_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMFECAQEwBQYDK2VwBCIEIF93k6rxZ8W38cm0rOwfGdH+YY3k10hP+7gd0falPLg0\ngSEAdW31QyWzfed4EPcw1rYuUa1QU+fXEL0HhdAfYZRkihc=\n-----END PRIVATE KEY-----\n";
    const PUBLIC_ISSUER_ED25519_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAdW31QyWzfed4EPcw1rYuUa1QU+fXEL0HhdAfYZRkihc=\n-----END PUBLIC KEY-----\n";

    const HOLDER_KEY_ED25519: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIOeIDnHHMoPCUTiq206gR+FdCdNtc31SzF1nKX31hvhd\n-----END PRIVATE KEY-----";

    const HOLDER_JWK_KEY_ED25519: &str = r#"{
        "alg": "EdDSA",
        "crv": "Ed25519",
        "kid": "52128f2e-900e-414e-81c3-0b5f86f0f7b3",
        "kty": "OKP",
        "x": "24QLWXJ18wtbg3k_MDGhGM17Xh39UftuxbwJZzRLzkA"
    }"#;

    #[async_test]
    async fn verify_full_presentation() -> std::io::Result<()> {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            }
        });
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = SDJWTKey::new(
            EncodingKey::from_ec_pem(private_issuer_bytes).unwrap(),
            None
        );
        let sd_jwt = SDJWTIssuer::new(issuer_key).issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            false,
            SDJWTSerializationFormat::Compact,
            None,
        )
            .await.unwrap();
        let presentation = SDJWTHolder::new(sd_jwt.clone(), SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation::<SDJWTKey>(
                user_claims.as_object().unwrap().clone(),
                None,
                None,
                None,
            )
            .await.unwrap();
        assert_eq!(sd_jwt, presentation);

        let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
        let issuer_pub_key: SDJWTPubKey = DecodingKey::from_ec_pem(public_issuer_bytes).unwrap().into();

        let verified_claims = SDJWTVerifier::new(Box::new(issuer_pub_key))
            .verify_presentation(presentation, None, None, SDJWTSerializationFormat::Compact)
            .await
            .unwrap();
        assert_eq!(user_claims, verified_claims);

        Ok(())
    }

    #[async_test]
    async fn verify_noclaim_presentation() -> std::io::Result<()> {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            }
        });
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = SDJWTKey::new(
            EncodingKey::from_ec_pem(private_issuer_bytes).unwrap(),
            None
        );
        let sd_jwt = SDJWTIssuer::new(issuer_key).issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
            None,
            false,
            SDJWTSerializationFormat::Compact,
            None,
        )
            .await.unwrap();

        let presentation = SDJWTHolder::new(sd_jwt.clone(), SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation::<SDJWTKey>(
                user_claims.as_object().unwrap().clone(),
                None,
                None,
                None,
            )
            .await.unwrap();
        assert_eq!(sd_jwt, presentation);

        let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
        let issuer_pub_key: SDJWTPubKey = DecodingKey::from_ec_pem(public_issuer_bytes).unwrap().into();

        let verified_claims = SDJWTVerifier::new(Box::new(issuer_pub_key))
            .verify_presentation(presentation, None, None, SDJWTSerializationFormat::Compact)
            .await
            .unwrap();
        assert_eq!(user_claims, verified_claims);

        Ok(())
    }

    #[async_test]
    async fn verify_arrayed_presentation() -> std::io::Result<()> {
        let user_claims = json!(
            {
              "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
              "name": "Bois",
              "iss": "https://example.com/issuer",
              "iat": 1683000000,
              "exp": 1883000000,
              "addresses": [
                {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
                },
                {
                "street_address": "456 Main St",
                "locality": "Anytown",
                "region": "NY",
                "country": "US"
                }
              ],
              "nationalities": [
                "US",
                "CA"
              ]
            }
        );
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = SDJWTKey::new(
            EncodingKey::from_ec_pem(private_issuer_bytes).unwrap(),
            None
        );
        let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(vec![
            "$.name",
            "$.addresses[1]",
            "$.addresses[1].country",
            "$.nationalities[0]",
        ]);
        let sd_jwt = SDJWTIssuer::new(issuer_key).issue_sd_jwt(
            user_claims.clone(),
            strategy,
            None,
            false,
            SDJWTSerializationFormat::Compact,
            None,
        )
            .await.unwrap();

        let mut claims_to_disclose = user_claims.clone();
        claims_to_disclose["addresses"] = Value::Array(vec![Value::Bool(true), Value::Bool(true)]);
        claims_to_disclose["nationalities"] =
            Value::Array(vec![Value::Bool(true), Value::Bool(true)]);
        let presentation = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation::<SDJWTKey>(
                claims_to_disclose.as_object().unwrap().clone(),
                None,
                None,
                None,
            )
            .await.unwrap();

        let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
        let issuer_pub_key: SDJWTPubKey = DecodingKey::from_ec_pem(public_issuer_bytes).unwrap().into();

        let verified_claims = SDJWTVerifier::new(Box::new(issuer_pub_key))
            .verify_presentation(presentation, None, None, SDJWTSerializationFormat::Compact)
            .await
            .unwrap();

        let expected_verified_claims = json!(
            {
                "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
                "addresses": [
                    {
                        "street_address": "Schulstr. 12",
                        "locality": "Schulpforta",
                        "region": "Sachsen-Anhalt",
                        "country": "DE",
                    },
                    {
                        "street_address": "456 Main St",
                        "locality": "Anytown",
                        "region": "NY",
                    },
                ],
                "nationalities": [
                    "US",
                    "CA",
                ],
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "exp": 1883000000,
                "name": "Bois"
            }
        );

        assert_eq!(verified_claims, expected_verified_claims);

        Ok(())
    }

    #[async_test]
    async fn verify_arrayed_no_sd_presentation() -> std::io::Result<()> {
        let user_claims = json!(
            {
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "exp": 1883000000,
                "array_with_recursive_sd": [
                    "boring",
                    {
                        "foo": "bar",
                        "baz": {
                            "qux": "quux"
                        }
                    },
                    ["foo", "bar"]
                ],
                "test2": ["foo", "bar"]
            }
        );
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = SDJWTKey::new(
            EncodingKey::from_ec_pem(private_issuer_bytes).unwrap(),
            None
        );
        let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(vec![
            "$.array_with_recursive_sd[1]",
            "$.array_with_recursive_sd[1].baz",
            "$.array_with_recursive_sd[2][0]",
            "$.array_with_recursive_sd[2][1]",
            "$.test2[0]",
            "$.test2[1]",
        ]);
        let sd_jwt = SDJWTIssuer::new(issuer_key).issue_sd_jwt(
            user_claims.clone(),
            strategy,
            None,
            false,
            SDJWTSerializationFormat::Compact,
            None,
        )
            .await.unwrap();

        let claims_to_disclose = json!({});

        let presentation = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation::<SDJWTKey>(
                claims_to_disclose.as_object().unwrap().clone(),
                None,
                None,
                None,
            )
            .await.unwrap();

        let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
        let issuer_pub_key: SDJWTPubKey = DecodingKey::from_ec_pem(public_issuer_bytes).unwrap().into();

        let verified_claims = SDJWTVerifier::new(Box::new(issuer_pub_key))
            .verify_presentation(presentation, None, None, SDJWTSerializationFormat::Compact)
            .await
            .unwrap();

        let expected_verified_claims = json!(
            {
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "exp": 1883000000,
                "array_with_recursive_sd":  [
                    "boring",
                    [],
                ],
                "test2": [],
            }
        );

        assert_eq!(verified_claims, expected_verified_claims);

        Ok(())
    }

    #[async_test]
    async fn verify_full_presentation_to_allow_other_algorithms_json_format() -> std::io::Result<()> {

        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            }
        });
        let private_issuer_bytes = PRIVATE_ISSUER_ED25519_PEM.as_bytes();
        let issuer_key = SDJWTKey::new(
            EncodingKey::from_ed_pem(private_issuer_bytes).unwrap(),
            Some("EdDSA".to_string())
        );
        let sd_jwt = SDJWTIssuer::new(issuer_key).issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            false,
            SDJWTSerializationFormat::JSON, // Changed to Json format
            None,
        )
        .await.unwrap();

        let presentation = SDJWTHolder::new(sd_jwt.clone(), SDJWTSerializationFormat::JSON) // Changed to Json format
            .unwrap()
            .create_presentation::<SDJWTKey>(
                user_claims.as_object().unwrap().clone(),
                None,
                None,
                None
            )
            .await.unwrap();
        assert_eq!(sd_jwt, presentation);

        let public_issuer_bytes = PUBLIC_ISSUER_ED25519_PEM.as_bytes();
        let issuer_pub_key: SDJWTPubKey = DecodingKey::from_ed_pem(public_issuer_bytes).unwrap().into();

        let verified_claims = SDJWTVerifier::new(Box::new(issuer_pub_key))
            .verify_presentation(presentation, None, None, SDJWTSerializationFormat::JSON)
            .await
            .unwrap();
        assert_eq!(user_claims, verified_claims);

        Ok(())
    }
    #[async_test]
    async fn verify_presentation_when_sd_jwt_uses_es256_and_key_binding_uses_eddsa() -> std::io::Result<()> {
        let user_claims = json!({
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            },
            "exp": 1883000000,
            "iat": 1683000000,
            "iss": "https://example.com/issuer",
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",

        });

        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = SDJWTKey::new(
            EncodingKey::from_ec_pem(private_issuer_bytes).unwrap(),
            Some("ES256".to_string()),
        );

        let mut issuer = SDJWTIssuer::new(issuer_key);
        let sd_jwt = issuer
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                Some(serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap()),
                false,
                SDJWTSerializationFormat::JSON,
                None,
            )
            .await
            .unwrap();

        let private_holder_bytes = HOLDER_KEY_ED25519.as_bytes();
        let holder_key = EncodingKey::from_ed_pem(private_holder_bytes).unwrap();

        let nonce = Some(String::from("testNonce"));
        let aud = Some(String::from("testAud"));

        let mut holder = SDJWTHolder::new(sd_jwt.clone(), SDJWTSerializationFormat::JSON).unwrap(); // Changed to Json format
        let presentation = holder
            .create_presentation(
                user_claims.as_object().unwrap().clone(),
                nonce.clone(),
                aud.clone(),
                Some(SDJWTKey::new(holder_key, Some("EdDSA".to_string()))),
            )
            .await
            .unwrap();

        let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
        let issuer_pub_key: SDJWTPubKey = DecodingKey::from_ec_pem(public_issuer_bytes)
            .unwrap()
            .into();

        let verified_claims = SDJWTVerifier::new(Box::new(issuer_pub_key))
            .verify_presentation(
                presentation,
                aud.clone(),
                nonce.clone(),
                SDJWTSerializationFormat::JSON,
            )
            .await
            .unwrap();

        let claims_to_check = json!({
            "iss": user_claims["iss"].clone(),
            "iat": user_claims["iat"].clone(),
            "exp": user_claims["exp"].clone(),
            "cnf": {
                "jwk": serde_json::from_str::<Value>(HOLDER_JWK_KEY_ED25519).unwrap(),
            },
            "sub": user_claims["sub"].clone(),
            "address": user_claims["address"].clone(),
        });

        assert_eq!(claims_to_check, verified_claims);

        Ok(())
    }
}
