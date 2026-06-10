// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! Holder side of Delegate SD-JWTs (dSD-JWT / dSD-JWT+KB).
//!
//! [`DelegateHolder`] loads either a plain holder-bound SD-JWT (to start a chain)
//! or an existing dSD-JWT (to re-delegate or present). It can
//! [`delegate`](DelegateHolder::delegate) (append a KB-SD-JWT link signed with this
//! party's `cnf` key) and, via
//! [`select_delegate_alternative`](DelegateHolder::select_delegate_alternative) +
//! [`present`](DelegateHolder::present), disclose exactly one of the final link's
//! `delegate_payload` alternatives, optionally with a final KB-JWT.
//!
//! It reuses the shared SD-JWT core ([`SDJWTCommon`], disclosure selection) rather
//! than the plain [`crate::holder::SDJWTHolder`], since a chain link is signed by a
//! Holder, not by the credential Issuer.

use std::collections::HashSet;
use std::str::FromStr;
use std::time;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{json, Map, Value};

use crate::delegate::{
    compute_issuer_jwt_hash, compute_sd_hash, link_binding_mode, link_delegate_payload_stubs,
    ChainBindingMode, DelegationChain,
};
use crate::disclosure::SDJWTDisclosure;
use crate::error::{Error, Result};
use crate::utils::{base64_hash, jwt_payload_decode};
use crate::{
    SDJWTCommon, SDJWTSerializationFormat, CNF_KEY, COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
    DEFAULT_DIGEST_ALG, DEFAULT_SIGNING_ALG, DELEGATE_PAYLOAD_KEY, DIGEST_ALG_KEY,
    ISSUER_JWT_HASH_KEY, JWT_SEPARATOR, KB_DIGEST_KEY, KB_JWT_TYP_HEADER, KB_SD_JWT_KB_TYP_HEADER,
    KB_SD_JWT_TYP_HEADER, SD_LIST_PREFIX,
};

/// Holder / Delegate Holder of a dSD-JWT.
pub struct DelegateHolder {
    /// Disclosure maps over every disclosure on the wire (issuer + all links), used
    /// for forwarding selection and alternative selection.
    engine: SDJWTCommon,
    /// The parsed delegation chain, or `None` for a freshly loaded plain SD-JWT
    /// that has not been delegated yet.
    chain: Option<DelegationChain>,
    /// Position-0 issuer-signed JWT (compact). For a freshly loaded plain SD-JWT
    /// this is the credential itself; for a loaded chain it is the chain's issuer JWT.
    issuer_jwt: String,
    /// Position-0 (issuer) payload, used to select which issuer disclosures to
    /// forward on first-hop delegation.
    issuer_payload: Map<String, Value>,
    /// Which final-link `delegate_payload` alternative to disclose when presenting.
    selected_alternative: Option<usize>,
}

impl DelegateHolder {
    /// Load a plain holder-bound SD-JWT (to start a chain) or an existing dSD-JWT
    /// (to re-delegate or present). Compact serialization only.
    pub fn load(sd_jwt_or_dsd_jwt: String) -> Result<Self> {
        let mut engine = SDJWTCommon {
            serialization_format: SDJWTSerializationFormat::Compact,
            ..Default::default()
        };

        if let Some(chain) = DelegationChain::try_parse_compact(&sd_jwt_or_dsd_jwt)? {
            // The disclosure map must resolve digests from EVERY segment of the chain.
            engine.input_disclosures = chain.all_disclosures();
            engine.create_hash_mappings()?;
            let issuer_jwt = chain.issuer_jwt.clone();
            let issuer_payload = decode_jwt_payload(&issuer_jwt)?;
            Ok(DelegateHolder {
                engine,
                chain: Some(chain),
                issuer_jwt,
                issuer_payload,
                selected_alternative: None,
            })
        } else {
            // Plain holder-bound SD-JWT (first-hop starting point).
            engine.parse_sd_jwt(sd_jwt_or_dsd_jwt)?;
            engine.create_hash_mappings()?;
            let issuer_payload = engine
                .unverified_input_sd_jwt_payload
                .clone()
                .ok_or_else(|| Error::InvalidState("Cannot read issuer payload".to_string()))?;
            let issuer_jwt = engine
                .unverified_sd_jwt
                .clone()
                .ok_or_else(|| Error::InvalidState("Cannot read issuer JWT".to_string()))?;
            Ok(DelegateHolder {
                engine,
                chain: None,
                issuer_jwt,
                issuer_payload,
                selected_alternative: None,
            })
        }
    }

    /// True if the loaded credential is already a dSD-JWT chain (vs. a plain
    /// holder-bound SD-JWT awaiting its first delegation).
    pub fn is_delegated(&self) -> bool {
        self.chain.is_some()
    }

    /// Number of KB-SD-JWT links between the issuer-signed JWT and this holder.
    /// Zero for a not-yet-delegated SD-JWT.
    pub fn delegation_depth(&self) -> usize {
        self.chain.as_ref().map_or(0, |c| c.links.len())
    }

    /// Append a KB-SD-JWT link, producing a Compact dSD-JWT (no trailing KB-JWT).
    ///
    /// # Arguments
    ///
    /// * `delegate_payloads` — one or more complete Delegate Payloads, each a
    ///   self-contained alternative delegation (an opaque JSON object). A single
    ///   element is embedded inline; multiple elements are each turned into an
    ///   array-element disclosure so several delegations can be signed at once and
    ///   the Delegate Holder reveals exactly one per Verifier (see
    ///   [`Self::select_delegate_alternative`]). All alternatives must agree on
    ///   whether they carry a `cnf` claim: all-with-`cnf` ⇒ `kb+sd-jwt+kb`
    ///   (further delegation / final KB-JWT possible), none ⇒ terminal
    ///   `kb+sd-jwt`, mixed ⇒ rejected.
    /// * `claims_to_disclose` — first-hop only: subset of the issuer SD-JWT's
    ///   claims to forward. Ignored on re-delegation (use `drop_disclosures`).
    /// * `drop_disclosures` — re-delegation only: disclosure strings to remove from
    ///   the forwarded chain (droppable iff no downstream `sd_hash`-bound link
    ///   committed to them; the last link's disclosures are always droppable). This
    ///   is also how a multi-alternative predecessor link is narrowed to one.
    /// * `holder_signing_key` — private key matching the preceding component's `cnf`.
    /// * `binding_mode` — `SdHash` or `IssuerJwtHash`.
    /// * `sign_alg` — JWS alg for the KB-SD-JWT (default: ES256).
    pub fn delegate(
        &mut self,
        delegate_payloads: Vec<Value>,
        claims_to_disclose: Option<Map<String, Value>>,
        drop_disclosures: Option<HashSet<String>>,
        holder_signing_key: EncodingKey,
        binding_mode: ChainBindingMode,
        sign_alg: Option<String>,
    ) -> Result<String> {
        if delegate_payloads.is_empty() {
            return Err(Error::InvalidDelegatePayload(
                "delegate_payloads must contain at least one alternative".into(),
            ));
        }

        // Determine the link `typ` from whether the alternatives carry `cnf`:
        // all-with-cnf ⇒ kb+sd-jwt+kb (delegatable), none ⇒ terminal kb+sd-jwt,
        // mixed ⇒ rejected (the typ is a single header for the whole KB-SD-JWT).
        let mut with_cnf = 0usize;
        for payload in &delegate_payloads {
            let obj = payload.as_object().ok_or_else(|| {
                Error::InvalidDelegatePayload(
                    "each delegate_payload alternative must be a JSON object".into(),
                )
            })?;
            if obj.contains_key(CNF_KEY) {
                with_cnf += 1;
            }
        }
        let typ_header = if with_cnf == delegate_payloads.len() {
            KB_SD_JWT_KB_TYP_HEADER.to_string()
        } else if with_cnf == 0 {
            KB_SD_JWT_TYP_HEADER.to_string()
        } else {
            return Err(Error::InvalidDelegatePayload(
                "delegate_payload alternatives must either all contain a cnf claim \
                 (kb+sd-jwt+kb) or none (kb+sd-jwt)"
                    .into(),
            ));
        };

        // Determine (a) the parent JWT this new link binds to, (b) its disclosures
        // (post-drop, for the new link's binding hash to commit to), and (c) the
        // prefix bytes (everything that precedes the new link in the output).
        let (parent_jwt, parent_disclosures, prefix_parts): (String, Vec<String>, Vec<String>) =
            match self.chain.clone() {
                None => {
                    let _ = drop_disclosures; // ignored on first-hop
                    let forwarded: Vec<String> = match (binding_mode, claims_to_disclose) {
                        (ChainBindingMode::IssuerJwtHash, None) => Vec::new(),
                        (_, Some(claims)) => crate::selector::select_disclosures(
                            &self.issuer_payload,
                            claims,
                            &self.engine.hash_to_decoded_disclosure,
                            &self.engine.hash_to_disclosure,
                        )?,
                        (ChainBindingMode::SdHash, None) => Vec::new(),
                    };
                    let mut prefix: Vec<String> = Vec::with_capacity(forwarded.len() + 1);
                    prefix.push(self.issuer_jwt.clone());
                    prefix.extend(forwarded.iter().cloned());
                    (self.issuer_jwt.clone(), forwarded, prefix)
                }
                Some(chain) => {
                    let _ = claims_to_disclose; // re-delegation uses drop_disclosures instead
                    let drops: HashSet<String> = drop_disclosures.unwrap_or_default();
                    let last_link = chain.links.last().ok_or_else(|| {
                        Error::InvalidState("delegation_chain is present but has no links".into())
                    })?;

                    // For each existing segment, decide whether its disclosures can
                    // be dropped:
                    //  - issuer segment      ← gated by chain.links[0]'s binding
                    //  - chain.links[i] seg  ← gated by chain.links[i+1]'s binding
                    //  - chain.links[last]   ← gated by OUR new link (we sign it now).
                    fn segment_droppable(
                        next_link_jwt: Option<&str>,
                        our_binding: ChainBindingMode,
                    ) -> bool {
                        match next_link_jwt {
                            Some(jwt) => {
                                link_binding_mode(jwt) == Some(ChainBindingMode::IssuerJwtHash)
                            }
                            None => {
                                let _ = our_binding;
                                true
                            }
                        }
                    }

                    let mut prefix: Vec<String> = Vec::new();
                    let mut used_drops: HashSet<&String> = HashSet::new();

                    // Issuer segment.
                    prefix.push(chain.issuer_jwt.clone());
                    let issuer_seg_droppable =
                        segment_droppable(chain.links.first().map(|l| l.jwt.as_str()), binding_mode);
                    for d in &chain.issuer_disclosures {
                        if drops.contains(d) {
                            if !issuer_seg_droppable {
                                return Err(Error::InvalidInput(
                                    "cannot drop disclosure from issuer segment: downstream link \
                                     uses sd_hash binding which committed to it"
                                        .to_string(),
                                ));
                            }
                            used_drops.insert(d);
                        } else {
                            prefix.push(d.clone());
                        }
                    }

                    // Each existing chain link's segment (with the mandatory empty
                    // component before each link).
                    let mut last_link_filtered_disclosures: Vec<String> = Vec::new();
                    for (i, link) in chain.links.iter().enumerate() {
                        prefix.push(String::new());
                        prefix.push(link.jwt.clone());
                        let next_jwt = chain.links.get(i + 1).map(|l| l.jwt.as_str());
                        let droppable = segment_droppable(next_jwt, binding_mode);
                        for d in &link.disclosures {
                            if drops.contains(d) {
                                if !droppable {
                                    return Err(Error::InvalidInput(format!(
                                        "cannot drop disclosure from chain link {}: downstream \
                                         link uses sd_hash binding which committed to it",
                                        i
                                    )));
                                }
                                used_drops.insert(d);
                            } else {
                                prefix.push(d.clone());
                                if i + 1 == chain.links.len() {
                                    last_link_filtered_disclosures.push(d.clone());
                                }
                            }
                        }
                    }

                    // Reject unrecognized drop targets (likely a caller bug).
                    if used_drops.len() < drops.len() {
                        let unmatched: Vec<&String> =
                            drops.iter().filter(|d| !used_drops.contains(d)).collect();
                        return Err(Error::InvalidInput(format!(
                            "drop_disclosures contains {} entries not present in the chain (e.g. {:?})",
                            unmatched.len(),
                            unmatched.first()
                        )));
                    }

                    (last_link.jwt.clone(), last_link_filtered_disclosures, prefix)
                }
            };

        let binding_hash = match binding_mode {
            ChainBindingMode::SdHash => compute_sd_hash(&parent_jwt, &parent_disclosures),
            ChainBindingMode::IssuerJwtHash => compute_issuer_jwt_hash(&parent_jwt),
        };
        let binding_key = match binding_mode {
            ChainBindingMode::SdHash => KB_DIGEST_KEY,
            ChainBindingMode::IssuerJwtHash => ISSUER_JWT_HASH_KEY,
        };

        let combined = sign_kb_sd_jwt_link(
            &holder_signing_key,
            sign_alg.as_deref(),
            &typ_header,
            delegate_payloads,
            binding_key,
            binding_hash,
        )?;

        // The new KB-SD-JWT is a chain link, so it MUST be preceded by an empty
        // component (`~~` on the wire).
        let prefix = prefix_parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
        Ok(format!(
            "{prefix}{sep}{sep}{combined}",
            sep = COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
        ))
    }

    /// Select which `delegate_payload` alternative of the final chain link to
    /// disclose in the next [`Self::present`]. `index` is the position in the
    /// `delegate_payloads` vector originally passed to [`Self::delegate`]. No effect
    /// for a single-alternative (inline) credential.
    pub fn select_delegate_alternative(&mut self, index: usize) {
        self.selected_alternative = Some(index);
    }

    /// Produce a presentation of the loaded dSD-JWT: the chain with exactly one
    /// final-link `delegate_payload` alternative disclosed, optionally followed by a
    /// KB-JWT proving possession of the final Delegate Holder's key.
    ///
    /// Pass all of `nonce`/`aud`/`holder_key` to append a KB-JWT (→ dSD-JWT+KB), or
    /// none of them to present a bare dSD-JWT.
    pub fn present(
        &self,
        nonce: Option<String>,
        aud: Option<String>,
        holder_key: Option<EncodingKey>,
        sign_alg: Option<String>,
    ) -> Result<String> {
        let chain = self.chain.as_ref().ok_or_else(|| {
            Error::InvalidInput(
                "this credential is not delegated yet; nothing to present".to_string(),
            )
        })?;
        let last = chain
            .links
            .last()
            .ok_or_else(|| Error::InvalidState("delegation chain has no links".into()))?;

        let kept = self.select_chain_alternative_disclosures()?;
        let base = chain.serialize_for_presentation(&kept);

        let kb_jwt = match (nonce, aud, holder_key) {
            (Some(nonce), Some(aud), Some(holder_key)) => {
                let sd_hash = compute_sd_hash(&last.jwt, &kept);
                Some(build_kb_jwt(nonce, aud, &holder_key, sign_alg, sd_hash)?)
            }
            (None, None, None) => None,
            _ => {
                return Err(Error::InvalidInput(
                    "Inconsistency in parameters to determine JWT KB by holder".to_string(),
                ))
            }
        };

        Ok(match kb_jwt {
            Some(kb) => format!("{}{}", base, kb),
            None => base,
        })
    }

    /// Resolve the disclosures of the chain's final link to keep in a presentation
    /// (chosen alternative kept, other alternatives dropped).
    fn select_chain_alternative_disclosures(&self) -> Result<Vec<String>> {
        let chain = self
            .chain
            .as_ref()
            .ok_or_else(|| Error::InvalidState("no delegation chain".into()))?;
        let last = chain
            .links
            .last()
            .ok_or_else(|| Error::InvalidState("delegation chain has no links".into()))?;

        let stubs = link_delegate_payload_stubs(&last.jwt).ok_or_else(|| {
            Error::InvalidDelegatePayload("final chain link has no delegate_payload array".into())
        })?;
        let alternative_hashes: HashSet<&String> = stubs.iter().filter_map(Option::as_ref).collect();

        // No array-element disclosures ⇒ a single inline alternative; keep as-is.
        if alternative_hashes.is_empty() {
            if matches!(self.selected_alternative, Some(i) if i != 0) {
                return Err(Error::InvalidInput(
                    "delegate_payload has a single inline alternative; only index 0 is valid"
                        .into(),
                ));
            }
            return Ok(last.disclosures.clone());
        }

        // Multiple alternatives ⇒ a selection is required.
        let index = self.selected_alternative.ok_or_else(|| {
            Error::InvalidInput(
                "this dSD-JWT bundles multiple delegate_payload alternatives; call \
                 select_delegate_alternative(index) before presenting"
                    .into(),
            )
        })?;
        let chosen_hash = stubs
            .get(index)
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                Error::InvalidInput(format!(
                    "delegate_payload alternative index {} is out of range or inline",
                    index
                ))
            })?
            .clone();

        let mut kept = Vec::new();
        let mut found = false;
        for d in &last.disclosures {
            let hash = base64_hash(d.as_bytes());
            if alternative_hashes.contains(&hash) {
                if hash == chosen_hash {
                    kept.push(d.clone());
                    found = true;
                }
            } else {
                kept.push(d.clone());
            }
        }
        if !found {
            return Err(Error::InvalidInput(format!(
                "selected delegate_payload alternative {} has no matching disclosure on the wire",
                index
            )));
        }
        Ok(kept)
    }
}

/// Decode the (unverified) payload of a compact JWS into a JSON object.
fn decode_jwt_payload(jwt: &str) -> Result<Map<String, Value>> {
    let body = jwt.split(JWT_SEPARATOR).nth(1).ok_or(Error::IndexOutOfBounds {
        idx: 1,
        length: 3,
        msg: format!("Invalid issuer JWT: {}", jwt),
    })?;
    jwt_payload_decode(body)
}

/// Sign one KB-SD-JWT chain link with a Holder's `cnf` private key and serialize it
/// compactly (`<jwt>~<d1>~...~<dn>~`). The link signer lives here (not on
/// `SDJWTIssuer`) because a chain link is signed by a Holder, not the Issuer.
fn sign_kb_sd_jwt_link(
    signing_key: &EncodingKey,
    sign_alg: Option<&str>,
    typ_header: &str,
    delegate_payloads: Vec<Value>,
    binding_key: &str,
    binding_hash: String,
) -> Result<String> {
    if delegate_payloads.is_empty() {
        return Err(Error::InvalidDelegatePayload(
            "delegate_payload must contain at least one alternative".into(),
        ));
    }
    for payload in &delegate_payloads {
        if !payload.is_object() {
            return Err(Error::InvalidDelegatePayload(
                "each delegate_payload alternative must be a JSON object".into(),
            ));
        }
        // Alternatives are opaque; they must not carry their own `_sd` digests.
        SDJWTCommon::check_for_sd_claim(payload)?;
    }

    // Build the `delegate_payload` array: a lone alternative inline, otherwise one
    // array-element disclosure per alternative (only the stubs are signed).
    let mut array: Vec<Value> = Vec::with_capacity(delegate_payloads.len());
    let mut disclosures: Vec<String> = Vec::new();
    if delegate_payloads.len() == 1 {
        array.extend(delegate_payloads);
    } else {
        for payload in delegate_payloads {
            let disclosure = SDJWTDisclosure::new(None, payload);
            array.push(json!({ SD_LIST_PREFIX: disclosure.hash }));
            disclosures.push(disclosure.raw_b64);
        }
    }

    let mut payload = Map::new();
    payload.insert(DELEGATE_PAYLOAD_KEY.to_owned(), Value::Array(array));
    payload.insert(
        DIGEST_ALG_KEY.to_owned(),
        Value::String(DEFAULT_DIGEST_ALG.to_owned()),
    );
    payload.insert(binding_key.to_owned(), Value::String(binding_hash));

    let alg = sign_alg.unwrap_or(DEFAULT_SIGNING_ALG);
    let mut header = Header::new(
        Algorithm::from_str(alg).map_err(|e| Error::DeserializationError(e.to_string()))?,
    );
    header.typ = Some(typ_header.to_string());
    let jwt = jsonwebtoken::encode(&header, &payload, signing_key)
        .map_err(|e| Error::DeserializationError(e.to_string()))?;

    let mut parts: Vec<String> = Vec::with_capacity(disclosures.len() + 1);
    parts.push(jwt);
    parts.extend(disclosures);
    Ok(format!(
        "{}{}",
        parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR),
        COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
    ))
}

/// Build a final KB-JWT (`typ=kb+jwt`) binding `sd_hash` to the presented chain.
fn build_kb_jwt(
    nonce: String,
    aud: String,
    holder_key: &EncodingKey,
    sign_alg: Option<String>,
    sd_hash: String,
) -> Result<String> {
    let alg = sign_alg.unwrap_or_else(|| DEFAULT_SIGNING_ALG.to_string());
    let mut payload: Map<String, Value> = Map::new();
    payload.insert("nonce".to_string(), Value::String(nonce));
    payload.insert("aud".to_string(), Value::String(aud));
    let timestamp = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .map_err(|e| Error::ConversionError(format!("timestamp: {}", e)))?
        .as_secs();
    payload.insert("iat".to_string(), timestamp.into());
    payload.insert(KB_DIGEST_KEY.to_string(), Value::String(sd_hash));

    let mut header = Header::new(
        Algorithm::from_str(&alg).map_err(|e| Error::DeserializationError(e.to_string()))?,
    );
    header.typ = Some(KB_JWT_TYP_HEADER.to_string());
    jsonwebtoken::encode(&header, &payload, holder_key)
        .map_err(|e| Error::DeserializationError(e.to_string()))
}
