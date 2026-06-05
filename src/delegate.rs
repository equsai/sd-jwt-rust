// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! Delegate SD-JWT (dSD-JWT / dSD-JWT+KB) support.
//!
//! Implements the chain types, compact-form tokenizer, and binding-hash helpers
//! used by [`SDJWTHolder::delegate`] and the verifier chain walk.
//!
//! See `docs/delegate-sd-jwt-design.md` for the protocol-level design.

use crate::error::{Error, Result};
use crate::utils::{base64_hash, base64url_decode};
use crate::{
    COMBINED_SERIALIZATION_FORMAT_SEPARATOR, ISSUER_JWT_HASH_KEY, JWT_SEPARATOR, KB_DIGEST_KEY,
    MAX_DELEGATION_DEPTH,
};

/// How a KB-SD-JWT binds to the preceding component in the chain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ChainBindingMode {
    /// `sd_hash` over the preceding JWT and its forwarded disclosures.
    /// Delegate Holder MUST keep the preceding component's disclosures on the wire.
    #[default]
    SdHash,
    /// `issuer_jwt_hash` over the preceding JWT only.
    /// Lets a Delegate Holder drop the preceding component's disclosures.
    IssuerJwtHash,
}

/// One KB-SD-JWT link in the chain, with the disclosures that follow it on the wire.
#[derive(Clone, Debug)]
pub(crate) struct ChainLink {
    pub jwt: String,
    pub disclosures: Vec<String>,
}

/// Parsed compact-form delegation chain. Position 0 is the issuer-signed JWT
/// (held outside this struct on `SDJWTCommon`); `links` is the ordered list
/// of KB-SD-JWTs; `trailing_kb_jwt` is the final KB-JWT (dSD-JWT+KB only).
#[derive(Clone, Debug)]
pub(crate) struct DelegationChain {
    pub issuer_jwt: String,
    pub issuer_disclosures: Vec<String>,
    pub links: Vec<ChainLink>,
    pub trailing_kb_jwt: Option<String>,
}

impl DelegationChain {
    /// Try to parse `input` as a compact-form delegation chain.
    ///
    /// Returns `Ok(Some(chain))` if the input contains at least one KB-SD-JWT link
    /// (i.e. is a dSD-JWT or dSD-JWT+KB); `Ok(None)` if the input is a plain SD-JWT
    /// or SD-JWT+KB (caller should fall back to the legacy parser).
    pub fn try_parse_compact(input: &str) -> Result<Option<Self>> {
        let tokens: Vec<&str> = input
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();
        if tokens.len() < 2 {
            return Ok(None);
        }
        let trailing_tilde = input.ends_with(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);

        // A "JWT-shaped" token contains JWT separators (`.`); a disclosure never does
        // because it's base64url-encoded (`.` is not in the base64url alphabet).
        let jwt_positions: Vec<usize> = tokens
            .iter()
            .enumerate()
            .filter_map(|(i, t)| {
                if !t.is_empty() && t.contains(JWT_SEPARATOR) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();

        // Need at least the issuer JWT.
        if jwt_positions.first() != Some(&0) {
            return Err(Error::ChainParseError(
                "input does not start with a JWT".to_string(),
            ));
        }

        // Classify: how many JWTs after position 0 are *chain links* (KB-SD-JWTs)?
        // If the input has a trailing `~`, no final KB-JWT — every non-issuer JWT is a link.
        // Otherwise the last JWT is the final KB-JWT.
        let (link_jwt_indices, final_kb_jwt_index): (Vec<usize>, Option<usize>) =
            if trailing_tilde {
                (jwt_positions[1..].to_vec(), None)
            } else {
                let last = *jwt_positions.last().unwrap();
                let mid: Vec<usize> = jwt_positions[1..]
                    .iter()
                    .copied()
                    .filter(|&i| i != last)
                    .collect();
                (mid, Some(last))
            };

        if link_jwt_indices.is_empty() {
            // Plain SD-JWT or SD-JWT+KB; not a delegation chain.
            return Ok(None);
        }

        if link_jwt_indices.len() > MAX_DELEGATION_DEPTH {
            return Err(Error::ChainDepthLimitExceeded(link_jwt_indices.len()));
        }

        // Spec rule: each chain-link KB-SD-JWT MUST be immediately preceded by an
        // empty component (`~~` on the wire). No other empty components are allowed
        // except the trailing one when there is no final KB-JWT.
        for (i, t) in tokens.iter().enumerate() {
            if !t.is_empty() {
                continue;
            }
            // Trailing terminator (no final KB-JWT).
            if trailing_tilde && i + 1 == tokens.len() {
                continue;
            }
            // Mandatory separator before the next chain link.
            if i + 1 < tokens.len() && link_jwt_indices.contains(&(i + 1)) {
                continue;
            }
            return Err(Error::ChainParseError(format!(
                "unexpected empty component at index {} (only allowed before a chain-link KB-SD-JWT)",
                i
            )));
        }
        for &link_idx in &link_jwt_indices {
            if link_idx == 0 || !tokens[link_idx - 1].is_empty() {
                return Err(Error::ChainParseError(format!(
                    "missing mandatory empty component before chain-link KB-SD-JWT at index {}",
                    link_idx
                )));
            }
        }

        // Walk tokens, building per-segment disclosure buckets between JWTs.
        let issuer_jwt = tokens[0].to_string();
        let mut links: Vec<ChainLink> = Vec::with_capacity(link_jwt_indices.len());
        let mut issuer_disclosures: Vec<String> = Vec::new();

        // Boundaries: [0, link_jwt_indices..., final_kb_jwt_index?, tokens.len()].
        // Disclosures of segment i live in tokens between segment-JWT i and segment-JWT i+1.
        let mut segment_starts: Vec<usize> = vec![0];
        segment_starts.extend(link_jwt_indices.iter().copied());
        let end_boundary = final_kb_jwt_index.unwrap_or(tokens.len());

        for (seg_idx, &seg_start) in segment_starts.iter().enumerate() {
            let next_boundary = segment_starts
                .get(seg_idx + 1)
                .copied()
                .unwrap_or(end_boundary);
            // Disclosures live strictly between seg_start+1 and next_boundary.
            // Empty tokens (the mandatory separator and the trailing terminator) were
            // validated above and are skipped here so they don't become disclosures.
            let mut bucket: Vec<String> = Vec::new();
            for t in &tokens[seg_start + 1..next_boundary] {
                if t.is_empty() {
                    continue;
                }
                if t.contains(JWT_SEPARATOR) {
                    return Err(Error::ChainParseError(format!(
                        "unexpected JWT token between segments at index {}",
                        seg_idx
                    )));
                }
                bucket.push((*t).to_string());
            }
            if seg_idx == 0 {
                issuer_disclosures = bucket;
            } else {
                links.push(ChainLink {
                    jwt: tokens[seg_start].to_string(),
                    disclosures: bucket,
                });
            }
        }

        let trailing_kb_jwt = final_kb_jwt_index.map(|i| tokens[i].to_string());

        Ok(Some(DelegationChain {
            issuer_jwt,
            issuer_disclosures,
            links,
            trailing_kb_jwt,
        }))
    }

    /// Serialize the chain to its compact form. Each non-final chain-link
    /// KB-SD-JWT is preceded by an empty component (the wire shows `~~`), per
    /// the dSD-JWT serialization rule:
    ///
    /// > the resulting array of components MUST have an empty component between
    /// > the last disclosure of each SD-JWT before the following KB-SD-JWT
    ///
    /// The final KB-JWT (when present) is NOT preceded by `~~` — only chain links
    /// (KB-SD-JWTs) take the empty separator.
    #[allow(dead_code)] // kept for test/diagnostic round-tripping
    pub fn serialize_compact(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        parts.push(&self.issuer_jwt);
        parts.extend(self.issuer_disclosures.iter().map(|s| s.as_str()));
        for link in &self.links {
            parts.push(""); // mandatory empty component before each chain link
            parts.push(&link.jwt);
            parts.extend(link.disclosures.iter().map(|s| s.as_str()));
        }
        let mut s = parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
        match &self.trailing_kb_jwt {
            Some(kb) => {
                s.push_str(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
                s.push_str(kb);
            }
            None => s.push_str(COMBINED_SERIALIZATION_FORMAT_SEPARATOR),
        }
        s
    }

    /// All disclosures across all chain segments, in chain order. Used to populate
    /// the verifier's hash-to-disclosure map so any link can resolve any digest.
    pub fn all_disclosures(&self) -> Vec<String> {
        let mut all = self.issuer_disclosures.clone();
        for link in &self.links {
            all.extend(link.disclosures.iter().cloned());
        }
        all
    }

    /// Serialize the chain WITHOUT the trailing KB-JWT, ending in `~`. Used as the
    /// hashed input for a final KB-JWT's `sd_hash` in a dSD-JWT+KB. Includes the
    /// mandatory empty component before each chain-link KB-SD-JWT (same rule as
    /// [`serialize_compact`]).
    pub fn serialize_for_final_kb_hash(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        parts.push(&self.issuer_jwt);
        parts.extend(self.issuer_disclosures.iter().map(|s| s.as_str()));
        for link in &self.links {
            parts.push(""); // mandatory empty component before each chain link
            parts.push(&link.jwt);
            parts.extend(link.disclosures.iter().map(|s| s.as_str()));
        }
        let mut s = parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
        s.push_str(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
        s
    }
}

/// `sd_hash` over a JWT + the disclosures that follow it on the wire.
/// Matches the construction used for plain SD-JWT+KB (`<jwt>~<d1>~...~<dn>~`).
pub(crate) fn compute_sd_hash(jwt: &str, disclosures: &[String]) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(disclosures.len() + 1);
    parts.push(jwt);
    parts.extend(disclosures.iter().map(|s| s.as_str()));
    let combined = format!(
        "{}{}",
        parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR),
        COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
    );
    base64_hash(combined.as_bytes())
}

/// `issuer_jwt_hash` over a JWT only (no disclosures).
pub(crate) fn compute_issuer_jwt_hash(jwt: &str) -> String {
    base64_hash(jwt.as_bytes())
}

/// Inspect a KB-SD-JWT's payload (without verifying its signature — the chain
/// member already holds the link, the goal here is solely to read which binding
/// claim is in use). Returns `Some(SdHash)` if `sd_hash` is present (preferred when
/// both are present, matching the verifier's preference order), `Some(IssuerJwtHash)`
/// if only `issuer_jwt_hash` is present, `None` if neither claim is present or the
/// JWT cannot be parsed.
pub(crate) fn link_binding_mode(link_jwt: &str) -> Option<ChainBindingMode> {
    let parts: Vec<&str> = link_jwt.split(JWT_SEPARATOR).collect();
    if parts.len() < 2 {
        return None;
    }
    let body_bytes = base64url_decode(parts[1]).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&body_bytes).ok()?;
    let obj = payload.as_object()?;
    if obj.contains_key(KB_DIGEST_KEY) {
        return Some(ChainBindingMode::SdHash);
    }
    if obj.contains_key(ISSUER_JWT_HASH_KEY) {
        return Some(ChainBindingMode::IssuerJwtHash);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_jwt(tag: &str) -> String {
        // Three non-empty segments separated by '.'; content irrelevant for tokenization.
        format!("hdr-{tag}.body-{tag}.sig-{tag}")
    }

    #[test]
    fn parse_plain_sd_jwt_returns_none() {
        // Trailing `~`, no chain link.
        let s = format!("{}~", fake_jwt("issuer"));
        assert!(DelegationChain::try_parse_compact(&s).unwrap().is_none());
    }

    #[test]
    fn parse_plain_sd_jwt_kb_returns_none() {
        let s = format!("{}~D1~{}", fake_jwt("issuer"), fake_jwt("kb"));
        assert!(DelegationChain::try_parse_compact(&s).unwrap().is_none());
    }

    #[test]
    fn parse_single_delegation_no_final_kb() {
        // Spec form: `~~` between issuer segment and chain-link KB-SD-JWT.
        let s = format!(
            "{}~D1~~{}~D2~",
            fake_jwt("issuer"),
            fake_jwt("kbsd1"),
        );
        let chain = DelegationChain::try_parse_compact(&s).unwrap().unwrap();
        assert_eq!(chain.issuer_jwt, fake_jwt("issuer"));
        assert_eq!(chain.issuer_disclosures, vec!["D1".to_string()]);
        assert_eq!(chain.links.len(), 1);
        assert_eq!(chain.links[0].jwt, fake_jwt("kbsd1"));
        assert_eq!(chain.links[0].disclosures, vec!["D2".to_string()]);
        assert!(chain.trailing_kb_jwt.is_none());
    }

    #[test]
    fn parse_single_delegation_with_final_kb() {
        // Spec form: `~~` before chain link, single `~` before final KB-JWT.
        let s = format!(
            "{}~D1~~{}~D2~{}",
            fake_jwt("issuer"),
            fake_jwt("kbsd1"),
            fake_jwt("finalkb"),
        );
        let chain = DelegationChain::try_parse_compact(&s).unwrap().unwrap();
        assert_eq!(chain.links.len(), 1);
        assert_eq!(chain.trailing_kb_jwt.as_deref(), Some(fake_jwt("finalkb").as_str()));
    }

    #[test]
    fn parse_zero_issuer_disclosures_compact_form() {
        // Zero forwarded issuer disclosures: the `~~` after the issuer JWT is the
        // mandatory separator (there were zero disclosures in between).
        let s = format!("{}~~{}~", fake_jwt("issuer"), fake_jwt("kbsd1"));
        let chain = DelegationChain::try_parse_compact(&s).unwrap().unwrap();
        assert!(chain.issuer_disclosures.is_empty());
        assert_eq!(chain.links.len(), 1);
    }

    #[test]
    fn parse_two_hop_delegation() {
        let s = format!(
            "{}~D1~~{}~D2~~{}~D3~",
            fake_jwt("issuer"),
            fake_jwt("kbsd1"),
            fake_jwt("kbsd2"),
        );
        let chain = DelegationChain::try_parse_compact(&s).unwrap().unwrap();
        assert_eq!(chain.links.len(), 2);
        assert_eq!(chain.links[0].disclosures, vec!["D2".to_string()]);
        assert_eq!(chain.links[1].disclosures, vec!["D3".to_string()]);
    }

    #[test]
    fn serialize_round_trip() {
        let s = format!(
            "{}~D1~~{}~D2~{}",
            fake_jwt("issuer"),
            fake_jwt("kbsd1"),
            fake_jwt("finalkb"),
        );
        let chain = DelegationChain::try_parse_compact(&s).unwrap().unwrap();
        assert_eq!(chain.serialize_compact(), s);
    }

    #[test]
    fn reject_missing_mandatory_empty_component() {
        // Spec violation: chain-link KB-SD-JWT not preceded by an empty component.
        let s = format!(
            "{}~D1~{}~D2~",
            fake_jwt("issuer"),
            fake_jwt("kbsd1"),
        );
        let err = DelegationChain::try_parse_compact(&s).unwrap_err();
        match err {
            Error::ChainParseError(msg) => {
                assert!(
                    msg.contains("missing mandatory empty component"),
                    "wrong error message: {msg}"
                );
            }
            other => panic!("expected ChainParseError, got {other:?}"),
        }
    }

    #[test]
    fn reject_extra_empty_component() {
        // Extra empty component not preceding any chain link.
        let s = format!(
            "{}~D1~~D2~~{}~D3~",
            fake_jwt("issuer"),
            fake_jwt("kbsd1"),
        );
        let err = DelegationChain::try_parse_compact(&s).unwrap_err();
        match err {
            Error::ChainParseError(msg) => {
                assert!(msg.contains("unexpected empty component"), "wrong message: {msg}");
            }
            other => panic!("expected ChainParseError, got {other:?}"),
        }
    }

    #[test]
    fn depth_limit_enforced() {
        // Build a too-deep chain in spec form (`~~` before each link).
        let mut s = fake_jwt("issuer");
        for i in 0..MAX_DELEGATION_DEPTH + 1 {
            s.push_str("~~");
            s.push_str(&fake_jwt(&format!("link{i}")));
        }
        s.push('~');
        let err = DelegationChain::try_parse_compact(&s).unwrap_err();
        assert!(matches!(err, Error::ChainDepthLimitExceeded(_)));
    }
}
