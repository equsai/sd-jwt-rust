// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! End-to-end Delegate SD-JWT tests: Issuer → Holder → Delegate Holder → Verifier.

mod utils;

use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{DecodingKey, EncodingKey};
use sd_jwt_rs::{
    ChainBindingMode, ClaimsForSelectiveDisclosureStrategy, SDJWTHolder, SDJWTIssuer,
    SDJWTSerializationFormat, SDJWTVerifier,
};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

use utils::fixtures::{HOLDER_JWK_KEY, HOLDER_KEY, ISSUER_KEY, ISSUER_PUBLIC_KEY};

// Second-hop keypair used in multi-hop delegation tests. Ed25519 keypair from the
// existing verifier.rs test suite (proven matching).
const DELEGATE2_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIOeIDnHHMoPCUTiq206gR+FdCdNtc31SzF1nKX31hvhd\n-----END PRIVATE KEY-----";
const DELEGATE2_JWK: &str = r#"{
    "alg": "EdDSA",
    "crv": "Ed25519",
    "kid": "52128f2e-900e-414e-81c3-0b5f86f0f7b3",
    "kty": "OKP",
    "x": "24QLWXJ18wtbg3k_MDGhGM17Xh39UftuxbwJZzRLzkA"
}"#;

fn issuer_key_resolver() -> Box<dyn Fn(&str, &jsonwebtoken::Header) -> DecodingKey> {
    Box::new(|_iss, _hdr| {
        DecodingKey::from_ec_pem(ISSUER_PUBLIC_KEY.as_bytes()).expect("ec pub key")
    })
}

fn issue_holder_bound_sd_jwt(claims: Value, holder_jwk: Jwk) -> String {
    let issuer_key = EncodingKey::from_ec_pem(ISSUER_KEY.as_bytes()).unwrap();
    SDJWTIssuer::new(issuer_key, None)
        .issue_sd_jwt(
            claims,
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(holder_jwk),
            false,
            SDJWTSerializationFormat::Compact,
        )
        .unwrap()
}

#[test]
fn single_delegation_no_final_kb_round_trips() {
    let user_claims = json!({
        "sub": "alice",
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "address": { "country": "DE" }
    });

    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims.clone(), holder_jwk);

    // Holder loads the SD-JWT and delegates to a Delegate Holder.
    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let holder_signing_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();

    let delegate_payload = json!({
        "scope": "purchase",
        "merchant": "merchant.example",
        "limit": 100
    });

    // No delegate_cnf → terminal kb+sd-jwt link, no further delegation possible.
    let dsd_jwt = holder
        .delegate(
            delegate_payload.clone(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(user_claims.as_object().unwrap().clone()),
            None,
            holder_signing_key,
            None,
            ChainBindingMode::SdHash,
            None,
        )
        .unwrap();

    // Verifier walks the chain.
    let verifier = SDJWTVerifier::new(
        dsd_jwt,
        issuer_key_resolver(),
        None,
        None,
        SDJWTSerializationFormat::Compact,
    )
    .expect("chain verification should succeed");

    // One Delegate Payload entry, no `+kb` ⇒ no cnf in chain_cnfs.
    assert_eq!(verifier.verified_delegate_payloads.len(), 1);
    assert!(verifier.chain_cnfs.is_empty());

    // Delegate Payload claims must be visible in verified_claims (layered on top of issuer).
    let claims = verifier.verified_claims.as_object().expect("object");
    assert_eq!(claims.get("scope"), Some(&Value::String("purchase".into())));
    assert_eq!(
        claims.get("merchant"),
        Some(&Value::String("merchant.example".into())),
    );
    assert_eq!(claims.get("limit"), Some(&Value::from(100)));

    // Issuer claims must also still be visible.
    assert_eq!(claims.get("sub"), Some(&Value::String("alice".into())));
    assert_eq!(
        claims.get("address").and_then(|v| v.as_object())
            .and_then(|o| o.get("country")),
        Some(&Value::String("DE".into())),
    );
}

#[test]
fn delegate_payload_appears_in_verified_delegate_payloads() {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "carol",
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims.clone(), holder_jwk);

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let holder_signing_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();

    let dsd_jwt = holder
        .delegate(
            json!({"scope": "read-only"}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(Map::new()), // forward no original disclosures
            None,
            holder_signing_key,
            None,
            ChainBindingMode::SdHash,
            None,
        )
        .unwrap();

    let verifier = SDJWTVerifier::new(
        dsd_jwt,
        issuer_key_resolver(),
        None,
        None,
        SDJWTSerializationFormat::Compact,
    )
    .unwrap();

    let dp = &verifier.verified_delegate_payloads[0];
    assert_eq!(dp.get("scope"), Some(&Value::String("read-only".into())));
}

#[test]
fn issuer_jwt_hash_binding_mode_works() {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "bob",
        "secret": "do-not-forward",
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk);

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let holder_signing_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();

    // IssuerJwtHash mode: Delegate Holder can drop the original disclosures from the wire.
    let dsd_jwt = holder
        .delegate(
            json!({"purpose": "audit"}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None, // skip forwarding entirely
            None,
            holder_signing_key,
            None,
            ChainBindingMode::IssuerJwtHash,
            None,
        )
        .unwrap();

    // The resulting compact form should contain no issuer disclosures between the
    // issuer JWT and the KB-SD-JWT. Per spec, the chain link is preceded by an
    // empty component (`~~`), so the layout is:
    //   <issuer-jwt> ~~ <KB-SD-JWT> ~ <D'1>...<D'N> ~
    let parts: Vec<&str> = dsd_jwt.split('~').collect();
    assert!(parts[1].is_empty(), "expected mandatory empty component after issuer JWT");
    assert!(parts[2].contains('.'), "expected KB-SD-JWT at position 2 (after ~~)");

    let verifier = SDJWTVerifier::new(
        dsd_jwt,
        issuer_key_resolver(),
        None,
        None,
        SDJWTSerializationFormat::Compact,
    )
    .expect("chain verification with issuer_jwt_hash binding should succeed");

    assert_eq!(verifier.verified_delegate_payloads.len(), 1);
    let claims = verifier.verified_claims.as_object().unwrap();
    assert_eq!(claims.get("purpose"), Some(&Value::String("audit".into())));
}

#[test]
fn dsd_jwt_with_kb_proof_of_possession_round_trips() {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "eve"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk);

    // Holder delegates to a Delegate Holder, binding to delegate_cnf so the Delegate
    // Holder can sign a final KB-JWT.
    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let holder_signing_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();
    let delegate2_jwk: Jwk = serde_json::from_str(DELEGATE2_JWK).unwrap();

    let dsd_jwt = holder
        .delegate(
            json!({"scope": "view-account", "exp": 1893456000_i64}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(Map::new()),
            None,
            holder_signing_key,
            Some(delegate2_jwk),
            ChainBindingMode::SdHash,
            None,
        )
        .unwrap();

    // Delegate Holder loads the dSD-JWT and creates a presentation with a final KB-JWT.
    let mut delegate = SDJWTHolder::new(dsd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    assert!(delegate.is_delegated());
    assert_eq!(delegate.delegation_depth(), 1);

    let delegate_signing_key =
        EncodingKey::from_ed_pem(DELEGATE2_KEY_PEM.as_bytes()).unwrap();

    let nonce = "test-nonce".to_string();
    let aud = "verifier.example".to_string();

    let presentation = delegate
        .create_presentation(
            Map::new(),
            Some(nonce.clone()),
            Some(aud.clone()),
            Some(delegate_signing_key),
            Some("EdDSA".into()),
        )
        .unwrap();

    // Verifier walks the chain AND validates the final KB-JWT.
    let verifier = SDJWTVerifier::new(
        presentation,
        issuer_key_resolver(),
        Some(aud),
        Some(nonce),
        SDJWTSerializationFormat::Compact,
    )
    .expect("dSD-JWT+KB verification should succeed");

    assert_eq!(verifier.verified_delegate_payloads.len(), 1);
    assert_eq!(
        verifier.chain_cnfs.len(),
        1,
        "kb+sd-jwt+kb link must yield one cnf in chain_cnfs"
    );
    let claims = verifier.verified_claims.as_object().unwrap();
    assert_eq!(claims.get("scope"), Some(&Value::String("view-account".into())));
}

#[test]
fn two_hop_delegation_round_trips() {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "frank"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk);

    // Hop 1: Holder → Delegate Holder #1 (cnf = delegate2_jwk, typ kb+sd-jwt+kb).
    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let holder_signing_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();
    let delegate2_jwk: Jwk = serde_json::from_str(DELEGATE2_JWK).unwrap();

    let after_hop1 = holder
        .delegate(
            json!({"hop": 1, "scope": "intermediate"}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(Map::new()),
            None,
            holder_signing_key,
            Some(delegate2_jwk),
            ChainBindingMode::SdHash,
            None,
        )
        .unwrap();

    // Hop 2: Delegate Holder #1 → Delegate Holder #2 (terminal kb+sd-jwt).
    let mut delegate1 = SDJWTHolder::new(after_hop1, SDJWTSerializationFormat::Compact).unwrap();
    let delegate1_signing_key =
        EncodingKey::from_ed_pem(DELEGATE2_KEY_PEM.as_bytes()).unwrap();

    let after_hop2 = delegate1
        .delegate(
            json!({"hop": 2, "scope": "leaf"}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            None,
            delegate1_signing_key,
            None, // terminal
            ChainBindingMode::SdHash,
            Some("EdDSA".into()),
        )
        .unwrap();

    // Verifier walks the 2-link chain.
    let verifier = SDJWTVerifier::new(
        after_hop2,
        issuer_key_resolver(),
        None,
        None,
        SDJWTSerializationFormat::Compact,
    )
    .expect("two-hop chain verification should succeed");

    assert_eq!(verifier.verified_delegate_payloads.len(), 2);
    // Hop1 was kb+sd-jwt+kb → contributes one cnf. Hop2 is terminal kb+sd-jwt → none.
    assert_eq!(verifier.chain_cnfs.len(), 1);

    let claims = verifier.verified_claims.as_object().unwrap();
    // hop2 claims override hop1 because we layer in chain order.
    assert_eq!(claims.get("hop"), Some(&Value::from(2)));
    assert_eq!(claims.get("scope"), Some(&Value::String("leaf".into())));
}

#[test]
fn final_kb_jwt_signed_with_wrong_key_fails() {
    // Delegate Holder receives a dSD-JWT+KB but signs the final KB-JWT with the
    // wrong key (the Holder's key, instead of their own). Verifier must reject.
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "grace"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk);

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let holder_signing_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();
    let delegate2_jwk: Jwk = serde_json::from_str(DELEGATE2_JWK).unwrap();

    let dsd_jwt = holder
        .delegate(
            json!({"scope": "view"}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(Map::new()),
            None,
            holder_signing_key,
            Some(delegate2_jwk),
            ChainBindingMode::SdHash,
            None,
        )
        .unwrap();

    let mut delegate = SDJWTHolder::new(dsd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    // Wrong: sign the final KB-JWT with the Holder's (P-256) key instead of
    // the Delegate Holder's (Ed25519) key.
    let wrong_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();

    let presentation = delegate
        .create_presentation(
            Map::new(),
            Some("n".into()),
            Some("a".into()),
            Some(wrong_key),
            Some("ES256".into()),
        )
        .unwrap();

    let result = SDJWTVerifier::new(
        presentation,
        issuer_key_resolver(),
        Some("a".into()),
        Some("n".into()),
        SDJWTSerializationFormat::Compact,
    );
    assert!(
        result.is_err(),
        "verifier must reject a final KB-JWT signed with the wrong key"
    );
}

#[test]
fn redelegation_with_wrong_holder_key_fails() {
    // Delegate Holder #1 re-delegates but signs the new link with the ORIGINAL
    // holder's key (P-256) instead of their own (Ed25519). The chain walker
    // should reject the new link's signature.
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "hank"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk);

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let holder_signing_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();
    let delegate2_jwk: Jwk = serde_json::from_str(DELEGATE2_JWK).unwrap();

    let after_hop1 = holder
        .delegate(
            json!({"hop": 1}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(Map::new()),
            None,
            holder_signing_key,
            Some(delegate2_jwk),
            ChainBindingMode::SdHash,
            None,
        )
        .unwrap();

    let mut delegate1 = SDJWTHolder::new(after_hop1, SDJWTSerializationFormat::Compact).unwrap();
    // Wrong: re-sign with the Holder's P-256 key (the chain expects Ed25519 cnf).
    let wrong_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();
    let after_hop2 = delegate1
        .delegate(
            json!({"hop": 2}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            None,
            wrong_key,
            None,
            ChainBindingMode::SdHash,
            Some("ES256".into()),
        )
        .unwrap();

    let result = SDJWTVerifier::new(
        after_hop2,
        issuer_key_resolver(),
        None,
        None,
        SDJWTSerializationFormat::Compact,
    );
    assert!(
        result.is_err(),
        "verifier must reject a re-delegation signed with the wrong holder key"
    );
}

#[test]
fn tamper_kb_sd_jwt_link_fails_verification() {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "dave"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk);

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let holder_signing_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();

    let dsd_jwt = holder
        .delegate(
            json!({"scope": "purchase"}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(Map::new()),
            None,
            holder_signing_key,
            None,
            ChainBindingMode::SdHash,
            None,
        )
        .unwrap();

    // Flip a byte inside the KB-SD-JWT's signature (last segment of the link JWT).
    // Per spec, the layout is: <issuer-jwt> ~~ <KB-SD-JWT> ~ <D'> ~
    let parts: Vec<&str> = dsd_jwt.split('~').collect();
    let kb_sd_jwt_idx = parts
        .iter()
        .skip(1)
        .position(|t| !t.is_empty() && t.contains('.'))
        .expect("KB-SD-JWT not found in chain")
        + 1;
    let kb_sd_jwt = parts[kb_sd_jwt_idx];
    let kb_parts: Vec<&str> = kb_sd_jwt.split('.').collect();
    assert_eq!(kb_parts.len(), 3);
    let mut tampered_sig = String::from(kb_parts[2]);
    let last = tampered_sig.pop().unwrap();
    let replacement = if last == 'A' { 'B' } else { 'A' };
    tampered_sig.push(replacement);
    let tampered_kb_jwt = format!("{}.{}.{}", kb_parts[0], kb_parts[1], tampered_sig);

    let mut tampered_parts = parts.clone();
    tampered_parts[kb_sd_jwt_idx] = &tampered_kb_jwt;
    let tampered = tampered_parts.join("~");

    let result = SDJWTVerifier::new(
        tampered,
        issuer_key_resolver(),
        None,
        None,
        SDJWTSerializationFormat::Compact,
    );

    assert!(
        result.is_err(),
        "verifier must reject a tampered chain link signature"
    );
}

#[test]
fn redelegation_can_drop_issuer_disclosures_when_link1_used_issuer_jwt_hash() {
    // Hop 1 uses IssuerJwtHash binding → issuer disclosures are unconstrained, so
    // Delegate Holder #1 can drop any of them when re-delegating.
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "ivy",
        "address": { "country": "DE", "city": "Berlin" }
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims.clone(), holder_jwk);

    // Hop 1: Holder forwards ALL issuer disclosures, but link 1 commits via
    // IssuerJwtHash (so the disclosures are NOT cryptographically frozen).
    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let holder_signing_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();
    let delegate2_jwk: Jwk = serde_json::from_str(DELEGATE2_JWK).unwrap();
    let after_hop1 = holder
        .delegate(
            json!({"hop": 1}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            // Forward ALL claims so disclosures appear on the wire.
            Some(user_claims.as_object().unwrap().clone()),
            None,
            holder_signing_key,
            Some(delegate2_jwk),
            ChainBindingMode::IssuerJwtHash, // ← key choice
            None,
        )
        .unwrap();

    // Snapshot disclosures present at hop 1 — pick one to drop in hop 2.
    let disclosures_before: Vec<&str> = after_hop1
        .split('~')
        .filter(|t| !t.is_empty() && !t.contains('.'))
        .collect();
    assert!(disclosures_before.len() >= 2);
    let drop_target = disclosures_before[0].to_string();
    let mut drops: HashSet<String> = HashSet::new();
    drops.insert(drop_target.clone());

    // Hop 2: Delegate Holder #1 re-delegates and drops one issuer disclosure.
    let mut delegate1 = SDJWTHolder::new(after_hop1.clone(), SDJWTSerializationFormat::Compact).unwrap();
    let delegate1_signing_key = EncodingKey::from_ed_pem(DELEGATE2_KEY_PEM.as_bytes()).unwrap();
    let after_hop2 = delegate1
        .delegate(
            json!({"hop": 2}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            Some(drops),
            delegate1_signing_key,
            None,
            ChainBindingMode::SdHash,
            Some("EdDSA".into()),
        )
        .expect("drop permitted when prior link used IssuerJwtHash");

    // Sanity: the dropped disclosure must no longer be on the wire.
    assert!(
        !after_hop2.split('~').any(|t| t == drop_target),
        "dropped disclosure must not appear in the re-delegated chain"
    );

    // The chain must still verify cleanly.
    let verifier = SDJWTVerifier::new(
        after_hop2,
        issuer_key_resolver(),
        None,
        None,
        SDJWTSerializationFormat::Compact,
    )
    .expect("chain must verify after permitted drop");
    assert_eq!(verifier.verified_delegate_payloads.len(), 2);
}

#[test]
fn redelegation_cannot_drop_disclosures_frozen_by_sd_hash() {
    // Hop 1 uses SdHash binding → issuer disclosures are cryptographically frozen.
    // Attempting to drop one of them on re-delegation must error.
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "jane",
        "address": { "country": "DE" }
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims.clone(), holder_jwk);

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let holder_signing_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();
    let delegate2_jwk: Jwk = serde_json::from_str(DELEGATE2_JWK).unwrap();
    let after_hop1 = holder
        .delegate(
            json!({"hop": 1}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(user_claims.as_object().unwrap().clone()),
            None,
            holder_signing_key,
            Some(delegate2_jwk),
            ChainBindingMode::SdHash, // ← freezes issuer disclosures
            None,
        )
        .unwrap();

    let issuer_disc = after_hop1
        .split('~')
        .find(|t| !t.is_empty() && !t.contains('.'))
        .unwrap()
        .to_string();
    let mut drops: HashSet<String> = HashSet::new();
    drops.insert(issuer_disc);

    let mut delegate1 = SDJWTHolder::new(after_hop1, SDJWTSerializationFormat::Compact).unwrap();
    let delegate1_signing_key = EncodingKey::from_ed_pem(DELEGATE2_KEY_PEM.as_bytes()).unwrap();
    let result = delegate1.delegate(
        json!({"hop": 2}),
        ClaimsForSelectiveDisclosureStrategy::AllLevels,
        None,
        Some(drops),
        delegate1_signing_key,
        None,
        ChainBindingMode::SdHash,
        Some("EdDSA".into()),
    );

    assert!(
        result.is_err(),
        "must reject drop of issuer disclosure when link 1 used SdHash"
    );
}

#[test]
fn redelegation_can_always_drop_last_segment_disclosures() {
    // Hop 1 forwards an issuer disclosure AND link-1 produces its own disclosures.
    // Even with hop 1 using SdHash (freezing issuer disclosures), Delegate Holder #1
    // can still drop disclosures from link 1's own segment because the link
    // committing to them is the one being signed right now (hop 2).
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "kira"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk);

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let holder_signing_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();
    let delegate2_jwk: Jwk = serde_json::from_str(DELEGATE2_JWK).unwrap();
    // Hop 1 has its OWN selectively-disclosable claims, generating link-1 disclosures.
    let after_hop1 = holder
        .delegate(
            json!({"hop": 1, "extra": "secret-1", "other": "secret-2"}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(Map::new()), // no forwarded issuer disclosures
            None,
            holder_signing_key,
            Some(delegate2_jwk),
            ChainBindingMode::SdHash,
            None,
        )
        .unwrap();

    // The disclosures we see on the wire belong to link 1.
    let link1_disclosures: Vec<String> = after_hop1
        .split('~')
        .filter(|t| !t.is_empty() && !t.contains('.'))
        .map(String::from)
        .collect();
    assert!(link1_disclosures.len() >= 2);
    let mut drops: HashSet<String> = HashSet::new();
    drops.insert(link1_disclosures[0].clone());

    let mut delegate1 = SDJWTHolder::new(after_hop1, SDJWTSerializationFormat::Compact).unwrap();
    let delegate1_signing_key = EncodingKey::from_ed_pem(DELEGATE2_KEY_PEM.as_bytes()).unwrap();
    let after_hop2 = delegate1
        .delegate(
            json!({"hop": 2}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            Some(drops),
            delegate1_signing_key,
            None,
            ChainBindingMode::SdHash,
            Some("EdDSA".into()),
        )
        .expect("dropping the last existing link's disclosures is always permitted");

    // Verification must succeed — hop 2 re-hashed over the post-drop set.
    SDJWTVerifier::new(
        after_hop2,
        issuer_key_resolver(),
        None,
        None,
        SDJWTSerializationFormat::Compact,
    )
    .expect("chain must verify after dropping last-segment disclosures");
}

#[test]
fn redelegation_unknown_drop_target_errors() {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "leo"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk);

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let holder_signing_key = EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap();
    let delegate2_jwk: Jwk = serde_json::from_str(DELEGATE2_JWK).unwrap();
    let after_hop1 = holder
        .delegate(
            json!({"scope": "x"}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(Map::new()),
            None,
            holder_signing_key,
            Some(delegate2_jwk),
            ChainBindingMode::IssuerJwtHash,
            None,
        )
        .unwrap();

    let mut drops: HashSet<String> = HashSet::new();
    drops.insert("not-a-real-disclosure-string".to_string());

    let mut delegate1 = SDJWTHolder::new(after_hop1, SDJWTSerializationFormat::Compact).unwrap();
    let delegate1_signing_key = EncodingKey::from_ed_pem(DELEGATE2_KEY_PEM.as_bytes()).unwrap();
    let result = delegate1.delegate(
        json!({"hop": 2}),
        ClaimsForSelectiveDisclosureStrategy::AllLevels,
        None,
        Some(drops),
        delegate1_signing_key,
        None,
        ChainBindingMode::SdHash,
        Some("EdDSA".into()),
    );
    assert!(
        result.is_err(),
        "must reject a drop target that doesn't exist in the chain"
    );
}
