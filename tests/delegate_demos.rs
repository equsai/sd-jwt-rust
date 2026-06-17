// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! End-to-end Delegate SD-JWT tests: Issuer -> SDJWTHolder -> SDJWTVerifier.

mod utils;

use async_std_test::async_test;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{DecodingKey, EncodingKey};
use sd_jwt_rs::key::{SDJWTKey, SDJWTPubKey};
use sd_jwt_rs::resolver::KeyResolver;
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

fn issuer_key_resolver() -> Box<dyn KeyResolver> {
    Box::new(SDJWTPubKey::from(
        DecodingKey::from_ec_pem(ISSUER_PUBLIC_KEY.as_bytes()).expect("ec pub key"),
    ))
}

/// The original Holder's signer (P-256 / ES256), matching `HOLDER_JWK_KEY`.
fn holder_signer() -> SDJWTKey {
    SDJWTKey::new(EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap(), None)
}

/// Delegate Holder #1's signer (Ed25519 / EdDSA), matching `DELEGATE2_JWK`.
fn delegate2_signer() -> SDJWTKey {
    SDJWTKey::new(
        EncodingKey::from_ed_pem(DELEGATE2_KEY_PEM.as_bytes()).unwrap(),
        Some("EdDSA".into()),
    )
}

/// Build a `cnf` claim object (`{"jwk": <jwk>}`) from a JWK JSON string, for
/// embedding inside a Delegate Payload (required for kb+sd-jwt+kb links).
fn cnf_claim(jwk_json: &str) -> Value {
    json!({ "jwk": serde_json::from_str::<Value>(jwk_json).unwrap() })
}

async fn issue_holder_bound_sd_jwt(claims: Value, holder_jwk: Jwk) -> String {
    let issuer_key = EncodingKey::from_ec_pem(ISSUER_KEY.as_bytes()).unwrap();
    SDJWTIssuer::new(SDJWTKey::new(issuer_key, None))
        .issue_sd_jwt(
            claims,
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(holder_jwk),
            false,
            SDJWTSerializationFormat::Compact,
            None,
        )
        .await
        .unwrap()
}

#[async_test]
async fn single_delegation_no_final_kb_round_trips() -> std::io::Result<()> {
    let user_claims = json!({
        "sub": "alice",
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "address": { "country": "DE" }
    });

    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims.clone(), holder_jwk).await;

    // Holder loads the SD-JWT and delegates to a Delegate Holder.
    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();

    let delegate_payload = json!({
        "scope": "purchase",
        "merchant": "merchant.example",
        "limit": 100
    });

    // No cnf in the payload → terminal kb+sd-jwt link, no further delegation possible.
    let dsd_jwt = holder
        .delegate(
            vec![delegate_payload.clone()],
            Some(user_claims.as_object().unwrap().clone()),
            None,
            holder_signer(),
            ChainBindingMode::SdHash,
        )
        .await
        .unwrap();

    // Verifier walks the chain.
    let mut verifier = SDJWTVerifier::new(issuer_key_resolver());
    let verified_claims = verifier
        .verify_presentation(dsd_jwt, None, None, SDJWTSerializationFormat::Compact)
        .await
        .expect("chain verification should succeed");

    // One Delegate Payload entry, no `+kb` ⇒ no cnf in chain_cnfs.
    assert_eq!(verifier.verified_delegate_payloads.len(), 1);
    assert!(verifier.chain_cnfs.is_empty());

    // Delegate Payload claims must be visible in claims (layered on top of issuer).
    let claims = verified_claims.as_object().expect("object");
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
    Ok(())
}

#[async_test]
async fn delegate_payload_appears_in_delegate_payloads() -> std::io::Result<()> {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "carol",
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims.clone(), holder_jwk).await;

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();

    let dsd_jwt = holder
        .delegate(
            vec![json!({"scope": "read-only"})],
            Some(Map::new()), // forward no original disclosures
            None,
            holder_signer(),
            ChainBindingMode::SdHash,
        )
        .await
        .unwrap();

    let mut verifier = SDJWTVerifier::new(issuer_key_resolver());
    verifier
        .verify_presentation(dsd_jwt, None, None, SDJWTSerializationFormat::Compact)
        .await
        .unwrap();

    let dp = &verifier.verified_delegate_payloads[0];
    assert_eq!(dp.get("scope"), Some(&Value::String("read-only".into())));
    Ok(())
}

#[async_test]
async fn issuer_jwt_hash_binding_mode_works() -> std::io::Result<()> {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "bob",
        "secret": "do-not-forward",
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk).await;

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();

    // IssuerJwtHash mode: Delegate Holder can drop the original disclosures from the wire.
    let dsd_jwt = holder
        .delegate(
            vec![json!({"purpose": "audit"})],
            None, // skip forwarding entirely
            None,
            holder_signer(),
            ChainBindingMode::IssuerJwtHash,
        )
        .await
        .unwrap();

    // The resulting compact form should contain no issuer disclosures between the
    // issuer JWT and the KB-SD-JWT. Per spec, the chain link is preceded by an
    // empty component (`~~`), so the layout is:
    //   <issuer-jwt> ~~ <KB-SD-JWT> ~ <D'1>...<D'N> ~
    let parts: Vec<&str> = dsd_jwt.split('~').collect();
    assert!(parts[1].is_empty(), "expected mandatory empty component after issuer JWT");
    assert!(parts[2].contains('.'), "expected KB-SD-JWT at position 2 (after ~~)");

    let mut verifier = SDJWTVerifier::new(issuer_key_resolver());
    let verified_claims = verifier
        .verify_presentation(dsd_jwt, None, None, SDJWTSerializationFormat::Compact)
        .await
        .expect("chain verification with issuer_jwt_hash binding should succeed");

    assert_eq!(verifier.verified_delegate_payloads.len(), 1);
    let claims = verified_claims.as_object().unwrap();
    assert_eq!(claims.get("purpose"), Some(&Value::String("audit".into())));
    Ok(())
}

#[async_test]
async fn dsd_jwt_with_kb_proof_of_possession_round_trips() -> std::io::Result<()> {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "eve"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk).await;

    // Holder delegates to a Delegate Holder, embedding the Delegate Holder's cnf so
    // they can sign a final KB-JWT.
    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();

    // cnf inside the Delegate Payload → kb+sd-jwt+kb, enabling the final KB-JWT.
    let dsd_jwt = holder
        .delegate(
            vec![json!({
                "scope": "view-account",
                "exp": 1893456000_i64,
                "cnf": cnf_claim(DELEGATE2_JWK),
            })],
            Some(Map::new()),
            None,
            holder_signer(),
            ChainBindingMode::SdHash,
        )
        .await
        .unwrap();

    // Delegate Holder loads the dSD-JWT and creates a presentation with a final KB-JWT.
    let mut delegate = SDJWTHolder::new(dsd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    assert!(delegate.is_delegated());
    assert_eq!(delegate.delegation_depth(), 1);

    let nonce = "test-nonce".to_string();
    let aud = "verifier.example".to_string();

    let presentation = delegate
        .create_presentation(
            Map::new(),
            Some(nonce.clone()),
            Some(aud.clone()),
            Some(delegate2_signer()),
        )
        .await
        .unwrap();

    // Verifier walks the chain AND validates the final KB-JWT.
    let mut verifier = SDJWTVerifier::new(issuer_key_resolver());
    let verified_claims = verifier
        .verify_presentation(presentation, Some(aud), Some(nonce), SDJWTSerializationFormat::Compact)
        .await
        .expect("dSD-JWT+KB verification should succeed");

    assert_eq!(verifier.verified_delegate_payloads.len(), 1);
    assert_eq!(
        verifier.chain_cnfs.len(),
        1,
        "kb+sd-jwt+kb link must yield one cnf in chain_cnfs"
    );
    let claims = verified_claims.as_object().unwrap();
    assert_eq!(claims.get("scope"), Some(&Value::String("view-account".into())));
    Ok(())
}

#[async_test]
async fn two_hop_delegation_round_trips() -> std::io::Result<()> {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "frank"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk).await;

    // Hop 1: Holder → Delegate Holder #1 (cnf = delegate2_jwk, typ kb+sd-jwt+kb).
    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();

    let after_hop1 = holder
        .delegate(
            vec![json!({"hop": 1, "scope": "intermediate", "cnf": cnf_claim(DELEGATE2_JWK)})],
            Some(Map::new()),
            None,
            holder_signer(),
            ChainBindingMode::SdHash,
        )
        .await
        .unwrap();

    // Hop 2: Delegate Holder #1 → Delegate Holder #2 (terminal kb+sd-jwt).
    let mut delegate1 = SDJWTHolder::new(after_hop1, SDJWTSerializationFormat::Compact).unwrap();

    let after_hop2 = delegate1
        .delegate(
            vec![json!({"hop": 2, "scope": "leaf"})],
            None,
            None,
            delegate2_signer(),
            ChainBindingMode::SdHash,
        )
        .await
        .unwrap();

    // Verifier walks the 2-link chain.
    let mut verifier = SDJWTVerifier::new(issuer_key_resolver());
    let verified_claims = verifier
        .verify_presentation(after_hop2, None, None, SDJWTSerializationFormat::Compact)
        .await
        .expect("two-hop chain verification should succeed");

    assert_eq!(verifier.verified_delegate_payloads.len(), 2);
    // Hop1 was kb+sd-jwt+kb → contributes one cnf. Hop2 is terminal kb+sd-jwt → none.
    assert_eq!(verifier.chain_cnfs.len(), 1);

    let claims = verified_claims.as_object().unwrap();
    // hop2 claims override hop1 because we layer in chain order.
    assert_eq!(claims.get("hop"), Some(&Value::from(2)));
    assert_eq!(claims.get("scope"), Some(&Value::String("leaf".into())));
    Ok(())
}

#[async_test]
async fn final_kb_jwt_signed_with_wrong_key_fails() -> std::io::Result<()> {
    // Delegate Holder receives a dSD-JWT+KB but signs the final KB-JWT with the
    // wrong key (the Holder's key, instead of their own). Verifier must reject.
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "grace"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk).await;

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();

    let dsd_jwt = holder
        .delegate(
            vec![json!({"scope": "view", "cnf": cnf_claim(DELEGATE2_JWK)})],
            Some(Map::new()),
            None,
            holder_signer(),
            ChainBindingMode::SdHash,
        )
        .await
        .unwrap();

    let mut delegate = SDJWTHolder::new(dsd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    // Wrong: sign the final KB-JWT with the Holder's (P-256) key instead of
    // the Delegate Holder's (Ed25519) key.
    let wrong_signer = SDJWTKey::new(
        EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap(),
        Some("ES256".into()),
    );

    let presentation = delegate
        .create_presentation(
            Map::new(),
            Some("n".into()),
            Some("a".into()),
            Some(wrong_signer),
        )
        .await
        .unwrap();

    let result = SDJWTVerifier::new(issuer_key_resolver())
        .verify_presentation(
            presentation,
            Some("a".into()),
            Some("n".into()),
            SDJWTSerializationFormat::Compact,
        )
        .await;
    assert!(
        result.is_err(),
        "verifier must reject a final KB-JWT signed with the wrong key"
    );
    Ok(())
}

#[async_test]
async fn redelegation_with_wrong_holder_key_fails() -> std::io::Result<()> {
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
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk).await;

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();

    let after_hop1 = holder
        .delegate(
            vec![json!({"hop": 1, "cnf": cnf_claim(DELEGATE2_JWK)})],
            Some(Map::new()),
            None,
            holder_signer(),
            ChainBindingMode::SdHash,
        )
        .await
        .unwrap();

    let mut delegate1 = SDJWTHolder::new(after_hop1, SDJWTSerializationFormat::Compact).unwrap();
    // Wrong: re-sign with the Holder's P-256 key (the chain expects Ed25519 cnf).
    let wrong_signer = SDJWTKey::new(
        EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap(),
        Some("ES256".into()),
    );
    let after_hop2 = delegate1
        .delegate(
            vec![json!({"hop": 2})],
            None,
            None,
            wrong_signer,
            ChainBindingMode::SdHash,
        )
        .await
        .unwrap();

    let result = SDJWTVerifier::new(issuer_key_resolver())
        .verify_presentation(after_hop2, None, None, SDJWTSerializationFormat::Compact)
        .await;
    assert!(
        result.is_err(),
        "verifier must reject a re-delegation signed with the wrong holder key"
    );
    Ok(())
}

#[async_test]
async fn tamper_kb_sd_jwt_link_fails_verification() -> std::io::Result<()> {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "dave"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk).await;

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();

    let dsd_jwt = holder
        .delegate(
            vec![json!({"scope": "purchase"})],
            Some(Map::new()),
            None,
            holder_signer(),
            ChainBindingMode::SdHash,
        )
        .await
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

    let result = SDJWTVerifier::new(issuer_key_resolver())
        .verify_presentation(tampered, None, None, SDJWTSerializationFormat::Compact)
        .await;

    assert!(
        result.is_err(),
        "verifier must reject a tampered chain link signature"
    );
    Ok(())
}

#[async_test]
async fn redelegation_can_drop_issuer_disclosures_when_link1_used_issuer_jwt_hash(
) -> std::io::Result<()> {
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
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims.clone(), holder_jwk).await;

    // Hop 1: Holder forwards ALL issuer disclosures, but link 1 commits via
    // IssuerJwtHash (so the disclosures are NOT cryptographically frozen).
    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let after_hop1 = holder
        .delegate(
            vec![json!({"hop": 1, "cnf": cnf_claim(DELEGATE2_JWK)})],
            // Forward ALL claims so disclosures appear on the wire.
            Some(user_claims.as_object().unwrap().clone()),
            None,
            holder_signer(),
            ChainBindingMode::IssuerJwtHash, // ← key choice
        )
        .await
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
    let after_hop2 = delegate1
        .delegate(
            vec![json!({"hop": 2})],
            None,
            Some(drops),
            delegate2_signer(),
            ChainBindingMode::SdHash,
        )
        .await
        .expect("drop permitted when prior link used IssuerJwtHash");

    // Sanity: the dropped disclosure must no longer be on the wire.
    assert!(
        !after_hop2.split('~').any(|t| t == drop_target),
        "dropped disclosure must not appear in the re-delegated chain"
    );

    // The chain must still verify cleanly.
    let mut verifier = SDJWTVerifier::new(issuer_key_resolver());
    verifier
        .verify_presentation(after_hop2, None, None, SDJWTSerializationFormat::Compact)
        .await
        .expect("chain must verify after permitted drop");
    assert_eq!(verifier.verified_delegate_payloads.len(), 2);
    Ok(())
}

#[async_test]
async fn redelegation_cannot_drop_disclosures_frozen_by_sd_hash() -> std::io::Result<()> {
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
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims.clone(), holder_jwk).await;

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let after_hop1 = holder
        .delegate(
            vec![json!({"hop": 1, "cnf": cnf_claim(DELEGATE2_JWK)})],
            Some(user_claims.as_object().unwrap().clone()),
            None,
            holder_signer(),
            ChainBindingMode::SdHash, // ← freezes issuer disclosures
        )
        .await
        .unwrap();

    let issuer_disc = after_hop1
        .split('~')
        .find(|t| !t.is_empty() && !t.contains('.'))
        .unwrap()
        .to_string();
    let mut drops: HashSet<String> = HashSet::new();
    drops.insert(issuer_disc);

    let mut delegate1 = SDJWTHolder::new(after_hop1, SDJWTSerializationFormat::Compact).unwrap();
    let result = delegate1
        .delegate(
            vec![json!({"hop": 2})],
            None,
            Some(drops),
            delegate2_signer(),
            ChainBindingMode::SdHash,
        )
        .await;

    assert!(
        result.is_err(),
        "must reject drop of issuer disclosure when link 1 used SdHash"
    );
    Ok(())
}

#[async_test]
async fn redelegation_narrows_multi_alternative_predecessor_link() -> std::io::Result<()> {
    // Hop 1 bundles TWO delegate_payload alternatives (each carrying its own cnf),
    // which become array-element disclosures in link 1's segment. When Delegate
    // Holder #1 re-delegates, it must narrow link 1 down to a single disclosed
    // alternative — always permitted because hop 2 is the link committing to
    // link 1's disclosures right now.
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "kira"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk).await;

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    // Two alternatives → both are array-element disclosures of link 1.
    let after_hop1 = holder
        .delegate(
            vec![
                json!({"hop": 1, "scope": "a", "cnf": cnf_claim(DELEGATE2_JWK)}),
                json!({"hop": 1, "scope": "b", "cnf": cnf_claim(DELEGATE2_JWK)}),
            ],
            Some(Map::new()), // no forwarded issuer disclosures
            None,
            holder_signer(),
            ChainBindingMode::SdHash,
        )
        .await
        .unwrap();

    // The disclosures on the wire are link 1's two alternatives.
    let alternatives: Vec<String> = after_hop1
        .split('~')
        .filter(|t| !t.is_empty() && !t.contains('.'))
        .map(String::from)
        .collect();
    assert_eq!(alternatives.len(), 2, "expected two alternative disclosures");
    // Drop one alternative, leaving exactly one disclosed.
    let mut drops: HashSet<String> = HashSet::new();
    drops.insert(alternatives[0].clone());

    let mut delegate1 = SDJWTHolder::new(after_hop1, SDJWTSerializationFormat::Compact).unwrap();
    let after_hop2 = delegate1
        .delegate(
            vec![json!({"hop": 2})],
            None,
            Some(drops),
            delegate2_signer(),
            ChainBindingMode::SdHash,
        )
        .await
        .expect("narrowing the last existing link's alternatives is always permitted");

    // Verification must succeed — link 1 now discloses exactly one alternative,
    // and hop 2 re-hashed over the post-drop set.
    let mut verifier = SDJWTVerifier::new(issuer_key_resolver());
    verifier
        .verify_presentation(after_hop2, None, None, SDJWTSerializationFormat::Compact)
        .await
        .expect("chain must verify after narrowing to one alternative");
    assert_eq!(verifier.verified_delegate_payloads.len(), 2);
    Ok(())
}

#[async_test]
async fn redelegation_unknown_drop_target_errors() -> std::io::Result<()> {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "leo"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk).await;

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let after_hop1 = holder
        .delegate(
            vec![json!({"scope": "x", "cnf": cnf_claim(DELEGATE2_JWK)})],
            Some(Map::new()),
            None,
            holder_signer(),
            ChainBindingMode::IssuerJwtHash,
        )
        .await
        .unwrap();

    let mut drops: HashSet<String> = HashSet::new();
    drops.insert("not-a-real-disclosure-string".to_string());

    let mut delegate1 = SDJWTHolder::new(after_hop1, SDJWTSerializationFormat::Compact).unwrap();
    let result = delegate1
        .delegate(
            vec![json!({"hop": 2})],
            None,
            Some(drops),
            delegate2_signer(),
            ChainBindingMode::SdHash,
        )
        .await;
    assert!(
        result.is_err(),
        "must reject a drop target that doesn't exist in the chain"
    );
    Ok(())
}

#[async_test]
async fn multi_alternative_select_and_present_round_trips() -> std::io::Result<()> {
    // A Holder signs TWO delegate_payload alternatives at once. The Delegate
    // Holder selects one and presents it; the Verifier sees exactly that one.
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "mona"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk).await;

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();

    // Two terminal alternatives (no cnf) → kb+sd-jwt link, both as disclosures.
    let dsd_jwt = holder
        .delegate(
            vec![
                json!({"scope": "verifier-a"}),
                json!({"scope": "verifier-b"}),
            ],
            Some(Map::new()),
            None,
            holder_signer(),
            ChainBindingMode::SdHash,
        )
        .await
        .unwrap();

    // Selecting alternative #1 and presenting reveals only "verifier-b".
    let mut delegate = SDJWTHolder::new(dsd_jwt.clone(), SDJWTSerializationFormat::Compact).unwrap();
    delegate.select_delegate_alternative(1);
    let presentation = delegate
        .create_presentation::<SDJWTKey>(Map::new(), None, None, None)
        .await
        .unwrap();

    let mut verifier = SDJWTVerifier::new(issuer_key_resolver());
    let verified_claims = verifier
        .verify_presentation(presentation, None, None, SDJWTSerializationFormat::Compact)
        .await
        .expect("presentation with one selected alternative must verify");
    assert_eq!(verifier.verified_delegate_payloads.len(), 1);
    assert_eq!(
        verified_claims.as_object().unwrap().get("scope"),
        Some(&Value::String("verifier-b".into()))
    );

    // Presenting without selecting an alternative must error.
    let mut delegate2 = SDJWTHolder::new(dsd_jwt.clone(), SDJWTSerializationFormat::Compact).unwrap();
    assert!(
        delegate2
            .create_presentation::<SDJWTKey>(Map::new(), None, None, None)
            .await
            .is_err(),
        "must require selecting one of multiple alternatives before presenting"
    );

    // And the freshly-delegated token (both alternatives disclosed) must fail the
    // verifier's "exactly one disclosed" rule.
    assert!(
        SDJWTVerifier::new(issuer_key_resolver())
            .verify_presentation(dsd_jwt, None, None, SDJWTSerializationFormat::Compact)
            .await
            .is_err(),
        "a multi-alternative token with more than one disclosed must be rejected"
    );
    Ok(())
}

// `exp` far in the past (2001-09-09). `nbf` far in the future (2100-01-01).
const PAST_EXP: i64 = 1_000_000_000;
const FUTURE_NBF: i64 = 4_102_444_800;

async fn delegate_with_lifetime(extra: Value) -> String {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000, // issuer credential itself is still valid
        "sub": "tina"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk).await;

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();

    let mut payload = json!({ "scope": "x" });
    payload
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());

    holder
        .delegate(
            vec![payload],
            Some(Map::new()),
            None,
            holder_signer(),
            ChainBindingMode::SdHash,
        )
        .await
        .unwrap()
}

#[async_test]
async fn expired_delegate_payload_is_rejected() -> std::io::Result<()> {
    let dsd_jwt = delegate_with_lifetime(json!({ "exp": PAST_EXP })).await;
    let result = SDJWTVerifier::new(issuer_key_resolver())
        .verify_presentation(dsd_jwt, None, None, SDJWTSerializationFormat::Compact)
        .await;
    assert!(
        result.is_err(),
        "verifier must reject a dSD-JWT whose Delegate Payload has expired"
    );
    Ok(())
}

#[async_test]
async fn not_yet_valid_delegate_payload_is_rejected() -> std::io::Result<()> {
    let dsd_jwt = delegate_with_lifetime(json!({ "nbf": FUTURE_NBF })).await;
    let result = SDJWTVerifier::new(issuer_key_resolver())
        .verify_presentation(dsd_jwt, None, None, SDJWTSerializationFormat::Compact)
        .await;
    assert!(
        result.is_err(),
        "verifier must reject a dSD-JWT whose Delegate Payload is not yet valid (nbf in the future)"
    );
    Ok(())
}

#[async_test]
async fn valid_delegate_payload_lifetime_round_trips() -> std::io::Result<()> {
    // `exp` in the future, `nbf` in the past → currently valid.
    let dsd_jwt = delegate_with_lifetime(json!({ "exp": 1883000000, "nbf": 1683000000 })).await;
    let mut verifier = SDJWTVerifier::new(issuer_key_resolver());
    let verified_claims = verifier
        .verify_presentation(dsd_jwt, None, None, SDJWTSerializationFormat::Compact)
        .await
        .expect("a dSD-JWT whose Delegate Payload is within its validity window must verify");
    assert_eq!(verifier.verified_delegate_payloads.len(), 1);
    assert_eq!(
        verified_claims.as_object().unwrap().get("scope"),
        Some(&Value::String("x".into()))
    );
    Ok(())
}

/// Build a dSD-JWT delegated to a Verifier, with `aud`/`nonce` bound inside the
/// final KB-SD-JWT link's Delegate Payload (and no trailing KB-JWT). `with_cnf`
/// selects a `kb+sd-jwt+kb` link (carries a cnf) vs a terminal `kb+sd-jwt`.
async fn delegate_to_verifier(aud: &str, nonce: &str, with_cnf: bool) -> String {
    let user_claims = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "nina"
    });
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issue_holder_bound_sd_jwt(user_claims, holder_jwk).await;

    let mut payload = json!({ "scope": "x", "aud": aud, "nonce": nonce });
    if with_cnf {
        payload
            .as_object_mut()
            .unwrap()
            .insert("cnf".to_string(), cnf_claim(DELEGATE2_JWK));
    }

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let dsd_jwt = holder
        .delegate(
            vec![payload],
            Some(Map::new()),
            None,
            holder_signer(),
            ChainBindingMode::SdHash,
        )
        .await
        .unwrap();

    // Present as-is (no trailing KB-JWT): the credential is delegated to the Verifier.
    let mut delegate = SDJWTHolder::new(dsd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    delegate
        .create_presentation::<SDJWTKey>(Map::new(), None, None, None)
        .await
        .unwrap()
}

#[async_test]
async fn aud_nonce_in_final_kb_sd_jwt_payload_round_trips() -> std::io::Result<()> {
    let aud = "verifier.example".to_string();
    let nonce = "nonce-xyz".to_string();
    // Terminal kb+sd-jwt: the chain has no trailing KB-JWT, so the Verifier must
    // read aud/nonce from the final Delegate Payload.
    let presentation = delegate_to_verifier(&aud, &nonce, false).await;

    let mut verifier = SDJWTVerifier::new(issuer_key_resolver());
    let verified_claims = verifier
        .verify_presentation(
            presentation,
            Some(aud.clone()),
            Some(nonce.clone()),
            SDJWTSerializationFormat::Compact,
        )
        .await
        .expect("aud/nonce bound in the final KB-SD-JWT Delegate Payload must verify");

    assert_eq!(verifier.verified_delegate_payloads.len(), 1);
    assert_eq!(
        verified_claims.as_object().unwrap().get("scope"),
        Some(&Value::String("x".into()))
    );
    Ok(())
}

#[async_test]
async fn aud_nonce_in_final_kb_sd_jwt_kb_payload_round_trips() -> std::io::Result<()> {
    // Same, but the final link is kb+sd-jwt+kb (carries a cnf). Still presented
    // without a trailing KB-JWT, so aud/nonce come from the Delegate Payload.
    let aud = "verifier.example".to_string();
    let nonce = "nonce-xyz".to_string();
    let presentation = delegate_to_verifier(&aud, &nonce, true).await;

    let mut verifier = SDJWTVerifier::new(issuer_key_resolver());
    verifier
        .verify_presentation(
            presentation,
            Some(aud),
            Some(nonce),
            SDJWTSerializationFormat::Compact,
        )
        .await
        .expect("aud/nonce in a kb+sd-jwt+kb Delegate Payload must verify without a trailing KB-JWT");
    Ok(())
}

#[async_test]
async fn wrong_aud_in_final_kb_sd_jwt_payload_is_rejected() -> std::io::Result<()> {
    let presentation = delegate_to_verifier("verifier.example", "nonce-xyz", false).await;
    let result = SDJWTVerifier::new(issuer_key_resolver())
        .verify_presentation(
            presentation,
            Some("attacker.example".into()), // wrong audience
            Some("nonce-xyz".into()),
            SDJWTSerializationFormat::Compact,
        )
        .await;
    assert!(
        result.is_err(),
        "verifier must reject a dSD-JWT whose Delegate Payload binds a different aud"
    );
    Ok(())
}

#[async_test]
async fn wrong_nonce_in_final_kb_sd_jwt_payload_is_rejected() -> std::io::Result<()> {
    let presentation = delegate_to_verifier("verifier.example", "nonce-xyz", false).await;
    let result = SDJWTVerifier::new(issuer_key_resolver())
        .verify_presentation(
            presentation,
            Some("verifier.example".into()),
            Some("stale-nonce".into()), // wrong nonce
            SDJWTSerializationFormat::Compact,
        )
        .await;
    assert!(
        result.is_err(),
        "verifier must reject a dSD-JWT whose Delegate Payload binds a different nonce"
    );
    Ok(())
}
