// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::{error, SDJWTJson, SDJWTSerializationFormat};
use error::{Error, Result};
use jsonwebtoken::{Algorithm, Header};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::ops::Add;
use std::str::FromStr;
use std::time;
use crate::utils::{base64_hash, encode};
use crate::SDJWTCommon;
use crate::{
    COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
    KB_DIGEST_KEY,
    SD_DIGESTS_KEY,
    SD_LIST_PREFIX,
};
use crate::signer::SDJWTSigner;

pub struct SDJWTHolder {
    sd_jwt_engine: SDJWTCommon,
    hs_disclosures: Vec<String>,
    key_binding_jwt_header: HashMap<String, Value>,
    key_binding_jwt_payload: HashMap<String, Value>,
    serialized_key_binding_jwt: String,
    sd_jwt_payload: Map<String, Value>,
    serialized_sd_jwt: String,
    sd_jwt_json: Option<SDJWTJson>,
}

impl SDJWTHolder {
    /// Build an instance of holder to create one or more presentations based on SD JWT provided by issuer.
    ///
    /// # Arguments
    /// * `sd_jwt_with_disclosures` - SD JWT with disclosures in the format specified by `serialization_format`
    /// * `serialization_format` - Serialization format of the SD JWT, see [SDJWTSerializationFormat].
    ///
    /// # Returns
    /// * `SDJWTHolder` - Instance of SDJWTHolder
    ///
    /// # Errors
    /// * `InvalidInput` - If the serialization format is not supported
    /// * `InvalidState` - If the SD JWT data is not valid
    /// * `DeserializationError` - If the SD JWT serialization is not valid
    pub fn new(sd_jwt_with_disclosures: String, serialization_format: SDJWTSerializationFormat) -> Result<Self> {
        let mut holder = SDJWTHolder {
            sd_jwt_engine: SDJWTCommon {
                serialization_format,
                ..Default::default()
            },
            hs_disclosures: Vec::new(),
            key_binding_jwt_header: HashMap::new(),
            key_binding_jwt_payload: HashMap::new(),
            serialized_key_binding_jwt: "".to_string(),
            sd_jwt_payload: Map::new(),
            serialized_sd_jwt: "".to_string(),
            sd_jwt_json: None,
        };

        holder
            .sd_jwt_engine
            .parse_sd_jwt(sd_jwt_with_disclosures.clone())?;

        //TODO Verify signature before accepting the JWT
        holder.sd_jwt_payload = holder
            .sd_jwt_engine
            .unverified_input_sd_jwt_payload
            .take()
            .ok_or(Error::InvalidState("Cannot take payload".to_string()))?;
        holder.serialized_sd_jwt = holder
            .sd_jwt_engine
            .unverified_sd_jwt
            .take()
            .ok_or(Error::InvalidState("Cannot take jwt".to_string()))?;
        holder.sd_jwt_json = holder.sd_jwt_engine.unverified_sd_jwt_json.clone();

        holder.sd_jwt_engine.create_hash_mappings()?;

        Ok(holder)
    }

    /// Create a presentation based on the SD JWT provided by issuer.
    ///
    /// # Arguments
    /// * `claims_to_disclose` - Claims to disclose in the presentation
    /// * `nonce` - Nonce to be used in the key-binding JWT
    /// * `aud` - Audience to be used in the key-binding JWT
    /// * `signer` - Signer used to sign the key-binding JWT
    ///
    /// # Returns
    /// * `String` - Presentation in the format specified by `serialization_format` in the constructor. It can be either compact or json.
    pub async fn create_presentation<S: SDJWTSigner>(
        &mut self,
        claims_to_disclose: Map<String, Value>,
        nonce: Option<String>,
        aud: Option<String>,
        signer: Option<S>,
    ) -> Result<String> {
        self.key_binding_jwt_header = Default::default();
        self.key_binding_jwt_payload = Default::default();
        self.serialized_key_binding_jwt = Default::default();
        self.hs_disclosures = self.select_disclosures(&self.sd_jwt_payload, claims_to_disclose)?;

        match (nonce, aud, signer) {
            (Some(nonce), Some(aud), Some(signer)) => {
                self.create_key_binding_jwt(nonce, aud, signer).await?
            }
            (None, None, None) => {}
            _ => {
                return Err(Error::InvalidInput(
                    "Inconsistency in parameters to determine JWT KB by holder".to_string(),
                ));
            }
        }

        let sd_jwt_presentation = if self.sd_jwt_engine.serialization_format == SDJWTSerializationFormat::Compact {
            let mut combined: Vec<&str> = Vec::with_capacity(self.hs_disclosures.len() + 2);
            combined.push(&self.serialized_sd_jwt);
            combined.extend(self.hs_disclosures.iter().map(|s| s.as_str()));
            combined.push(&self.serialized_key_binding_jwt);
            let joined = combined.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
            joined.to_string()
        } else {
            let mut sd_jwt_json = self
                .sd_jwt_json
                .take()
                .ok_or(Error::InvalidState("Cannot take SDJWTJson".to_string()))?;
            sd_jwt_json.disclosures = self.hs_disclosures.clone();
            if !self.serialized_key_binding_jwt.is_empty() {
                sd_jwt_json.kb_jwt = Some(self.serialized_key_binding_jwt.clone());
            }
            serde_json::to_string(&sd_jwt_json)
                .map_err(|e| Error::DeserializationError(e.to_string()))?
        };

        Ok(sd_jwt_presentation)
    }

    fn select_disclosures(
        &self,
        sd_jwt_claims: &Map<String, Value>,
        claims_to_disclose: Map<String, Value>,
    ) -> Result<Vec<String>> {
        let mut hash_to_disclosure = Vec::new();
        let default_list = Vec::new();
        let sd_map: HashMap<&str, (&Value, &str)> = sd_jwt_claims
            .get(SD_DIGESTS_KEY)
            .and_then(Value::as_array)
            .unwrap_or(&default_list)
            .iter()
            .filter_map(|digest| {
                let digest = match digest.as_str() {
                    Some(digest) => digest,
                    None => return None,
                };
                if let Some(Value::Array(disclosure)) =
                    self.sd_jwt_engine.hash_to_decoded_disclosure.get(digest)
                {
                    let key = match disclosure[1].as_str() {
                        Some(digest) => digest,
                        None => return None,
                    };
                    return Some((key, (&disclosure[2], digest)));
                }
                None
            })
            .collect(); //TODO split to 2 maps
        for (key_to_disclose, value_to_disclose) in claims_to_disclose {
            match value_to_disclose {
                Value::String(optional) if optional.as_str() == "optional"
                    && !sd_map.contains_key(key_to_disclose.as_str()) => continue,
                Value::Bool(true) | Value::Number(_) | Value::String(_) => {
                    /* disclose without children */
                }
                Value::Array(claims_to_disclose) => {
                    if let Some(sd_jwt_claims) = sd_jwt_claims
                        .get(&key_to_disclose)
                        .and_then(Value::as_array)
                    {
                        hash_to_disclosure.append(
                            &mut self.select_disclosures_from_disclosed_list(
                                sd_jwt_claims,
                                &claims_to_disclose,
                            )?,
                        )
                    } else if let Some(sd_jwt_claims) = sd_map
                        .get(key_to_disclose.as_str())
                        .and_then(|(sd, _)| sd.as_array())
                    {
                        hash_to_disclosure.append(
                            &mut self.select_disclosures_from_disclosed_list(
                                sd_jwt_claims,
                                &claims_to_disclose,
                            )?,
                        )
                    }
                }
                Value::Object(claims_to_disclose) if (!claims_to_disclose.is_empty()) => {
                    let sd_jwt_claims = if let Some(next) = sd_jwt_claims
                        .get(&key_to_disclose)
                        .and_then(Value::as_object)
                    {
                        next
                    } else {
                        sd_map.get(key_to_disclose.as_str())
                            .ok_or(Error::KeyNotFound(format!("Disclosure with key = '{}' is not found", key_to_disclose.to_string())))?
                            .0
                            .as_object()
                            .ok_or(Error::ConversionError("json object".to_string()))?
                    };
                    hash_to_disclosure
                        .append(&mut self.select_disclosures(sd_jwt_claims, claims_to_disclose)?);
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
                hash_to_disclosure.push(self.sd_jwt_engine.hash_to_disclosure[*digest].to_owned());
            } else {
                return Err(Error::InvalidState(
                    format!("Requested claim '{key_to_disclose}' doesn't exist"),
                ));
            }
        }

        Ok(hash_to_disclosure)
    }

    fn select_disclosures_from_disclosed_list(
        &self,
        sd_jwt_claims: &[Value],
        claims_to_disclose: &[Value],
    ) -> Result<Vec<String>> {
        let mut hash_to_disclosure: Vec<String> = Vec::new();
        for (claim_to_disclose, sd_jwt_claims) in claims_to_disclose.iter().zip(sd_jwt_claims) {
            match (claim_to_disclose, sd_jwt_claims) {
                (Value::Bool(true), Value::Object(sd_jwt_claims)) => {
                    if let Some(Value::String(digest)) = sd_jwt_claims.get(SD_LIST_PREFIX) {
                        hash_to_disclosure
                            .push(self.sd_jwt_engine.hash_to_disclosure[digest].to_owned());
                    }
                }
                (claim_to_disclose, Value::Object(sd_jwt_claims)) => {
                    if let Some(Value::String(digest)) = sd_jwt_claims.get(SD_LIST_PREFIX) {
                        let disclosure = self.sd_jwt_engine.hash_to_decoded_disclosure[digest]
                            .as_array()
                            .ok_or(Error::ConversionError("json array".to_string()))?;
                        match (claim_to_disclose, disclosure.get(1)) {
                            (
                                Value::Array(claim_to_disclose),
                                Some(Value::Array(sd_jwt_claims)),
                            ) => {
                                hash_to_disclosure.push(
                                    self.sd_jwt_engine.hash_to_disclosure[digest].clone()
                                );
                                hash_to_disclosure.append(
                                    &mut self.select_disclosures_from_disclosed_list(
                                        sd_jwt_claims,
                                        claim_to_disclose,
                                    )?,
                                );
                            }
                            (
                                Value::Object(claim_to_disclose),
                                Some(Value::Object(sd_jwt_claims)),
                            ) => {
                                hash_to_disclosure
                                    .push(self.sd_jwt_engine.hash_to_disclosure[digest].to_owned());
                                hash_to_disclosure.append(&mut self.select_disclosures(
                                    sd_jwt_claims,
                                    claim_to_disclose.to_owned(),
                                )?);
                            }
                            _ => {}
                        }
                    } else if let Some(claim_to_disclose) = claim_to_disclose.as_object() {
                        hash_to_disclosure.append(
                            &mut self
                                .select_disclosures(sd_jwt_claims, claim_to_disclose.to_owned())?,
                        );
                    }
                }
                (Value::Array(claim_to_disclose), Value::Array(sd_jwt_claims)) => {
                    hash_to_disclosure.append(&mut self.select_disclosures_from_disclosed_list(
                        sd_jwt_claims,
                        claim_to_disclose,
                    )?);
                }
                _ => {}
            }
        }

        Ok(hash_to_disclosure)
    }
    async fn create_key_binding_jwt<S: SDJWTSigner>(
        &mut self,
        nonce: String,
        aud: String,
        signer: S,
    ) -> Result<()> {
        let alg = signer.algorithm();
        // Set key-binding fields
        self.key_binding_jwt_header
            .insert("alg".to_string(), alg.into());
        self.key_binding_jwt_header
            .insert("typ".to_string(), crate::KB_JWT_TYP_HEADER.into());
        self.key_binding_jwt_payload
            .insert("nonce".to_string(), nonce.into());
        self.key_binding_jwt_payload
            .insert("aud".to_string(), aud.into());
        let timestamp = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .map_err(|e| Error::ConversionError(format!("timestamp: {}", e)))?
            .as_secs();
        self.key_binding_jwt_payload
            .insert("iat".to_string(), timestamp.into());
        self.set_key_binding_digest_key()?;
        // Create key-binding jwt
        let mut header = Header::new(
            Algorithm::from_str(alg)
                .map_err(|e| Error::DeserializationError(e.to_string()))?,
        );

        header.typ = Some(crate::KB_JWT_TYP_HEADER.into());
        self.serialized_key_binding_jwt = encode(&header, &self.key_binding_jwt_payload, &signer).await?;
        Ok(())
    }

    fn set_key_binding_digest_key(&mut self) -> Result<()> {
        let mut combined: Vec<&str> = Vec::with_capacity(self.hs_disclosures.len() + 1);
        combined.push(&self.serialized_sd_jwt);
        combined.extend(self.hs_disclosures.iter().map(|s| s.as_str()));
        let combined = combined
            .join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .add(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);

        let sd_hash = base64_hash(combined.as_bytes());
        self.key_binding_jwt_payload
            .insert(KB_DIGEST_KEY.to_owned(), Value::String(sd_hash));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::issuer::ClaimsForSelectiveDisclosureStrategy;
    use crate::{SDJWTHolder, SDJWTIssuer, COMBINED_SERIALIZATION_FORMAT_SEPARATOR, SDJWTSerializationFormat};
    use jsonwebtoken::EncodingKey;
    use serde_json::{json, Map, Value};
    use std::collections::HashSet;
    use async_std_test::async_test;
    use crate::key::SDJWTKey;

    const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
    const PRIVATE_HOLDER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0tI02eGRti3I3oVD\nJNJPjnqZPLoTgb1LjAKHghdHS6ihRANCAATcyYx2XscFQm+cq9hXjzhP+IhocalY\nWuBJDqoAjF1BtV159qmKAVtBk1RkN4rVlwGCvHElWbqzXQmbzi/psban\n-----END PRIVATE KEY-----\n";
    const PUBLIC_HOLDER_JWK: &str = r#"{
            "kty": "EC",
            "crv": "P-256",
            "x": "3MmMdl7HBUJvnKvYV484T_iIaHGpWFrgSQ6qAIxdQbU",
            "y": "XXn2qYoBW0GTVGQ3itWXAYK8cSVZurNdCZvOL-mxtqc",
            "d": "0tI02eGRti3I3oVDJNJPjnqZPLoTgb1LjAKHghdHS6g"
         }"#;

    #[async_test]
    async fn create_full_presentation() -> std::io::Result<()> {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": "1683000000",
            "exp": "1883000000",
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
        let presentation = SDJWTHolder::new(
            sd_jwt.clone(),
            SDJWTSerializationFormat::Compact,
        )
            .unwrap()
            .create_presentation::<SDJWTKey>(
                user_claims.as_object().unwrap().clone(),
                None,
                None,
                None,
            )
            .await.unwrap();
        assert_eq!(sd_jwt, presentation);

        Ok(())
    }
    #[async_test]
    async fn create_presentation_empty_object_as_disclosure_value() -> std::io::Result<()> {
        let mut user_claims = json!({
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
        let issued = sd_jwt.clone();
        user_claims["address"] = Value::Object(Map::new());
        user_claims["email"] = Value::Bool(false);
        let presentation =
            SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
                .unwrap()
                .create_presentation::<SDJWTKey>(
                    user_claims.as_object().unwrap().clone(),
                    None,
                    None,
                    None,
                )
                .await.unwrap();

        let mut parts: Vec<&str> = issued
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();

        parts.remove(6);
        parts.remove(5);
        parts.remove(4);
        parts.remove(3);
        let expected = parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
        assert_eq!(expected, presentation);

        Ok(())
    }

    #[async_test]
    #[should_panic(expected = "Disclosure with key = 'email' is not found")]
    async fn create_presentation_with_non_existing_key_in_disclosures() -> std::io::Result<()> {
        let mut user_claims = json!({
            "birthdate": ["1955-04-12"],
            "family_name": "Neal",
            "given_name": "Tyler",
            "username": "tneal",
            "email": "tyler.neal@example.com",
            "iss": "did:key:zDnaeWEtv3fqyb8tTY7NGysY8RavUrhYtFe6qd9eddRWkSDFw",
            "iat": 1730118723,
            "exp": 1761654723,
        });
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = SDJWTKey::new(
            EncodingKey::from_ec_pem(private_issuer_bytes).unwrap(),
            None
        );
        let sd_jwt = SDJWTIssuer::new(issuer_key).issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::Custom(vec!["$.given_name", "$.family_name", "$.username", "$.email.work"]),
            None,
            false,
            SDJWTSerializationFormat::Compact,
            None
        )
            .await.unwrap();
        // Choose what to reveal
        user_claims["given_name"] = Value::Bool(true);
        user_claims["family_name"] = Value::Bool(true);
        user_claims["username"] = Value::Bool(true);
        user_claims["email"] = Value::Object(serde_json::Map::from_iter([("work".to_string(), Value::Bool(true))]));

        let presentation =
            SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
                .unwrap()
                .create_presentation::<SDJWTKey>(
                    user_claims.as_object().unwrap().clone(),
                    None,
                    None,
                    None,
                )
                .await.unwrap();
        Ok(())
    }

    #[async_test]
    async fn create_presentation_for_arrayed_disclosures() -> std::io::Result<()> {
        let mut user_claims = json!(
            {
              "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
              "name": "Bois",
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
        let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(vec![
            "$.name",
            "$.addresses[1]",
            "$.addresses[1].country",
            "$.nationalities[0]",
        ]);

        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = SDJWTKey::new(
            EncodingKey::from_ec_pem(private_issuer_bytes).unwrap(),
            None
        );
        let sd_jwt = SDJWTIssuer::new(issuer_key).issue_sd_jwt(
            user_claims.clone(),
            strategy,
            None,
            false,
            SDJWTSerializationFormat::Compact,
            None,
        )
            .await.unwrap();
        // Choose what to reveal
        user_claims["addresses"] = Value::Array(vec![Value::Bool(true), Value::Bool(false)]);
        user_claims["nationalities"] = Value::Array(vec![Value::Bool(true), Value::Bool(true)]);

        let issued = sd_jwt.clone();
        println!("{}", issued);
        let presentation =
            SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
                .unwrap()
                .create_presentation::<SDJWTKey>(
                    user_claims.as_object().unwrap().clone(),
                    None,
                    None,
                    None,
                )
                .await.unwrap();
        println!("{}", presentation);
        let mut issued_parts: HashSet<&str> = issued
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();
        issued_parts.remove("");

        let mut revealed_parts: HashSet<&str> = presentation
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();
        revealed_parts.remove("");

        let union: HashSet<_> = issued_parts.intersection(&revealed_parts).collect();
        assert_eq!(union.len(), 3);

        Ok(())
    }

    #[async_test]
    async fn create_presentation_for_recursive_disclosures() -> std::io::Result<()> {
        // Input data used to create the SD-JWT and presentation fixtures,
        // can be used to debug in case the test fails:

        // let mut user_claims = json!(
        //     {
        //         "foo": ["one", "two"],
        //         "bar": {
        //           "red": 1,
        //           "green": 2
        //         },
        //         "qux": [
        //           ["blue", "yellow"]
        //         ],
        //         "baz": [
        //           ["orange", "purple"],
        //           ["black", "white"]
        //         ],
        //         "animals": {
        //           "snake": {
        //             "name": "python",
        //             "age": 10
        //           },
        //           "bird": {
        //             "name": "eagle",
        //             "age": 20
        //           }
        //         }
        //       }
        // );
        // let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(vec![
        //     "$.foo[0]",
        //     "$.foo[1]",
        //     "$.bar.red",
        //     "$.bar.green",
        //     "$.qux[0]",
        //     "$.qux[0][0]",
        //     "$.qux[0][1]",
        //     "$.baz[0]",
        //     "$.baz[0][0]",
        //     "$.baz[0][1]",
        //     "$.baz[1]",
        //     "$.baz[1][0]",
        //     "$.baz[1][1]",
        //     "$.animals.snake",
        //     "$.animals.snake.name",
        //     "$.animals.snake.age",
        //     "$.animals.bird",
        //     "$.animals.bird.name",
        //     "$.animals.bird.age",
        // ]);

        // let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        // let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        // let sd_jwt = SDJWTIssuer::new(issuer_key, None).issue_sd_jwt(
        //     user_claims.clone(),
        //     strategy,
        //     None,
        //     false,
        //     SDJWTSerializationFormat::Compact,
        // )
        //     .unwrap();

        let sd_jwt = String::from("eyJhbGciOiJFUzI1NiJ9.eyJmb28iOlt7Ii4uLiI6Ii1XMWROTk0tNUI3WlpxR3R4MkF6RTA3X0hpRUpOZVJtNGtEQ1VORTVDNFUifSx7Ii4uLiI6ImpuUURqUEFoclY1bjMtRW5PVEZHWTcwMkd0T3FhN3hua3pVM0E4aElSX3cifV0sImJhciI6eyJfc2QiOlsiX25yZUxad2xVYlp1SmtqS1RVdHR5YkhqUTNrY2J4cnZab1dxUmVBbG4tcyIsImhGcjdBRElQbjZvQ3lSckNBN0VtNldLaGk1UjdXMWJjYWFZUFFrelpGMXciXX0sInF1eCI6W3siLi4uIjoieHl6MkRSSDRTSkpjdFFtMDEtSzROVVllMTMzMWh6U3VkTXd3MENDODEyUSJ9XSwiYmF6IjpbeyIuLi4iOiJRMGcyVmYzNnl6TnNvUkdNb0dsODZnZ2QyWGFVTmg5bGN6STFfbmFZYUhnIn0seyIuLi4iOiJZcGpMNTJKd1BfYmFFS21OaHFLazE3TWFrMl9fSWJCNmctY0haSHd6dmwwIn1dLCJhbmltYWxzIjp7Il9zZCI6WyJyQ19LNzlObG95SkFPWXRCOW9ITFlsTVJSS1V4UTNnaTZ0Wld0Zm90TWRjIiwidjUyd3d6bzB5Ymw2U2V1MjZWYklUODh5bHk1LXVMZkdlYTdkWnMxSHBwMCJdfSwiX3NkX2FsZyI6InNoYS0yNTYifQ.piidRp0pHJYmtExCJnLExaaWMTBX50mLwM6gFVYnD72DszyjpKbAoZhyAXT-I4CqqSpiHZg-2w8s26XBraqX6w~WyJCQ2k5UXlsWVVqVEpXWWVfbzRzOWxnIiwgIm9uZSJd~WyJSLXZ0bDBmbWF6N01zR1ZWRFh3T3BnIiwgInR3byJd~WyJXNWlOQ1Z1Qlo4OW9aV2dIUkxzRWJBIiwgInJlZCIsIDFd~WyJTQW5hNUJnaHJxUXJ0amR5SGxiejJBIiwgImdyZWVuIiwgMl0~WyJENVJrNVlIUkdJVXM5enp6OFUtOTVnIiwgImJsdWUiXQ~WyI0Y2tnSjJuWVhhV21jM3pVQ253d3N3IiwgInllbGxvdyJd~WyJ2Ml8tRG5JN0lEZ1loYVMzTG9Kb013IiwgW3siLi4uIjogIkhqMUQtZE1SNXR0YmpLcl9DUENETzRuVGlkTWR1YVNpMnlnYlhtcmR4MGcifSwgeyIuLi4iOiAiUl9Sb253SFY3bzR6Y0o3TV9jcTlobVpLZ2o2RkMtdmNXTko4bzNkeTg2MCJ9XV0~WyJwRHQtcEtfaklUYXhCVENJRFNvUnhBIiwgIm9yYW5nZSJd~WyJ1b3FDS0lpZGJzQmxhczhUaU5Kakh3IiwgInB1cnBsZSJd~WyJJWWFXMzVPNzBoUWg4OGlqWVBUVXZRIiwgW3siLi4uIjogIjlWdnFSbjk1ZUN6QnVkNkhYOG1faVRNMERZSVVxN0ZheFFtanowV1llbUkifSwgeyIuLi4iOiAiTmFOeXozWEJRZVc4Z1JRd28ySlN5NmhtbnJZT1JxRjMxeUhfWkhqbkRxNCJ9XV0~WyI4cFNkNHl0TWlPdnVGaFhQSXBPbW5BIiwgImJsYWNrIl0~WyJxLWR0QXhtZzY5cWZLMFpvS1BSbWFnIiwgIndoaXRlIl0~WyIzTzY0WmVYSjF6XzJWMXdrMGhJdUdBIiwgW3siLi4uIjogImRmVnVjbkwwMC1FVFh0RGpHaDlpRHYtSE5PZmRyZ1VuTlNYRk01VUlIRVkifSwgeyIuLi4iOiAiUlRnVmxQb25RTVZJNkEzNUJic21KTThDeDVTVTN1ZXJBMENyYmpvRW02USJ9XV0~WyJNQTlSbGMwUlAxNnVJWER6blRqOWJ3IiwgIm5hbWUiLCAicHl0aG9uIl0~WyJrblRLb0lKVzZuQ1VzeW1sN3lKWTNBIiwgImFnZSIsIDEwXQ~WyJlUEdwazZjdEhOSS1HS2JKbjZrR3lBIiwgInNuYWtlIiwgeyJfc2QiOiBbIjREU0s5REpJVEhROElITFFESld6SV9yM0lheXBIek5Ma19tc3BUa2xDVzQiLCAiYy11UFhEQkZJX2FDV1BUUHlYNFV0OWdDWW1DQ1FqUEw5TnRFZGotdWZtMCJdfV0~WyJOMzgyX2xTU1dpSzZsbGdPNFFhbUdnIiwgIm5hbWUiLCAiZWFnbGUiXQ~WyJjVWZVRVBrX0pDZm1KQzhWQUp1V1pBIiwgImFnZSIsIDIwXQ~WyJSVDh5My1Odmh6QXo4Q2ctS1NDRGh3IiwgImJpcmQiLCB7Il9zZCI6IFsiUVhINU9mSF8tMGtFYkEwWDBnd0RLenphc05ZYWRWekNWRGFrYlZfWnNxNCIsICJoUmtPNjRIVXZuaEFPbDBRS1NlZDFUWUhtb0VpRW9zb0R0WmsyRVl4ejdNIl19XQ~");
        let expected_presentation = String::from("eyJhbGciOiJFUzI1NiJ9.eyJmb28iOlt7Ii4uLiI6Ii1XMWROTk0tNUI3WlpxR3R4MkF6RTA3X0hpRUpOZVJtNGtEQ1VORTVDNFUifSx7Ii4uLiI6ImpuUURqUEFoclY1bjMtRW5PVEZHWTcwMkd0T3FhN3hua3pVM0E4aElSX3cifV0sImJhciI6eyJfc2QiOlsiX25yZUxad2xVYlp1SmtqS1RVdHR5YkhqUTNrY2J4cnZab1dxUmVBbG4tcyIsImhGcjdBRElQbjZvQ3lSckNBN0VtNldLaGk1UjdXMWJjYWFZUFFrelpGMXciXX0sInF1eCI6W3siLi4uIjoieHl6MkRSSDRTSkpjdFFtMDEtSzROVVllMTMzMWh6U3VkTXd3MENDODEyUSJ9XSwiYmF6IjpbeyIuLi4iOiJRMGcyVmYzNnl6TnNvUkdNb0dsODZnZ2QyWGFVTmg5bGN6STFfbmFZYUhnIn0seyIuLi4iOiJZcGpMNTJKd1BfYmFFS21OaHFLazE3TWFrMl9fSWJCNmctY0haSHd6dmwwIn1dLCJhbmltYWxzIjp7Il9zZCI6WyJyQ19LNzlObG95SkFPWXRCOW9ITFlsTVJSS1V4UTNnaTZ0Wld0Zm90TWRjIiwidjUyd3d6bzB5Ymw2U2V1MjZWYklUODh5bHk1LXVMZkdlYTdkWnMxSHBwMCJdfSwiX3NkX2FsZyI6InNoYS0yNTYifQ.piidRp0pHJYmtExCJnLExaaWMTBX50mLwM6gFVYnD72DszyjpKbAoZhyAXT-I4CqqSpiHZg-2w8s26XBraqX6w~WyJSLXZ0bDBmbWF6N01zR1ZWRFh3T3BnIiwgInR3byJd~WyJTQW5hNUJnaHJxUXJ0amR5SGxiejJBIiwgImdyZWVuIiwgMl0~WyI0Y2tnSjJuWVhhV21jM3pVQ253d3N3IiwgInllbGxvdyJd~WyJ2Ml8tRG5JN0lEZ1loYVMzTG9Kb013IiwgW3siLi4uIjogIkhqMUQtZE1SNXR0YmpLcl9DUENETzRuVGlkTWR1YVNpMnlnYlhtcmR4MGcifSwgeyIuLi4iOiAiUl9Sb253SFY3bzR6Y0o3TV9jcTlobVpLZ2o2RkMtdmNXTko4bzNkeTg2MCJ9XV0~WyJ1b3FDS0lpZGJzQmxhczhUaU5Kakh3IiwgInB1cnBsZSJd~WyJJWWFXMzVPNzBoUWg4OGlqWVBUVXZRIiwgW3siLi4uIjogIjlWdnFSbjk1ZUN6QnVkNkhYOG1faVRNMERZSVVxN0ZheFFtanowV1llbUkifSwgeyIuLi4iOiAiTmFOeXozWEJRZVc4Z1JRd28ySlN5NmhtbnJZT1JxRjMxeUhfWkhqbkRxNCJ9XV0~WyI4cFNkNHl0TWlPdnVGaFhQSXBPbW5BIiwgImJsYWNrIl0~WyJxLWR0QXhtZzY5cWZLMFpvS1BSbWFnIiwgIndoaXRlIl0~WyIzTzY0WmVYSjF6XzJWMXdrMGhJdUdBIiwgW3siLi4uIjogImRmVnVjbkwwMC1FVFh0RGpHaDlpRHYtSE5PZmRyZ1VuTlNYRk01VUlIRVkifSwgeyIuLi4iOiAiUlRnVmxQb25RTVZJNkEzNUJic21KTThDeDVTVTN1ZXJBMENyYmpvRW02USJ9XV0~WyJrblRLb0lKVzZuQ1VzeW1sN3lKWTNBIiwgImFnZSIsIDEwXQ~WyJlUEdwazZjdEhOSS1HS2JKbjZrR3lBIiwgInNuYWtlIiwgeyJfc2QiOiBbIjREU0s5REpJVEhROElITFFESld6SV9yM0lheXBIek5Ma19tc3BUa2xDVzQiLCAiYy11UFhEQkZJX2FDV1BUUHlYNFV0OWdDWW1DQ1FqUEw5TnRFZGotdWZtMCJdfV0~WyJjVWZVRVBrX0pDZm1KQzhWQUp1V1pBIiwgImFnZSIsIDIwXQ~WyJSVDh5My1Odmh6QXo4Q2ctS1NDRGh3IiwgImJpcmQiLCB7Il9zZCI6IFsiUVhINU9mSF8tMGtFYkEwWDBnd0RLenphc05ZYWRWekNWRGFrYlZfWnNxNCIsICJoUmtPNjRIVXZuaEFPbDBRS1NlZDFUWUhtb0VpRW9zb0R0WmsyRVl4ejdNIl19XQ~");

        // Choose what to reveal
        let revealed = json!(
            {
                "foo": [false, true],
                "bar": {
                  "red": false,
                  "green": true
                },
                "qux": [
                  [false, true]
                ],
                "baz": [
                  [false, true],
                  [true, true]
                ],
                "animals": {
                  "snake": {
                    "name": false,
                    "age": true
                  },
                  "bird": {
                    "name": false,
                    "age": true
                  }
                }
              }
        );

        let presentation =
            SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
                .unwrap()
                .create_presentation::<SDJWTKey>(
                    revealed.as_object().unwrap().clone(),
                    None,
                    None,
                    None,
                )
                .await.unwrap();

        let presentation: HashSet<_> = presentation
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR).map(String::from)
            .collect();

        let expected: HashSet<_> = expected_presentation
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .map(String::from).collect();

        assert_eq!(presentation, expected);

        Ok(())
    }

    #[async_test]
    async fn create_presentation_with_optional_claims_to_reveal() -> std::io::Result<()> {
        let sd_jwt = String::from("eyJhbGciOiJFUzI1NiJ9.eyJmb28iOlt7Ii4uLiI6Ii1XMWROTk0tNUI3WlpxR3R4MkF6RTA3X0hpRUpOZVJtNGtEQ1VORTVDNFUifSx7Ii4uLiI6ImpuUURqUEFoclY1bjMtRW5PVEZHWTcwMkd0T3FhN3hua3pVM0E4aElSX3cifV0sImJhciI6eyJfc2QiOlsiX25yZUxad2xVYlp1SmtqS1RVdHR5YkhqUTNrY2J4cnZab1dxUmVBbG4tcyIsImhGcjdBRElQbjZvQ3lSckNBN0VtNldLaGk1UjdXMWJjYWFZUFFrelpGMXciXX0sInF1eCI6W3siLi4uIjoieHl6MkRSSDRTSkpjdFFtMDEtSzROVVllMTMzMWh6U3VkTXd3MENDODEyUSJ9XSwiYmF6IjpbeyIuLi4iOiJRMGcyVmYzNnl6TnNvUkdNb0dsODZnZ2QyWGFVTmg5bGN6STFfbmFZYUhnIn0seyIuLi4iOiJZcGpMNTJKd1BfYmFFS21OaHFLazE3TWFrMl9fSWJCNmctY0haSHd6dmwwIn1dLCJhbmltYWxzIjp7Il9zZCI6WyJyQ19LNzlObG95SkFPWXRCOW9ITFlsTVJSS1V4UTNnaTZ0Wld0Zm90TWRjIiwidjUyd3d6bzB5Ymw2U2V1MjZWYklUODh5bHk1LXVMZkdlYTdkWnMxSHBwMCJdfSwiX3NkX2FsZyI6InNoYS0yNTYifQ.piidRp0pHJYmtExCJnLExaaWMTBX50mLwM6gFVYnD72DszyjpKbAoZhyAXT-I4CqqSpiHZg-2w8s26XBraqX6w~WyJCQ2k5UXlsWVVqVEpXWWVfbzRzOWxnIiwgIm9uZSJd~WyJSLXZ0bDBmbWF6N01zR1ZWRFh3T3BnIiwgInR3byJd~WyJXNWlOQ1Z1Qlo4OW9aV2dIUkxzRWJBIiwgInJlZCIsIDFd~WyJTQW5hNUJnaHJxUXJ0amR5SGxiejJBIiwgImdyZWVuIiwgMl0~WyJENVJrNVlIUkdJVXM5enp6OFUtOTVnIiwgImJsdWUiXQ~WyI0Y2tnSjJuWVhhV21jM3pVQ253d3N3IiwgInllbGxvdyJd~WyJ2Ml8tRG5JN0lEZ1loYVMzTG9Kb013IiwgW3siLi4uIjogIkhqMUQtZE1SNXR0YmpLcl9DUENETzRuVGlkTWR1YVNpMnlnYlhtcmR4MGcifSwgeyIuLi4iOiAiUl9Sb253SFY3bzR6Y0o3TV9jcTlobVpLZ2o2RkMtdmNXTko4bzNkeTg2MCJ9XV0~WyJwRHQtcEtfaklUYXhCVENJRFNvUnhBIiwgIm9yYW5nZSJd~WyJ1b3FDS0lpZGJzQmxhczhUaU5Kakh3IiwgInB1cnBsZSJd~WyJJWWFXMzVPNzBoUWg4OGlqWVBUVXZRIiwgW3siLi4uIjogIjlWdnFSbjk1ZUN6QnVkNkhYOG1faVRNMERZSVVxN0ZheFFtanowV1llbUkifSwgeyIuLi4iOiAiTmFOeXozWEJRZVc4Z1JRd28ySlN5NmhtbnJZT1JxRjMxeUhfWkhqbkRxNCJ9XV0~WyI4cFNkNHl0TWlPdnVGaFhQSXBPbW5BIiwgImJsYWNrIl0~WyJxLWR0QXhtZzY5cWZLMFpvS1BSbWFnIiwgIndoaXRlIl0~WyIzTzY0WmVYSjF6XzJWMXdrMGhJdUdBIiwgW3siLi4uIjogImRmVnVjbkwwMC1FVFh0RGpHaDlpRHYtSE5PZmRyZ1VuTlNYRk01VUlIRVkifSwgeyIuLi4iOiAiUlRnVmxQb25RTVZJNkEzNUJic21KTThDeDVTVTN1ZXJBMENyYmpvRW02USJ9XV0~WyJNQTlSbGMwUlAxNnVJWER6blRqOWJ3IiwgIm5hbWUiLCAicHl0aG9uIl0~WyJrblRLb0lKVzZuQ1VzeW1sN3lKWTNBIiwgImFnZSIsIDEwXQ~WyJlUEdwazZjdEhOSS1HS2JKbjZrR3lBIiwgInNuYWtlIiwgeyJfc2QiOiBbIjREU0s5REpJVEhROElITFFESld6SV9yM0lheXBIek5Ma19tc3BUa2xDVzQiLCAiYy11UFhEQkZJX2FDV1BUUHlYNFV0OWdDWW1DQ1FqUEw5TnRFZGotdWZtMCJdfV0~WyJOMzgyX2xTU1dpSzZsbGdPNFFhbUdnIiwgIm5hbWUiLCAiZWFnbGUiXQ~WyJjVWZVRVBrX0pDZm1KQzhWQUp1V1pBIiwgImFnZSIsIDIwXQ~WyJSVDh5My1Odmh6QXo4Q2ctS1NDRGh3IiwgImJpcmQiLCB7Il9zZCI6IFsiUVhINU9mSF8tMGtFYkEwWDBnd0RLenphc05ZYWRWekNWRGFrYlZfWnNxNCIsICJoUmtPNjRIVXZuaEFPbDBRS1NlZDFUWUhtb0VpRW9zb0R0WmsyRVl4ejdNIl19XQ~");
        let expected_presentation = String::from("eyJhbGciOiJFUzI1NiJ9.eyJmb28iOlt7Ii4uLiI6Ii1XMWROTk0tNUI3WlpxR3R4MkF6RTA3X0hpRUpOZVJtNGtEQ1VORTVDNFUifSx7Ii4uLiI6ImpuUURqUEFoclY1bjMtRW5PVEZHWTcwMkd0T3FhN3hua3pVM0E4aElSX3cifV0sImJhciI6eyJfc2QiOlsiX25yZUxad2xVYlp1SmtqS1RVdHR5YkhqUTNrY2J4cnZab1dxUmVBbG4tcyIsImhGcjdBRElQbjZvQ3lSckNBN0VtNldLaGk1UjdXMWJjYWFZUFFrelpGMXciXX0sInF1eCI6W3siLi4uIjoieHl6MkRSSDRTSkpjdFFtMDEtSzROVVllMTMzMWh6U3VkTXd3MENDODEyUSJ9XSwiYmF6IjpbeyIuLi4iOiJRMGcyVmYzNnl6TnNvUkdNb0dsODZnZ2QyWGFVTmg5bGN6STFfbmFZYUhnIn0seyIuLi4iOiJZcGpMNTJKd1BfYmFFS21OaHFLazE3TWFrMl9fSWJCNmctY0haSHd6dmwwIn1dLCJhbmltYWxzIjp7Il9zZCI6WyJyQ19LNzlObG95SkFPWXRCOW9ITFlsTVJSS1V4UTNnaTZ0Wld0Zm90TWRjIiwidjUyd3d6bzB5Ymw2U2V1MjZWYklUODh5bHk1LXVMZkdlYTdkWnMxSHBwMCJdfSwiX3NkX2FsZyI6InNoYS0yNTYifQ.piidRp0pHJYmtExCJnLExaaWMTBX50mLwM6gFVYnD72DszyjpKbAoZhyAXT-I4CqqSpiHZg-2w8s26XBraqX6w~WyJSLXZ0bDBmbWF6N01zR1ZWRFh3T3BnIiwgInR3byJd~WyJTQW5hNUJnaHJxUXJ0amR5SGxiejJBIiwgImdyZWVuIiwgMl0~WyI0Y2tnSjJuWVhhV21jM3pVQ253d3N3IiwgInllbGxvdyJd~WyJ2Ml8tRG5JN0lEZ1loYVMzTG9Kb013IiwgW3siLi4uIjogIkhqMUQtZE1SNXR0YmpLcl9DUENETzRuVGlkTWR1YVNpMnlnYlhtcmR4MGcifSwgeyIuLi4iOiAiUl9Sb253SFY3bzR6Y0o3TV9jcTlobVpLZ2o2RkMtdmNXTko4bzNkeTg2MCJ9XV0~WyJ1b3FDS0lpZGJzQmxhczhUaU5Kakh3IiwgInB1cnBsZSJd~WyJJWWFXMzVPNzBoUWg4OGlqWVBUVXZRIiwgW3siLi4uIjogIjlWdnFSbjk1ZUN6QnVkNkhYOG1faVRNMERZSVVxN0ZheFFtanowV1llbUkifSwgeyIuLi4iOiAiTmFOeXozWEJRZVc4Z1JRd28ySlN5NmhtbnJZT1JxRjMxeUhfWkhqbkRxNCJ9XV0~WyI4cFNkNHl0TWlPdnVGaFhQSXBPbW5BIiwgImJsYWNrIl0~WyJxLWR0QXhtZzY5cWZLMFpvS1BSbWFnIiwgIndoaXRlIl0~WyIzTzY0WmVYSjF6XzJWMXdrMGhJdUdBIiwgW3siLi4uIjogImRmVnVjbkwwMC1FVFh0RGpHaDlpRHYtSE5PZmRyZ1VuTlNYRk01VUlIRVkifSwgeyIuLi4iOiAiUlRnVmxQb25RTVZJNkEzNUJic21KTThDeDVTVTN1ZXJBMENyYmpvRW02USJ9XV0~WyJrblRLb0lKVzZuQ1VzeW1sN3lKWTNBIiwgImFnZSIsIDEwXQ~WyJlUEdwazZjdEhOSS1HS2JKbjZrR3lBIiwgInNuYWtlIiwgeyJfc2QiOiBbIjREU0s5REpJVEhROElITFFESld6SV9yM0lheXBIek5Ma19tc3BUa2xDVzQiLCAiYy11UFhEQkZJX2FDV1BUUHlYNFV0OWdDWW1DQ1FqUEw5TnRFZGotdWZtMCJdfV0~WyJjVWZVRVBrX0pDZm1KQzhWQUp1V1pBIiwgImFnZSIsIDIwXQ~WyJSVDh5My1Odmh6QXo4Q2ctS1NDRGh3IiwgImJpcmQiLCB7Il9zZCI6IFsiUVhINU9mSF8tMGtFYkEwWDBnd0RLenphc05ZYWRWekNWRGFrYlZfWnNxNCIsICJoUmtPNjRIVXZuaEFPbDBRS1NlZDFUWUhtb0VpRW9zb0R0WmsyRVl4ejdNIl19XQ~");

        // Choose what to reveal
        let revealed = json!(
            {
                "optional": "optional",
                "foo": [false, true],
                "bar": {
                  "red": false,
                  "green": true
                },
                "qux": [
                  [false, true]
                ],
                "baz": [
                  [false, true],
                  [true, true]
                ],
                "animals": {
                  "snake": {
                    "name": false,
                    "age": "optional"
                  },
                  "bird": {
                    "name": false,
                    "age": true
                  }
                }
              }
        );

        let presentation =
            SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
                .unwrap()
                .create_presentation::<SDJWTKey>(
                    revealed.as_object().unwrap().clone(),
                    None,
                    None,
                    None,
                )
                .await.unwrap();

        let presentation: HashSet<_> = presentation
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR).map(String::from)
            .collect();

        let expected: HashSet<_> = expected_presentation
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .map(String::from).collect();

        assert_eq!(presentation, expected);

        Ok(())
    }

    #[async_test]
    #[should_panic(
        expected = "Requested claim 'unknown' doesn't exist"
    )]
    async fn create_presentation_with_unknown_claim_to_reveal_should_fail() -> std::io::Result<()> {
        let sd_jwt = String::from("eyJhbGciOiJFUzI1NiJ9.eyJmb28iOlt7Ii4uLiI6Ii1XMWROTk0tNUI3WlpxR3R4MkF6RTA3X0hpRUpOZVJtNGtEQ1VORTVDNFUifSx7Ii4uLiI6ImpuUURqUEFoclY1bjMtRW5PVEZHWTcwMkd0T3FhN3hua3pVM0E4aElSX3cifV0sImJhciI6eyJfc2QiOlsiX25yZUxad2xVYlp1SmtqS1RVdHR5YkhqUTNrY2J4cnZab1dxUmVBbG4tcyIsImhGcjdBRElQbjZvQ3lSckNBN0VtNldLaGk1UjdXMWJjYWFZUFFrelpGMXciXX0sInF1eCI6W3siLi4uIjoieHl6MkRSSDRTSkpjdFFtMDEtSzROVVllMTMzMWh6U3VkTXd3MENDODEyUSJ9XSwiYmF6IjpbeyIuLi4iOiJRMGcyVmYzNnl6TnNvUkdNb0dsODZnZ2QyWGFVTmg5bGN6STFfbmFZYUhnIn0seyIuLi4iOiJZcGpMNTJKd1BfYmFFS21OaHFLazE3TWFrMl9fSWJCNmctY0haSHd6dmwwIn1dLCJhbmltYWxzIjp7Il9zZCI6WyJyQ19LNzlObG95SkFPWXRCOW9ITFlsTVJSS1V4UTNnaTZ0Wld0Zm90TWRjIiwidjUyd3d6bzB5Ymw2U2V1MjZWYklUODh5bHk1LXVMZkdlYTdkWnMxSHBwMCJdfSwiX3NkX2FsZyI6InNoYS0yNTYifQ.piidRp0pHJYmtExCJnLExaaWMTBX50mLwM6gFVYnD72DszyjpKbAoZhyAXT-I4CqqSpiHZg-2w8s26XBraqX6w~WyJCQ2k5UXlsWVVqVEpXWWVfbzRzOWxnIiwgIm9uZSJd~WyJSLXZ0bDBmbWF6N01zR1ZWRFh3T3BnIiwgInR3byJd~WyJXNWlOQ1Z1Qlo4OW9aV2dIUkxzRWJBIiwgInJlZCIsIDFd~WyJTQW5hNUJnaHJxUXJ0amR5SGxiejJBIiwgImdyZWVuIiwgMl0~WyJENVJrNVlIUkdJVXM5enp6OFUtOTVnIiwgImJsdWUiXQ~WyI0Y2tnSjJuWVhhV21jM3pVQ253d3N3IiwgInllbGxvdyJd~WyJ2Ml8tRG5JN0lEZ1loYVMzTG9Kb013IiwgW3siLi4uIjogIkhqMUQtZE1SNXR0YmpLcl9DUENETzRuVGlkTWR1YVNpMnlnYlhtcmR4MGcifSwgeyIuLi4iOiAiUl9Sb253SFY3bzR6Y0o3TV9jcTlobVpLZ2o2RkMtdmNXTko4bzNkeTg2MCJ9XV0~WyJwRHQtcEtfaklUYXhCVENJRFNvUnhBIiwgIm9yYW5nZSJd~WyJ1b3FDS0lpZGJzQmxhczhUaU5Kakh3IiwgInB1cnBsZSJd~WyJJWWFXMzVPNzBoUWg4OGlqWVBUVXZRIiwgW3siLi4uIjogIjlWdnFSbjk1ZUN6QnVkNkhYOG1faVRNMERZSVVxN0ZheFFtanowV1llbUkifSwgeyIuLi4iOiAiTmFOeXozWEJRZVc4Z1JRd28ySlN5NmhtbnJZT1JxRjMxeUhfWkhqbkRxNCJ9XV0~WyI4cFNkNHl0TWlPdnVGaFhQSXBPbW5BIiwgImJsYWNrIl0~WyJxLWR0QXhtZzY5cWZLMFpvS1BSbWFnIiwgIndoaXRlIl0~WyIzTzY0WmVYSjF6XzJWMXdrMGhJdUdBIiwgW3siLi4uIjogImRmVnVjbkwwMC1FVFh0RGpHaDlpRHYtSE5PZmRyZ1VuTlNYRk01VUlIRVkifSwgeyIuLi4iOiAiUlRnVmxQb25RTVZJNkEzNUJic21KTThDeDVTVTN1ZXJBMENyYmpvRW02USJ9XV0~WyJNQTlSbGMwUlAxNnVJWER6blRqOWJ3IiwgIm5hbWUiLCAicHl0aG9uIl0~WyJrblRLb0lKVzZuQ1VzeW1sN3lKWTNBIiwgImFnZSIsIDEwXQ~WyJlUEdwazZjdEhOSS1HS2JKbjZrR3lBIiwgInNuYWtlIiwgeyJfc2QiOiBbIjREU0s5REpJVEhROElITFFESld6SV9yM0lheXBIek5Ma19tc3BUa2xDVzQiLCAiYy11UFhEQkZJX2FDV1BUUHlYNFV0OWdDWW1DQ1FqUEw5TnRFZGotdWZtMCJdfV0~WyJOMzgyX2xTU1dpSzZsbGdPNFFhbUdnIiwgIm5hbWUiLCAiZWFnbGUiXQ~WyJjVWZVRVBrX0pDZm1KQzhWQUp1V1pBIiwgImFnZSIsIDIwXQ~WyJSVDh5My1Odmh6QXo4Q2ctS1NDRGh3IiwgImJpcmQiLCB7Il9zZCI6IFsiUVhINU9mSF8tMGtFYkEwWDBnd0RLenphc05ZYWRWekNWRGFrYlZfWnNxNCIsICJoUmtPNjRIVXZuaEFPbDBRS1NlZDFUWUhtb0VpRW9zb0R0WmsyRVl4ejdNIl19XQ~");

        // Choose what to reveal
        let revealed = json!(
            {
                "unknown": true,
                "foo": [false, true],
                "bar": {
                  "red": false,
                  "green": true
                },
                "qux": [
                  [false, true]
                ],
                "baz": [
                  [false, true],
                  [true, true]
                ],
                "animals": {
                  "snake": {
                    "name": false,
                    "age": true
                  },
                  "bird": {
                    "name": false,
                    "age": true
                  }
                }
              }
        );

        SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation::<SDJWTKey>(
                revealed.as_object().unwrap().clone(),
                None,
                None,
                None,
            )
            .await.unwrap();

        Ok(())
    }

    #[async_test]
    async fn create_presentation_with_key_binding() -> std::io::Result<()> {
        let mut user_claims = json!({
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

        let private_holder_bytes = PRIVATE_HOLDER_PEM.as_bytes();
        let holder_key = EncodingKey::from_ec_pem(private_holder_bytes).unwrap();
        let holder_public_jwk = serde_json::from_value(PUBLIC_HOLDER_JWK.parse().unwrap()).unwrap();

        let sd_jwt = SDJWTIssuer::new(issuer_key).issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(holder_public_jwk),
            false,
            SDJWTSerializationFormat::Compact,
            None,
        ).await.unwrap();

        user_claims["address"] = Value::Object(Map::new());
        let presentation_with_kb =
            SDJWTHolder::new(sd_jwt.clone(), SDJWTSerializationFormat::Compact)
                .unwrap()
                .create_presentation(
                    user_claims.as_object().unwrap().clone(),
                    Some("1".to_string()),
                    Some("https://example.com/aud".to_string()),
                    Some(SDJWTKey::new(holder_key, None)),
                )
                .await.unwrap();

        // TODO: Validate Key Binding part
        let (presentation, _) = presentation_with_kb
            .rsplit_once(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .unwrap();

        let presentation = format!("{presentation}{COMBINED_SERIALIZATION_FORMAT_SEPARATOR}");

        let mut parts: Vec<&str> = sd_jwt
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();

        parts.remove(6);
        parts.remove(5);
        parts.remove(4);
        parts.remove(3);
        let expected = parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
        assert_eq!(expected, presentation);

        Ok(())
    }
}
