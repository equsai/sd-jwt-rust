use crate::error::Error;
use crate::error::Error::DeserializationError;
use crate::{error, SDJWTCommon, SDJWTSerializationFormat};

use crate::signer::SDJWTSigner;
use base64::engine::general_purpose;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use error::Result;
use jsonwebtoken::Header;
#[cfg(feature = "mock_salts")]
use lazy_static::lazy_static;
#[cfg(feature = "delegate")]
use crate::DELEGATE_PAYLOAD_KEY;
use rand::prelude::ThreadRng;
use rand::RngCore;
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;
#[cfg(feature = "mock_salts")]
use std::{collections::VecDeque, sync::Mutex};

#[cfg(feature = "mock_salts")]
lazy_static! {
    pub static ref SALTS: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
}

/// Decodes a SD-JWT and returns the decoded payload as a JSON `Value`.
///
/// # Parameters
///
/// - `sd_jwt` - The SD-JWT that needs to be decoded.
/// * `serialization_format` - The serialization format of the SD-JWT, see [SDJWTSerializationFormat].
/// # Returns
/// * `Value` - The decoded payload as a JSON `Value`
pub fn decode_sd_jwt(
    sd_jwt: String,
    serialization_format: SDJWTSerializationFormat,
) -> Result<Value> {
    let mut sd_jwt_engine = SDJWTCommon {
        serialization_format,
        ..Default::default()
    };

    sd_jwt_engine.parse_sd_jwt(sd_jwt)?;
    sd_jwt_engine.create_hash_mappings()?;
    sd_jwt_engine.extract_sd_claims()
}

/// Decodes a Delegate SD-JWT (dSD-JWT / dSD-JWT+KB) and returns one claims object
/// per component, in chain order:
///
/// - element `0` is the issuer-signed SD-JWT's claims with disclosures resolved,
///   exactly as [`decode_sd_jwt`] would return them;
/// - each subsequent element is the corresponding chain link's `delegate_payload`
///   with its disclosures resolved — i.e. the delegated claims. When a link
///   discloses a single alternative (the usual presented case) that object is
///   returned; when several alternatives are still disclosed they are returned as
///   a JSON array.
///
/// Like [`decode_sd_jwt`], the result is *unverified*: no signatures, chain
/// bindings, `typ`, or lifetimes are checked. A plain SD-JWT (no chain) yields a
/// single-element vector, matching [`decode_sd_jwt`] wrapped in a `Vec`.
///
/// # Parameters
///
/// - `dsd_jwt` - The Delegate SD-JWT to decode.
/// - `serialization_format` - The serialization format, see [SDJWTSerializationFormat].
///
/// # Returns
/// * `Vec<Value>` - The issuer claims followed by each link's resolved delegate payload.
#[cfg(feature = "delegate")]
pub fn decode_dsd_jwt(
    dsd_jwt: String,
    serialization_format: SDJWTSerializationFormat,
) -> Result<Vec<Value>> {

    let mut sd_jwt_engine = SDJWTCommon {
        serialization_format,
        ..Default::default()
    };

    sd_jwt_engine.parse_sd_jwt(dsd_jwt)?;
    sd_jwt_engine.create_hash_mappings()?;

    // First element: the issuer SD-JWT's claims with disclosures resolved.
    let mut components = vec![sd_jwt_engine.extract_sd_claims()?];

    // Remaining elements: each chain link's delegate_payload, disclosures resolved.
    if let Some(chain) = sd_jwt_engine.delegation_chain.clone() {
        for (idx, link) in chain.links.iter().enumerate() {
            let claims: Value = link.payload.clone().into_iter().collect();
            let unpacked = crate::verifier::unpack_disclosed_claims(
                &claims,
                &sd_jwt_engine.hash_to_decoded_disclosure,
                &mut Vec::new(),
            )?;
            let alternatives = unpacked
                .as_object()
                .and_then(|obj| obj.get(DELEGATE_PAYLOAD_KEY))
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    Error::InvalidDelegatePayload(format!(
                        "link {}: delegate_payload is missing or not an array",
                        idx
                    ))
                })?;
            let delegate_payload = match alternatives.as_slice() {
                [single] => single.clone(),
                many => Value::Array(many.to_vec()),
            };
            components.push(delegate_payload);
        }
    }

    Ok(components)
}

#[doc(hidden)]
pub fn base64_hash(data: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

pub(crate) fn base64url_encode(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[doc(hidden)]
pub fn base64url_decode(b64data: &str) -> Result<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(b64data)
        .map_err(|e| Error::DeserializationError(e.to_string()))
}

pub(crate) fn generate_salt() -> String {
    let mut buf = [0u8; 16];
    ThreadRng::default().fill_bytes(&mut buf);
    base64url_encode(&buf)
}

#[cfg(feature = "mock_salts")]
pub(crate) fn generate_salt_mock() -> String {
    let mut salts = SALTS.lock().unwrap();
    return salts.pop_front().expect("SALTS is empty");
}

pub(crate) fn jwt_payload_decode(b64data: &str) -> Result<serde_json::Map<String, Value>> {
    serde_json::from_str(
        &String::from_utf8(
            base64url_decode(b64data).map_err(|e| DeserializationError(e.to_string()))?,
        )
            .map_err(|e| DeserializationError(e.to_string()))?,
    )
        .map_err(|e| DeserializationError(e.to_string()))
}

pub(crate) async fn encode<T: Serialize, S: SDJWTSigner>(
    header: &Header,
    claims: &T,
    signer: &S
) -> Result<String> {
    let encoded_header = b64_encode_part(header)?;
    let encoded_claims = b64_encode_part(claims)?;
    let message = [encoded_header, encoded_claims].join(".");
    let signature = signer.sign(message.as_bytes()).await?;

    Ok([message, signature].join("."))
}

pub(crate) fn b64_encode_part<T: Serialize>(input: &T) -> Result<String> {
    let json = serde_json::to_vec(input)
        .map_err(|e| Error::DeserializationError(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

/// MaybeSend is a marker to determine whether a type is Send or not. We use this trait to wrap the Send requirement for wasm32 target.
#[cfg(not(target_arch = "wasm32"))]
pub trait WasmNotSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> WasmNotSend for T {}

#[cfg(target_arch = "wasm32")]
pub trait WasmNotSend {}
#[cfg(target_arch = "wasm32")]
impl<T> WasmNotSend for T {}

/// MaybeSync is a marker to determine whether a type is Sync or not. We use this trait to wrap the Sync requirement for wasm32 target.
#[cfg(not(target_arch = "wasm32"))]
pub trait WasmNotSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync> WasmNotSync for T {}

#[cfg(target_arch = "wasm32")]
pub trait WasmNotSync {}
#[cfg(target_arch = "wasm32")]
impl<T> WasmNotSync for T {}

#[cfg(test)]
mod tests {
    use crate::{utils, SDJWTSerializationFormat};
    use serde_json::json;

    #[test]
    fn decode_sd_jwt() {
        let expected_decoded_value = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            },
        });

        let sd_jwt = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6IkdOV2FBTDJQVlVVMkp\
        JVDg5bTZxMGM3U3ZjNDBTLWJ2UjFTT0Q3REZCb1UifQ.eyJfc2QiOlsiNjFQTEd5NnE2N19pWkxNUjRTRWp2aWtOLVp\
        IZVlDb01VZVNCXzBTNUpMOCIsIlhaOE1SNXdlR0ktclp0RGM2eDZZVFdqVGdPT1JQVWVCcnR0RjliVU1CSzQiXSwiX3\
        NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsImlhdCI6MTY4MzAwMDAwM\
        CwiZXhwIjoxODgzMDAwMDAwfQ.c25UTRTIyGnXCe1ec60FhzHQpnSdCl3l_n3_oWRDxSLoOBhn0955jw_CONd-o_j7m\
        UNCY9Wv_lOgHqMsErsBSg~WyJNZkJmMEdpdE1UeFdyc3FaOHpvakFnIiwgInN1YiIsICI2YzVjMGE0OS1iNTg5LTQzM\
        WQtYmFlNy0yMTkxMjJhOWVjMmMiXQ~WyJBcjdCdEN4TkpRR3JjcERZZ045RmVRIiwgInN0cmVldF9hZGRyZXNzIiwgI\
        lNjaHVsc3RyLiAxMiJd~WyIwdkxMblJmN2dGYnpjb19nc1Z1VlBnIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0\
        ~WyJFbEd4TTFQTUZZdjNYYnpJaWsxWmRBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd~WyI4dEw2ODJob2s0b\
        WRMMzd4aG1TMG53IiwgImNvdW50cnkiLCAiREUiXQ~WyJXc3h1VkI4TFN6ODRlNFI3dnVXOTRBIiwgImFkZHJlc3MiL\
        CB7Il9zZCI6WyJGSVI1Z3BSS1RMaHNkdDk0NS1BZW9oMDIzN2ZPLVhTem1QcjEwa0VGeU9RIiwiZVJvcEU3UjZva3lh\
        YnpYdF8ybXJjWXJTSUw3cnNTeENqNXlJVlY1N3h0WSIsIm55OVJlSS1CaXFqTm9Sb0ZTQ05JYzI4SmwtNi1WSHlUWWx\
        XeVI2WjVwRG8iLCJ3MkRmMl9ZQ2JoZXExVk5ucFptYXlIZTl5UFhWanBxXzdBdlpRbUpJVEE0Il19XQ~";

        let decoded_value =
            utils::decode_sd_jwt(sd_jwt.to_string(), SDJWTSerializationFormat::Compact).unwrap();

        assert_eq!(expected_decoded_value, decoded_value);
    }
}
