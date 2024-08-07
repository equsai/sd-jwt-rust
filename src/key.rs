use std::str::FromStr;
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, crypto, EncodingKey};
use crate::DEFAULT_SIGNING_ALG;
use crate::error::{ Error, Result};
use crate::signer::SDJWTSigner;

pub struct SDJWTKey {
    algorithm: Option<String>,
    private_key: EncodingKey
}

impl SDJWTKey {
    /// Creates a new `SDJWTKey` instance.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The private key used for signing.
    /// * `algorithm` - The algorithm used for signing. If `None`,
    /// the default algorithm (ES256) algorithm will be used.
    ///
    /// # Returns
    ///
    /// A new `SDJWTKey` instance.
    pub fn new(private_key: EncodingKey, algorithm: Option<String>) -> SDJWTKey {
        SDJWTKey { algorithm, private_key }
    }
}

#[async_trait]
impl SDJWTSigner for SDJWTKey {
    /// Description. See [SDJWTSigner::algorithm] for further information.
    fn algorithm(&self) -> &str {
        self.algorithm.as_deref().unwrap_or_else(|| DEFAULT_SIGNING_ALG)
    }

    /// Description. See [SDJWTSigner::sign] for further information.
    async fn sign(&self, message: &[u8]) -> Result<String> {
        let algorithm = Algorithm::from_str(self.algorithm())
            .map_err(|e| Error::DeserializationError(e.to_string()))?;

        crypto::sign(message, &self.private_key, algorithm)
            .map_err(|e| Error::SigningError(e.to_string()))
    }
}