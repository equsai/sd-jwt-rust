use async_trait::async_trait;
use crate::error::Result;

#[async_trait]
pub trait SDJWTSigner: Sync + Send {
    /// Return the source algorithm.
    fn algorithm(&self) -> &str;

    /// Return a Base64 URL-safe encoded signature of the data
    ///
    /// # Arguments
    ///
    /// * `message` - The message data to sign.
    async fn sign(&self, message: &[u8]) -> Result<String>;
}