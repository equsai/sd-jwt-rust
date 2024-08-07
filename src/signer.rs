use crate::error::Result;

pub trait SDJWTSigner {
    /// Return the source algorithm.
    fn algorithm(&self) -> &str;

    /// Return a Base64 URL-safe encoded signature of the data
    ///
    /// # Arguments
    ///
    /// * `message` - The message data to sign.
    fn sign(&self, message: &[u8]) -> Result<String>;
}