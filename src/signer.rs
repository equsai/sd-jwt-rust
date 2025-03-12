use async_trait::async_trait;
use crate::error::Result;
use crate::utils::{WasmNotSend, WasmNotSync};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait SDJWTSigner: WasmNotSync + WasmNotSend {
    /// Return the source algorithm.
    fn algorithm(&self) -> &str;

    /// Return a Base64 URL-safe encoded signature of the data
    ///
    /// # Arguments
    ///
    /// * `message` - The message data to sign.
    async fn sign(&self, message: &[u8]) -> Result<String>;
}