use async_trait::async_trait;
use jsonwebtoken::{DecodingKey, Header};

use crate::error::Result;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[async_trait]
pub trait KeyResolver: Sync + Send {
    async fn resolve(&self, input: &str, header: &Header) -> Result<DecodingKey>;
}
