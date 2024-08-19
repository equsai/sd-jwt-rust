use async_trait::async_trait;
use jsonwebtoken::{DecodingKey, Header};

use crate::error::Result;

#[async_trait]
pub trait KeyResolver: Sync + Send {
    async fn resolve(&self, input: &str, header: &Header) -> Result<DecodingKey>;
}
