// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

pub type Result<T> = ::core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("conversion error: Cannot convert to {0}")]
    ConversionError(String),

    #[error("invalid input: {0}")]
    DeserializationError(String),

    #[error("data field is not expected: {0}")]
    DataFieldMismatch(String),

    #[error("Digest {0} appears multiple times")]
    DuplicateDigestError(String),

    #[error("Key {0} appears multiple times")]
    DuplicateKeyError(String),

    #[error("invalid disclosure: {0}")]
    InvalidDisclosure(String),

    #[error("invalid array disclosure: {0}")]
    InvalidArrayDisclosureObject(String),

    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("index {idx} is out of bounds for the provided array with length {length}: {msg}")]
    IndexOutOfBounds {
        idx: usize,
        length: usize,
        msg: String,
    },

    #[error("invalid state: {0}")]
    InvalidState(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("signing error: {0}")]
    SigningError(String),

    #[cfg(feature = "delegate")]
    #[error("malformed delegation chain: {0}")]
    ChainParseError(String),

    #[cfg(feature = "delegate")]
    #[error("signature verification failed for chain link {link}: {reason}")]
    ChainSignatureFailed { link: usize, reason: String },

    #[cfg(feature = "delegate")]
    #[error("typ mismatch on chain link {link}: found {found:?}, expected {expected}")]
    ChainTypMismatch {
        link: usize,
        found: Option<String>,
        expected: &'static str,
    },

    #[cfg(feature = "delegate")]
    #[error("chain link {link} is missing both sd_hash and issuer_jwt_hash")]
    MissingChainBinding { link: usize },

    #[cfg(feature = "delegate")]
    #[error("chain link {link} contains both sd_hash and issuer_jwt_hash")]
    AmbiguousChainBinding { link: usize },

    #[cfg(feature = "delegate")]
    #[error("chain link {link} binding hash mismatch")]
    InvalidChainBinding { link: usize },

    #[cfg(feature = "delegate")]
    #[error("invalid delegate payload: {0}")]
    InvalidDelegatePayload(String),

    #[cfg(feature = "delegate")]
    #[error("token lifetime invalid: {component} has expired (exp={exp})")]
    ChainExpired { component: String, exp: i64 },

    #[cfg(feature = "delegate")]
    #[error("token lifetime invalid: {component} is not yet valid (nbf={nbf})")]
    ChainNotYetValid { component: String, nbf: i64 },

    #[cfg(feature = "delegate")]
    #[error("delegation chain depth {0} exceeds configured limit")]
    ChainDepthLimitExceeded(usize),

    #[error("{0}")]
    Unspecified(String),
}
