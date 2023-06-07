//! Convenience types for lib specific error handling

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ValidatorCreateError {
	#[error("hyper error: {0}")]
	Hyper(#[from] hyper::Error),
	#[error("http error: {0}")]
	Http(#[from] hyper::http::Error),
	#[error("Apple Keys Error")]
	AppleKeys,
	#[error("serde_json error: {0}")]
	SerdeJson(#[from] serde_json::Error),
	#[error("jsonwebtoken key error: {0}")]
	KeyError(#[from] jsonwebtoken::errors::Error),
}

#[derive(Error, Debug)]
pub enum ValidateCodeError {
	#[error("Error response from apple: {0}: {1}")]
	ErrorResponse(String, String),
}

#[derive(Error, Debug)]
pub enum ValidateRefreshTokenError {
	#[error("Error response from apple: {0}: {1}")]
	ErrorResponse(String, String),
}

#[derive(Error, Debug)]
pub enum ValidationError {
	#[error("Header algorithm unspecified")]
	HeaderAlgorithmUnspecified,
	#[error("Key ID not found")]
	KidNotFound,
	#[error("Key not found")]
	KeyNotFound,
	#[error("Iss claim mismatch")]
	IssClaimMismatch,
	#[error("Client ID mismatch")]
	ClientIdMismatch,
	#[error(transparent)]
	Jwt(#[from] jsonwebtoken::errors::Error),
	#[error("hyper error: {0}")]
	Hyper(#[from] hyper::Error),
	#[error("http error: {0}")]
	Http(#[from] hyper::http::Error),
}

// /// Convenience type for Results
// pub type Result<T> = std::result::Result<T, Error>;
