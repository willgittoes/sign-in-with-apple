#![forbid(unsafe_code)]
#![deny(clippy::pedantic)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::perf)]
#![deny(clippy::nursery)]
#![deny(clippy::match_like_matches_macro)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

mod data;
mod error;

pub use data::{Claims, ClaimsServer2Server};

use data::{KeyComponents, APPLE_ISSUER, APPLE_PUB_KEYS};
use error::{ValidateCodeError, ValidateRefreshTokenError};
pub use error::{ValidationError, ValidatorCreateError};
use hyper::{body, Body, Client, Request};
use hyper_tls::HttpsConnector;
use jsonwebtoken::{
	self, decode, decode_header, get_current_timestamp, DecodingKey,
	EncodingKey, Header, TokenData, Validation,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;

pub struct Validator {
	client_id: String,
	team_id: String,
	key_id: String,
	private_key: EncodingKey,
	keys: HashMap<String, KeyComponents>,
}

impl Validator {
	pub async fn new(
		client_id: String,
		team_id: String,
		key_id: String,
		private_key: &[u8],
	) -> Result<Validator, ValidatorCreateError> {
		let private_key = EncodingKey::from_ec_pem(private_key)?;
		Ok(Validator {
			client_id,
			team_id,
			key_id,
			private_key,
			keys: fetch_apple_keys().await?,
		})
	}
}

async fn fetch_apple_keys(
) -> Result<HashMap<String, KeyComponents>, ValidatorCreateError> {
	let https = HttpsConnector::new();
	let client = Client::builder().build::<_, hyper::Body>(https);

	let req = Request::builder()
		.method("GET")
		.uri(APPLE_PUB_KEYS)
		.body(Body::from(""))?;

	let resp = client.request(req).await?;
	let buf = body::to_bytes(resp).await?;

	let mut resp: HashMap<String, Vec<KeyComponents>> =
		serde_json::from_slice(&buf)?;

	resp.remove("keys").map_or(
		Err(ValidatorCreateError::AppleKeys),
		|res| {
			Ok(res
				.into_iter()
				.map(|val| (val.kid.clone(), val))
				.collect::<HashMap<String, KeyComponents>>())
		},
	)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshToken {
	pub access_token: String,
	pub token_type: String,
	pub refresh_token: String,
	pub expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum ValidateCodeResponse {
	Error {
		error: String,
		error_description: String,
	},
	RefreshToken(RefreshToken),
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidateCodeClaims {
	sub: String,
	aud: String,
	iss: String,
	iat: u64,
	exp: u64,
}

impl Validator {
	/// decoe token with optional expiry validation
	pub async fn decode_token<T: DeserializeOwned>(
		&self,
		token: String,
		ignore_expire: bool,
	) -> Result<TokenData<T>, ValidationError> {
		let header = decode_header(token.as_str())?;

		let kid = match header.kid {
			Some(k) => k,
			None => return Err(ValidationError::KidNotFound),
		};

		let pubkey = match self.keys.get(&kid) {
			Some(key) => key,
			None => return Err(ValidationError::KeyNotFound),
		};

		let mut val = Validation::new(header.alg);
		val.validate_exp = !ignore_expire;
		let token_data = decode::<T>(
			token.as_str(),
			&DecodingKey::from_rsa_components(&pubkey.n, &pubkey.e)
				.unwrap(),
			&val,
		)?;

		Ok(token_data)
	}

	pub async fn validate_jwt(
		&self,
		token: String,
		ignore_expire: bool,
	) -> Result<TokenData<Claims>, ValidationError> {
		let token_data =
			self.decode_token::<Claims>(token, ignore_expire).await?;

		if token_data.claims.iss != APPLE_ISSUER {
			return Err(ValidationError::IssClaimMismatch);
		}

		if token_data.claims.aud != self.client_id {
			return Err(ValidationError::ClientIdMismatch);
		}
		Ok(token_data)
	}

	async fn client_secret(&self) -> String {
		let my_claims = ValidateCodeClaims {
			sub: self.client_id.to_string(),
			aud: "https://appleid.apple.com".to_string(),
			iss: self.team_id.to_string(),
			iat: get_current_timestamp(),
			exp: get_current_timestamp() + 86400 * 169,
		};

		let mut my_header =
			Header::new(jsonwebtoken::Algorithm::ES256);
		my_header.kid = Some(self.key_id.to_string());
		jsonwebtoken::encode(
			&my_header,
			&my_claims,
			&self.private_key,
		)
		.unwrap()
	}

	pub async fn validate_auth_code(
		&self,
		authorization_code: &str,
	) -> Result<RefreshToken, ValidateCodeError> {
		let client = reqwest::Client::new();
		let client_secret = self.client_secret().await;
		let params: [(&str, &str); 4] = [
			("client_id", &self.client_id),
			("client_secret", client_secret.as_str()),
			("code", authorization_code),
			("grant_type", "authorization_code"),
		];
		let res: ValidateCodeResponse = client
			.post("https://appleid.apple.com/auth/token")
			.header(
				"Content-Type",
				"application/x-www-form-urlencoded",
			)
			.form(&params)
			.send()
			.await
			.unwrap()
			.json()
			.await
			.expect("failed to get payload");

		match res {
			ValidateCodeResponse::Error {
				error,
				error_description,
			} => Err(ValidateCodeError::ErrorResponse(
				error,
				error_description,
			)),
			ValidateCodeResponse::RefreshToken(refresh_token) => {
				Ok(refresh_token)
			}
		}
	}
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessToken {
	pub access_token: String,
	pub token_type: String,
	pub id_token: String,
	pub expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum AccessTokenResponse {
	Error {
		error: String,
		error_description: String,
	},
	AccessToken(AccessToken),
}

impl Validator {
	pub async fn validate_refresh_code(
		&self,
		refresh_token: &str,
	) -> Result<AccessToken, ValidateRefreshTokenError> {
		let client = reqwest::Client::new();
		let client_secret = self.client_secret().await;
		let valid_refresh_params = [
			("client_id", self.client_id.as_str()),
			("client_secret", client_secret.as_str()),
			("refresh_token", refresh_token),
			("grant_type", "refresh_token"),
		];
		let res: AccessTokenResponse = client
			.post("https://appleid.apple.com/auth/token")
			.header(
				"Content-Type",
				"application/x-www-form-urlencoded",
			)
			.form(&valid_refresh_params)
			.send()
			.await
			.unwrap()
			.json()
			.await
			.expect("failed to get payload");

		match res {
			AccessTokenResponse::Error {
				error,
				error_description,
			} => Err(ValidateRefreshTokenError::ErrorResponse(
				error,
				error_description,
			)),
			AccessTokenResponse::AccessToken(access_token) => {
				Ok(access_token)
			}
		}
	}
}

/// allows to check whether the `validate` result was errored because of an expired signature
#[must_use]
pub fn is_expired(
	validate_result: &Result<TokenData<Claims>, ValidationError>,
) -> bool {
	if let Err(ValidationError::Jwt(error)) = validate_result {
		return matches!(
			error.kind(),
			jsonwebtoken::errors::ErrorKind::ExpiredSignature
		);
	}

	false
}
