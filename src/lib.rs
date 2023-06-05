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
use error::{KeyFetchError, ValidationError};
use hyper::{body, Body, Client, Request};
use hyper_tls::HttpsConnector;
use jsonwebtoken::{
	self, decode, decode_header, DecodingKey, TokenData, Validation,
};
use serde::de::DeserializeOwned;
use std::collections::HashMap;

pub struct Validator {
	keys: HashMap<String, KeyComponents>,
}

impl Validator {
	async fn new() -> Result<Validator, KeyFetchError> {
		Ok(Validator {
			keys: fetch_apple_keys().await?,
		})
	}

	fn from_keys(keys: HashMap<String, KeyComponents>) -> Validator {
		Validator { keys }
	}
}

//TODO: put verification into a struct and only fetch apple keys once in the beginning
async fn fetch_apple_keys(
) -> Result<HashMap<String, KeyComponents>, KeyFetchError> {
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

	resp.remove("keys")
		.map_or(Err(KeyFetchError::AppleKeys), |res| {
			Ok(res
				.into_iter()
				.map(|val| (val.kid.clone(), val))
				.collect::<HashMap<String, KeyComponents>>())
		})
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

	pub async fn validate(
		&self,
		client_id: String,
		token: String,
		ignore_expire: bool,
	) -> Result<TokenData<Claims>, ValidationError> {
		let token_data =
			self.decode_token::<Claims>(token, ignore_expire).await?;

		if token_data.claims.iss != APPLE_ISSUER {
			return Err(ValidationError::IssClaimMismatch);
		}

		if token_data.claims.aud != client_id {
			return Err(ValidationError::ClientIdMismatch);
		}
		Ok(token_data)
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

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use crate::{
		data::KeyComponents, is_expired, ClaimsServer2Server,
		ValidationError, Validator,
	};

	fn create_test_validator() -> Validator {
		Validator::from_keys(
			HashMap::from([
			  ("W6WcOKB".to_string(), KeyComponents {
				kty: "RSA".to_string(),
				kid: "W6WcOKB".to_string(),
				r#use: "sig".to_string(),
				alg: "RS256".to_string(),
				n: "2Zc5d0-zkZ5AKmtYTvxHc3vRc41YfbklflxG9SWsg5qXUxvfgpktGAcxXLFAd9Uglzow9ezvmTGce5d3DhAYKwHAEPT9hbaMDj7DfmEwuNO8UahfnBkBXsCoUaL3QITF5_DAPsZroTqs7tkQQZ7qPkQXCSu2aosgOJmaoKQgwcOdjD0D49ne2B_dkxBcNCcJT9pTSWJ8NfGycjWAQsvC8CGstH8oKwhC5raDcc2IGXMOQC7Qr75d6J5Q24CePHj_JD7zjbwYy9KNH8wyr829eO_G4OEUW50FAN6HKtvjhJIguMl_1BLZ93z2KJyxExiNTZBUBQbbgCNBfzTv7JrxMw".to_string(),
				e: "AQAB".to_string()
			  }),
			  ("YuyXoY".to_string(), KeyComponents {
				kty: "RSA".to_string(),
				kid: "YuyXoY".to_string(),
				r#use: "sig".to_string(),
				alg: "RS256".to_string(),
				n: "1JiU4l3YCeT4o0gVmxGTEK1IXR-Ghdg5Bzka12tzmtdCxU00ChH66aV-4HRBjF1t95IsaeHeDFRgmF0lJbTDTqa6_VZo2hc0zTiUAsGLacN6slePvDcR1IMucQGtPP5tGhIbU-HKabsKOFdD4VQ5PCXifjpN9R-1qOR571BxCAl4u1kUUIePAAJcBcqGRFSI_I1j_jbN3gflK_8ZNmgnPrXA0kZXzj1I7ZHgekGbZoxmDrzYm2zmja1MsE5A_JX7itBYnlR41LOtvLRCNtw7K3EFlbfB6hkPL-Swk5XNGbWZdTROmaTNzJhV-lWT0gGm6V1qWAK2qOZoIDa_3Ud0Gw".to_string(),
				e: "AQAB".to_string()
			  }),
			  ("fh6Bs8C".to_string(), KeyComponents {
				kty: "RSA".to_string(),
				kid: "fh6Bs8C".to_string(),
				r#use: "sig".to_string(),
				alg: "RS256".to_string(),
				n: "u704gotMSZc6CSSVNCZ1d0S9dZKwO2BVzfdTKYz8wSNm7R_KIufOQf3ru7Pph1FjW6gQ8zgvhnv4IebkGWsZJlodduTC7c0sRb5PZpEyM6PtO8FPHowaracJJsK1f6_rSLstLdWbSDXeSq7vBvDu3Q31RaoV_0YlEzQwPsbCvD45oVy5Vo5oBePUm4cqi6T3cZ-10gr9QJCVwvx7KiQsttp0kUkHM94PlxbG_HAWlEZjvAlxfEDc-_xZQwC6fVjfazs3j1b2DZWsGmBRdx1snO75nM7hpyRRQB4jVejW9TuZDtPtsNadXTr9I5NjxPdIYMORj9XKEh44Z73yfv0gtw".to_string(),
				e: "AQAB".to_string()
			  })])
		)
	}

	#[tokio::test]
	async fn validate_test(
	) -> std::result::Result<(), ValidationError> {
		let user_token =
			"001026.16112b36378440d995af22b268f00984.1744";
		let token = "eyJraWQiOiJZdXlYb1kiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmdhbWVyb2FzdGVycy5zdGFjazQiLCJleHAiOjE2MTQ1MTc1OTQsImlhdCI6MTYxNDQzMTE5NCwic3ViIjoiMDAxMDI2LjE2MTEyYjM2Mzc4NDQwZDk5NWFmMjJiMjY4ZjAwOTg0LjE3NDQiLCJjX2hhc2giOiJNNVVDdW5GdTFKNjdhdVE2LXEta093IiwiZW1haWwiOiJ6ZGZ1N2p0dXVzQHByaXZhdGVyZWxheS5hcHBsZWlkLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsImlzX3ByaXZhdGVfZW1haWwiOiJ0cnVlIiwiYXV0aF90aW1lIjoxNjE0NDMxMTk0LCJub25jZV9zdXBwb3J0ZWQiOnRydWV9.GuMJfVbnEvqppwwHFZjn3GDJtB4c4rl7C4PZzyDsdyiuXcFcXq52Ti0WSJBsqtfyT2dXvYxVxebHtONSQha_9DiM5qfYTZbpDDlIXrOMy1fkfStocold_wHWavofIpoJQVUMj45HLHtjixiNE903Pho6eY2UjEUjB3aFe8txuFIMv2JsaMCYzG4-e632FKBn63SroCkLc-8b4EVV4iYqnC5AfZArXhVjUevhhlaBH0E8Az2OGEe74U2WgBvMXEilmd62Ek-uInnrpJRgYQfYXvehQ1yT3aMiIgJICTQFMDdL1KAvs6mc081lNJLFYvViWlMH-Y7E5ajtUiMApiNYsg";

		let result = create_test_validator()
			.validate(user_token.to_string(), token.to_string(), true)
			.await?;

		assert_eq!(result.claims.sub, user_token);
		assert_eq!(result.claims.aud, "com.gameroasters.stack4");

		Ok(())
	}

	#[tokio::test]
	async fn validate_no_email() {
		let token = "eyJraWQiOiJlWGF1bm1MIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmdhbWVyb2FzdGVycy5zdGFjazQiLCJleHAiOjE2MzA4Mjc4MzAsImlhdCI6MTYzMDc0MTQzMCwic3ViIjoiMDAxMDI2LjE2MTEyYjM2Mzc4NDQwZDk5NWFmMjJiMjY4ZjAwOTg0LjE3NDQiLCJjX2hhc2giOiI0QjZKWTU4TmstVUJsY3dMa2VLc2lnIiwiYXV0aF90aW1lIjoxNjMwNzQxNDMwLCJub25jZV9zdXBwb3J0ZWQiOnRydWV9.iW0xk__fPD0mlh9UU-vh9VnR8yekWq64sl5re5d7UmDJxb1Fzk1Kca-hkA_Ka1LhSmKADdFW0DYEZhckqh49DgFtFdx6hM9t7guK3yrvBglhF5LAyb8NR028npxioLTTIgP_aR6Bpy5AyLQrU-yYEx2WTPYV5ln9n8vW154gZKRyl2KBlj9fS11BL_X1UFbFrL21GG_iPbB4qt5ywwTPoJ-diGN5JQzP5fk4yU4e4YmHhxJrT0NTTux2mB3lGJLa6YN-JYe_BuVV9J-sg_2r_ugTOUp3xQpfntu8xgQrY5W0oPxAPM4sibNLsye2kgPYYxfRYowc0JIjOcOd_JHDbQ";

		create_test_validator()
			.validate(
				"001026.16112b36378440d995af22b268f00984.1744".into(),
				token.to_string(),
				true,
			)
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn validate_expired() {
		let token = "eyJraWQiOiJlWGF1bm1MIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmdhbWVyb2FzdGVycy5zdGFjazQiLCJleHAiOjE2MzA4Mjc4MzAsImlhdCI6MTYzMDc0MTQzMCwic3ViIjoiMDAxMDI2LjE2MTEyYjM2Mzc4NDQwZDk5NWFmMjJiMjY4ZjAwOTg0LjE3NDQiLCJjX2hhc2giOiI0QjZKWTU4TmstVUJsY3dMa2VLc2lnIiwiYXV0aF90aW1lIjoxNjMwNzQxNDMwLCJub25jZV9zdXBwb3J0ZWQiOnRydWV9.iW0xk__fPD0mlh9UU-vh9VnR8yekWq64sl5re5d7UmDJxb1Fzk1Kca-hkA_Ka1LhSmKADdFW0DYEZhckqh49DgFtFdx6hM9t7guK3yrvBglhF5LAyb8NR028npxioLTTIgP_aR6Bpy5AyLQrU-yYEx2WTPYV5ln9n8vW154gZKRyl2KBlj9fS11BL_X1UFbFrL21GG_iPbB4qt5ywwTPoJ-diGN5JQzP5fk4yU4e4YmHhxJrT0NTTux2mB3lGJLa6YN-JYe_BuVV9J-sg_2r_ugTOUp3xQpfntu8xgQrY5W0oPxAPM4sibNLsye2kgPYYxfRYowc0JIjOcOd_JHDbQ";

		let res = create_test_validator()
			.validate(
				"001026.16112b36378440d995af22b268f00984.1744".into(),
				token.to_string(),
				false,
			)
			.await;

		assert!(is_expired(&res));
	}

	#[tokio::test]
	async fn test_server_to_server_payload() {
		let token = "eyJraWQiOiJlWGF1bm1MIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmdhbWVyb2FzdGVycy5zdGFjazQiLCJleHAiOjE2MzAxNzE4MTIsImlhdCI6MTYzMDA4NTQxMiwianRpIjoiQjk0T2REMDNwRnNhWWFOLUZ0djdtQSIsImV2ZW50cyI6IntcInR5cGVcIjpcImVtYWlsLWRpc2FibGVkXCIsXCJzdWJcIjpcIjAwMTAyNi4xNjExMmIzNjM3ODQ0MGQ5OTVhZjIyYjI2OGYwMDk4NC4xNzQ0XCIsXCJldmVudF90aW1lXCI6MTYzMDA4NTQwMzY0OCxcImVtYWlsXCI6XCJ6ZGZ1N2p0dXVzQHByaXZhdGVyZWxheS5hcHBsZWlkLmNvbVwiLFwiaXNfcHJpdmF0ZV9lbWFpbFwiOlwidHJ1ZVwifSJ9.SSdUM88GHqrS0QXHtaehbPxLQkAB3s1-qzcy3i2iRoSCzDhA1Q3o_FhiCbqOsbiPDOQ9aA1Z8-oAz1p3-TMfHy6QdIs1vLxBmNTe5IazNJw_7wwDZG2nr-bsKPUQldE--tK1EUFXQqQxQbfjJJE0JFEwPib2rmnb-t0mRopKMx2wg3CUlI64BHI2O8giGCbWB7UbJs2BpcUuapVShCIR7Eqxy0_ud81CUDjKzZK2CcmSRGDIk8g9pRqOHmPUFMOrDjj6_hUR9mf-xCrCedoC9f05z_yKD026A4gWGFn4pxTP8-uDTRPxcONax_vnQHBUDigYi8HXuzWorTx2ORPjaw";

		let result = create_test_validator()
			.decode_token::<ClaimsServer2Server>(
				token.to_string(),
				true,
			)
			.await
			.unwrap();

		assert_eq!(result.claims.aud, "com.gameroasters.stack4");
		assert_eq!(
			result.claims.events.sub,
			"001026.16112b36378440d995af22b268f00984.1744"
		);

		println!("{:?}", result);
	}
}
