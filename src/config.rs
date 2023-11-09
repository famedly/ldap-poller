//! Config for the LDAP client.
use std::{path::PathBuf, sync::Arc, time::Duration};

use ldap3::LdapConnSettings;
use rustls::{Certificate, RootCertStore};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::Error;

/// Configuration for which variant of ISO8601 to use for parsing and
/// serializing time. Configured according the syntax definition
/// `( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )` described in
/// RFC4517 section 3.1.13
pub const TIME_FORMAT: &[time::format_description::FormatItem] =
	time::macros::format_description!("[year][month][day][hour][minute][second]Z");

/// LDAP configuration.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Config {
	/// The URL to connect to the server with. Supports ldap, ldaps, and ldapi
	/// schemes
	pub url: Url,
	/// Connection settings.
	#[serde(default)]
	pub connection: ConnectionConfig,
	/// The username for the LDAP search user
	pub search_user: String,
	/// The password for the LDAP search user
	pub search_password: String,
	/// Filters and bases to use for searches
	pub searches: Searches,
	/// Names of attributes to search for and extract data from
	pub attributes: AttributeConfig,
	/// How caching of user data should be performed
	pub cache_method: CacheMethod,
	/// Check for deleted entries (full search on every sync needed)
	pub check_for_deleted_entries: bool,
}

/// Configuration for how to connect to the LDAP server. Uses defaults from
/// [`LdapConnSettings`] for unset values.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConnectionConfig {
	/// Timeout to establish a connection in seconds. Infinite if unset.
	#[serde(default)]
	pub timeout: Option<u64>,

	/// Use StartTLS extended operation for establishing a secure connection,
	/// rather than TLS on a dedicated port. False if unset.
	#[serde(default)]
	pub starttls: Option<bool>,

	/// Disable verification of TLS certificates. False if unset.
	#[serde(default)]
	pub no_tls_verify: Option<bool>,

	/// Optional TLS config
	#[serde(default)]
	pub tls: Option<TLSConfig>,
}

/// TLS Configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TLSConfig {
	/// TLS root certificate path
	pub root_certificate_path: PathBuf,
}

/// Names of attributes to use for extracting relevant data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeConfig {
	/// The attribute containing the immutable unique id of the user
	pub pid: String,
	/// Name of the attribute that holds the time an object was most recently
	/// modified
	pub updated: String,
	/// Additional attributes
	pub additional: Vec<String>,
}

impl AttributeConfig {
	/// Returns the list of LDAP object attributes the server should return.
	#[must_use]
	pub fn to_vec(&self) -> Vec<String> {
		let mandatory = [self.pid.clone(), self.updated.clone()];
		[&self.additional[..], &mandatory[..]].concat()
	}

	/// Returns an example AttributesConfig
	#[allow(dead_code)]
	pub(crate) fn example() -> Self {
		AttributeConfig {
			pid: "objectGUID".to_owned(),
			updated: "mtime".to_owned(),
			additional: vec!["admin".to_owned()],
		}
	}
}

/// Configurable filters and bases to use for LDAP searches
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Searches {
	/// If set, enables the [simple paged search control] and sets the page size
	/// to the given value
	///
	/// [simple paged search control]: https://www.rfc-editor.org/rfc/rfc2696.html
	#[serde(default)]
	pub page_size: Option<i32>,
	/// The search filter to use when enumerating users
	pub user_filter: String,
	/// The search base to use when enumerating users
	pub user_base: String,
}

/// Configuration for how caching should be performed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheMethod {
	/// Check if the modification time of the user entry is newer than the
	/// cached one
	ModificationTime,
	/// Don't perform any caching and forward every entry unconditionally
	Disabled,
}

impl ConnectionConfig {
	/// Create a [`LdapConnSettings`] based on this [`ConnectionConfig`]
	pub(crate) async fn to_settings(&self) -> Result<LdapConnSettings, Error> {
		let mut settings = LdapConnSettings::new();
		if let Some(timeout) = self.timeout {
			settings = settings.set_conn_timeout(Duration::from_secs(timeout));
		}
		if let Some(starttls) = self.starttls {
			settings = settings.set_starttls(starttls);
		}
		if let Some(no_tls_verify) = self.no_tls_verify {
			settings = settings.set_no_tls_verify(no_tls_verify);
		}
		if let Some(config) = &self.tls {
			let contents = tokio::fs::read(&config.root_certificate_path).await?;
			let certs = rustls_pemfile::certs(&mut contents.as_slice())?;
			if certs.is_empty() {
				return Err(Error::Invalid("No certificates found".to_owned()));
			}
			let mut store = RootCertStore::empty();
			for cert in certs.into_iter().map(Certificate) {
				store.add(&cert)?;
			}
			let client_config = rustls::ClientConfig::builder()
				.with_safe_defaults()
				.with_root_certificates(Arc::new(store))
				.with_no_client_auth();
			settings = settings.set_config(client_config.into());
		}
		Ok(settings)
	}
}

#[cfg(test)]
mod tests {
	#![allow(clippy::unwrap_used, clippy::items_after_statements)]

	use std::path::PathBuf;

	use time::PrimitiveDateTime;

	use super::TIME_FORMAT;
	use crate::{config::TLSConfig, ConnectionConfig};

	#[test]
	fn test_time_config() -> Result<(), Box<dyn std::error::Error>> {
		PrimitiveDateTime::parse("20130516200520Z", &TIME_FORMAT)?;

		Ok(())
	}

	#[tokio::test]
	async fn test_tls_config() -> Result<(), Box<dyn std::error::Error>> {
		// default test
		ConnectionConfig::default().to_settings().await?;

		// working test
		ConnectionConfig {
			tls: Some(TLSConfig {
				root_certificate_path: PathBuf::from("docker-env/certs/RootCA.crt"),
			}),
			..Default::default()
		}
		.to_settings()
		.await?;

		// invalid crt test
		assert!(matches!(
			ConnectionConfig {
				tls: Some(TLSConfig { root_certificate_path: PathBuf::from("src/config.rs") }),
				..Default::default()
			}
			.to_settings()
			.await
			.err()
			.unwrap(),
			crate::error::Error::Invalid(_)
		));

		Ok(())
	}
}
