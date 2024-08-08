//! Config for the LDAP client.
use std::{path::PathBuf, time::Duration};

use ldap3::LdapConnSettings;
use native_tls::{Certificate, Identity, TlsConnector};
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

/// Configuration for how to connect to the LDAP server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionConfig {
	/// Timeout to establish a connection in seconds.
	pub timeout: u64,

	/// LDAP operation timeout. For search per reply.
	pub operation_timeout: Duration,

	/// TLS config
	pub tls: TLSConfig,
}

/// TLS Configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TLSConfig {
	/// Use StartTLS extended operation for establishing a secure connection,
	/// rather than TLS on a dedicated port.
	pub starttls: bool,

	/// Disable verification of TLS certificates
	pub no_tls_verify: bool,

	/// TLS root certificates path
	pub root_certificates_path: Option<PathBuf>,

	/// Path of the TLS client key to use for the connection
	pub client_key_path: Option<PathBuf>,

	/// Path of the TLS client certificate to use for the connection
	pub client_certificate_path: Option<PathBuf>,
}

/// Names of attributes to use for extracting relevant data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeConfig {
	/// The attribute containing the immutable unique id of the user
	pub pid: String,
	/// Name of the attribute that holds the time an object was most recently
	/// modified
	pub updated: Option<String>,
	/// Additional attributes
	pub additional: Vec<String>,
	/// Attributes to track for changes
	pub attrs_to_track: Vec<String>,
	/// Whether to explicitly filter for attributes in the ldap search request
	pub filter_attributes: bool,
}

impl AttributeConfig {
	/// Returns the list of LDAP object attributes the server should return.
	#[must_use]
	pub fn get_attr_filter(&self) -> Vec<String> {
		if self.filter_attributes {
			let mut mandatory = vec![self.pid.clone()];
			if let Some(updated) = &self.updated {
				mandatory.push(updated.clone());
			}
			[&self.additional[..], &mandatory[..], &self.attrs_to_track[..]].concat()
		} else {
			vec!["*".to_owned()]
		}
	}

	/// Returns an example AttributesConfig
	#[allow(dead_code)]
	pub(crate) fn example() -> Self {
		AttributeConfig {
			pid: "objectGUID".to_owned(),
			updated: Some("mtime".to_owned()),
			additional: vec!["admin".to_owned()],
			attrs_to_track: vec!["enabled".to_owned()],
			filter_attributes: true,
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

		settings = settings.set_conn_timeout(Duration::from_secs(self.timeout));
		settings = settings.set_starttls(self.tls.starttls);
		settings = settings.set_no_tls_verify(self.tls.no_tls_verify);

		if let Some(path) = &self.tls.root_certificates_path {
			let mut connector = TlsConnector::builder();

			let root_certificate =
				Certificate::from_pem(tokio::fs::read(path).await?.as_slice())
					.map_err(|_| Error::Invalid("Could not read root certificate".to_owned()))?;
			connector.add_root_certificate(root_certificate);

			match (&self.tls.client_key_path, &self.tls.client_certificate_path) {
				(Some(key_path), Some(cert_path)) => {
					let identity = Identity::from_pkcs8(
						tokio::fs::read(cert_path).await?.as_slice(),
						tokio::fs::read(key_path).await?.as_slice(),
					)
					.map_err(|_| Error::Invalid("Could not read client certificates".to_owned()))?;
					connector.identity(identity);
				}
				(None, None) => {}
				_ => Err(Error::Invalid(
					"Both a client certificate and key file in PKCS8 format must be specified"
						.to_owned(),
				))?,
			}

			let connector = connector.build().map_err(|_| {
				Error::Invalid("Could not build TlsConnector with custom root certs".to_owned())
			})?;
			settings = settings.set_connector(connector);
		}
		Ok(settings)
	}
}

#[cfg(test)]
mod tests {
	#![allow(clippy::unwrap_used, clippy::expect_used, clippy::items_after_statements)]

	use std::{io::ErrorKind, path::PathBuf};

	use time::PrimitiveDateTime;

	use super::TIME_FORMAT;
	use crate::{config::TLSConfig, error, AttributeConfig, ConnectionConfig};

	#[test]
	fn test_time_config() -> Result<(), Box<dyn std::error::Error>> {
		PrimitiveDateTime::parse("20130516200520Z", &TIME_FORMAT)?;

		Ok(())
	}

	#[test]
	fn test_attr_filter() -> Result<(), Box<dyn std::error::Error>> {
		let config = AttributeConfig::example();

		assert_eq!(config.get_attr_filter(), ["admin", "objectGUID", "mtime", "enabled"]);

		let mut config = AttributeConfig::example();
		config.filter_attributes = false;

		assert_eq!(config.get_attr_filter(), ["*"]);

		Ok(())
	}

	#[tokio::test]
	async fn test_tls_config() -> Result<(), Box<dyn std::error::Error>> {
		std::process::Command::new("sh")
			.arg("docker-env/certs/generate_certs.sh")
			.output()
			.expect("failed to create tls certs");

		// working test
		ConnectionConfig {
			tls: TLSConfig {
				client_key_path: Some(PathBuf::from("docker-env/certs/client.key")),
				client_certificate_path: Some(PathBuf::from("docker-env/certs/client.crt")),
				root_certificates_path: Some(PathBuf::from("docker-env/certs/RootCA.crt")),
				starttls: false,
				no_tls_verify: false,
			},
			timeout: 5,
			operation_timeout: std::time::Duration::from_secs(5),
		}
		.to_settings()
		.await?;

		// invalid crt test
		assert!(matches!(
			ConnectionConfig {
				tls: TLSConfig {
					client_key_path: Some(PathBuf::from("docker-env/certs/client.key")),
					client_certificate_path: Some(PathBuf::from("docker-env/certs/client.crt")),
					root_certificates_path: Some(PathBuf::from("src/config.rs")),
					starttls: false,
					no_tls_verify: false,
				},
				timeout: 5,
				operation_timeout: std::time::Duration::from_secs(5),
			}
			.to_settings()
			.await
			.err()
			.unwrap(),
			error::Error::Invalid(_)
		));

		// invalid path test
		assert!(matches!(
			ConnectionConfig {
				tls: TLSConfig {
					client_key_path: Some(PathBuf::from("invalid_path")),
					client_certificate_path: Some(PathBuf::from("invalid_path")),
					root_certificates_path: Some(PathBuf::from("invalid_path")),
					starttls: false,
					no_tls_verify: false,
				},
				timeout: 5,
				operation_timeout: std::time::Duration::from_secs(5),
			}
			.to_settings()
			.await
			.err()
			.unwrap(),
			error::Error::Io(io_err) if io_err.kind() == ErrorKind::NotFound
		));

		Ok(())
	}
}
