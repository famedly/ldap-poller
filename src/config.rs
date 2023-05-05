//! Config for the LDAP client.
use std::time::Duration;

use ldap3::LdapConnSettings;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::{iso8601, Iso8601};
use url::Url;

/// Configuration for which variant of ISO8601 to use for parsing and
/// serializing time. Configured according the syntax definition
/// `( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )` described in
/// RFC4517 section 3.1.13
pub const TIME_CONFIG: iso8601::EncodedConfig =
	iso8601::Config::DEFAULT.set_use_separators(false).encode();
/// The time format used to parse and format timestamps in attribute values. See
/// also [`TIME_CONFIG`]
pub const TIME_FORMAT: Iso8601<TIME_CONFIG> = Iso8601;

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
}

/// Names of attributes to use for extracting relevant data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeConfig {
	/// The attribute containing the immutable unique id of the user
	pub pid: String,
	/// Name of the attribute that holds the time an object was most recently
	/// modified
	pub updated: String,
	/// Display name of the user.
	pub name: String,
	/// The attribute determining whether a user has administrator rights.
	pub admin: String,
	/// The attribute that determines whether or not a user is (de)activated.
	pub enabled: String,
}

impl AttributeConfig {
	/// Returns the list of LDAP object attributes the server should return.
	#[must_use]
	pub fn as_list(&self) -> [&str; 5] {
		["dn", &self.updated, &self.name, &self.admin, &self.enabled]
	}

	/// Construct a sample value of this structure suitable for tests
	#[cfg(test)]
	#[must_use]
	pub fn example() -> Self {
		AttributeConfig {
			pid: "uid".to_owned(),
			updated: "mtime".to_owned(),
			name: "cn".to_owned(),
			admin: "admin".to_owned(),
			enabled: "deactivated".to_owned(),
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
	/// Compare the hash of relevant information
	Hash,
	/// Check if the modification time of the user entry is newer than the
	/// cached one
	ModificationTime,
	/// Don't perform any caching and forward every entry unconditionally
	Disabled,
}

impl ConnectionConfig {
	/// Create a [`LdapConnSettings`] based on this [`ConnectionConfig`]
	pub(crate) fn to_settings(&self) -> LdapConnSettings {
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
		// TODO: Option for native platform TLS certs when using rustls
		settings
	}
}
