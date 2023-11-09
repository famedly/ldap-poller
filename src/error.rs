//! Error codes

/// Errors that can occur when using this library
#[derive(thiserror::Error, Debug)]
pub enum Error {
	/// A required attribute in a search result was missing.
	#[error("Missing data")]
	Missing,
	/// The contents of an attribute did not confirm to the expected syntax.
	#[error("Malformed data: {0}")]
	Invalid(String),
	/// An underlying protocol error or similar occurred, or the LDAP library
	/// was used incorrectly.
	#[error(transparent)]
	Ldap(#[from] ldap3::LdapError),

	/// An underlying IO error occurred.
	#[error(transparent)]
	Io(#[from] std::io::Error),

	/// An underlying Rustls error occurred.
	#[error(transparent)]
	Rustls(#[from] rustls::Error),
}
