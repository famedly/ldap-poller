//! Repeatedly poll an LDAP directory server for user information.
//!
//! The library works by repeatedly performing a search against a directory
//! server, and then using the configured caching mechanism to check if the
//! entry for a given user (disambiguated by the "persistent ID" attribute) has
//! changed since the previously performed search. If any changed or new entries
//! are found
//!
//! For a general primer on LDAP, the [introduction] in the `ldap3` crate which
//! is used here for interfacing with LDAP is an excellent resource. The site
//! "firstyear's blog-a-log" also has [a guide][firstyear] which is more
//! visually oriented and goes into more detail about searching
//!
//! [introduction]: https://github.com/inejge/ldap3/blob/master/LDAP-primer.md
//! [firstyear]: https://fy.blackhats.net.au/blog/html/pages/ldap_guide_part_1_foundations.html
//!
//! # Getting started
//! A minimal example of running the client might look like so:
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::Duration;
//!
//! use ldap_poller::{
//! 	config::{
//! 		AttributeConfig, CacheMethod, Config, ConnectionConfig, Searches,
//! 		TLSConfig,
//! 	},
//! 	ldap::Ldap,
//! };
//! use url::Url;
//!
//! // Configuration can also be deserialized with serde. It's hand-constructed
//! // here for demonstration purposes.
//! let config = Config {
//! 	url: Url::parse("ldap://localhost")?,
//! 	connection: ConnectionConfig {
//! 		timeout: 5,
//! 		tls: TLSConfig {
//! 			root_certificates_path: None,
//! 			client_key_path: None,
//! 			client_certificate_path: None,
//! 			starttls: false,
//! 			no_tls_verify: false,
//! 		},
//! 		operation_timeout: Duration::from_secs(5),
//! 	},
//! 	search_user: "admin".to_owned(),
//! 	search_password: "verysecret".to_owned(),
//! 	searches: Searches {
//! 		user_base: "ou=people,dc=example,dc=com".to_owned(),
//! 		user_filter: "(objectClass=inetOrgPerson)".to_owned(),
//! 		page_size: None,
//! 	},
//! 	attributes: AttributeConfig {
//! 		pid: "objectGUID".to_owned(),
//! 		updated: Some("mtime".to_owned()),
//! 		additional: vec![
//! 			"cn".to_owned(),
//! 			"admin".to_owned(),
//! 			"enabled".to_owned(),
//! 		],
//! 		filter_attributes: true,
//! 		attrs_to_track: vec!["enabled".to_owned()],
//! 	},
//! 	cache_method: CacheMethod::ModificationTime,
//! 	check_for_deleted_entries: false,
//! };
//!
//! let (mut client, mut receiver) = Ldap::new(config.clone(), None);
//! tokio::spawn(async move {
//! 	client.sync(std::time::Duration::from_secs(5)).await;
//! });
//! while let Some(entry) = receiver.recv().await {
//! 	println!("Received entry: {entry:#?}");
//! }
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Limitations
//! * This library (currently) does not make use of any controls (i.e.
//!   extensions) such as [persistent search] or [content synchronization] for
//!   reducing the overhead of replication.
//! * Updated entries are sent via a channel. This may not be an ideal design
//!   approach.
//! * [secrecy](https://docs.rs/secrecy) is not used for storing the search user
//!   password, it probably should be
//! * Does not currently have any handling for user entries being removed from
//!   the directory tree.
//!
//! [persistent search]: https://datatracker.ietf.org/doc/html/draft-ietf-ldapext-psearch-03
//! [content synchronization]: https://www.rfc-editor.org/rfc/rfc4533.html

mod cache;
pub mod config;
pub mod entry;
pub mod error;
pub mod ldap;

pub use ldap3::{self, SearchEntry};

pub use crate::{
	config::{AttributeConfig, CacheMethod, Config, ConnectionConfig, Searches},
	entry::SearchEntryExt,
	ldap::{Cache, Ldap},
};
