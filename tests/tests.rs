#![allow(
	clippy::dbg_macro,
	clippy::expect_used,
	clippy::missing_docs_in_private_items,
	clippy::print_stderr,
	clippy::print_stdout,
	clippy::unwrap_used
)]

use ldap_poller::{
	config::{AttributeConfig, CacheMethod, Config, ConnectionConfig, Searches},
	ldap::{Ldap, UserEntry},
};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};
use url::Url;

#[ignore = "docker"]
#[tokio::test]
async fn ldap_user_first_sync_test() {
	let tracing_filter = EnvFilter::default().add_directive(LevelFilter::DEBUG.into());
	tracing_subscriber::fmt().with_env_filter(tracing_filter).init();

	let config = Config {
		url: Url::parse("ldap://localhost:1389").unwrap(),
		connection: ConnectionConfig::default(),
		search_user: String::new(),
		search_password: String::new(),
		searches: Searches {
			user_base: "ou=users,dc=example,dc=org".to_owned(),
			user_filter: "(objectClass=inetOrgPerson)".to_owned(),
			page_size: None,
		},
		attributes: AttributeConfig {
			pid: "entryUUID".to_owned(),
			updated: "modifyTimestamp".to_owned(),
			name: "cn".to_owned(),
			admin: "admin".to_owned(),
			enabled: "enabled".to_owned(),
		},
		cache_method: CacheMethod::ModificationTime,
	};

	let (mut client, mut receiver) = Ldap::new(config.clone());
	tokio::spawn(async move {
		client.sync().await.unwrap();
	});
	while let Some(entry) = receiver.recv().await {
		// println!("Received entry: {entry:#?}");
		let user = UserEntry::from_search(entry, &config.attributes).unwrap();
		// println!("Parsed entry as: {user:#?}");

		assert_eq!(user.name, Some("skarl".to_owned()));
		assert_eq!(user.admin, Some(true));
	}
}
