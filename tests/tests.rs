#![allow(
	clippy::dbg_macro,
	clippy::expect_used,
	clippy::missing_docs_in_private_items,
	clippy::print_stderr,
	clippy::print_stdout,
	clippy::unwrap_used
)]

use std::error::Error;

use ldap3::SearchEntry;
use ldap_poller::{
	config::{AttributeConfig, CacheMethod, Config, ConnectionConfig, Searches},
	ldap::{Ldap, UserEntry},
};
use serial_test::serial;
use tracing_subscriber::{filter::LevelFilter, EnvFilter};
use url::Url;

mod common;

use common::{
	ldap_add_organizational_unit, ldap_add_user, ldap_connect, ldap_delete_organizational_unit,
	ldap_delete_user, ldap_user_add_attribute,
};

#[must_use]
pub fn setup_ldap_poller(sync_once: bool) -> (Config, tokio::sync::mpsc::Receiver<SearchEntry>) {
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
			pid: "cn".to_owned(),
			updated: "modifyTimestamp".to_owned(),
			name: "displayName".to_owned(),
			admin: "admin".to_owned(),
			enabled: "enabled".to_owned(),
		},
		cache_method: CacheMethod::ModificationTime,
	};

	let (mut client, receiver) = Ldap::new(config.clone());

	let _handle = tokio::spawn(async move {
		if sync_once {
			client.sync_once().await.unwrap();
		} else {
			client.sync().await.unwrap();
		}
	});

	(config, receiver)
}

#[ignore = "docker"]
#[tokio::test]
#[serial]
async fn ldap_user_sync_once_test() -> Result<(), Box<dyn Error>> {
	let tracing_filter = EnvFilter::default().add_directive(LevelFilter::DEBUG.into());
	tracing_subscriber::fmt().with_env_filter(tracing_filter).init();

	let mut ldap = ldap_connect().await?;
	let _ = ldap_delete_organizational_unit(&mut ldap, "users").await;

	ldap_add_organizational_unit(&mut ldap, "users").await?;
	ldap_add_user(&mut ldap, "user01", "User1").await?;
	ldap_user_add_attribute(&mut ldap, "user01", "displayName", "MyName1").await?;
	ldap_add_user(&mut ldap, "user02", "User2").await?;
	ldap_user_add_attribute(&mut ldap, "user02", "displayName", "MyName2").await?;
	ldap_add_user(&mut ldap, "user03", "User3").await?;
	ldap_user_add_attribute(&mut ldap, "user03", "displayName", "MyName3").await?;

	let (config, mut receiver) = setup_ldap_poller(true);

	let mut users = vec![];
	while let Some(entry) = receiver.recv().await {
		let user = UserEntry::from_search(entry, &config.attributes).unwrap();
		users.push(user);
	}

	assert_eq!(users.len(), 3);
	assert_eq!(users[0].name.as_ref().unwrap(), "MyName1");
	assert_eq!(users[1].name.as_ref().unwrap(), "MyName2");
	assert_eq!(users[2].name.as_ref().unwrap(), "MyName3");

	ldap_delete_user(&mut ldap, "user01").await?;
	ldap_delete_user(&mut ldap, "user02").await?;
	ldap_delete_user(&mut ldap, "user03").await?;
	ldap_delete_organizational_unit(&mut ldap, "users").await?;
	ldap.unbind().await?;

	Ok(())
}

#[ignore = "docker"]
#[tokio::test]
#[serial]
async fn ldap_user_sync_create_test() -> Result<(), Box<dyn Error>> {
	let mut ldap = ldap_connect().await?;
	let _ = ldap_delete_organizational_unit(&mut ldap, "users").await;

	ldap_add_organizational_unit(&mut ldap, "users").await.unwrap();
	ldap_add_user(&mut ldap, "user01", "User1").await.unwrap();
	ldap_user_add_attribute(&mut ldap, "user01", "displayName", "MyName1").await?;

	let (config, mut receiver) = setup_ldap_poller(false);

	let mut users = vec![];
	if let Some(entry) = receiver.recv().await {
		let user = UserEntry::from_search(entry, &config.attributes).unwrap();
		users.push(user);
	}

	assert_eq!(users.len(), 1);
	assert_eq!(users[0].name.as_ref().unwrap(), "MyName1");

	ldap_add_user(&mut ldap, "user02", "User2").await.unwrap();
	ldap_user_add_attribute(&mut ldap, "user02", "displayName", "MyName2").await?;

	if let Some(entry) = receiver.recv().await {
		let user = UserEntry::from_search(entry, &config.attributes).unwrap();
		users.push(user);
	}

	assert_eq!(users.len(), 2);
	assert_eq!(users[0].name.as_ref().unwrap(), "MyName1");
	assert_eq!(users[1].name.as_ref().unwrap(), "MyName2");

	ldap_delete_user(&mut ldap, "user01").await?;
	ldap_delete_user(&mut ldap, "user02").await?;
	ldap_delete_organizational_unit(&mut ldap, "users").await?;
	ldap.unbind().await?;

	Ok(())

	// ldap_add_organizational_unit(&mut ldap, "users").await.unwrap();
	// ldap_add_user(&mut ldap, "user03", "User3").await.unwrap();
	// ldap_user_add_attribute(&mut ldap, "user03", "displayName",
	// "MyName3").await.unwrap(); assert_eq!(
	// 	ldap_search_user(&mut ldap,
	// "user03").await?.attrs["displayName"].first().unwrap(), 	"MyName3"
	// );
	// ldap_delete_user(&mut ldap, "user03").await?;
	// ldap_delete_organizational_unit(&mut ldap, "users").await?;
	// ldap.unbind().await?;
}
