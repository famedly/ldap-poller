#![allow(
	clippy::dbg_macro,
	clippy::expect_used,
	clippy::missing_docs_in_private_items,
	clippy::print_stderr,
	clippy::print_stdout,
	clippy::unwrap_used,
	clippy::bool_assert_comparison
)]
use std::{error::Error, time::Duration};

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

use crate::common::ldap_user_replace_attribute;

#[must_use]
pub fn setup_ldap_poller(
	sync_once: bool,
) -> (Config, tokio::sync::mpsc::Receiver<SearchEntry>, tokio::task::JoinHandle<()>) {
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
			enabled: "employeeType".to_owned(),
		},
		cache_method: CacheMethod::ModificationTime,
	};

	let (mut client, receiver) = Ldap::new(config.clone());

	let handle = tokio::spawn(async move {
		if sync_once {
			client.sync_once(None).await.unwrap();
		} else {
			client.sync(Duration::from_secs(1), None).await.unwrap();
		}
	});

	(config, receiver, handle)
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

	let (config, mut receiver, handle) = setup_ldap_poller(true);

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
	handle.abort();

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

	let (config, mut receiver, handle) = setup_ldap_poller(false);

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
	handle.abort();

	Ok(())
}

#[ignore = "docker"]
#[tokio::test]
#[serial]
async fn ldap_user_sync_modification_test() -> Result<(), Box<dyn Error>> {
	let mut ldap = ldap_connect().await?;
	let _ = ldap_delete_organizational_unit(&mut ldap, "users").await;

	ldap_add_organizational_unit(&mut ldap, "users").await.unwrap();
	ldap_add_user(&mut ldap, "user01", "User1").await.unwrap();
	ldap_user_add_attribute(&mut ldap, "user01", "displayName", "MyName1").await?;

	let (config, mut receiver, handle) = setup_ldap_poller(false);

	let mut users = vec![];
	if let Some(entry) = receiver.recv().await {
		let user = UserEntry::from_search(entry, &config.attributes).unwrap();
		users.push(user);
	}

	tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

	assert_eq!(users.len(), 1);
	assert_eq!(users[0].name.as_ref().unwrap(), "MyName1");

	ldap_user_replace_attribute(&mut ldap, "user01", "displayName", "MyNameNew").await?;

	if let Some(entry) = receiver.recv().await {
		let user = UserEntry::from_search(entry, &config.attributes).unwrap();
		users.push(user);
	}

	assert_eq!(users.len(), 2);
	assert_eq!(users[0].name.as_ref().unwrap(), "MyName1");
	assert_eq!(users[1].name.as_ref().unwrap(), "MyNameNew");

	tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

	ldap_user_add_attribute(&mut ldap, "user01", "employeeType", "FALSE").await?;

	if let Some(entry) = receiver.recv().await {
		let user = UserEntry::from_search(entry, &config.attributes).unwrap();
		users.push(user);
	}

	assert_eq!(users.len(), 3);
	assert_eq!(users[2].enabled.unwrap(), false);

	tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

	ldap_user_replace_attribute(&mut ldap, "user01", "employeeType", "TRUE").await?;

	if let Some(entry) = receiver.recv().await {
		let user = UserEntry::from_search(entry, &config.attributes).unwrap();
		users.push(user);
	}

	assert_eq!(users.len(), 4);
	assert_eq!(users[3].enabled.unwrap(), true);

	ldap_delete_user(&mut ldap, "user01").await?;
	ldap_delete_organizational_unit(&mut ldap, "users").await?;
	ldap.unbind().await?;
	handle.abort();

	Ok(())
}
