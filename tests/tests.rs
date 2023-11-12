#![allow(
	clippy::dbg_macro,
	clippy::expect_used,
	clippy::missing_docs_in_private_items,
	clippy::print_stderr,
	clippy::print_stdout,
	clippy::unwrap_used,
	clippy::bool_assert_comparison
)]
use core::panic;
use std::{error::Error, path::PathBuf, time::Duration};

use ldap_poller::{
	config::{AttributeConfig, CacheMethod, Config, ConnectionConfig, Searches, TLSConfig},
	ldap::{EntryStatus, Ldap},
	SearchEntryExt,
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

#[derive(Debug)]
#[allow(dead_code)]
struct LdapPollerSetup {
	pub ldap: Ldap,
	pub config: Config,
	pub receiver: tokio::sync::mpsc::Receiver<EntryStatus>,
	pub thread_handle: tokio::task::JoinHandle<()>,
}

#[must_use]
fn setup_ldap_poller(
	sync_once: bool,
	cache: Option<ldap_poller::Cache>,
	check_for_deleted_entries: bool,
	tls: bool,
) -> LdapPollerSetup {
	let url = {
		if tls {
			Url::parse("ldaps://localhost:1336").unwrap()
		} else {
			Url::parse("ldap://localhost:1389").unwrap()
		}
	};

	let connection = {
		let mut c = ConnectionConfig {
			timeout: 5,
			tls: TLSConfig {
				root_certificates_path: Some(PathBuf::from("docker-env/certs/RootCA.crt")),
				starttls: false,
				no_tls_verify: false,
			},
			operation_timeout: Duration::from_secs(5),
		};
		if !tls {
			c.tls.root_certificates_path = None;
		}
		c
	};

	let config = Config {
		url,
		connection,
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
			additional: vec![
				"displayName".to_owned(),
				"admin".to_owned(),
				"employeeType".to_owned(),
			],
		},
		cache_method: CacheMethod::ModificationTime,
		check_for_deleted_entries,
	};

	let (client, receiver) = Ldap::new(config.clone(), cache);
	let mut client_clone = client.clone();

	let handle = tokio::spawn(async move {
		if sync_once {
			client_clone.sync_once(None).await.unwrap();
		} else {
			client_clone.sync(Duration::from_secs(1)).await.unwrap();
		}
	});

	LdapPollerSetup { ldap: client, config, receiver, thread_handle: handle }
}

#[ignore = "docker"]
#[tokio::test]
#[serial]
async fn ldap_user_sync_once_test() -> Result<(), Box<dyn Error>> {
	let tracing_filter = EnvFilter::default().add_directive(LevelFilter::DEBUG.into());
	tracing_subscriber::fmt().with_env_filter(tracing_filter).init();

	sync_one_test(false).await
}

async fn sync_one_test(tls: bool) -> Result<(), Box<dyn Error>> {
	let mut ldap = ldap_connect(tls).await?;
	let _ = ldap_delete_organizational_unit(&mut ldap, "users").await;

	ldap_add_organizational_unit(&mut ldap, "users").await?;
	ldap_add_user(&mut ldap, "user01", "User1").await?;
	ldap_user_add_attribute(&mut ldap, "user01", "displayName", "MyName1").await?;
	ldap_add_user(&mut ldap, "user02", "User2").await?;
	ldap_user_add_attribute(&mut ldap, "user02", "displayName", "MyName2").await?;
	ldap_add_user(&mut ldap, "user03", "User3").await?;
	ldap_user_add_attribute(&mut ldap, "user03", "displayName", "MyName3").await?;

	let LdapPollerSetup { mut receiver, ldap: _, config: _, thread_handle } =
		setup_ldap_poller(true, None, false, tls);

	let mut users = vec![];
	while let Some(entry) = receiver.recv().await {
		match entry {
			EntryStatus::New(entry) => {
				users.push(entry);
			}
			_ => panic!("Unexpected entry status"),
		}

		if users.len() == 3 {
			break;
		}
	}

	assert_eq!(users.len(), 3);
	assert_eq!(users[0].attr_first("displayName").unwrap(), "MyName1");
	assert_eq!(users[1].attr_first("displayName").unwrap(), "MyName2");
	assert_eq!(users[2].attr_first("displayName").unwrap(), "MyName3");

	ldap_delete_user(&mut ldap, "user01").await?;
	ldap_delete_user(&mut ldap, "user02").await?;
	ldap_delete_user(&mut ldap, "user03").await?;
	ldap_delete_organizational_unit(&mut ldap, "users").await?;
	ldap.unbind().await?;
	thread_handle.abort();
	Ok(())
}

#[ignore = "docker"]
#[tokio::test]
#[serial]
async fn ldap_user_sync_create_test() -> Result<(), Box<dyn Error>> {
	let mut ldap = ldap_connect(false).await?;
	let _ = ldap_delete_organizational_unit(&mut ldap, "users").await;

	ldap_add_organizational_unit(&mut ldap, "users").await.unwrap();
	ldap_add_user(&mut ldap, "user01", "User1").await.unwrap();
	ldap_user_add_attribute(&mut ldap, "user01", "displayName", "MyName1").await?;

	let LdapPollerSetup { mut receiver, ldap: _, config: _, thread_handle } =
		setup_ldap_poller(false, None, true, false);

	let mut users = vec![];
	if let Some(entry) = receiver.recv().await {
		match entry {
			EntryStatus::New(entry) => {
				users.push(entry);
			}
			_ => panic!("Unexpected entry status"),
		}
	}

	assert_eq!(users.len(), 1);
	assert_eq!(users[0].attr_first("displayName").unwrap(), "MyName1");

	ldap_add_user(&mut ldap, "user02", "User2").await.unwrap();
	ldap_user_add_attribute(&mut ldap, "user02", "displayName", "MyName2").await?;

	if let Some(entry) = receiver.recv().await {
		match entry {
			EntryStatus::New(entry) => {
				users.push(entry);
			}
			_ => panic!("Unexpected entry status"),
		}
	}

	assert_eq!(users.len(), 2);
	assert_eq!(users[0].attr_first("displayName").unwrap(), "MyName1");
	assert_eq!(users[1].attr_first("displayName").unwrap(), "MyName2");

	ldap_delete_user(&mut ldap, "user01").await?;
	ldap_delete_user(&mut ldap, "user02").await?;

	let mut deleted_users = Vec::new();

	while let Some(entry) = receiver.recv().await {
		match entry {
			EntryStatus::Removed(id) => {
				deleted_users.push(id);
			}
			_ => panic!("Unexpected entry status"),
		}

		if deleted_users.len() == 2 {
			break;
		}
	}

	assert_eq!(deleted_users.len(), 2);
	assert!(deleted_users.contains(&"user01".as_bytes().to_vec()));
	assert!(deleted_users.contains(&"user02".as_bytes().to_vec()));

	ldap_delete_organizational_unit(&mut ldap, "users").await?;
	ldap.unbind().await?;
	thread_handle.abort();

	Ok(())
}

#[ignore = "docker"]
#[tokio::test]
#[serial]
async fn ldap_user_sync_modification_test() -> Result<(), Box<dyn Error>> {
	let mut ldap = ldap_connect(false).await?;
	let _ = ldap_delete_organizational_unit(&mut ldap, "users").await;

	ldap_add_organizational_unit(&mut ldap, "users").await.unwrap();
	ldap_add_user(&mut ldap, "user01", "User1").await.unwrap();
	ldap_user_add_attribute(&mut ldap, "user01", "displayName", "MyName1").await?;

	let LdapPollerSetup { mut receiver, ldap: _, config: _, thread_handle } =
		setup_ldap_poller(false, None, true, false);

	let mut users = vec![];
	if let Some(entry) = receiver.recv().await {
		match entry {
			EntryStatus::New(entry) => {
				users.push(entry);
			}
			_ => panic!("Unexpected entry status"),
		}
	}

	tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

	assert_eq!(users.len(), 1);
	assert_eq!(users[0].attr_first("displayName").unwrap(), "MyName1");

	ldap_user_replace_attribute(&mut ldap, "user01", "displayName", "MyNameNew").await?;

	if let Some(entry) = receiver.recv().await {
		match entry {
			EntryStatus::Changed(new_entry, _old_entry) => {
				users.push(new_entry);
			}
			_ => panic!("Unexpected entry status"),
		}
	}

	assert_eq!(users.len(), 2);
	assert_eq!(users[0].attr_first("displayName").unwrap(), "MyName1");
	assert_eq!(users[1].attr_first("displayName").unwrap(), "MyNameNew");

	tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

	ldap_user_add_attribute(&mut ldap, "user01", "employeeType", "FALSE").await?;

	if let Some(entry) = receiver.recv().await {
		match entry {
			EntryStatus::Changed(new_entry, _old_entry) => {
				users.push(new_entry);
			}
			_ => panic!("Unexpected entry status"),
		}
	}

	assert_eq!(users.len(), 3);
	assert_eq!(users[2].bool_first("employeeType").unwrap().unwrap(), false);

	tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

	ldap_user_replace_attribute(&mut ldap, "user01", "employeeType", "TRUE").await?;

	if let Some(entry) = receiver.recv().await {
		match entry {
			EntryStatus::Changed(new_entry, _old_entry) => {
				users.push(new_entry);
			}
			_ => panic!("Unexpected entry status"),
		}
	}

	assert_eq!(users.len(), 4);
	assert_eq!(users[3].bool_first("employeeType").unwrap().unwrap(), true);

	ldap_delete_user(&mut ldap, "user01").await?;

	if let Some(entry) = receiver.recv().await {
		match entry {
			EntryStatus::Removed(id) => {
				assert_eq!(id, "user01".as_bytes());
			}
			_ => panic!("Unexpected entry status"),
		}
	}

	ldap_delete_organizational_unit(&mut ldap, "users").await?;
	ldap.unbind().await?;
	thread_handle.abort();

	Ok(())
}

#[ignore = "docker"]
#[tokio::test]
#[serial]
async fn ldap_user_sync_cache_test() -> Result<(), Box<dyn Error>> {
	let mut ldap = ldap_connect(false).await?;
	let _ = ldap_delete_organizational_unit(&mut ldap, "users").await;

	ldap_add_organizational_unit(&mut ldap, "users").await.unwrap();
	ldap_add_user(&mut ldap, "user01", "User1").await.unwrap();
	ldap_user_add_attribute(&mut ldap, "user01", "displayName", "MyName1").await?;

	let LdapPollerSetup { mut receiver, ldap: ldap_poller, config: _, thread_handle } =
		setup_ldap_poller(false, None, false, false);

	let mut users = vec![];
	if let Some(entry) = receiver.recv().await {
		match entry {
			EntryStatus::New(entry) => {
				users.push(entry);
			}
			_ => panic!("Unexpected entry status"),
		}
	}

	assert_eq!(users.len(), 1);
	assert_eq!(users[0].attr_first("displayName").unwrap(), "MyName1");

	let cache = ldap_poller.persist_cache().await.unwrap();
	thread_handle.abort();

	ldap_add_user(&mut ldap, "user02", "User2").await.unwrap();
	ldap_user_add_attribute(&mut ldap, "user02", "displayName", "MyName2").await?;

	let LdapPollerSetup { mut receiver, ldap: _, config: _, thread_handle } =
		setup_ldap_poller(false, Some(cache), false, false);

	if let Some(entry) = receiver.recv().await {
		match entry {
			EntryStatus::New(entry) => {
				users.push(entry);
			}
			_ => panic!("Unexpected entry status"),
		}
	}

	assert_eq!(users.len(), 2);
	assert_eq!(users[0].attr_first("displayName").unwrap(), "MyName1");
	assert_eq!(users[1].attr_first("displayName").unwrap(), "MyName2");

	ldap_delete_user(&mut ldap, "user01").await?;
	ldap_delete_user(&mut ldap, "user02").await?;
	ldap_delete_organizational_unit(&mut ldap, "users").await?;
	ldap.unbind().await?;
	thread_handle.abort();

	Ok(())
}

#[ignore = "docker"]
#[tokio::test]
#[serial]
async fn ldap_tls_test() -> Result<(), Box<dyn Error>> {
	sync_one_test(true).await
}
