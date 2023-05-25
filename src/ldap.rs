//! Client for connecting to LDAP and syncing entries

use std::{collections::HashMap, sync::Arc};

use ldap3::{
	adapters::{Adapter, EntriesOnly, PagedResults},
	LdapConnAsync, Scope, SearchEntry,
};
use time::OffsetDateTime;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, warn};

pub use crate::cache::Cache;
use crate::{
	cache::CacheEntries,
	config::{AttributeConfig, CacheMethod, Config},
	entry::SearchEntryExt,
};

/// Holds data and provides interface for interactions with an LDAP server.
#[derive(Debug, Clone)]
pub struct Ldap {
	/// The configuration of the LDAP client.
	config: Config,
	/// The sender half of the channel where changes to user data are pushed.
	sender: mpsc::Sender<SearchEntry>,
	/// Data for the cache
	cache: Arc<RwLock<Cache>>,
}

/// Data about a user
#[derive(Debug, Clone)]
pub struct UserEntry {
	/// The immutable globally unique ID of the user.
	pub pid: Vec<u8>,
	/// Display name.
	pub name: Option<String>,
	/// Whether the user has administrator rights.
	pub admin: Option<bool>,
	/// Whether the user has been enabled.
	pub enabled: Option<bool>,
}

impl UserEntry {
	/// Converts a [`SearchEntry`] to a [`UserEntry`] using the attribute names
	/// in the given configuration.
	pub fn from_search(entry: SearchEntry, attributes: &AttributeConfig) -> Result<Self, Error> {
		let pid = entry.bin_attr_first(&attributes.pid).ok_or(Error::Missing)?.to_owned();
		let name = entry.attr_first(&attributes.name).map(String::from);
		let admin = entry.bool_first(&attributes.admin).transpose()?;
		let enabled = entry.bool_first(&attributes.enabled).transpose()?;
		Ok(Self { pid, name, admin, enabled })
	}
}

impl Ldap {
	/// Create a new [`Ldap`] with the given configuration and optional saved
	/// cache. Also returns a channel receiver which will be used to push
	/// updates to user data.
	#[must_use]
	pub fn new(config: Config, cache: Option<Cache>) -> (Self, mpsc::Receiver<SearchEntry>) {
		let (sender, receiver) = mpsc::channel::<SearchEntry>(1024);
		let cache: Cache = if let Some(cache) = cache {
			cache
		} else {
			let cache_entries = match config.cache_method {
				CacheMethod::Hash => CacheEntries::Hash(HashMap::new()),
				CacheMethod::ModificationTime => CacheEntries::Modified(HashMap::new()),
				CacheMethod::Disabled => CacheEntries::None,
			};
			Cache { last_sync_time: None, entries: cache_entries }
		};
		(Ldap { config, sender, cache: Arc::new(RwLock::new(cache)) }, receiver)
	}

	/// Create a connection to an ldap server based on the settings and url
	/// specified in the configuration.
	async fn connect(&self) -> Result<(LdapConnAsync, ldap3::Ldap), Error> {
		let settings = self.config.connection.to_settings();
		let (conn, ldap) =
			LdapConnAsync::from_url_with_settings(settings, &self.config.url).await?;
		Ok((conn, ldap))
	}

	/// Perform a sync repeatedly forever
	pub async fn sync(
		&mut self,
		duration_between_searches: std::time::Duration,
	) -> Result<(), Error> {
		loop {
			let new_time = OffsetDateTime::now_utc();
			let last_time = self.cache.read().await.last_sync_time;
			if let Err(e) = self.sync_once(last_time).await {
				tracing::error!("after_sync: {e}");
			}
			self.cache.write().await.last_sync_time = Some(new_time);
			tokio::time::sleep(duration_between_searches).await;
		}
	}

	/// Perform a search of all available users, pushing any entries which have
	/// changed
	pub async fn sync_once(&mut self, last_sync_time: Option<OffsetDateTime>) -> Result<(), Error> {
		// TODO: more LDAP server configurations.
		let (conn, mut ldap) = self.connect().await?;
		let conn = tokio::spawn(async move {
			if let Err(err) = conn.drive().await {
				warn!("Ldap connection error {err}");
			}
		});

		ldap.simple_bind(&self.config.search_user, &self.config.search_password).await?;

		// Prepare search parameters
		let mut adapters: Vec<Box<dyn Adapter<_, _>>> = vec![Box::new(EntriesOnly::new())];
		if let Some(page_size) = self.config.searches.page_size {
			adapters.push(Box::new(PagedResults::new(page_size)));
		}
		let attributes = self.config.attributes.clone();
		let filter = if let Some(last_sync_time) = last_sync_time {
			format!(
				"(&{}({}>={}))",
				self.config.searches.user_filter,
				self.config.attributes.updated,
				last_sync_time.format(&crate::config::TIME_FORMAT).map_err(|_| Error::Invalid)?,
			)
		} else {
			self.config.searches.user_filter.clone()
		};

		let mut search = ldap
			.streaming_search_with(
				adapters,
				&self.config.searches.user_base,
				Scope::Subtree,
				&filter,
				attributes.as_list(),
			)
			.await?;

		// Perform the search
		while let Some(entry) = search.next().await?.map(SearchEntry::construct) {
			if !self.cache.write().await.entries.has_changed(&entry, &self.config.attributes) {
				continue;
			}

			if let Err(e) = self.sender.send(entry).await {
				error!("Sending update failed: {e}");
			}
		}
		search.finish().await.success()?;
		ldap.unbind().await?;

		if let Err(err) = conn.await {
			warn!("Failed to join background task: {err}");
		}

		Ok(())
	}

	/// Persist the cache
	pub async fn persist_cache(&self) -> Result<Cache, Error> {
		Ok(self.cache.read().await.clone())
	}
}

/// Errors that can occur when using this library
#[derive(thiserror::Error, Debug)]
pub enum Error {
	/// A required attribute in a search result was missing.
	#[error("Missing data")]
	Missing,
	/// The contents of an attribute did not confirm to the expected syntax.
	#[error("Malformed data")]
	Invalid,
	/// An underlying protocol error or similar occurred, or the LDAP library
	/// was used incorrectly.
	#[error(transparent)]
	Ldap(#[from] ldap3::LdapError),
}
