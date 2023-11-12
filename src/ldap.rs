//! Client for connecting to LDAP and syncing entries

use std::{
	collections::{HashMap, HashSet},
	sync::Arc,
};

use ldap3::{
	adapters::{Adapter, EntriesOnly, PagedResults},
	LdapConnAsync, Scope, SearchEntry,
};
use time::OffsetDateTime;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, warn};

pub use crate::cache::Cache;
use crate::{
	cache::{CacheEntries, CacheEntryStatus},
	config::{CacheMethod, Config},
	error::Error,
};

/// Holds data and provides interface for interactions with an LDAP server.
#[derive(Debug, Clone)]
pub struct Ldap {
	/// The configuration of the LDAP client.
	config: Arc<Config>,
	/// The sender half of the channel where changes to user data are pushed.
	sender: mpsc::Sender<EntryStatus>,
	/// Data for the cache
	cache: Arc<RwLock<Cache>>,
}

/// Possible status of an entry
#[derive(Debug, Clone)]
pub enum EntryStatus {
	/// The entry is new
	New(SearchEntry),
	/// The entry has changed
	Changed(SearchEntry, SearchEntry),
	/// The entry was removed
	Removed(Vec<u8>),
}

impl Ldap {
	/// Create a new [`Ldap`] with the given configuration and optional saved
	/// cache. Also returns a channel receiver which will be used to push
	/// updates to user data.
	#[must_use]
	pub fn new(config: Config, cache: Option<Cache>) -> (Self, mpsc::Receiver<EntryStatus>) {
		let (sender, receiver) = mpsc::channel::<EntryStatus>(1024);
		let cache: Cache = if let Some(cache) = cache {
			cache
		} else {
			let cache_entries = match config.cache_method {
				CacheMethod::ModificationTime => CacheEntries::Modified(HashMap::new()),
				CacheMethod::Disabled => CacheEntries::None,
			};
			Cache { last_sync_time: None, entries: cache_entries, missing: HashSet::new() }
		};
		(Ldap { config: Arc::new(config), sender, cache: Arc::new(RwLock::new(cache)) }, receiver)
	}

	/// Create a connection to an ldap server based on the settings and url
	/// specified in the configuration.
	async fn connect(&self) -> Result<(LdapConnAsync, ldap3::Ldap), Error> {
		let settings = self.config.connection.to_settings().await?;
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

		ldap.with_timeout(self.config.connection.operation_timeout)
			.simple_bind(&self.config.search_user, &self.config.search_password)
			.await?;

		// Prepare search parameters
		let mut adapters: Vec<Box<dyn Adapter<_, _>>> = vec![Box::new(EntriesOnly::new())];
		if let Some(page_size) = self.config.searches.page_size {
			adapters.push(Box::new(PagedResults::new(page_size)));
		}
		let attributes = self.config.attributes.clone();
		let filter = match (self.config.check_for_deleted_entries, last_sync_time) {
			(false, Some(last_sync_time)) => {
				format!(
					"(&{}({}>={}))",
					self.config.searches.user_filter,
					self.config.attributes.updated,
					last_sync_time
						.format(&crate::config::TIME_FORMAT)
						.map_err(|_| Error::Invalid("TIME_FORMAT is invalid".to_owned()))?,
				)
			}
			_ => self.config.searches.user_filter.clone(),
		};

		let mut search = ldap
			.with_timeout(self.config.connection.operation_timeout)
			.streaming_search_with(
				adapters,
				&self.config.searches.user_base,
				Scope::Subtree,
				&filter,
				attributes.to_vec(),
			)
			.await?;

		self.cache.write().await.start_comparison();

		// Perform the search
		while let Some(entry) = search.next().await?.map(SearchEntry::construct) {
			let status = self.cache.write().await.check_entry(&entry, &self.config.attributes);
			match status {
				Ok(CacheEntryStatus::Missing) => {
					self.send_channel_update(EntryStatus::New(entry)).await;
				}
				Ok(CacheEntryStatus::Unchanged) => continue,
				Ok(CacheEntryStatus::Changed(old)) => {
					self.send_channel_update(EntryStatus::Changed(entry, old.into())).await;
				}
				Err(err) => {
					error!("Validating cache entry failed: {err}");
					continue;
				}
			}
		}
		search.finish().await.success()?;

		if self.config.check_for_deleted_entries {
			let missing =
				self.cache.write().await.end_comparison_and_return_missing_entries().clone();
			for id in missing {
				self.send_channel_update(EntryStatus::Removed(id.clone())).await;
			}
		}

		ldap.with_timeout(self.config.connection.operation_timeout).unbind().await?;

		if let Err(err) = conn.await {
			warn!("Failed to join background task: {err}");
		}

		Ok(())
	}

	/// Helper function to send an update to the user data channel
	async fn send_channel_update(&mut self, status: EntryStatus) {
		if let Err(e) = self.sender.send(status).await {
			error!("Sending update failed: {e}");
		}
	}

	/// Persist the cache
	pub async fn persist_cache(&self) -> Result<Cache, Error> {
		Ok(self.cache.read().await.clone())
	}
}
