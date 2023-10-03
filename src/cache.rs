//! Caching mechanisms to check whether user data has changed
use std::collections::{HashMap, HashSet};

use ldap3::SearchEntry;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::{
	config::{AttributeConfig, TIME_FORMAT},
	entry::SearchEntryExt,
};

/// Cache data with information about the last sync and user entries
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Cache {
	/// The time of the last sync
	pub(crate) last_sync_time: Option<OffsetDateTime>,
	/// Cached data entries used to check whether an entry has changed
	pub(crate) entries: CacheEntries,
	/// Set of missing entries during comparison
	pub(crate) missing: HashSet<Vec<u8>>,
}

/// Possible status of a checked entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CacheEntryStatus {
	/// The entry is missing
	Missing,
	/// The entry is present and unchanged
	Unchanged,
	/// The entry is present and has changed
	Changed,
}

impl Cache {
	/// Start a new comparison with the current entries
	pub(crate) fn start_comparison(&mut self) {
		self.missing = self.entries.get_expected();
	}

	/// Check whether an entry is changed or unchanged and update expeted
	/// entries
	pub(crate) fn check_entry(
		&mut self,
		entry: &SearchEntry,
		attributes_config: &AttributeConfig,
	) -> Result<CacheEntryStatus, Error> {
		let id = entry.bin_attr_first(&attributes_config.pid).ok_or(Error::Missing)?;
		self.missing.remove(id);
		self.entries.check_cache_entry_status(entry, attributes_config)
	}

	/// End a running comparison with the current entries
	pub(crate) fn end_comparison_and_return_missing_entries(&mut self) -> &HashSet<Vec<u8>> {
		&self.missing
	}
}

/// Cache data entries used to check whether an entry has changed
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CacheEntries {
	/// Use the modification time attribute to check whether a user entry has
	/// changed.
	Modified(HashMap<Vec<u8>, OffsetDateTime>),
	/// Don't cache anything, forward all results unconditionally
	None,
}

impl CacheEntries {
	/// Get initial hash set of expected entries
	pub(crate) fn get_expected(&self) -> HashSet<Vec<u8>> {
		match *self {
			CacheEntries::Modified(ref cache) => cache.keys().cloned().collect(),
			CacheEntries::None => HashSet::new(),
		}
	}

	/// Check whether an entry is present or changed
	pub(crate) fn check_cache_entry_status(
		&mut self,
		entry: &SearchEntry,
		attributes_config: &AttributeConfig,
	) -> Result<CacheEntryStatus, Error> {
		match *self {
			CacheEntries::Modified(ref mut cache) => {
				match has_mtime_changed(cache, entry, attributes_config) {
					Ok(status) => Ok(status),
					Err(err) => {
						tracing::warn!("Validating modification time failed: {err}");
						Err(err)
					}
				}
			}
			CacheEntries::None => Ok(CacheEntryStatus::Missing),
		}
	}
}

/// Check whether the modification time of an entry has changed
fn has_mtime_changed(
	times: &mut HashMap<Vec<u8>, OffsetDateTime>,
	entry: &SearchEntry,
	attributes_config: &AttributeConfig,
) -> Result<CacheEntryStatus, Error> {
	let time = entry.attr_first(&attributes_config.updated).ok_or(Error::Missing)?;
	let id = entry.bin_attr_first(&attributes_config.pid).ok_or(Error::Missing)?;
	let time = PrimitiveDateTime::parse(time, &TIME_FORMAT)?.assume_utc();
	match times.get_mut(id) {
		Some(cached) if time > *cached => {
			*cached = time;
			Ok(CacheEntryStatus::Changed)
		}
		Some(_) => Ok(CacheEntryStatus::Unchanged),
		None => {
			times.insert(id.to_owned(), time);
			Ok(CacheEntryStatus::Missing)
		}
	}
}

/// Errors that can occur when attempting to check if an entry has changed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
	/// A time value was malformed and failed to parse.
	#[error("Malformed time")]
	Time(#[from] time::error::Parse),
	/// An expected attribute was not present.
	#[error("Missing attribute")]
	Missing,
}

#[cfg(test)]
mod tests {
	#![allow(clippy::unwrap_used, clippy::items_after_statements)]

	use std::collections::HashMap;

	use ldap3::SearchEntry;
	use time::{Duration, OffsetDateTime};

	use crate::{
		cache::CacheEntryStatus,
		config::{AttributeConfig, TIME_FORMAT},
	};

	#[test]
	fn has_mtime_changed() -> Result<(), Box<dyn std::error::Error>> {
		let mut cache = HashMap::new();

		// Construct example values
		let attributes = AttributeConfig::example();
		let now = OffsetDateTime::now_utc();
		let mut entry = SearchEntry {
			dn: "uid=foo,ou=people,dc=example,dc=com".to_owned(),
			attrs: {
				let attributes = attributes.clone();
				HashMap::from([
					(attributes.pid, vec!["john_doe".to_owned()]),
					(attributes.updated, vec![now.format(&TIME_FORMAT)?]),
				])
			},
			bin_attrs: HashMap::new(),
		};

		assert_eq!(
			super::has_mtime_changed(&mut cache, &entry, &attributes)?,
			CacheEntryStatus::Missing,
			"Newly inserted entry should be considered missing",
		);
		assert_eq!(
			super::has_mtime_changed(&mut cache, &entry, &attributes)?,
			CacheEntryStatus::Unchanged,
			"Unmodified entry should not be considered changed",
		);

		// Change the modification time
		let now = now + Duration::seconds(30);
		entry.attrs.insert(attributes.updated.clone(), vec![now.format(&TIME_FORMAT)?]);

		assert_eq!(
			super::has_mtime_changed(&mut cache, &entry, &attributes)?,
			CacheEntryStatus::Changed,
			"Modified entry should be considered changed",
		);

		Ok(())
	}
}
