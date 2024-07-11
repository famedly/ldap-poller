//! Caching mechanisms to check whether user data has changed
use std::collections::{HashMap, HashSet};

use ldap3::SearchEntry;
use time::OffsetDateTime;

use crate::{config::AttributeConfig, entry::SearchEntryExt};

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
	Changed(SerializedSearchEntry),
}

impl Cache {
	/// Start a new comparison with the current entries
	pub(crate) fn start_comparison(&mut self) {
		self.missing = self.entries.get_expected();
	}

	/// Check whether an entry is changed or unchanged and update expected
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

/// Serialized version of a search entry
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SerializedSearchEntry {
	/// Entry DN.
	pub dn: String,
	/// Attributes.
	pub attrs: HashMap<String, Vec<String>>,
	/// Binary-valued attributes.
	pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

impl From<SearchEntry> for SerializedSearchEntry {
	fn from(entry: SearchEntry) -> Self {
		SerializedSearchEntry { dn: entry.dn, attrs: entry.attrs, bin_attrs: entry.bin_attrs }
	}
}

impl From<SerializedSearchEntry> for SearchEntry {
	fn from(entry: SerializedSearchEntry) -> Self {
		SearchEntry { dn: entry.dn, attrs: entry.attrs, bin_attrs: entry.bin_attrs }
	}
}

impl SearchEntryExt for SerializedSearchEntry {
	fn attr_first(&self, attr: &str) -> Option<&str> {
		self.attrs.get(attr)?.first().map(String::as_str)
	}

	fn bin_attr_first(&self, attr: &str) -> Option<&[u8]> {
		self.attrs
			.get(attr)
			.and_then(|attr| attr.first().map(String::as_bytes))
			.or_else(|| self.bin_attrs.get(attr).and_then(|attr| attr.first().map(Vec::as_slice)))
	}
}

/// Cache data entries used to check whether an entry has changed
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CacheEntries {
	/// Use the modification time attribute to check whether a user entry has
	/// changed.
	Modified(HashMap<Vec<u8>, SerializedSearchEntry>),
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
				match has_any_attr_changed(cache, entry, attributes_config) {
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
fn has_any_attr_changed(
	cache: &mut HashMap<Vec<u8>, SerializedSearchEntry>,
	entry: &SearchEntry,
	attributes_config: &AttributeConfig,
) -> Result<CacheEntryStatus, Error> {
	let id = entry.bin_attr_first(&attributes_config.pid).ok_or(Error::Missing)?;
	match cache.get_mut(id) {
		Some(old_entry) => {
			if attributes_config
				.attrs_to_track
				.iter()
				.chain(attributes_config.updated.iter())
				.any(|attr| entry.bin_attr_first(attr) != old_entry.bin_attr_first(attr))
			{
				let old_entry_clone = old_entry.clone();
				*old_entry = Into::<SerializedSearchEntry>::into(entry.clone());
				Ok(CacheEntryStatus::Changed(old_entry_clone))
			} else {
				Ok(CacheEntryStatus::Unchanged)
			}
		}
		None => {
			cache.insert(id.to_owned(), Into::<SerializedSearchEntry>::into(entry.clone()));
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
		entry::SearchEntryExt,
	};

	#[test]
	fn attr_first() {
		let entry = super::SerializedSearchEntry {
			dn: String::from("dontcare"),
			attrs: [(
				String::from("name"),
				vec![String::from("Foo Bar"), String::from("Bar McBaz")],
			)]
			.into_iter()
			.collect(),
			bin_attrs: HashMap::default(),
		};
		assert_eq!(
			entry.attr_first("attribute_does_not_exist"),
			None,
			"Undefined attributes should return None"
		);
		assert_eq!(entry.attr_first("name"), Some("Foo Bar"), "Should return the first value");
		assert_ne!(entry.attr_first("name"), Some("Bar McBaz"), "Should return the correct value");
	}

	#[test]
	fn has_any_attr_changed() -> Result<(), Box<dyn std::error::Error>> {
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
					(attributes.updated.unwrap(), vec![now.format(&TIME_FORMAT)?]),
					("enabled".into(), vec!["yes".into()]),
				])
			},
			bin_attrs: HashMap::new(),
		};

		assert_eq!(
			super::has_any_attr_changed(&mut cache, &entry, &attributes)?,
			CacheEntryStatus::Missing,
			"Newly inserted entry should be considered missing",
		);
		assert_eq!(
			super::has_any_attr_changed(&mut cache, &entry, &attributes)?,
			CacheEntryStatus::Unchanged,
			"Unmodified entry should not be considered changed",
		);

		let old = entry.clone();
		// Change the modification time
		let now = now + Duration::seconds(30);
		entry
			.attrs
			.insert(attributes.updated.as_ref().unwrap().clone(), vec![now.format(&TIME_FORMAT)?]);

		assert_eq!(
			super::has_any_attr_changed(&mut cache, &entry, &attributes)?,
			CacheEntryStatus::Changed(old.into()),
			"Modified entry should be considered changed",
		);

		assert_eq!(
			super::has_any_attr_changed(&mut cache, &entry, &attributes)?,
			CacheEntryStatus::Unchanged,
			"Unmodified entry should not be considered changed",
		);

		let old = entry.clone();

		entry.attrs.insert("enabled".into(), vec!["no".into()]);

		assert_eq!(
			super::has_any_attr_changed(&mut cache, &entry, &attributes)?,
			CacheEntryStatus::Changed(old.into()),
			"Modified entry should be considered changed",
		);

		Ok(())
	}
}
