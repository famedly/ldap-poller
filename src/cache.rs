//! Caching mechanisms to check whether user data has changed
use std::collections::HashMap;

use ldap3::SearchEntry;
use sha2::{Digest, Sha256};
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
}

/// Cache data entries used to check whether an entry has changed
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CacheEntries {
	/// Store a hash of the relevant attribute values to check whether a user
	/// entry has changed.
	Hash(HashMap<String, Vec<u8>>),
	/// Use the modification time attribute to check whether a user entry has
	/// changed.
	Modified(HashMap<String, OffsetDateTime>),
	/// Don't cache anything, forward all results unconditionally
	None,
}

impl CacheEntries {
	/// Check's whether a user's data has changed
	pub(crate) fn has_changed(
		&mut self,
		entry: &SearchEntry,
		attributes: &AttributeConfig,
	) -> bool {
		match *self {
			CacheEntries::Hash(ref mut cache) => has_hash_changed(cache, entry),
			CacheEntries::Modified(ref mut cache) => {
				match has_mtime_changed(cache, entry, attributes) {
					Ok(has_changed) => has_changed,
					Err(err) => {
						tracing::warn!("Validating modification time failed: {err}");
						true
					}
				}
			}
			CacheEntries::None => true,
		}
	}
}

/// Check whether the modification time of an entry has changed
fn has_mtime_changed(
	times: &mut HashMap<String, OffsetDateTime>,
	entry: &SearchEntry,
	attributes: &AttributeConfig,
) -> Result<bool, Error> {
	let time = entry.attr_first(&attributes.updated).ok_or(Error::Missing)?;
	let time = PrimitiveDateTime::parse(time, &TIME_FORMAT)?.assume_utc();
	match times.get_mut(&entry.dn) {
		Some(cached) if time > *cached => {
			*cached = time;
			Ok(true)
		}
		Some(_) => Ok(false),
		None => {
			times.insert(entry.dn.clone(), time);
			Ok(true)
		}
	}
}

/// Check whether the hash of a search entry's contents has changed
fn has_hash_changed(hashes: &mut HashMap<String, Vec<u8>>, entry: &SearchEntry) -> bool {
	let mut hasher = Sha256::new();
	for attribute in entry.attrs.keys().chain(entry.bin_attrs.keys()) {
		// Guard against collisions
		hasher.update([0]);
		hasher.update(attribute);
		if let Some(values) = entry.attrs.get(attribute) {
			for value in values {
				// Guard against collisions
				hasher.update([1]);
				hasher.update(value);
			}
		}
		if let Some(values) = entry.bin_attrs.get(attribute) {
			for value in values {
				hasher.update([1]);
				hasher.update(value);
			}
		}
	}
	let new_hash = hasher.finalize().to_vec();
	match hashes.get_mut(&entry.dn) {
		// Unchanged entry
		Some(old_hash) if old_hash == &new_hash => false,
		// Entry has changed
		Some(old_hash) => {
			*old_hash = new_hash;
			true
		}
		// Entry is new
		None => {
			hashes.insert(entry.dn.clone(), new_hash);
			true
		}
	}
}

/// Errors that can occur when attempting to check if an entry has changed.
#[derive(Debug, thiserror::Error)]
enum Error {
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

	use crate::config::{AttributeConfig, TIME_FORMAT};

	#[test]
	fn has_hash_changed() -> Result<(), Box<dyn std::error::Error>> {
		let mut cache = HashMap::new();

		// Construct an example entry
		let mut entry = SearchEntry {
			dn: "uid=foo,ou=people,dc=example,dc=com".to_owned(),
			attrs: HashMap::from([
				("cn".to_owned(), vec!["Jane Doe".to_owned()]),
				("admin".to_owned(), vec!["FALSE".to_owned()]),
				("enabled".to_owned(), vec!["TRUE".to_owned()]),
			]),
			bin_attrs: HashMap::from([(
				"objectGUID".to_owned(),
				vec![vec![
					147, 123, 243, 42, 224, 235, 66, 224, 186, 238, 188, 8, 115, 89, 136, 214,
				]],
			)]),
		};

		// message for assertions that an entry is considered unchanged
		const UNMODIFIED: &str = "Unmodified entry should not be considered changed";

		assert!(
			super::has_hash_changed(&mut cache, &entry),
			"Newly inserted entry should be considered changed"
		);
		assert!(!super::has_hash_changed(&mut cache, &entry), "{UNMODIFIED}");

		// Replace string attribute value
		*entry.attrs.get_mut("admin").unwrap() = vec!["TRUE".to_owned()];
		assert!(
			super::has_hash_changed(&mut cache, &entry),
			"Modified attribute value should be considered changed"
		);
		assert!(!super::has_hash_changed(&mut cache, &entry), "{UNMODIFIED}");

		// TODO: Add tests for hash collision, added attribute value,
		// binary attribute change

		Ok(())
	}

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

		assert!(
			super::has_mtime_changed(&mut cache, &entry, &attributes)?,
			"Newly inserted entry should be considered changed",
		);
		assert!(
			!super::has_mtime_changed(&mut cache, &entry, &attributes)?,
			"Unmodified entry should not be considered changed",
		);

		// Change the modification time
		let now = now + Duration::seconds(30);
		entry.attrs.insert(attributes.updated.clone(), vec![now.format(&TIME_FORMAT)?]);

		assert!(
			super::has_mtime_changed(&mut cache, &entry, &attributes)?,
			"Modified entry should be considered changed",
		);

		Ok(())
	}
}
