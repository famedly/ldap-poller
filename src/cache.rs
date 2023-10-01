//! Caching mechanisms to check whether user data has changed
use std::collections::HashMap;

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
}

/// Cache data entries used to check whether an entry has changed
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CacheEntries {
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
	let id = entry.attr_first(&attributes.pid).ok_or(Error::Missing)?;
	let time = PrimitiveDateTime::parse(time, &TIME_FORMAT)?.assume_utc();
	match times.get_mut(id) {
		Some(cached) if time > *cached => {
			*cached = time;
			Ok(true)
		}
		Some(_) => Ok(false),
		None => {
			times.insert(id.to_owned(), time);
			Ok(true)
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
