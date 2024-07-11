//! Helper methods for extracting data from search results.
use ldap3::SearchEntry;

use crate::error::Error;

/// An extension trait for [`SearchEntry`] that provides convenience methods for
/// extracting data.
pub trait SearchEntryExt {
	/// Get the first value of an attribute. Will return `None` if attribute
	/// value is not valid UTF-8.
	fn attr_first(&self, attr: &str) -> Option<&str>;

	/// Get the first value of an attribute, in binary form
	fn bin_attr_first(&self, attr: &str) -> Option<&[u8]>;

	/// Get the first value of an attribute, interpreted as a boolean.
	fn bool_first(&self, attr: &str) -> Option<Result<bool, Error>> {
		match self.attr_first(attr) {
			Some("TRUE") => Some(Ok(true)),
			Some("FALSE") => Some(Ok(false)),
			Some(_) => Some(Err(Error::Invalid(attr.to_owned()))),
			None => None,
		}
	}
}

impl SearchEntryExt for SearchEntry {
	fn attr_first(&self, attr: &str) -> Option<&str> {
		let attr = self.attrs.get(attr)?;
		attr.first().map(String::as_str)
	}

	fn bin_attr_first(&self, attr: &str) -> Option<&[u8]> {
		if let Some(attr) = self.attrs.get(attr) {
			return attr.first().map(String::as_bytes);
		}

		if let Some(attr) = self.bin_attrs.get(attr) {
			return attr.first().map(Vec::as_slice);
		}
		None
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use ldap3::SearchEntry;

	use super::SearchEntryExt;

	#[test]
	fn attr_first() {
		let entry = SearchEntry {
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
}
