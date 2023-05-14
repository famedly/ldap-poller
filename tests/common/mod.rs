use std::error::Error;

use ldap3::{LdapConnAsync, SearchEntry};

pub async fn ldap_add_organizational_unit(
	ldap: &mut ldap3::Ldap,
	ou: &str,
) -> Result<(), Box<dyn Error>> {
	ldap.add(
		&format!("ou={},dc=example,dc=org", ou),
		vec![("objectClass", ["organizationalUnit"].into())],
	)
	.await?
	.success()?;
	Ok(())
}

pub async fn ldap_delete_organizational_unit(
	ldap: &mut ldap3::Ldap,
	ou: &str,
) -> Result<(), Box<dyn Error>> {
	ldap.delete(&format!("ou={},dc=example,dc=org", ou)).await?.success()?;
	Ok(())
}

pub async fn ldap_connect() -> Result<ldap3::Ldap, Box<dyn Error>> {
	let (conn, mut ldap) = LdapConnAsync::new("ldap://localhost:1389").await?;
	let _handle = tokio::spawn(async move {
		if let Err(err) = conn.drive().await {
			panic!("Ldap connection error {err}");
		}
	});
	ldap.simple_bind("cn=admin,dc=example,dc=org", "adminpassword").await?;
	Ok(ldap)
}

pub async fn ldap_delete_user(ldap: &mut ldap3::Ldap, cn: &str) -> Result<(), Box<dyn Error>> {
	ldap.delete(&format!("cn={},ou=users,dc=example,dc=org", cn)).await?.success()?;
	Ok(())
}

pub async fn ldap_add_user(
	ldap: &mut ldap3::Ldap,
	cn: &str,
	sn: &str,
) -> Result<(), Box<dyn Error>> {
	ldap.add(
		&format!("cn={},ou=users,dc=example,dc=org", cn),
		vec![("objectClass", ["inetOrgPerson"].into()), ("sn", [sn].into())],
	)
	.await?
	.success()?;
	Ok(())
}

pub async fn ldap_user_add_attribute(
	ldap: &mut ldap3::Ldap,
	cn: &str,
	attribute: &str,
	value: &str,
) -> Result<(), Box<dyn Error>> {
	ldap.modify(
		&format!("cn={},ou=users,dc=example,dc=org", cn),
		vec![ldap3::Mod::Add(attribute, [value].into())],
	)
	.await?
	.success()?;
	Ok(())
}

pub async fn ldap_search_user(
	ldap: &mut ldap3::Ldap,
	cn: &str,
) -> Result<SearchEntry, Box<dyn Error>> {
	let (result, _res) = ldap
		.search(
			&format!("cn={},ou=users,dc=example,dc=org", cn),
			ldap3::Scope::Base,
			"(objectClass=inetOrgPerson)",
			vec!["*"],
		)
		.await?
		.success()?;
	let entry = result.first().ok_or("No entry found")?.clone();
	Ok(SearchEntry::construct(entry))
}
