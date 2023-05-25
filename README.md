# ldap-poller

[![pipeline status][badge-pipeline-img]][badge-pipeline-url]
[![coverage report][badge-coverage-img]][badge-coverage-url]
[![docs main][badge-docs-main-img]][badge-docs-main-url]

[badge-pipeline-img]: https://gitlab.com/famedly/company/backend/libraries/ldap-poller/badges/main/pipeline.svg
[badge-pipeline-url]: https://gitlab.com/famedly/company/backend/libraries/ldap-poller/-/commits/main
[badge-coverage-img]: https://gitlab.com/famedly/company/backend/libraries/ldap-poller/badges/main/coverage.svg
[badge-coverage-url]: https://gitlab.com/famedly/company/backend/libraries/ldap-poller/-/commits/main
[badge-docs-main-img]: https://img.shields.io/badge/docs-main-blue
[badge-docs-main-url]: https://famedly.gitlab.io/company/backend/libraries/ldap-poller/index.html

Repeatedly poll an LDAP directory server for user information.

The library works by repeatedly performing a search against a directory
server, and then using the configured caching mechanism to check if the
entry for a given user (disambiguated by the "persistent ID" attribute) has
changed since the previously performed search. If any changed or new entries
are found

For a general primer on LDAP, the [introduction] in the `ldap3` crate which
is used here for interfacing with LDAP is an excellent resource. The site
"firstyear's blog-a-log" also has [a guide][firstyear] which is more
visually oriented and goes into more detail about searching

[introduction]: https://github.com/inejge/ldap3/blob/master/LDAP-primer.md
[firstyear]: https://fy.blackhats.net.au/blog/html/pages/ldap_guide_part_1_foundations.html

## Getting started
A minimal example of running the client might look like so:
```rust
use ldap_poller::{
	config::{
		AttributeConfig, CacheMethod, Config, ConnectionConfig, Searches,
	},
	ldap::{Ldap, UserEntry},
};
use url::Url;

// Configuration can also be deserialized with serde. It's hand-constructed
// here for demonstration purposes.
let config = Config {
	url: Url::parse("ldap://localhost")?,
	connection: ConnectionConfig::default(),
	search_user: "admin".to_owned(),
	search_password: "verysecret".to_owned(),
	searches: Searches {
		user_base: "ou=people,dc=example,dc=com".to_owned(),
		user_filter: "(objectClass=inetOrgPerson)".to_owned(),
		page_size: None,
	},
	attributes: AttributeConfig {
		pid: "objectGUID".to_owned(),
		updated: "mtime".to_owned(),
		name: "cn".to_owned(),
		admin: "admin".to_owned(),
		enabled: "enabled".to_owned(),
	},
	cache_method: CacheMethod::ModificationTime,
};

let (mut client, mut receiver) = Ldap::new(config.clone(), None);
tokio::spawn(async move {
	client.sync(std::time::Duration::from_secs(5)).await;
});
while let Some(entry) = receiver.recv().await {
	println!("Received entry: {entry:#?}");
	let user = UserEntry::from_search(entry, &config.attributes)?;
	println!("Parsed entry as: {user:#?}");
}

```

## Limitations
* This library (currently) does not make use of any controls (i.e.
  extensions) such as [persistent search] or [content synchronization] for
  reducing the overhead of replication.
* Updated entries are sent via a channel. This may not be an ideal design
  approach.
* [secrecy](https://docs.rs/secrecy) is not used for storing the search user
  password, it probably should be
* Does not currently have any handling for user entries being removed from
  the directory tree.

[persistent search]: https://datatracker.ietf.org/doc/html/draft-ietf-ldapext-psearch-03
[content synchronization]: https://www.rfc-editor.org/rfc/rfc4533.html

## Testing

This library has two test modes: mock and integration tests. To run the mock tests without additional dependencies: 

```
cargo test
```

For the integration tests it uses a docker compose setup with a ready-to-go LDAP
server. The setup and teardown is automated with the tool
`cargo-make` which uses the tasks in `Makefile.toml`.
The docker compose files are in `docker-compose/`. To run the integration tests, run the following commands:

```
cargo make start-docker-setup
cargo test -- --ignored
cargo make stop-docker-setup 
```


## Lints

We have plenty of lints in `lints.toml` that we use. Cargo currently does not natively support an extra file for lints, so we use `cargo-lints`. To check everything with our lints, run this locally:

```sh
cargo lints clippy --workspace --all-targets
```

and this in your IDE:
```sh
cargo lints clippy --workspace --all-targets --message-format=json
```

A few lints are commented out in `lints.toml`. This is because they should not be enabled by default, because e.g. they have false positives. However, they can be very useful sometimes.

## Pre-commit usage

1. If not installed, install with your package manager, or `pip install --user pre-commit`
2. Run `pre-commit autoupdate` to update the pre-commit config to use the newest template
3. Run `pre-commit install` to install the pre-commit hooks to your local environment

---

# Famedly

**This project is part of the source code of Famedly.**

We think that software for healthcare should be open source, so we publish most
parts of our source code at [gitlab.com/famedly](https://gitlab.com/famedly/company).

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of
conduct, and the process for submitting pull requests to us.

For licensing information of this project, have a look at the [LICENSE](LICENSE.md)
file within the repository.

If you compile the open source software that we make available to develop your
own mobile, desktop or embeddable application, and cause that application to
connect to our servers for any purposes, you have to aggree to our Terms of
Service. In short, if you choose to connect to our servers, certain restrictions
apply as follows:

- You agree not to change the way the open source software connects and
  interacts with our servers
- You agree not to weaken any of the security features of the open source software
- You agree not to use the open source software to gather data
- You agree not to use our servers to store data for purposes other than
  the intended and original functionality of the Software
- You acknowledge that you are solely responsible for any and all updates to
  your software

No license is granted to the Famedly trademark and its associated logos, all of
which will continue to be owned exclusively by Famedly GmbH. Any use of the
Famedly trademark and/or its associated logos is expressly prohibited without
the express prior written consent of Famedly GmbH.

For more
information take a look at [Famedly.com](https://famedly.com) or contact
us by [info@famedly.com](mailto:info@famedly.com?subject=[GitLab]%20More%20Information%20)
