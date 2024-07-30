#!/bin/bash
set -e

cd "$(dirname "$0")"
openssl req -x509 -nodes -new -sha256 -days 358000 -newkey rsa:2048 -keyout RootCA.key -out RootCA.pem -subj "/C=DE/CN=ldap-poller"
openssl x509 -outform pem -in RootCA.pem -out RootCA.crt
openssl req -x509 -out localhost.crt -keyout localhost.key -newkey rsa:2048 -nodes -sha256 -CA RootCA.pem -CAkey RootCA.key -subj '/CN=localhost' -extensions EXT -config <( printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
openssl req -x509 -nodes -sha256 -newkey rsa:2048 -CAkey RootCA.key -CA RootCA.crt -keyout client.key -out client.crt -subj "/CN=admin.example.org"
