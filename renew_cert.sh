#!/usr/bin/env bash

set -e

# Usage:
#
# ./renew_cert.sh example.com me@example.com

cd /home/private/nfsn-le

# Check if certificate is in need of renewal.
if openssl x509 -checkend 3000000 -noout -in "/home/protected/ssl/$1.crt"
then
	# Certificate is still valid.
	exit 0
else
	echo "Certificate for $1 is in need of renewal".
	mkdir -p backups
	mv "/home/protected/ssl/$1.crt" "backups/$1.crt"
	mv "/home/protected/ssl/$1.key" "backups/$1.key"
	./new_cert.sh "$1" "$2"
fi
