#!/usr/bin/env bash

set -e

# Usage:
#
# ./renew_cert.sh example.com me@example.com

certsdir="/home/protected/certs"
backupdir="/home/protected/certbackup"

cd /home/private/nfsn-le

# Check if certificate is in need of renewal.
if openssl x509 -checkend 3000000 -noout -in "$certsdir/$1.crt"
then
	# Certificate is still valid.
	exit 0
else
	echo "Certificate for $1 is in need of renewal".
	mkdir -p $backupdir
	mv "$certsdir/$1.crt" "$backupdir/$1.crt"
	mv "$certsdir/$1.key" "$backupdir/$1.key"
	./new_cert.sh "$1" "$2"
fi
