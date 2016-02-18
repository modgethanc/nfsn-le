#!/usr/bin/env bash

set -e

# Usage:
#
# ./renew_cert.sh example.com me@example.com

cd /home/protected/ssl

# Check if certificate is in need of renewal.
if openssl x509 -checkend 2592000 -noout -in $1.crt
then
	# Certificate is still valid.
	exit 0
else
	# Certificate has less than one month to go, renewal is needed.
	mkdir -p backups
	mv $1.crt backups/$1.crt.bak
	mv $1.key backups/$1.key.bak
	/home/protected/ssl/nfsn-le/new_cert.sh $1 $2
fi
