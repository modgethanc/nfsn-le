#!/usr/bin/env bash

# Usage:
#
# ./renew_cert.sh example.com me@example.com

# Check if certificate is in need of renewal.
if openssl x509 -checkend 2592000 -noout -in $1.crt
then
	# Certificate is still valid.
	exit 0
else
	# Certificate has less than one month to go, renewal is needed.
	mv $1.crt $1.crt.bak
	mv $1.key $1.key.bak
	./new_cert.sh $1 $2
fi
