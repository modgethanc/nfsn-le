#!/usr/bin/env bash

set -e

# Usage:
#
# ./new_cert.sh example.com me@example.com
# user.key and user.pub already exist in the current directory.

cd /home/private/nfsn-le
mkdir -p /home/protected/ssl
curl -s -o "/home/protected/ssl/$1.chn" https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem

# Generate the certificate.
openssl genrsa 4096 > "/home/protected/ssl/$1.key"
openssl req -new -sha256 -key "/home/protected/ssl/$1.key" -subj "/CN=$1" > $1.csr

mkdir -p /home/public/.well-known/acme-challenge
if [ -z "$2" ]
then
	echo "Using anonymous registration."
	python /home/protected/ssl/nfsn-le/sign_csr.py --public-key user.pub $1.csr > "/home/protected/ssl/$1.crt"
else
	python /home/protected/ssl/nfsn-le/sign_csr.py --public-key user.pub --email $2 $1.csr > "/home/protected/ssl/$1.crt"
fi
rm -rf $1.csr *.json *.sig /home/public/.well-known
