#!/usr/bin/env bash

set -e

# Usage:
#
# ./new_cert.sh example.com me@example.com
# user.key and user.pub already exist in the current directory.

cd /home/private/nfsn-le
mkdir -p /home/private/nfsn-le/certs
curl -s -o "certs/$1.chn" https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem

# Generate the certificate.
openssl genrsa 4096 > "certs/$1.key"
openssl req -new -sha256 -key "certs/$1.key" -subj "/CN=$1" > $1.csr

mkdir -p /home/public/.well-known/acme-challenge
python ./sign_csr.py --public-key user.pub --email "$2" "$1.csr" > "certs/$1.crt"
rm -rf $1.csr *.json *.sig /home/public/.well-known
echo "'cat certs/*' for info to supply to nfsn"
