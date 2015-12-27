#!/usr/bin/env bash

set -e

# Usage:
#
# ./new_cert.sh example.com me@example.com
# user.key and user.pub already exist in the current directory.

openssl genrsa 4096 > $1.key
openssl req -new -sha256 -key $1.key -subj "/CN=$1" > $1.csr

mkdir -p /home/public/.well-known/acme-challenge
curl -s -o $1.chn https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem

python sign_csr.py --public-key user.pub --email $2 $1.csr > $1.crt

rm $1.csr *.json *.sig /home/public/.well-known/acme-challenge/*
