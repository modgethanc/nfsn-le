#!/usr/bin/env bash

set -e

# Usage:
#
# ./setup.sh example.com me@example.com

cd /home/private/nfsn-le

# Check for existing LE keys.
if [ ! -f "user.key" ] && [ ! -f "user.pub" ]
then
	echo "Generating new LE keys"
	openssl genrsa 4096 > user.key
	openssl rsa -in user.key -pubout > user.pub
fi

# Output renewal task.
echo <<EOM
Add this as a scheduled task:

tag: tls$1
shell command: /home/private/nfsn-le/renew.sh "$1" "$2"
user: 'me'
day: friday
hour: 0
date: *
EOM

# Generate new cert.
./new_cert.sh $1 $2
