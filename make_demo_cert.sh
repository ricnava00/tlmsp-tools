#!/bin/sh

tag=$1
if [ -n "$tag" ]; then
    tag="${tag}-"
fi

echo "Creating ${tag}key.pem and ${tag}cert.pem"
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -keyout ${tag}key.pem -out ${tag}cert.pem -subj "/C=CC/ST=ST/L=LL/O=OO/OU=OU/CN=example.com"
