#!/bin/sh
#
# Convert a PEM certificate to PKCS12 using OpenSSL
#

if [ $# -ne 1 ] ; then
    echo "usage: $0 name"
    exit 1
fi

#openssl pkcs12 -export -out $1.pfx -inkey $1.pem -in $1.pem -certfile ca.pem
openssl pkcs12 -export -out $1.pfx -inkey $1.pem -in $1.pem 
