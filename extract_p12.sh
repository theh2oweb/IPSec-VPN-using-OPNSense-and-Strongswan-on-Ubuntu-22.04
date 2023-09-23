#!/bin/bash

# YOUR <PARAMETERS>
P12=<certificate>.p12
OUTPUT=<peer>

# DO NOT MODIFY BELOW HERE

openssl version | grep -Ei "^openssl 3\.[0-9\.a-z]* " > /dev/null 2>&1
if [[ $? == 0 ]]; then
        echo "Using OpenSSL version 3"
	LEGACY="-legacy"

	# https://www.openssl.org/docs/man3.0/man1/openssl-pkcs12.html
	# -legacy
	    # In the legacy mode, the default algorithm for certificate encryption is RC2_CBC or
	    # 3DES_CBC depending on whether the RC2 cipher is enabled in the build. The default 
	    # algorithm for private key encryption is 3DES_CBC. If the legacy option is not specified, 
	    # then the legacy provider is not loaded and the default encryption algorithm for both 
	    # certificates and private keys is AES_256_CBC with PBKDF2 for key derivation.
else
        echo "Not using OpenSSL version 3"
	LEGACY=""
fi

read -sp "Enter P12 file password: " PASSWORD

echo ""
echo "### Extract private key ###"
openssl pkcs12 -in ${P12} -nocerts -out ${OUTPUT}.key ${LEGACY} -noenc -password pass:${PASSWORD}

echo ""
echo "### Extract certificates ###"
openssl pkcs12 -in ${P12} -clcerts -nokeys -out ${OUTPUT}.crt ${LEGACY} -password pass:${PASSWORD}

echo ""
echo "### Extract CA certificate ###"
openssl pkcs12 -in ${P12} -cacerts -nokeys ${LEGACY} -password pass:${PASSWORD} | openssl x509 -out ${OUTPUT}-CA.crt

echo ""
echo "### Check RSA key ###"
openssl rsa -check -noout -in ${OUTPUT}.key

echo ""
echo "### Verify private key matches certificate ###"
CERT=$(openssl x509 -noout -modulus -in ${OUTPUT}.crt | openssl md5)
KEY=$(openssl rsa -noout -modulus -in ${OUTPUT}.key | openssl md5)
if [[ $CERT == $KEY ]]; then
    echo "OK, ${OUTPUT}.key matches ${OUTPUT}.crt"
else
    echo "ERROR, ${OUTPUT}.key DOES NOT matches ${OUTPUT}.crt"
fi

echo ""
echo "### Verify certificate matches authority ###"
openssl verify -CAfile ${OUTPUT}-CA.crt ${OUTPUT}.crt

echo ""
