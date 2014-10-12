#!/bin/bash

# generate 2048-bit RSA key pair
openssl genrsa -des3 -out private.pem 2048

# export public key to separate file
echo "Exporting public key to file..."
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
