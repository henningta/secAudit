#!/bin/bash
#
# genkeys.sh - generate keys and certificates
#
# *.pub         - public key                    
# *.priv        - private key
# *.cert.csr    - certificate signing request
# *.cert        - signed certificate
#
# N.B:  Public keys are in X.509 style and pivate keys are in
#       the "traditional" or "SSLeay" format
#
# author(s)	Travis Henning, Timothy Thong


# set the error flag if a command fails
err=0   
function status()
{
        if [[ $? -ne 0 ]]; then err=1
        fi  
}

# base filenames of entities involved
UNTRUSTED='untrusted'
TRUSTED='trusted'

DIR=keys
if [[ ! -d $DIR ]]; then mkdir $DIR
fi

cd $DIR

# generate untrusted server keys and CSR

# generate 2048-bit RSA key pair
echo -e "\n===> Generating keys for the untrusted server...\n"
openssl genrsa -out ${UNTRUSTED}.priv 2048
status

# export public key to separate file
openssl rsa -in ${UNTRUSTED}.priv -outform PEM -pubout -out ${UNTRUSTED}.pub

# create certificate signing request (CSR) file for untrusted server
echo -e "\n===> Generating CSR for untrusted server...\n"
openssl req -new -key ${UNTRUSTED}.priv \
 -subj "/C=US/ST=Indiana/O=Purdue University/CN=Untrusted Server/" \
> ${UNTRUSTED}.cert.csr
status

# generate trusted server keys and CSR

echo -e "\n===> Generating keys for trusted server CSR...\n"
openssl genrsa -out ${TRUSTED}.priv 2048
status

openssl rsa -in ${TRUSTED}.priv -outform PEM -pubout -out ${TRUSTED}.pub
status

# export trusted server public key to separate file
openssl rsa -in ${TRUSTED}.priv -outform PEM -pubout -out ${TRUSTED}.pub
status

# trusted server acts as a CA and self-signs it's own cert
echo -e "\n===> Self-signing trusted server cert"
openssl req -new -x509  -days 365 -in ${TRUSTED}.cert.csr -key ${TRUSTED}.priv \
 -out ${TRUSTED}.cert -subj "/C=US/ST=Indiana/O=Purdue University/CN=Trusted Server/" 
status

# trusted server signs the CSR
echo -e "\n===> Signing certificate of untrusted server...\n"
openssl x509 -req -in ${UNTRUSTED}.cert.csr -out ${UNTRUSTED}.cert \
 -CA ${TRUSTED}.cert -CAkey ${TRUSTED}.priv -CAcreateserial
status

if [[ $err -eq 1 ]] ; then 
        echo -e "\nOne or more errors had occurred\n"
else
        echo -e "\nAll keys and certificate generated successfully\n"
fi

