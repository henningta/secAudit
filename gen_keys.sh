#!/bin/bash
#
# genkeys.sh - generate keys and certificates
#
# *.pub         - public key                    
# *.priv        - private key
# *.cert.csr    - certificate signing request
# *.cert        - signed certificate


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

# generate 2048-bit RSA key pair
echo -e "\n===> Generating keys for the untrusted server...\n"
openssl genrsa -out ${UNTRUSTED}.priv 2048
status

# export public key to separate file
openssl rsa -in ${UNTRUSTED}.priv -outform PEM -pubout -out ${UNTRUSTED}.pub

# generate trusted server keys and CSR
echo -e "\n===> Generating keys and self-signing trusted server CSR...\n"
openssl req -x509 -nodes -newkey rsa:2048 -keyout ${TRUSTED}.priv -outform PEM \
 -out ${TRUSTED}.cert \
 -subj "/C=US/ST=Indiana/O=Purdue University/CN=Trusted Server/" 
status

# export trusted server public key to separate file
openssl rsa -in ${TRUSTED}.priv -outform PEM -pubout -out ${TRUSTED}.pub
status

# create certificate signing request (CSR) file for untrusted server
echo -e "\n===> Generating CSR of untrusted server...\n"
openssl req -new -key ${UNTRUSTED}.priv \
 -subj "/C=US/ST=Indiana/O=Purdue University/CN=Untrusted Server/" \
> ${UNTRUSTED}.cert.csr
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

