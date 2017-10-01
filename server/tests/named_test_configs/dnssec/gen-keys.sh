#!/bin/bash

OPENSSL=/usr/local/opt/openssl/bin/openssl

# Install with cargo install kt
KT=kt

RSA_2048=rsa_2048.pem

[ -f ${RSA_2048:?} ] || ${OPENSSL:?} genrsa -des3 -out ${RSA_2048:?} 2048

ED25519=ed25519.pk8

[ -f ${ED25519:?} ] || ${KT:?} generate ed25519 --out=${ED25519:?}