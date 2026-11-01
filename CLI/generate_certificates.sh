#!/bin/bash
echo "=== Generating BSI Direct Trust Certificates ==="
echo ""

# Create certificates directory
mkdir -p certificates

echo "1. Generating SMGW self-signed certificate..."
openssl ecparam -genkey -name prime256v1 -out certificates/smgw-key.pem
openssl req -new -x509 -key certificates/smgw-key.pem -out certificates/smgw-cert.pem \
  -days 365 -subj "/C=DE/ST=Berlin/L=Berlin/O=SMGW-Device/CN=smgw.local/emailAddress=smgw@example.com" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "keyUsage=digitalSignature, keyEncipherment, keyAgreement" \
  -addext "extendedKeyUsage=serverAuth, clientAuth" \
  -addext "subjectAltName=DNS:smgw.local,IP:127.0.0.1"

echo "2. Generating CLS self-signed certificate..."
openssl ecparam -genkey -name prime256v1 -out certificates/cls-key.pem
openssl req -new -x509 -key certificates/cls-key.pem -out certificates/cls-cert.pem \
  -days 365 -subj "/C=DE/ST=Berlin/L=Berlin/O=CLS-Device/CN=cls.local/emailAddress=cls@example.com" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "keyUsage=digitalSignature, keyEncipherment" \
  -addext "extendedKeyUsage=clientAuth"

echo "3. Generating Backend self-signed certificate..."
openssl ecparam -genkey -name prime256v1 -out certificates/backend-key.pem
openssl req -new -x509 -key certificates/backend-key.pem -out certificates/backend-cert.pem \
  -days 365 -subj "/C=DE/ST=Berlin/L=Berlin/O=Backend-Server/CN=backend.local/emailAddress=backend@example.com" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "keyUsage=digitalSignature, keyEncipherment, keyCertSign" \
  -addext "extendedKeyUsage=serverAuth"

echo "4. Generating certificate fingerprints..."
openssl x509 -fingerprint -sha256 -noout -in certificates/smgw-cert.pem | cut -d'=' -f2 > certificates/smgw-fingerprint.txt
openssl x509 -fingerprint -sha256 -noout -in certificates/cls-cert.pem | cut -d'=' -f2 > certificates/cls-fingerprint.txt
openssl x509 -fingerprint -sha256 -noout -in certificates/backend-cert.pem | cut -d'=' -f2 > certificates/backend-fingerprint.txt

# Create empty pinned files
touch certificates/pinned_smgw_certs.txt
touch certificates/pinned_smgw_cert.pem

echo ""
echo "=== Certificates Generated Successfully ==="
echo ""
echo "Fingerprints:"
echo "-------------"
echo "SMGW:    $(cat certificates/smgw-fingerprint.txt)"
echo "CLS:     $(cat certificates/cls-fingerprint.txt)"
echo "Backend: $(cat certificates/backend-fingerprint.txt)"
echo ""
echo "Files created in 'certificates/' directory:"
ls -la certificates/