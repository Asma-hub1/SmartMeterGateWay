#!/bin/bash
echo "Generating BSI-compliant certificates (Direct Pinning/TOFU model)..."

# Create certificates directory
mkdir -p certificates

# Generate unique self-signed certificates for each device
# These are CT_Selfsigned certificates as per BSI spec

echo "1. Generating SMGW self-signed certificate (GW_HAN_TLS_CRT)..."
openssl ecparam -genkey -name prime256v1 -out certificates/smgw-key.pem
openssl req -new -x509 -key certificates/smgw-key.pem -out certificates/smgw-cert.pem \
  -days 3650 -subj "/C=DE/O=SMGW-Device/CN=smgw-$(date +%s)" \
  -addext "keyUsage = digitalSignature, keyEncipherment" \
  -addext "extendedKeyUsage = serverAuth"

echo "2. Generating CLS self-signed certificate..."
openssl ecparam -genkey -name prime256v1 -out certificates/cls-key.pem
openssl req -new -x509 -key certificates/cls-key.pem -out certificates/cls-cert.pem \
  -days 3650 -subj "/C=DE/O=CLS-Device/CN=cls-$(date +%s)" \
  -addext "keyUsage = digitalSignature, keyEncipherment" \
  -addext "extendedKeyUsage = clientAuth"

echo "3. Generating Backend self-signed certificate..."
openssl ecparam -genkey -name prime256v1 -out certificates/backend-key.pem
openssl req -new -x509 -key certificates/backend-key.pem -out certificates/backend-cert.pem \
  -days 3650 -subj "/C=DE/O=Backend-Server/CN=backend-$(date +%s)" \
  -addext "keyUsage = digitalSignature, keyEncipherment" \
  -addext "extendedKeyUsage = serverAuth"

echo "4. Generating certificate fingerprints for verification..."
openssl x509 -fingerprint -sha256 -noout -in certificates/smgw-cert.pem | cut -d'=' -f2 > certificates/smgw-fingerprint.txt
openssl x509 -fingerprint -sha256 -noout -in certificates/cls-cert.pem | cut -d'=' -f2 > certificates/cls-fingerprint.txt
openssl x509 -fingerprint -sha256 -noout -in certificates/backend-cert.pem | cut -d'=' -f2 > certificates/backend-fingerprint.txt

echo "All certificates generated!"
echo "Fingerprints:"
echo "  SMGW:    $(cat certificates/smgw-fingerprint.txt)"
echo "  CLS:     $(cat certificates/cls-fingerprint.txt)"
echo "  Backend: $(cat certificates/backend-fingerprint.txt)"