#!/bin/sh

CERT_DIR="certs"
CERT_RSA_BITS=4096
CERT_DAYS=365

# I can't say exactly why, but omitting the common name (/CN=) led to 
# failures between the MBED TLS client and python2.7 ssl (openssl)
#
# The error was "Level: Fatal, Description: Unknown CA", per wireshark:
# TCP Payload (TLS1.2): 15 03 03 00 02 02 30
CERT_CA_SUBJ="/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=CertificateAuthority"
CERT_CLIENT_SUBJ="/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=Client"
CERT_SERVER_SUBJ="/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=Server"


# Gen CA key and cert
openssl req -x509 -new -newkey rsa:$CERT_RSA_BITS -nodes -keyout $CERT_DIR/CA.key -sha256 -days $CERT_DAYS -out $CERT_DIR/CA.pem -subj "$CERT_CA_SUBJ" 2>/dev/null
if [ $? -ne 0 ]; then
	echo "Failed to create CA certificate ($?)"
	exit
fi

# Gen client key and certificate signing request (CSR)
openssl req -new -newkey rsa:$CERT_RSA_BITS -nodes -keyout $CERT_DIR/Client.key -sha256 -days $CERT_DAYS -out $CERT_DIR/Client.csr -subj "$CERT_CLIENT_SUBJ" 2>/dev/null
if [ $? -ne 0 ]; then
	echo "Failed to create client CSR"
	exit
fi

# Gen server key and certificate signing request (CSR)
openssl req -new -newkey rsa:$CERT_RSA_BITS -nodes -keyout $CERT_DIR/Server.key -sha256 -days $CERT_DAYS -out $CERT_DIR/Server.csr -subj "$CERT_SERVER_SUBJ" 2>/dev/null
if [ $? -ne 0 ]; then
	echo "Failed to create server CSR"
	exit
fi

# Sign client CSR, creating client cert
openssl x509 -req -in $CERT_DIR/Client.csr -CA $CERT_DIR/CA.pem -CAkey $CERT_DIR/CA.key -CAcreateserial -out $CERT_DIR/Client.pem 2>/dev/null
if [ $? -ne 0 ]; then
	echo "Failed to sign client CSR"
	exit
fi

# Sign server CSR, creating server cert
openssl x509 -req -in $CERT_DIR/Server.csr -CA $CERT_DIR/CA.pem -CAkey $CERT_DIR/CA.key -CAserial $CERT_DIR/CA.srl -out $CERT_DIR/Server.pem 2>/dev/null
if [ $? -ne 0 ]; then
	echo "Failed to sign server CSR"
	exit
fi

echo "The following files have been created in \"$CERT_DIR/\":\n" \
	     "\tCA.key\t\t-\tThe CA's private key\n" \
	     "\tCA.pem\t\t-\tThe CA's x509 certificate\n" \
	     "\tCA.srl\t\t-\tThe CA's serial number file\n" \
	     "\tClient.key\t-\tThe client's private key\n" \
	     "\tClient.csr\t-\tThe client's CSR\n" \
	     "\tClient.pem\t-\tThe client's CA-signed certificate\n" \
	     "\tServer.key\t-\tThe server's private key\n" \
	     "\tServer.csr\t-\tThe server's CSR\n" \
	     "\tServer.pem\t-\tThe server's CA-signed certificate\n" \
	     "\n\nSave all .key and .pem files!"
