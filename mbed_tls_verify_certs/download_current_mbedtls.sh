#!/bin/sh

MBED_VER=`curl -s https://tls.mbed.org/download/latest-stable-version`
if [ $? -ne 0 ]; then
	echo "Failed to get current MBED TLS version."
	exit
fi

curl -s https://tls.mbed.org/download/mbedtls-$MBED_VER-gpl.tgz | tar -xz
if [ $? -ne 0 ]; then
	echo "Failed to get current MBED TLS source."
	exit
fi

sed -i "s/MBED_DIR =.*/MBED_DIR = mbedtls-$MBED_VER/" Makefile

echo "Success!  You should run \`make\` now."
