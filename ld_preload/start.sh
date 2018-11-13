#!/bin/sh

./main

./main "Hello, World!"

LD_PRELOAD=`pwd`/evil_lib.so ./main

LD_PRELOAD=`pwd`/evil_lib.so ./main "Hello, World!"
