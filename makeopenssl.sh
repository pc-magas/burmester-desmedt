#!/bin/bash

cd ./openssl
./config --prefix=$(pwd)/../build_openssl --openssldir=$(pwd)/../build_openssl
make && make test && make install