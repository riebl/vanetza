#!/bin/sh
GTEST_VERSION=1.6.0
GTEST_NAME=gtest-$GTEST_VERSION

wget -nc http://googletest.googlecode.com/files/${GTEST_NAME}.zip
unzip ${GTEST_NAME}.zip ${GTEST_NAME}/src/* ${GTEST_NAME}/include/*
rm -rf gtest-src
mv $GTEST_NAME gtest-src

