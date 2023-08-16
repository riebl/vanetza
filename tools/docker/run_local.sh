#!/bin/bash
set -e
: ${UBUNTU_VERSION:=bionic}
SCRIPT_DIR=$(dirname ${BASH_SOURCE[0]})
ROOT_DIR=$(readlink -m "${SCRIPT_DIR}/../..")

echo "Compiling Vanetza for Ubuntu ${UBUNTU_VERSION} and running tests..."
docker build --build-arg UBUNTU_VERSION=${UBUNTU_VERSION} --tag vanetza/docker-ci:${UBUNTU_VERSION} ${SCRIPT_DIR}
docker run --rm -it -v${ROOT_DIR}:/home/build-user/workspace:ro vanetza/docker-ci:${UBUNTU_VERSION}
