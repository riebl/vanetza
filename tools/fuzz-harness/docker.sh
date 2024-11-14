#!/bin/bash
set -eu
HARNESS_DIR=$(realpath $(dirname $0))
SOURCE_DIR=$HARNESS_DIR/../..

docker build $HARNESS_DIR
IMAGE=$(docker build -q $HARNESS_DIR)

mkdir -p $HARNESS_DIR/output
docker run --rm -it \
    --security-opt seccomp=unconfined \
    -v$SOURCE_DIR:/source:ro \
    -v$HARNESS_DIR/input:/input:ro \
    -v$HARNESS_DIR/output:/output \
    -e HOST_USER_ID=$(id -u) -e HOST_GROUP_ID=$(id -g) \
    $IMAGE
