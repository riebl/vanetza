#!/bin/bash
set -e
REPO=${1:?missing git repository}
BRANCH=${2:-master}
COMMIT=${3:-HEAD}

git clone --depth=25 --branch=${BRANCH} $REPO vanetza
cd vanetza
git checkout ${COMMIT}
