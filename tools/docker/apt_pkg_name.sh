#!/bin/bash
set -euo pipefail

source /etc/os-release
case $VERSION_CODENAME in
  bionic)
    ;&
  focal)
    ;&
  jammy)
    GEOGRAPHICLIB=libgeographic-dev
    ;;
  noble)
    GEOGRAPHICLIB=libgeographiclib-dev
    ;;
  *)
    echo "Unsupported Ubuntu version: $VERSION_CODENAME"
    exit 1
    ;;
esac

case $1 in
  geographiclib)
    echo $GEOGRAPHICLIB
    ;;
  *)
    echo "Unknown package name: $1"
    exit 1
    ;;
esac
