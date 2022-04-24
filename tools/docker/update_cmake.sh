#!/bin/bash
source /etc/os-release
export DEBIAN_FRONTEND=noninteractive

install_kitware_repo() {
    GPG_KEYFILE=/usr/share/keyrings/kitware-archive-keyring.gpg
    wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor > $GPG_KEYFILE
    echo "deb [signed-by=$GPG_KEYFILE] https://apt.kitware.com/ubuntu/ ${UBUNTU_CODENAME} main" > /etc/apt/sources.list.d/kitware.list
    echo "Added Kitware repository for Ubuntu $UBUNTU_CODENAME"
}

if [[ "${UBUNTU_CODENAME}" == "xenial" ]]; then
    apt-get update && apt-get install -y apt-transport-https wget
    install_kitware_repo
elif [[ "${UBUNTU_CODENAME}" == "bionic" ]]; then
    apt-get update && apt-get install -y gpg wget
    install_kitware_repo
else
    # Ubuntu focal and later ship with a sufficiently new CMake version
    echo "No need to add Kitware repository for Ubuntu $UBUNTU_CODENAME"
fi
