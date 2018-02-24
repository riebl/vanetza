set -e

pushd "$HOME/deps"

wget -nc --no-check-certificate "https://cmake.org/files/v3.1/cmake-${CMAKE_VERSION}.tar.gz"
tar xzf cmake-${CMAKE_VERSION}.tar.gz

popd
