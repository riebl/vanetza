set -e

pushd "$HOME/deps"

if [ -d ${CRYPTOPP_ROOT} ]; then
  echo "using Crypto++ from Travis cache"
else
  wget -nc 'https://sourceforge.net/projects/cryptopp/files/cryptopp/5.6.2/cryptopp562.zip'
  unzip cryptopp562.zip -d ${CRYPTOPP_ROOT}

  pushd ${CRYPTOPP_ROOT}
  make dynamic install CXXFLAGS="-fPIC -DNDEBUG -march=native -pipe" PREFIX=./install
  popd
fi

popd
