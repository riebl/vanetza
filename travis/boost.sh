set -e

pushd "$HOME/deps"

if [ -d ${BOOST_ROOT} ]; then
  echo "using Boost from Travis cache"
else
  wget -nc 'https://sourceforge.net/projects/boost/files/boost/1.58.0/boost_1_58_0.tar.bz2'
  tar xjf boost_1_58_0.tar.bz2

  pushd ${BOOST_ROOT}
  ./bootstrap.sh
  ./b2 --with-date_time --with-serialization --with-system --with-program_options
  popd
fi

popd
