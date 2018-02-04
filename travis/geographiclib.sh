set -e

pushd "$HOME/deps"

if [ -d ${GEOGRAPHICLIB_ROOT} ]; then
  echo "using GeographicLib from Travis cache"
else
  wget -nc 'https://sourceforge.net/projects/geographiclib/files/distrib/archive/GeographicLib-1.37.tar.gz'
  tar xzf GeographicLib-1.37.tar.gz

  pushd ${GEOGRAPHICLIB_ROOT}
  ./configure
  make
  popd
fi
