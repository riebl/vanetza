set -e

git clone https://github.com/eclipse/titan.core.git $HOME/titan.core
cd $HOME/titan.core
make -j4
make install
