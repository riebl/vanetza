set -e

git clone https://github.com/eclipse/titan.core.git $HOME/titan.core
cd $HOME/titan.core

cp travis/titan-makefile $HOME/titan.core/Makefile.personal

make -j4
make install
