set -e

git clone https://github.com/eclipse/titan.core.git $HOME/titan.core

cp travis/titan-makefile $HOME/titan.core/Makefile.personal
cd $HOME/titan.core

make -j4
make install
