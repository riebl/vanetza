#!/usr/bin/env bash

BUILD_DIR=${BUILD_DIR:-$PWD/../../build}
ITS_G5_TS_DIR=$BUILD_DIR/its-g5-ts

echo "Using build directory '$BUILD_DIR'"

set -e
set -x

if [ ! -d $BUILD_DIR ]; then
    echo "Build directory '$BUILD_DIR' does not exist."
    exit 1
fi

needs_update=0

if [ ! -d $ITS_G5_TS_DIR ]; then
    git clone https://github.com/elnrnag/ITSG5_TS_Titanized_TA $ITS_G5_TS_DIR

    wget https://netcologne.dl.sourceforge.net/project/jnetpcap/jnetpcap/1.3/jnetpcap-1.3.0-1.ubuntu.x86_64.tgz -O $BUILD_DIR/jnetpcap.tgz
    pushd $BUILD_DIR
    tar -xvzf jnetpcap.tgz
    popd

    needs_update=1
else
    pushd $ITS_G5_TS_DIR

    if git checkout master && git fetch origin master && [ `git rev-list HEAD...origin/master --count` != 0 ] && git merge origin/master; then
        needs_update=1
    fi

    popd
fi

if [ $needs_update = 1 ]; then
    pushd $ITS_G5_TS_DIR

    mkdir build || true
    pushd build
    ../src/install.script
    make
    popd

    popd
fi

if ip a show vanet0; then
    echo "Interface vanet0 already exists, aborting."
    exit 1
fi

if ip a show vanet1; then
    echo "Interface vanet1 already exists, aborting."
    exit 1
fi

echo "Creating network interfaces..."
sudo ip link add vanet0 type veth peer name vanet1
sudo ip link set dev vanet0 up
sudo ip link set dev vanet1 up

function clean_up_interfaces {
    # Deleting one interface deletes both, because they're peered
    echo "Cleaning up network interfaces..."
    sudo ip link delete vanet0
}

trap clean_up_interfaces EXIT

if [ ! -f $BUILD_DIR/bin/uppertester ]; then
    echo "Missing $BUILD_DIR/bin/uppertester, did you compile it?"
    exit 1
fi

# Starting UpperTester in the background
sudo $BUILD_DIR/bin/uppertester -i vanet0 &
UPPERTESTER_PID=$!

# Allow observing output on failures
sleep 3

function clean_up_uppertester {
    echo "Shutting down UpperTester..."
    sudo pkill -TERM -P $UPPERTESTER_PID && wait $UPPERTESTER_PID || true

    clean_up_interfaces
}

trap clean_up_uppertester EXIT

# Starting TRI mapper
pushd $ITS_G5_TS_DIR/titan_tri_mapper

# Set correct MAC address and UpperTester address in test adapter configuration
VANET_MAC=$(ip a show vanet1 | grep "link/ether" | awk '{print $2}' | sed 's/://g')
sed -i -E "s/\"LocalEthernetMAC\": \"([a-f0-9]+)\"/\"LocalEthernetMAC\": \"$VANET_MAC\"/" taproperties.cfg
sed -i -E 's/"UpperTesterSettings": "192.168.1.100:12345"/"UpperTesterSettings": "127.0.0.1:5000"/' taproperties.cfg

sudo java -Djava.library.path=$BUILD_DIR/jnetpcap-1.3.0 -jar TitanTriMapper.jar -l info &
TITAN_TRI_MAPPER_PID=$!

function clean_up_titan_tri_mapper {
    echo "Shutting down TITAN TRI Mapper..."
    sudo pkill -TERM -P $TITAN_TRI_MAPPER_PID && wait $TITAN_TRI_MAPPER_PID || true

    clean_up_uppertester
}

trap clean_up_titan_tri_mapper EXIT

popd

# Wait until mapper is up
sleep 3

cp ./ttcn3.config $ITS_G5_TS_DIR/build/cfg.cfg
pushd $ITS_G5_TS_DIR/build

ttcn3_start ./ITS_Exec cfg.cfg | tee ttcn3.log | grep -v TRI_encode | grep -v TRI_decode

popd
