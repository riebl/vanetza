Title: Running socktap on nfiniity devices

# Introduction
The CUBE EVK from [nfiniity](https://www.nfiniity.com/#portfolio) fully supports the Vanetza stack and its socktap application. An integrated V2X module listens for requests whether from a local or remote application. The communication protocol between host and V2X module is covered in Google's Protobuf that is used in the respective link-layer implementation.

# Configuration
Before building and running socktap you need to configure the v2x module and the wifi once.

## V2X Radio Configuration - C-V2X or DSRC
First of all select your desired radio configuration using the `v2xconfig` tool:

    :::shell
    # start dsrc or cv2x and enable auto-start
    v2xconfig start enable dsrc 

## Connect to your local WiFi
This is only need for the wireless remote radio mode.

    :::shell
    sudo nmcli dev wifi connect '<ssid>' password '<password>'
    # get your ip
    ip a

# Building and Running Socktap for Wireless Mode
You can build and run socktap directly on your personal computer and select `cube-evk` as link-layer. The EVK runs gpsd as well to feed socktap with GNSS data. In this mode, the host applicaton and the EVK do not need to be at the same location. Moreover, the integrated LTE module allows the user to do field tests with the EVK from remote.

    :::shell
    mkdir build && cd build
    cmake -DBUILD_SOCKTAP=ON -DSOCKTAP_WITH_CUBE_EVK=ON ..

    # use fix position data
    ./bin/socktap -l cube-evk -p static --cube-ip <cube-ip>

    # use the ublox module on the EVK for positioning data
    ./bin/socktap -l cube-evk -p gpsd --gpsd-host <cube-ip> --cube-ip <cube-ip>

# Building and Running Socktap on the EVK
You can also build and run socktap on the EVK itself and it will connect to the local V2X module.

    :::shell
    mkdir build && cd build
    cmake -DBUILD_SOCKTAP=ON -DSOCKTAP_WITH_CUBE_EVK=ON ..

    # use fix position data
    ./bin/socktap -l cube-evk -p static

    # use the ublox module on the EVK for positioning data
    ./bin/socktap -l cube-evk -p gpsd --gpsd-host 127.0.0.1




