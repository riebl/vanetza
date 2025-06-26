# Building for cube:evk

The cube:evk from [cubesys - an nfiniity company](https://www.nfiniity.com/#hardware-section) fully supports the Vanetza stack and its socktap application. An integrated V2X module listens for requests whether from a local or remote application. The communication protocol between host and V2X module is covered in Google's Protobuf that is used in the respective link-layer implementation.

## Configuration
Before building and running socktap you need to configure the V2X module and the WiFi once.

### V2X Radio Configuration - C-V2X or DSRC
First of all select your desired radio configuration using the `v2xconfig` tool on the cube:evk:

    :::shell
    # start dsrc or cv2x and enable auto-start
    cube> v2xconfig start enable dsrc 

### Connect to your local WiFi
This is only needed for the wireless remote radio mode.

    :::shell
    cube> sudo nmcli dev wifi connect '<ssid>' password '<password>'
    # get your ip
    cube> ip a

## Building and Running Socktap for Wireless Remote Radio Mode
You can build and run socktap directly on your personal computer (host) and select `cube-evk` as link-layer. Further, gpsd daemon is running on the cube:evk that can feed socktap with GNSS data. 

In `wireless remote radio mode` you develop, debug and run Vanetza/socktap on your personal computer. There is no need to flash or transfer the application onto your cube:evk. The V2X radio on the cube:evk listens for incoming requests from remote. Both devices need to be pingable from each other only.

    :::shell
    host> mkdir build && cd build
    host> cmake -DBUILD_SOCKTAP=ON -DSOCKTAP_WITH_CUBE_EVK=ON ..

    # use fix position data
    host> ./bin/socktap -l cube-evk -p static --cube-ip <cube-ip>

    # use the ublox module on the cube:evk for positioning data
    host> ./bin/socktap -l cube-evk -p gpsd --gpsd-host <cube-ip> --cube-ip <cube-ip>

Moreover, the integrated LTE module allows the user to do field tests with the cube:evk from remote.

## Building and Running Socktap on the cube:evk
You can also build and run socktap on the cube:evk itself and it will connect to the local V2X module.

    :::shell
    cube> mkdir build && cd build
    cube> cmake -DBUILD_SOCKTAP=ON -DSOCKTAP_WITH_CUBE_EVK=ON ..

    # use fix position data
    cube> ./bin/socktap -l cube-evk -p static

    # use the ublox module on the cube:evk for positioning data
    cube> ./bin/socktap -l cube-evk -p gpsd --gpsd-host 127.0.0.1

