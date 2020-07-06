# Socktap

*socktap* runs Vanetza on top of Linux raw packet sockets and demonstrates the basic API usage.
This enables tests on commodity hardware, i.e. no special V2X or Car2X hardware is required.
However, raw packet sockets cannot replace such dedicated hardware entirely.
Consider *socktap* as an experimental application showcasing some of Vanetza's features.

You can enable the build process for this application by the `BUILD_SOCKTAP` CMake option.
When *socktap* is going to be built, [gpsd](http://catb.org/gpsd) is required as an additional dependency.

!!! warning
    A bug in gpsd<=3.15 causes a segmentation fault when *socktap* tries to fetch GPS data.
    More recent versions include a bugfix, e.g. gpsd>=3.17 is known to work.
    See also the corresponding [issue ticket #69](https://github.com/riebl/vanetza/issues/69).

If you have access to V2X hardware from Cohda Wireless, you can also run *socktap* on their units.
A special CMake option `SOCKTAP_WITH_COHDA_LLC` exists to build *socktap* for operation on Cohda's LLC API.
Please refer to our [Cohda SDK building recipe](/recipes/cohda-sdk-build) for details.


## Variants

There are multiple variants of *socktap*.
*socktap-hello* sends simple BTP-B messages with the binary payload `0xc0ffee`.
*socktap-cam* sends vehicle CAM messages and optionally supports some security options.

## Permissions

Since *socktap* builds upon raw packet sockets you need to run it with special privileges.
Either run *socktap* as root user or set the `CAP_NET_RAW` capabilities on the executables.
You can do this via `sudo setcap cap_net_raw+ep bin/socktap-<variant>`.
When `CAP_NET_RAW` is attached to the *socktap* binary you can run it as ordinary user.

## Running

You can locate *socktap* in your build directory at **bin/socktap-<variant>**.
It requires the network device name as startup argument on which *socktap* should send and receive packets.
Usually, such devices are named *eth0* or *wlan0*.
You can look up the available devices on your machine with the `ip link` command.
If you want to use the local loopback device (usually `lo`) you need to override the used MAC address using `--mac-address` to receive packets.
This is due to the MAC address being `00:00:00:00:00:00` for both sides and the router dropping incoming packets with its own address.

# Acknowledgement

This demo application has been initially developed as part of a student's project at Hochschule Darmstadt in summer term 2016.
Participating students were in alphabetical order: Sachin Kashyap Bukkambudhi Satyanarayana, Alvita Marina Menezes, Mrunmayi Parchure, Subashini Rajan and Deeksha Venkadari Yogendra.
Since then, [@kelunik](https://github.com/kelunik) and [@glmax](https://github.com/glmax) have contributed a lot to *socktap*.
