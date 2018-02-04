# UpperTester

This directory contains an upper tester implementation for ETSI's TTCN-3 test suite. A TTCN-3 compiler is required to execute these tests.

## Running

A script is provided that works on Ubuntu, which does the following steps automatically.
You're encouraged to read through the script and the following instructions.
If you use the script, you have to setup TITAN manually, everything else is covered by the script.

```bash
# With $PWD being the current directory
./run.sh
```

This guide will provide instructions how to run these tests manually using the open source TTCN-3 compiler [TITAN](https://github.com/eclipse/titan.core).

The TITAN TRI Mapper requires a network interface with a MAC address where it injects and captures packets. The easiest way to have a local virtual interface is to create two `peer` virtual interfaces.

```
sudo ip link add veth0 type veth peer name veth1
sudo ip link set dev veth0 up
sudo ip link set dev veth1 up
```

This will create the two interface `veth0` and `veth1` that are connected. If a packet is sent on `veth0` it will be available at `veth1` and the other way around.

The MAC address can be queried using `sudo ip link` and looking for the correct interface.

You need to setup TITAN as instructed in their documentation.

We make use of a [fork of the official test suite](https://github.com/elnrnag/ITSG5_TS_Titanized_TA), as the official test suite isn't compatible with TITAN (yet). Please clone the linked repository and install it as instructed in its README. You might need to add `jnetpcap` to your Java installation.

Switch to the `titan_tri_mapper` directory of the clone and copy `jnetpcap.jar` there. Adjust the `taproperties.cfg` to contain the correct MAC address for the virtual interface. Use the MAC address of the `veth1@veth0` interface. Then launch `sudo java -Djava.library.path=/path/to/jnetpcap -jar TitanTriMapper.jar -l info` where `/path/to/jnetpcap` is the path to the directory containing `libjnetpcap.so`.

Next, launch the upper tester using `bin/uppertester -i veth0` from the build directory of Vanetza.

Last, start the test suite by running `ttcn3_start ./ITS_Exec cfg.cfg ItsBtp_TestControl`. You might want to append ` | grep -v TRI_encode | grep -v TRI_decode` to suppress the verbose encoding and decoding output.

You might need to `up` and `down` one network interface after each test run to repeat the tests, because the TITAN TRI Mapper only seems to capture the frames, but not consume them. You can do so using `sudo ip link set dev veth0 down && sudo ip link set dev veth0 up`.
