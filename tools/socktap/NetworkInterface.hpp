#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <stdio.h>
#include<iostream>

// Function to fetch the name of first ethernet device on the computer
char* getFirstEthernetDeviceName();

// Function to verify the selected device is present on the computer
bool NIC(std::string networkInterfaceName);
