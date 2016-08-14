#include "FirstEthernetInterface.hpp"

char* getFirstEthernetDeviceName() 
{
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) == -1) 
	{
		perror("getifaddrs");
		exit (EXIT_FAILURE);
	}
	ifa = ifaddr->ifa_next;
	return ifa->ifa_name;
}
