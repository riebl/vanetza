#include "NetworkInterface.hpp"

char* getFirstEthernetDeviceName() 
{
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) == -1) 
	{
		perror("getifaddrs");
		exit (EXIT_FAILURE);
	}
	ifa = ifaddr->ifa_next;
	if(ifa==NULL)
	{
	  std::cout << " No ethernet interface other than loopback is found on this system." << std::endl;
	  exit(0);
	}
	    
	return ifa->ifa_name;
}


bool NIC(std::string networkInterfaceName) 
{
	struct ifaddrs *addrs, *tmp;

	if (getifaddrs(&addrs) == -1) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}

	getifaddrs(&addrs);
	tmp = addrs;

	while (tmp) 
	{
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
		{
		  if(tmp->ifa_name == networkInterfaceName)
		  {
// 			printf("%s\n", tmp->ifa_name);
			freeifaddrs(addrs);
			return true;
		  }
		}
		tmp = tmp->ifa_next;
	}
	freeifaddrs(addrs);
	return false;
}
	