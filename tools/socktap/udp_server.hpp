#ifndef UDP_SERVER_HPP
#define UDP_SERVER_HPP

#include "application.hpp"
#include <vanetza/btp/ports.hpp>
#include <vanetza/asn1/cam.hpp>
#include <vanetza/asn1/denm.hpp>
#include <vanetza/asn1/packet_visitor.hpp>
#include <vanetza/facilities/cam_functions.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <boost/asio/io_service.hpp>
#include <boost/asio.hpp>



namespace asio = boost::asio;
using asio::ip::udp;

class UDPServer
{
public:
    UDPServer(int port);
    
    void handleReceivedUDP();
private:
    int port_;
    int server_port;
    
    int sockfd;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;

    void initializeSocket();
    
};

#endif /* UDP_SERVER_HPP_HPP */
