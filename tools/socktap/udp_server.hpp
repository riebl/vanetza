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

struct Denm_Data{
    int type;
    int lat;
    int lon;
};

class UDPServer  : public Application
{
public:
    UDPServer(int port, vanetza::PositionProvider& positioning, vanetza::Runtime& rt);
    
    PortType port() override;
    void indicate(const DataIndication&, UpPacketPtr) override;

    void handleReceivedUDP();
private:
    vanetza::Runtime& runtime_;
    vanetza::PositionProvider& positioning_;

    int port_;
    int server_port;
    
    int sockfd;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;

    void initializeSocket();
    void sendDenm(Denm_Data* data);
    int splitData(char* buffer, Denm_Data* data);
    void populateStruct(char* data, Denm_Data* denm_data, int index);    
    
};

#endif /* UDP_SERVER_HPP_HPP */
