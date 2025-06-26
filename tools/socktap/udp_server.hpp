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
using namespace vanetza;
using namespace vanetza::facilities;

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

    void print_received_message(bool flag);
    void print_generated_message(bool flag);
private:
    vanetza::Runtime& runtime_;
    vanetza::PositionProvider& positioning_;

    int port_;
    int server_port;

    bool print_rx_msg_ = false;
    bool print_tx_msg_ = false;
    
    int sockfd;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;

    void initializeSocket();
    void sendDenm(Denm_Data* data);
    int splitData(char* buffer, Denm_Data* data);
    void populateStruct(char* data, Denm_Data* denm_data, int index);    

    void print_indented_denm(std::ostream& os, const asn1::Denm& denm, const std::string& indent = "\t", unsigned start = 0);
    
};

#endif /* UDP_SERVER_HPP_HPP */
