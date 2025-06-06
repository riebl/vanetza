#ifndef ITS_APPLICTION_HPP
#define ITS_APPLICTION_HPP

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

class ITC_LCI_Application : public Application
{
public:
    ITC_LCI_Application(vanetza::PositionProvider& positioning, vanetza::Runtime& rt);
    
    PortType port() override;
    void indicate(const DataIndication&, UpPacketPtr) override;
    void set_interval(vanetza::Clock::duration);
    void print_received_message(bool flag);
    void print_generated_message(bool flag);
    void setSendToServer(bool send_to_server);
    void setServerPort(int serverPort);
    void setServerIP(const char * serverIP);
    void setStationID(int station_id);
    

    int createSocket();
private:
    void schedule_timer();
    void on_timer(vanetza::Clock::time_point);
    
    int closeSocket();
    int sendToServer(u_int64_t* dataToSend, int size);
    int decodeCAM(const vanetza::asn1::Cam& recvd, char* message);
   

    vanetza::PositionProvider& positioning_;
    vanetza::Runtime& runtime_;
    vanetza::Clock::duration cam_interval_;
    bool print_rx_msg_ = false;
    bool print_tx_msg_ = false;
    bool send_to_server = false;
    
    int sockfd; 
    int server_port;
    const char* serverIP;
    
    struct sockaddr_in servaddr; 
    int station_id;
};

#endif /* ITS_APPLICTION_HPP */
