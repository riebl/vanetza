#ifndef CAM_APPLICATION_HPP_EUIC2VFR
#define CAM_APPLICATION_HPP_EUIC2VFR

#include "application.hpp"
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

class CamApplication : public Application
{
public:
    CamApplication(vanetza::PositionProvider& positioning, vanetza::Runtime& rt);
    
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

#endif /* CAM_APPLICATION_HPP_EUIC2VFR */
