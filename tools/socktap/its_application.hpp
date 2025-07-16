#ifndef ITS_APPLICATION_HPP_EUIC2VFR
#define ITS_APPLICATION_HPP_EUIC2VFR

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
#include <boost/asio/io_service.hpp>
#include <boost/asio.hpp>

#include <nlohmann/json.hpp>
using json = nlohmann::json;
namespace asio = boost::asio;

struct Denm_Data{
    int type;
    int lat;
    int lon;
};

class ITSApplication : public Application
{
public:
    ITSApplication(vanetza::PositionProvider& positioning, vanetza::Runtime& rt, asio::io_service& io_service, unsigned short port);
    
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

    void start_receive();
    void sendCAMToServer(const std::string& data, int size);
    void sendToServer(u_int64_t* dataToSend, int size);
    void create_CPM(const json& j);
    void sendDenm(const json& j);
    void handle_message(std::size_t bytes_transferred);
    void handle_receive_error(const std::error_code& error);

    int splitData(char* buffer, Denm_Data* data);
    void populateStruct(char* data, Denm_Data* denm_data, int index);    

    vanetza::PositionProvider& positioning_;
    vanetza::Runtime& runtime_;
    vanetza::Clock::duration cam_interval_;
    bool print_rx_msg_ = false;
    bool print_tx_msg_ = false;
    bool send_to_server = false;
    
    int server_port;
    const char* serverIP;

    int station_id;

    asio::ip::udp::socket denm_socket;                    // member socket
    asio::ip::udp::endpoint remote_endpoint;

    asio::ip::udp::socket cam_socket;                    // member socket
    asio::ip::udp::endpoint cam_endpoint;

    std::array<char, 1024> recv_buffer;
    
};

#endif /* CAM_APPLICATION_HPP_EUIC2VFR */
