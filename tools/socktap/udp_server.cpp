#include "udp_server.hpp"
#include <vanetza/btp/ports.hpp>
#include <vanetza/asn1/cam.hpp>
#include <vanetza/asn1/denm.hpp>
#include <vanetza/asn1/packet_visitor.hpp>
#include <vanetza/facilities/cam_functions.hpp>
#include <boost/units/cmath.hpp>
#include <boost/units/systems/si/prefixes.hpp>
#include <chrono>
#include <exception>
#include <functional>
#include <iostream>
#include <thread>
#include <boost/asio/io_service.hpp>
#include <boost/asio.hpp>


// This is a very simple CA application sending CAMs at a fixed rate.

using namespace vanetza;
using namespace vanetza::facilities;
using namespace std::chrono;
using DataRequest = vanetza::btp::DataRequestGeoNetParams;
using DownPacketPtr = vanetza::geonet::Router::DownPacketPtr;
using DataConfirm = vanetza::geonet::DataConfirm;
using DataIndication = vanetza::btp::DataIndication;


UDPServer::UDPServer(int port, PositionProvider& positioning, Runtime& rt):
    port_(9001), positioning_(positioning), runtime_(rt)
{
    this->server_port = port_;
    this->initializeSocket();
    
}

void UDPServer::initializeSocket(){
    if ( (this->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 

    memset(&this->server_addr, 0, sizeof(this->server_addr)); 

    this->server_addr.sin_family    = AF_INET; // IPv4 
    this->server_addr.sin_addr.s_addr = INADDR_ANY; 
    this->server_addr.sin_port = htons(this->server_port); 
      
    // Bind the socket with the server address 
    if ( bind(this->sockfd, (const struct sockaddr *)&this->server_addr,  
            sizeof(this->server_addr)) < 0 ) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
}

void UDPServer::handleReceivedUDP(){
    while (true)
    {
        socklen_t len;
        int n; 
        char buffer[1024];
        
        len = sizeof(this->client_addr);  //len is value/result 
    
        n = recvfrom(this->sockfd, (char *)buffer, 1024,  
                    MSG_WAITALL, ( struct sockaddr *) &this->client_addr, 
                    &len); 
        if(n > 0){
            buffer[n] = '\0'; 
            Denm_Data* data = (Denm_Data*)malloc(sizeof(Denm_Data));
            int res = splitData(buffer, data);
            if(res > 0){
                sendDenm(data);
            }
        }
        
    }
    
}


int UDPServer::splitData(char* buffer, Denm_Data* data){
    int i = 0;
    int j = 0;
    int z = 0;
    char result[20];

    while(buffer[i] != '\0'){
        if(buffer[i] != ','){
            result[j] = buffer[i];
            j++;
        }else{
            result[j+1] = '\0';
            j = 0;
            this->populateStruct(result, data, z);
            z++;
            memset(result, 0, sizeof(result));
            
        }
        i++;
    }
    result[j+1] = '\0';
    this->populateStruct(result, data, z);

    return z;
}

void UDPServer::populateStruct(char* data, Denm_Data* denm_data, int index){
     switch (index)
    {
        case 0:
            denm_data->type = atoi(data);
            break;
        case 1:
            denm_data->lat = atoi(data);
            break;
        case 2:
            denm_data->lon = atoi(data);
            break;
        default:
            break;
    }
}

void UDPServer::sendDenm(Denm_Data* data){
    
    int counter  = 1;
   vanetza::asn1::Denm message;

    // Header	
    ItsPduHeader_t& header = message->header;
	header.protocolVersion = 2;
    header.messageID = ItsPduHeader__messageID_denm;
    header.stationID = 1;
	
    //CoopAwareness_t& cam = message->cam;

    // Management
    ManagementContainer_t& management = message->denm.management;
        //action id
    management.actionID.originatingStationID = 1;
    management.actionID.sequenceNumber = counter;


        //detection time
    const auto time_now = duration_cast<milliseconds>(runtime_.now().time_since_epoch());
    uint64_t time = 45000000000;
    
    management.detectionTime.buf = (uint8_t*) malloc(sizeof(uint64_t));
    management.detectionTime.size = sizeof(uint64_t);

    for (size_t i = 0; i < management.detectionTime.size; ++i) {
        management.detectionTime.buf[i] = (time >> (8 * (management.detectionTime.size - 1 - i))) & 0xFF;
    }

        //reference time
    uint64_t ref_time = 45000000000;
    
    management.referenceTime.buf = (uint8_t*) malloc(sizeof(uint64_t));
    management.referenceTime.size = sizeof(uint64_t);

    for (size_t i = 0; i < management.referenceTime.size; ++i) {
        management.referenceTime.buf[i] = (ref_time >> (8 * (management.referenceTime.size - 1 - i))) & 0xFF;
    }

        //pos
    auto pos = positioning_.position_fix();
    if (!pos.confidence) {
        std::cerr << "Skipping DENM, no valid position" << std::endl;
        return;
    }
    copy(pos, management.eventPosition);
    management.stationType = StationType_passengerCar;

    SituationContainer* situation = vanetza::asn1::allocate<SituationContainer_t>();
    situation->eventType.causeCode = 9;
    situation->eventType.subCauseCode = 0;
    message->denm.situation = situation;
 

    std::string error;
	if (!message.validate(error)) {
		throw std::runtime_error("Invalid DENM: " + error);
	}
    DownPacketPtr packet { new DownPacket() };
    packet->layer(OsiLayer::Application) = std::move(message);
    DataRequest request;
    request.its_aid = aid::DEN;
    request.transport_type = geonet::TransportType::SHB;
    request.communication_profile = geonet::CommunicationProfile::ITS_G5;


    auto confirm = Application::request(request, std::move(packet));
    if (!confirm.accepted()) {
        throw std::runtime_error("DENM application data request failed");
    }
}

void UDPServer::indicate(const DataIndication& indication, UpPacketPtr packet){

}

UDPServer::PortType UDPServer::port()
{
    return btp::ports::CAM;
}