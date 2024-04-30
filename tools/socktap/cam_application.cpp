#include "cam_application.hpp"
#include <vanetza/btp/ports.hpp>
#include <vanetza/asn1/cam.hpp>
#include <vanetza/asn1/packet_visitor.hpp>
#include <vanetza/facilities/cam_functions.hpp>
#include <boost/units/cmath.hpp>
#include <boost/units/systems/si/prefixes.hpp>
#include <chrono>
#include <exception>
#include <functional>
#include <iostream>

// This is a very simple CA application sending CAMs at a fixed rate.

using namespace vanetza;
using namespace vanetza::facilities;
using namespace std::chrono;

CamApplication::CamApplication(PositionProvider& positioning, Runtime& rt) :
    positioning_(positioning), runtime_(rt), cam_interval_(seconds(1))
{
    this->send_to_server = false;
    schedule_timer();    

    this->station_id = 1;
    this->server_port = 9000;
    this->serverIP = strdup("192.168.1.124");
}

int CamApplication::createSocket(){
    // Creating socket file descriptor 
    if ( (this->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        return -1;
    } 
    printf("socket created\n");
   
    memset(&this->servaddr, 0, sizeof(this->servaddr)); 
       
    // Filling server information 
    this->servaddr.sin_family = AF_INET; 
    this->servaddr.sin_port = htons(this->server_port); 
    this->servaddr.sin_addr.s_addr = inet_addr(this->serverIP); 
    return 0;
}

int CamApplication::closeSocket(){
    return close(this->sockfd);
}

void CamApplication::setSendToServer(bool send_to_server){
    this->send_to_server = send_to_server;
}

void CamApplication::setServerPort(int serverPort){
    this->server_port = serverPort;
}

void CamApplication::setServerIP(const char * serverIP){
    this->serverIP = serverIP;
}

void CamApplication::setStationID(int station_id){
    this->station_id = station_id;
}

int  CamApplication::sendToServer(u_int64_t* dataToSend, int size){
    int sent = sendto(this->sockfd, (const u_int64_t *)dataToSend, size, 
        MSG_CONFIRM, (const struct sockaddr *) &this->servaddr,  
            sizeof(this->servaddr)); 
        std::cout<<"Sending message to UDP Server:" << this->serverIP << " " << this->server_port <<std::endl; 
    return sent;
}

void CamApplication::set_interval(Clock::duration interval)
{
    cam_interval_ = interval;
    runtime_.cancel(this);
    schedule_timer();
}

void CamApplication::print_generated_message(bool flag)
{
    print_tx_msg_ = flag;
}

void CamApplication::print_received_message(bool flag)
{
    print_rx_msg_ = flag;
}

CamApplication::PortType CamApplication::port()
{
    return btp::ports::CAM;
}

int decodeCAM(const asn1::Cam& recvd, char* message){
    const ItsPduHeader_t& header = recvd->header;
    const CoopAwareness_t& cam = recvd->cam;
    const BasicContainer_t& basic = cam.camParameters.basicContainer;
    int size = sprintf(message, "%ld;%ld;%ld",header.stationID,basic.referencePosition.longitude,basic.referencePosition.latitude);
    return strlen(message);
}

void CamApplication::indicate(const DataIndication& indication, UpPacketPtr packet)
{
    asn1::PacketVisitor<asn1::Cam> visitor;
    std::shared_ptr<const asn1::Cam> cam = boost::apply_visitor(visitor, *packet);

    std::cout << "CAM application received a packet with " << (cam ? "decodable" : "broken") << " content" << std::endl;
    if (cam && print_rx_msg_) {
        std::cout << "Received CAM contains\n";
        print_indented(std::cout, *cam, "  ", 1);
    }
    
    if(cam && send_to_server){
        std::cout << "sending to udp server" << std::endl;
        char message [100];
        int size = decodeCAM(*cam, message);
        this->sendToServer((u_int64_t*)message, size);
    }
    
}

void CamApplication::schedule_timer()
{
    runtime_.schedule(cam_interval_, std::bind(&CamApplication::on_timer, this, std::placeholders::_1), this);
}

void CamApplication::on_timer(Clock::time_point)
{
    schedule_timer();
    vanetza::asn1::Cam message;

    ItsPduHeader_t& header = message->header;
    header.protocolVersion = 2;
    header.messageID = ItsPduHeader__messageID_cam;
    header.stationID = this->station_id; // some dummy value

    const auto time_now = duration_cast<milliseconds>(runtime_.now().time_since_epoch());
    uint16_t gen_delta_time = time_now.count();

    CoopAwareness_t& cam = message->cam;
    cam.generationDeltaTime = gen_delta_time * GenerationDeltaTime_oneMilliSec;

    auto position = positioning_.position_fix();

    if (!position.confidence) {
        std::cerr << "Skipping CAM, because no good position is available, yet." << position.confidence << std::endl;
        return;
    }

    BasicContainer_t& basic = cam.camParameters.basicContainer;
    basic.stationType = StationType_passengerCar;
    copy(position, basic.referencePosition);

    cam.camParameters.highFrequencyContainer.present = HighFrequencyContainer_PR_basicVehicleContainerHighFrequency;

    BasicVehicleContainerHighFrequency& bvc = cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency;
    bvc.heading.headingValue = 0;
    bvc.heading.headingConfidence = HeadingConfidence_equalOrWithinOneDegree;

    bvc.speed.speedValue = 0;
    bvc.speed.speedConfidence = SpeedConfidence_equalOrWithinOneCentimeterPerSec;

    bvc.driveDirection = DriveDirection_forward;
    bvc.longitudinalAcceleration.longitudinalAccelerationValue = LongitudinalAccelerationValue_unavailable;

    bvc.vehicleLength.vehicleLengthValue = VehicleLengthValue_unavailable;
    bvc.vehicleLength.vehicleLengthConfidenceIndication = VehicleLengthConfidenceIndication_noTrailerPresent;
    bvc.vehicleWidth = VehicleWidth_unavailable;

    bvc.curvature.curvatureValue = 0;
    bvc.curvature.curvatureConfidence = CurvatureConfidence_unavailable;
    bvc.curvatureCalculationMode = CurvatureCalculationMode_yawRateUsed;

    bvc.yawRate.yawRateValue = YawRateValue_unavailable;

    std::string error;
    if (!message.validate(error)) {
        throw std::runtime_error("Invalid high frequency CAM: %s" + error);
    }

    if (print_tx_msg_) {
        std::cout << "Generated CAM contains\n";
        print_indented(std::cout, message, "  ", 1);
    }

    DownPacketPtr packet { new DownPacket() };
    packet->layer(OsiLayer::Application) = std::move(message);

    DataRequest request;
    request.its_aid = aid::CA;
    request.transport_type = geonet::TransportType::SHB;
    request.communication_profile = geonet::CommunicationProfile::ITS_G5;

    auto confirm = Application::request(request, std::move(packet));
    if (!confirm.accepted()) {
        throw std::runtime_error("CAM application data request failed");
    }
}
