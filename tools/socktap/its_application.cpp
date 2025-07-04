#include "its_application.hpp"
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
#include <boost/asio/io_service.hpp>
#include <boost/asio.hpp>

// This is a very simple CA application sending CAMs at a fixed rate.

using namespace vanetza;
using namespace vanetza::facilities;
using namespace std::chrono;
namespace asio = boost::asio;

ITSApplication::ITSApplication(PositionProvider& positioning, Runtime& rt, asio::io_service& io_service, unsigned short denm_port) :
    positioning_(positioning), runtime_(rt), cam_interval_(seconds(1)),
    denm_socket(io_service, asio::ip::udp::endpoint(asio::ip::udp::v4(), int(9001))),
    cam_socket(io_service)
{
    schedule_timer();    
    this->station_id = 1;
    this->server_port = 9000;
    this->serverIP = strdup("192.168.1.124");
    this->start_receive();
}


void ITSApplication::handle_receive_error(const std::error_code& error){
    std::cerr << "Receive error: " << error.message() << std::endl;
    
}

void ITSApplication::handle_message(std::size_t bytes_transferred){
    std::string data(this->recv_buffer.data(), bytes_transferred);  // Only use valid part of buffer
    std::vector<std::string> result;
    std::stringstream ss(data);
    std::string item;
    int i = 0;
    Denm_Data* denm_data = (Denm_Data*)malloc(sizeof(Denm_Data));
    while (std::getline(ss, item, ',')) {
        std::vector<char> vec(item.begin(), item.end());
        vec.push_back('\0'); 
        populateStruct(vec.data(), denm_data, i);
        i ++;
    }
    this->sendDenm(denm_data);
    free(denm_data);
}

void ITSApplication::start_receive(){
    
    this->denm_socket.async_receive_from(
        asio::buffer(this->recv_buffer), this->remote_endpoint,
        [this](std::error_code error, std::size_t bytes_transferred)
        {
            if (error || bytes_transferred == 0) {
                this->handle_receive_error(error);
                return;
            }
            this->handle_message(bytes_transferred);
            start_receive();  // Keep listening
        });
}


void ITSApplication::populateStruct(char* data, Denm_Data* denm_data, int index){
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

int ITSApplication::createSocket(){
    
    //this->cam_socket = asio::ip::udp::socket socket(io_service);
    cam_socket.open(asio::ip::udp::v4());
    this->cam_endpoint = asio::ip::udp::endpoint(asio::ip::address::from_string(this->serverIP), this->server_port);

    return 0;
}



void ITSApplication::setSendToServer(bool send_to_server){
    this->send_to_server = send_to_server;
}

void ITSApplication::setServerPort(int serverPort){
    this->server_port = serverPort;
}

void ITSApplication::setServerIP(const char * serverIP){
    this->serverIP = serverIP;
}


void ITSApplication::setStationID(int station_id){
    this->station_id = station_id;
}

void  ITSApplication::sendToServer(u_int64_t* dataToSend, int size){
    this->cam_socket.async_send_to(
            asio::buffer(dataToSend, size),
            this->cam_endpoint,
            [dataToSend](const std::error_code& ec, std::size_t bytes_sent) {
                if (!ec) {
                    std::cout << "Async sent "<< bytes_sent << " bytes)" << std::endl;
                } else {
                    std::cerr << "Send failed: " << ec.message() << std::endl;
                }
            }
    );
}

void ITSApplication::set_interval(Clock::duration interval)
{
    cam_interval_ = interval;
    runtime_.cancel(this);
    if(cam_interval_<=vanetza::Clock::duration{0}){
        std::cout << "CAM period to low, disabling" << std::endl;
        return;
    }
    
    schedule_timer();
}

void ITSApplication::print_generated_message(bool flag)
{
    print_tx_msg_ = flag;
}

void ITSApplication::print_received_message(bool flag)
{
    print_rx_msg_ = flag;
}

ITSApplication::PortType ITSApplication::port()
{
    return btp::ports::CAM;
}

int decode(const asn1::Cam& recvd, char* message){
    const ItsPduHeader_t& header = recvd->header;
    const CoopAwareness_t& cam = recvd->cam;
    const BasicContainer_t& basic = cam.camParameters.basicContainer;
    const BasicVehicleContainerHighFrequency& bvc = cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency;
    //int size = sprintf(message, "%ld;%ld;%ld;%ld;ld\n",header.stationID,basic.referencePosition.latitude,basic.referencePosition.longitude,bvc.speed.speedValue,bvc.longitudinalAcceleration.longitudinalAccelerationValue);
    int size = sprintf(
        message, 
        "{\"objectID\":%ld,\"speed\":%ld,\"speedConfidence\":%ld,\"longAcc\":%ld,\"longAccConfidence\":%ld,\"heading\":%ld,\"headingConfidence\":%ld,\"lat\":%ld,\"lon\":%ld,\"length\":%ld,\"lengthConfidence\":%ld,\"lane\":%ld,\"laneConfidence\":%ld,\"altitude\":%ld,\"altitudeConfidence\":%ld,\"vehicleLength\":%ld,\"vehicleLengthConfidence\":%ld,\"positionConfidence\":%ld}\n",
        header.stationID,
        bvc.speed.speedValue,
        bvc.speed.speedConfidence,
        bvc.longitudinalAcceleration.longitudinalAccelerationValue,
        bvc.longitudinalAcceleration.longitudinalAccelerationConfidence,
        bvc.heading.headingValue,
        bvc.heading.headingConfidence,
        basic.referencePosition.latitude,
        basic.referencePosition.longitude,
        bvc.vehicleLength.vehicleLengthValue,
        bvc.vehicleLength.vehicleLengthConfidenceIndication,
        0,
        0,
        0,
        bvc.vehicleLength.vehicleLengthValue,
        bvc.vehicleLength.vehicleLengthConfidenceIndication,
        0,
        0
        );
    return strlen(message);
}

void ITSApplication::indicate(const DataIndication& indication, UpPacketPtr packet)
{
    printf("Received MEssage\n\n");
    asn1::PacketVisitor<asn1::Cam> visitor;
    std::shared_ptr<const asn1::Cam> cam = boost::apply_visitor(visitor, *packet);

    packet.get();

    std::cout << "CAM application received a packet with " << (cam ? "decodable" : "broken") << " content" << std::endl;
    if (cam && print_rx_msg_) {
        std::cout << "Received CAM contains\n";
        print_indented(std::cout, *cam, "  ", 1);
    }
    
    if(cam && send_to_server){
        char message [500];
        int size = decode(*cam, message);
        this->sendToServer((u_int64_t*)message, size);
    }
    
}

void ITSApplication::schedule_timer()
{
    runtime_.schedule(cam_interval_, std::bind(&ITSApplication::on_timer, this, std::placeholders::_1), this);
}

void ITSApplication::on_timer(Clock::time_point)
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

    bvc.longitudinalAcceleration.longitudinalAccelerationValue = 0;
    bvc.longitudinalAcceleration.longitudinalAccelerationConfidence = AccelerationConfidence_pointOneMeterPerSecSquared;

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

void ITSApplication::sendDenm(Denm_Data* denm_data){

    printf("sending denm: %ld %ld %d\n", denm_data->type, denm_data->lat, denm_data->lon );
    
    int counter  = 1;
   vanetza::asn1::Denm message;

    // Header	
    ItsPduHeader_t& header = message->header;
	header.protocolVersion = 2;
    header.messageID = ItsPduHeader__messageID_denm;
    header.stationID = 1;
	

    // Management
    ManagementContainer_t& management = message->denm.management;
        //action id
    management.actionID.originatingStationID = 1;
    management.actionID.sequenceNumber = counter;


        //detection time
    const auto time_now = duration_cast<milliseconds>(runtime_.now().time_since_epoch());
    uint64_t time = 45000000000;

	// XXX: possible memory leak, free allocated memory 
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

    //print_indented_denm(std::cout, message, "  ", 1);

    auto confirm = Application::request(request, std::move(packet));
    if (!confirm.accepted()) {
        throw std::runtime_error("DENM application data request failed");
    }
    
}
