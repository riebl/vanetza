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
#include <nlohmann/json.hpp>
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
    std::cout << "[Received UDP data]: " << data << std::endl; 
    try {
        // Parse JSON from received data
        nlohmann::json proto2json = nlohmann::json::parse(data);
        
        // print json
        std::cout << "[Parsed proto2 received]:\n" << proto2json.dump(4) << std::endl;
        if (proto2json["proto2Objects"].empty()) {
            //objects empty is event object -> send DENM
            std::cout << "Only proto2Event filled " << std::endl;
            this->sendDenm(proto2json);
        }else if(proto2json["proto2Events"].empty()){
            //gonna be objects so prepare CPM
            
        }       
    } catch (nlohmann::json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
    }
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

void ITSApplication::sendDenm(const json& j){

   // printf("sending denm: %ld %ld %d\n", denm_data->type, denm_data->lat, denm_data->lon );
    const auto& proto2event = j["proto2Event"];
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
    //management.actionID.originatingStationID = 1;
    management.actionID.originatingStationID = atoi(proto2event.value("origin", "1").c_str());
    management.actionID.sequenceNumber = counter;


        //detection time
    const auto time_now = duration_cast<milliseconds>(runtime_.now().time_since_epoch());
    //uint64_t time = 45000000000;
   /* uint64_t time = time_now.count();
    management.detectionTime.buf = (uint8_t*) malloc(sizeof(uint64_t));
    management.detectionTime.size = sizeof(uint64_t);
    
    for (size_t i = 0; i < management.detectionTime.size; ++i) {
        management.detectionTime.buf[i] = (time >> (8 * (management.detectionTime.size - 1 - i))) & 0xFF;
    }

    //reference time
   // uint64_t ref_time = 45000000000;
    uint64_t ref_time = time_now.count();
    management.referenceTime.buf = (uint8_t*) malloc(sizeof(uint64_t));
    management.referenceTime.size = sizeof(uint64_t);

    for (size_t i = 0; i < management.referenceTime.size; ++i) {
        management.referenceTime.buf[i] = (ref_time >> (8 * (management.referenceTime.size - 1 - i))) & 0xFF;
    }*/

    //detectionTime and referenceTime are set using asn_long2INTEGER() — no manual malloc/free, so no leaks there.
    INTEGER_t* detectionTime = &management.detectionTime;
    long timeValue = time_now.count();
    int ret = asn_long2INTEGER(detectionTime, timeValue);
    if (ret != 0) {
        throw std::runtime_error("Failed to set detectionTime integer");
    }

    // Same for referenceTime
    INTEGER_t* referenceTime = &management.referenceTime;
    ret = asn_long2INTEGER(referenceTime, timeValue);
    if (ret != 0) {
        throw std::runtime_error("Failed to set referenceTime integer");
    }
    //pos
    /*auto pos = positioning_.position_fix();
    if (!pos.confidence) {
        std::cerr << "Skipping DENM, no valid position" << std::endl;
        return;
    }
    copy(pos, management.eventPosition);*/

    //management event position
    management.eventPosition.altitude.altitudeValue= proto2event.value("altitude", 0);
    management.eventPosition.latitude= proto2event.value("lat", 0);
    management.eventPosition.longitude= proto2event.value("lon", 0);

    //xxx possible memory leak
   management.relevanceDistance = vanetza::asn1::allocate<RelevanceDistance_t>();
    if (management.relevanceDistance == nullptr) {
        // Handle malloc failure if needed
        // e.g., log error, return, throw, etc.
    }

    // Assign the correct enum value based on radius
    int radius = proto2event.value("radius", 0);

    if (radius < 50) {
        *management.relevanceDistance = RelevanceDistance_lessThan50m;
    } else if (radius < 100) {
        *management.relevanceDistance = RelevanceDistance_lessThan100m;
    } else if (radius < 200) {
        *management.relevanceDistance = RelevanceDistance_lessThan200m;
    } else if (radius < 500) {
        *management.relevanceDistance = RelevanceDistance_lessThan500m;
    } else if (radius < 1000) {
        *management.relevanceDistance = RelevanceDistance_lessThan1000m;
    } else if (radius < 5000) {
        *management.relevanceDistance = RelevanceDistance_lessThan5km;
    } else if (radius < 10000) {
        *management.relevanceDistance = RelevanceDistance_lessThan10km;
    } else {
        *management.relevanceDistance = RelevanceDistance_over10km;
    }
    
    management.stationType = StationType_passengerCar;

    SituationContainer* situation = vanetza::asn1::allocate<SituationContainer_t>();
   // situation->eventType.causeCode = 9;
    situation->eventType.causeCode = atoi(proto2event.value("eventType", "9").c_str());
    situation->eventType.subCauseCode = 0;
    message->denm.situation = situation;
     //print generated DENM
    std::cout << "Generated DENM contains\n";
    asn_fprint(stdout, &asn_DEF_DENM,message.operator->());

    std::string error;
	if (!message.validate(error)) {
        vanetza::asn1::free(asn_DEF_DENM, message.operator->());
		throw std::runtime_error("Invalid DENM: " + error);
	}
    
    // message is moved, so no need to worry about manual cleanups here
    // After this point, the ownership of `message` data has transferred to `packet`,
    // and it will be cleaned up automatically when `packet` is destroyed.
    // No further manual freeing of `message` resources is necessary.
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
