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

    print_indented_denm(std::cout, message, "  ", 1);

    auto confirm = Application::request(request, std::move(packet));
    if (!confirm.accepted()) {
        throw std::runtime_error("DENM application data request failed");
    }
    
}

void UDPServer::indicate(const DataIndication& indication, UpPacketPtr packet){
    printf("Received MEssage2\n\n");

}

UDPServer::PortType UDPServer::port()
{
    return btp::ports::CAM;
}

void UDPServer::print_generated_message(bool flag)
{
    print_tx_msg_ = flag;
}

void UDPServer::print_received_message(bool flag)
{
    print_rx_msg_ = flag;
}

void UDPServer::print_indented_denm(std::ostream& os, const asn1::Denm& message, const std::string& indent, unsigned level)
{
    auto prefix = [&](const char* field) -> std::ostream& {
        for (unsigned i = 0; i < level; ++i) {
            os << indent;
        }
        os << field << ": ";
        return os;
    };

    const ItsPduHeader_t& header = message->header;
    prefix("ITS PDU Header") << "\n";
    ++level;
    prefix("Protocol Version") << header.protocolVersion << "\n";
    prefix("Message ID") << header.messageID << "\n";
    prefix("Station ID") << header.stationID << "\n";
    --level;

    /*
    const CoopAwareness_t& cam = message->cam;
    prefix("CoopAwarensess") << "\n";
    ++level;
    prefix("Generation Delta Time") << cam.generationDeltaTime << "\n";

    prefix("Basic Container") << "\n";
    ++level;
    const BasicContainer_t& basic = cam.camParameters.basicContainer;
    prefix("Station Type") << basic.stationType << "\n";
    prefix("Reference Position") << "\n";
    ++level;
    prefix("Longitude") << basic.referencePosition.longitude << "\n";
    prefix("Latitude") << basic.referencePosition.latitude << "\n";
    prefix("Semi Major Orientation") << basic.referencePosition.positionConfidenceEllipse.semiMajorOrientation << "\n";
    prefix("Semi Major Confidence") << basic.referencePosition.positionConfidenceEllipse.semiMajorConfidence << "\n";
    prefix("Semi Minor Confidence") << basic.referencePosition.positionConfidenceEllipse.semiMinorConfidence << "\n";
    prefix("Altitude [Confidence]") << basic.referencePosition.altitude.altitudeValue
        << " [" << basic.referencePosition.altitude.altitudeConfidence << "]\n";
    --level;
    --level;

    if (cam.camParameters.highFrequencyContainer.present == HighFrequencyContainer_PR_basicVehicleContainerHighFrequency) {
        prefix("High Frequency Container [Basic Vehicle]") << "\n";
        ++level;
        const BasicVehicleContainerHighFrequency& bvc =
            cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency;
        prefix("Heading [Confidence]") << bvc.heading.headingValue
            << " [" << bvc.heading.headingConfidence << "]\n";
        prefix("Speed [Confidence]") << bvc.speed.speedValue
            << " [" << bvc.speed.speedConfidence << "]\n";
        prefix("Drive Direction") << bvc.driveDirection << "\n";
        prefix("Longitudinal Acceleration [Confidence]") << bvc.longitudinalAcceleration.longitudinalAccelerationValue
            << " [" << bvc.longitudinalAcceleration.longitudinalAccelerationConfidence << "]\n";
        prefix("Vehicle Length [Confidence Indication]") << bvc.vehicleLength.vehicleLengthValue
            << " [" << bvc.vehicleLength.vehicleLengthConfidenceIndication << "]\n";
        prefix("Vehicle Width") << bvc.vehicleWidth << "\n";
        prefix("Curvature [Confidence]") << bvc.curvature.curvatureValue
            << " [" << bvc.curvature.curvatureConfidence << "]\n";
        prefix("Curvature Calculation Mode") << bvc.curvatureCalculationMode << "\n";
        prefix("Yaw Rate [Confidence]") << bvc.yawRate.yawRateValue
            << " [" << bvc.yawRate.yawRateConfidence << "]\n";
        --level;
    } else if (cam.camParameters.highFrequencyContainer.present == HighFrequencyContainer_PR_rsuContainerHighFrequency) {
        prefix("High Frequency Container [RSU]") << "\n";
        const RSUContainerHighFrequency_t& rsu = cam.camParameters.highFrequencyContainer.choice.rsuContainerHighFrequency;
        if (nullptr != rsu.protectedCommunicationZonesRSU && nullptr != rsu.protectedCommunicationZonesRSU->list.array) {
            ++level;
            int size = rsu.protectedCommunicationZonesRSU->list.count;
            for (int i = 0; i < size; i++)
            {
                prefix("Protected Zone") << "\n";
                ++level;
                prefix("Type") << rsu.protectedCommunicationZonesRSU->list.array[i]->protectedZoneType << "\n";
                if (rsu.protectedCommunicationZonesRSU->list.array[i]->expiryTime
                    && nullptr != rsu.protectedCommunicationZonesRSU->list.array[i]->expiryTime->buf
                    && rsu.protectedCommunicationZonesRSU->list.array[i]->expiryTime->size > 0)
                    prefix("Expiry Time") << (unsigned) rsu.protectedCommunicationZonesRSU->list.array[i]->expiryTime->buf[0] << "\n";
                prefix("Latitude") << rsu.protectedCommunicationZonesRSU->list.array[i]->protectedZoneLatitude << "\n";
                prefix("Longitude") << rsu.protectedCommunicationZonesRSU->list.array[i]->protectedZoneLongitude << "\n";
                if (nullptr != rsu.protectedCommunicationZonesRSU->list.array[i]->protectedZoneRadius)
                    prefix("Radius") << *(rsu.protectedCommunicationZonesRSU->list.array[i]->protectedZoneRadius) << "\n";
                if (nullptr != rsu.protectedCommunicationZonesRSU->list.array[i]->protectedZoneRadius)
                    prefix("ID") << *(rsu.protectedCommunicationZonesRSU->list.array[i]->protectedZoneID) << "\n";
                --level;
            }
            --level;
        }
    } else {
        prefix("High Frequency Container") << "empty\n";
    }

    if (nullptr != cam.camParameters.lowFrequencyContainer) {
        if (cam.camParameters.lowFrequencyContainer->present == LowFrequencyContainer_PR_basicVehicleContainerLowFrequency) {
            prefix("Low Frequency Container") << "\n";
            const BasicVehicleContainerLowFrequency_t& lfc =
                cam.camParameters.lowFrequencyContainer->choice.basicVehicleContainerLowFrequency;
            ++level;
            prefix("Vehicle Role") << (lfc.vehicleRole) << "\n";

            if (nullptr != lfc.exteriorLights.buf && lfc.exteriorLights.size > 0)
                prefix("Exterior Lights") << unsigned(*(lfc.exteriorLights.buf)) << "\n";
            if (nullptr != lfc.pathHistory.list.array) {
                int size = lfc.pathHistory.list.count;
                for (int i = 0; i < size; i++)
                {
                    prefix("Path history point") << "\n";
                    ++level;
                    prefix("Latitude") << (lfc.pathHistory.list.array[i]->pathPosition.deltaLatitude) << "\n";
                    prefix("Longitude") << (lfc.pathHistory.list.array[i]->pathPosition.deltaLongitude) << "\n";
                    prefix("Altitude") << (lfc.pathHistory.list.array[i]->pathPosition.deltaAltitude) << "\n";
                    if (lfc.pathHistory.list.array[i]->pathDeltaTime)
                        prefix("Delta time") << *(lfc.pathHistory.list.array[i]->pathDeltaTime) << "\n";
                    --level;
                }
            }
            --level;
        }
        else // LowFrequencyContainer_PR_NOTHING
            prefix("Low Frequency Container") << "present but empty" << "\n";
    }
    else
        prefix("Low Frequency Container") << "not present" << "\n";

    if (nullptr != cam.camParameters.specialVehicleContainer) {
        if (cam.camParameters.specialVehicleContainer->present == SpecialVehicleContainer_PR_publicTransportContainer) {
            prefix("Special Vehicle Container [Public Transport]") << "\n";
            PublicTransportContainer_t& ptc = cam.camParameters.specialVehicleContainer->choice.publicTransportContainer;
            ++level;
            prefix("Embarkation Status") << ptc.embarkationStatus << "\n";
            if (ptc.ptActivation) {
                prefix("PT Activation Type") << ptc.ptActivation->ptActivationType << "\n";
                if (0 != ptc.ptActivation->ptActivationData.size) {
                    int size = ptc.ptActivation->ptActivationData.size;
                    for (int i = 0; i < ptc.ptActivation->ptActivationData.size; i++)
                    prefix("PT Activation Data") << (unsigned) ptc.ptActivation->ptActivationData.buf[i] << "\n";
                }
            }
            --level;
        } else if (cam.camParameters.specialVehicleContainer->present == SpecialVehicleContainer_PR_specialTransportContainer) {
            prefix("Special Vehicle Container [Special Transport]") << "\n";
            SpecialTransportContainer_t& stc = cam.camParameters.specialVehicleContainer->choice.specialTransportContainer;
            ++level;
            if (nullptr != stc.specialTransportType.buf && stc.specialTransportType.size > 0)
                prefix("Type") << (unsigned) stc.specialTransportType.buf[0] << "\n";
            if (nullptr != stc.lightBarSirenInUse.buf && stc.lightBarSirenInUse.size > 0)
                prefix("Light Bar Siren in Use") << (unsigned) stc.lightBarSirenInUse.buf[0] << "\n";
            --level;
        } else if (cam.camParameters.specialVehicleContainer->present == SpecialVehicleContainer_PR_dangerousGoodsContainer) {
            prefix("Special Vehicle Container [Dangerous Goods]") << "\n";
            DangerousGoodsContainer_t& dgc = cam.camParameters.specialVehicleContainer->choice.dangerousGoodsContainer;
            ++level;
            prefix("Dangerous Goods Basic Type") << (unsigned)dgc.dangerousGoodsBasic << "\n";
            --level;
        } else if (cam.camParameters.specialVehicleContainer->present == SpecialVehicleContainer_PR_roadWorksContainerBasic) {
            prefix("Special Vehicle Container [Road Works]") << "\n";
            RoadWorksContainerBasic_t& rwc = cam.camParameters.specialVehicleContainer->choice.roadWorksContainerBasic;
            ++level;
            if (nullptr != rwc.roadworksSubCauseCode)
                prefix("Sub Cause Code") << *(rwc.roadworksSubCauseCode) << "\n";
            if (nullptr != rwc.lightBarSirenInUse.buf && rwc.lightBarSirenInUse.size > 0)
                prefix("Light Bar Siren in Use") << (unsigned) rwc.lightBarSirenInUse.buf[0] << "\n";
            if (nullptr != rwc.closedLanes) {
                if (rwc.closedLanes->innerhardShoulderStatus)
                    prefix("Inner Hard Shoulder Status") << *(rwc.closedLanes->innerhardShoulderStatus) << "\n";
                if (rwc.closedLanes->outerhardShoulderStatus)
                    prefix("Outer Hard Shoulder Status") << *(rwc.closedLanes->outerhardShoulderStatus) << "\n";
                if (rwc.closedLanes->drivingLaneStatus && nullptr != rwc.closedLanes->drivingLaneStatus->buf
                    && rwc.closedLanes->drivingLaneStatus->size > 0)
                    prefix("Driving Lane Status") << (unsigned) rwc.closedLanes->drivingLaneStatus->buf[0] << "\n";
            }
            --level;
        } else if (cam.camParameters.specialVehicleContainer->present == SpecialVehicleContainer_PR_rescueContainer) {
            prefix("Special Vehicle Container [Rescue]") << "\n";
            RescueContainer_t& rc = cam.camParameters.specialVehicleContainer->choice.rescueContainer;
            ++level;
            if (nullptr != rc.lightBarSirenInUse.buf && rc.lightBarSirenInUse.size > 0)
                prefix("Light Bar Siren in Use") << (unsigned) rc.lightBarSirenInUse.buf[0] << "\n";
            --level;
        } else if (cam.camParameters.specialVehicleContainer->present == SpecialVehicleContainer_PR_emergencyContainer) {
            prefix("Special Vehicle Container [Emergency]") << "\n";
            EmergencyContainer_t& ec = cam.camParameters.specialVehicleContainer->choice.emergencyContainer;
            ++level;
            if (nullptr != ec.lightBarSirenInUse.buf && ec.lightBarSirenInUse.size > 0)
                prefix("Light Bar Siren in Use") << (unsigned) ec.lightBarSirenInUse.buf[0] << "\n";
            if (nullptr != ec.incidentIndication) {
                prefix("Incident Indication Cause Code") << ec.incidentIndication->causeCode << "\n";
                prefix("Incident Indication Sub Cause Code") << ec.incidentIndication->subCauseCode << "\n";
            }
            if (nullptr != ec.emergencyPriority && nullptr != ec.emergencyPriority->buf
                && ec.emergencyPriority->size > 0) {
                prefix("Emergency Priority") << (unsigned) ec.emergencyPriority->buf[0] << "\n";
            }
            --level;
        } else if (cam.camParameters.specialVehicleContainer->present == SpecialVehicleContainer_PR_safetyCarContainer) {
            prefix("Special Vehicle Container [Safety Car]") << "\n";
            SafetyCarContainer_t& sc = cam.camParameters.specialVehicleContainer->choice.safetyCarContainer;
            ++level;
            if (nullptr != sc.lightBarSirenInUse.buf && sc.lightBarSirenInUse.size > 0)
                prefix("Light Bar Siren in Use") << (unsigned) sc.lightBarSirenInUse.buf[0] << "\n";
            if (nullptr != sc.incidentIndication) {
                prefix("Incident Indication Cause Code") << sc.incidentIndication->causeCode << "\n";
                prefix("Incident Indication Sub Cause Code") << sc.incidentIndication->subCauseCode << "\n";
            }
            if (nullptr != sc.trafficRule) {
                prefix("Traffic Rule") << *(sc.trafficRule) << "\n";
            }
            if (nullptr != sc.speedLimit) {
                prefix("Speed Limit") << *(sc.speedLimit) << "\n";
            }
            --level;
        }
        else // SpecialVehicleContainer_PR_NOTHING
            prefix("Special Vehicle Container") << ("present but empty") << "\n";
    }
    else
        prefix("Special Vehicle Container") << "not present" << "\n";
    */
    --level;
}