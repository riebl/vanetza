#include "application.hpp"
#include <vanetza/btp/header.hpp>
#include <vanetza/btp/header_conversion.hpp>
// ERIK
#include <vanetza/asn1/cam.hpp>
#include <cassert>

using namespace vanetza;

Application::DataConfirm Application::request(const DataRequest& request, DownPacketPtr packet)
{
    DataConfirm confirm(DataConfirm::ResultCode::Rejected_Unspecified);
    if (router_ && packet) {
        btp::HeaderB btp_header;
        btp_header.destination_port = this->port();
        btp_header.destination_port_info = host_cast<uint16_t>(0);
        packet->layer(OsiLayer::Transport) = btp_header;

        switch (request.transport_type) {
            case geonet::TransportType::SHB:
                confirm = router_->request(request_shb(request), std::move(packet));
                break;
            case geonet::TransportType::GBC:
                confirm = router_->request(request_gbc(request), std::move(packet));
                break;
            default:
                // TODO remaining transport types are not implemented
                break;
        }
    }

    return confirm;
}

void initialize_request(const Application::DataRequest& generic, geonet::DataRequest& geonet)
{
    geonet.upper_protocol = geonet::UpperProtocol::BTP_B;
    geonet.communication_profile = generic.communication_profile;
    geonet.its_aid = generic.its_aid;
    if (generic.maximum_lifetime) {
        geonet.maximum_lifetime = generic.maximum_lifetime.get();
    }
    geonet.repetition = generic.repetition;
    geonet.traffic_class = generic.traffic_class;
}

geonet::GbcDataRequest Application::request_gbc(const DataRequest& generic)
{
    assert(router_);
    geonet::GbcDataRequest gbc(router_->get_mib());
    initialize_request(generic, gbc);
    gbc.destination = boost::get<geonet::Area>(generic.destination);
    return gbc;
}

geonet::ShbDataRequest Application::request_shb(const DataRequest& generic)
{
    assert(router_);
    geonet::ShbDataRequest shb(router_->get_mib());
    initialize_request(generic, shb);
    return shb;
}

Application::PromiscuousHook* Application::promiscuous_hook()
{
    return nullptr;
}

void Application::Printcam(asn1::Cam message)
{
// Erik de Britto e Silva - github user : erikbritto
// University of Antwerp - erik.debrittoesilva@uantwerpen.be
// imec - IDLab - erik.britto@imec.be
// Sint-Pietersvliet 7 - The Beacon
// 2060 - Antwerpen - Belgium

    // tab = increasing tabulation level
    std::string tab = "\t"; 
    // ********************************* ITS PDU HEADER
    ItsPduHeader_t& header = message->header;
    std::cout << "Protocol version : " 
	      << header.protocolVersion
              << std::endl;
    std::cout << "Message ID : "
	      << header.messageID
              << std::endl;
    std::cout << "Station Id : "
	      << header.stationID
              << std::endl;
   
    // ********************************* START of CAM - DeltaTime 
    CoopAwareness_t& cam = message->cam;
    std::cout << tab +"Deltatime = "
	      << cam.generationDeltaTime
              << std::endl;
       
    // ******************************** CAM PARAMETERS BASIC CONTAINER
    BasicContainer_t& basic = cam.camParameters.basicContainer;
    std::cout << tab + "Station Typex = "
              << basic.stationType
              << std::endl;
    std::cout << tab + "Ref Pos Longitude = "
              << basic.referencePosition.longitude
              << std::endl;
    std::cout << tab + "Ref Pos Latitude = "
              << basic.referencePosition.latitude
              << std::endl;
    std::cout << tab + "Semi Major Orientation = "
              << basic.referencePosition.positionConfidenceEllipse.semiMajorOrientation
              << std::endl;
    std::cout << tab + "Semi Major Confidence = "
              << basic.referencePosition.positionConfidenceEllipse.semiMajorConfidence
              << std::endl;
    std::cout << tab + "Semi Minor Confidence = "
              << basic.referencePosition.positionConfidenceEllipse.semiMinorConfidence
              << std::endl;
    std::cout << tab + "Ref Pos Altitude = "
              << basic.referencePosition.altitude.altitudeValue
              << std::endl;
    std::cout << tab + "Ref Pos Altitude Conf = "
              << basic.referencePosition.altitude.altitudeConfidence
              << std::endl;

    std::cout << tab + "High Freq Container Present = "
              << cam.camParameters.highFrequencyContainer.present
              << std::endl;

    std::string error;
    if (!message.validate(error)) {
        std::cout << "Invalid High Frequency CAM: " << error << std::endl;
    }                  
                 
    tab += tab;
    // ******************************** BASIC VEHICLE HIGH FREQUENCY CONTAINER
    BasicVehicleContainerHighFrequency& bvc = cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency;
    std::cout << tab + "HF Heading = "
              << bvc.heading.headingValue
              << std::endl;
    std::cout << tab + "HF Heading Conf = "
              << bvc.heading.headingConfidence
              << std::endl;
    std::cout << tab + "HF Speed =  "
              << bvc.speed.speedValue
              << std::endl;
    std::cout << tab + "HF Speed Conf = "
              << bvc.speed.speedConfidence
              << std::endl;

    std::cout << tab + "HF Drive Directionx = "
              << bvc.driveDirection
              << std::endl;
                 
    std::cout << tab + "HF Longitudinal Accel = "
              << bvc.longitudinalAcceleration.longitudinalAccelerationValue
              << std::endl;

    std::cout << tab + "HF Vehicle Lenght = "
              << bvc.vehicleLength.vehicleLengthValue
              << std::endl;
    std::cout << tab + "HF Vehicle Leng Conf Indication: = "
              << bvc.vehicleLength.vehicleLengthConfidenceIndication
              << std::endl;
    std::cout << tab + "HF Vehicle Width = "
              << bvc.vehicleWidth
              << std::endl;

    std::cout << tab + "HF Curvature = "
              << bvc.curvature.curvatureValue
              << std::endl;
    std::cout << tab + "HF Curvature Conf = "
              << bvc.curvature.curvatureConfidence
              << std::endl;
    std::cout << tab + "HF Curvature Calculation Mode = "
              << bvc.curvatureCalculationMode
              << std::endl;

    std::cout << tab + "HF Yaw Rate = "
              << bvc.yawRate.yawRateValue
              << std::endl;
    
    std::cout << tab + "HF Yaw Rate = "
              << bvc.yawRate.yawRateValue
              << std::endl;
    
    tab += tab;
    // ******************************** BASIC VEHICLE LOW FREQUENCY CONTAINER


    tab += tab;
    // ******************************** SPECIAL VEHICLE CONTAINER
}

