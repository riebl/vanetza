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

// This is rather simple application that decodes received CAMs in a regular interval
  
// Erik de Britto e Silva
// University of Antwerp - erik.debrittoesilva@uantwerpen.be
// imec - IDLab - erik.britto@imec.be
// Sint-Pietersvliet 7 - The Beacon
// 2060 - Antwerpen - Belgium

using namespace vanetza;
using namespace vanetza::facilities;
using namespace std::chrono;

auto microdegree = vanetza::units::degree * boost::units::si::micro;

template<typename T, typename U>
long round(const boost::units::quantity<T>& q, const U& u)
{
	boost::units::quantity<U> v { q };
	return std::round(v.value());

}

CamApplication::CamApplication(PositionProvider& positioning, const Runtime& rt, boost::asio::steady_timer& timer, milliseconds cam_interval)
    : positioning_(positioning), runtime_(rt), cam_interval_(cam_interval), timer_(timer)
{
   schedule_timer();
}

CamApplication::PortType CamApplication::port()
{
    return btp::ports::CAM;
}

void CamApplication::schedule_timer()
{
    timer_.expires_from_now(cam_interval_);
    timer_.async_wait(std::bind(&CamApplication::on_timer, this, std::placeholders::_1));
}



void CamApplication::indicate(const DataIndication& indication, UpPacketPtr packet)
{
    std::cout << "Decode CAM application received a packet with ";

    vanetza::CohesivePacket* p = boost::get<vanetza::CohesivePacket>(packet.get());
    if (!p) {
        std::cout << "broken content" << std::endl;
        return;
    };


    /*
     * https://github.com/riebl/vanetza/issues/75
     */
    auto bf = create_byte_view(*p, OsiLayer::Session, OsiLayer::Application);
    vanetza::asn1::Cam message;

    if (message.decode(bf.begin(), bf.end())) {
        std::cout << "decodable content" << std::endl;
    } else {
        std::cout << "failed decode buffer" << std::endl;
        return;

    };

    // ********************************* ITS PDU HEADER
    ItsPduHeader_t& header = message->header;
    std::cout << "header.protocolVersion: "
              << header.protocolVersion
              << std::endl;
    std::cout << "header.messageID: "
              << header.messageID
              << std::endl;
    std::cout << "header.stationID: "
              << header.stationID
              << std::endl;
   
    // ********************************* START of CAM - DeltaTime 
    CoopAwareness_t& cam = message->cam;
    std::cout << "cam.generationDeltaTime: "
              << cam.generationDeltaTime
              << std::endl;
       
    // ******************************** CAM PARAMETERS BASIC CONTAINER
    BasicContainer_t& basic = cam.camParameters.basicContainer;
    std::cout << "cam.camParameters.basicContainer.stationType: "
              << basic.stationType
              << std::endl;
    std::cout << "cam.camParameters.basicContainer.referencePosition.longitude: "
              << basic.referencePosition.longitude
              << std::endl;
    std::cout << "cam.camParameters.basicContainer.referencePosition.latitude: "
              << basic.referencePosition.latitude
              << std::endl;
    std::cout << "cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorOrientation: "
              << basic.referencePosition.positionConfidenceEllipse.semiMajorOrientation
              << std::endl;
    std::cout << "cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorConfidence: "
              << basic.referencePosition.positionConfidenceEllipse.semiMajorConfidence
              << std::endl;
    std::cout << "cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorConfidence: "
              << basic.referencePosition.positionConfidenceEllipse.semiMinorConfidence
              << std::endl;
    std::cout << "cam.camParameters.basicContainer.referencePosition.altitude.altitudeValue: "
              << basic.referencePosition.altitude.altitudeValue
              << std::endl;
    std::cout << "cam.camParameters.basicContainer.referencePosition.altitude.altitudeConfidence: "
              << basic.referencePosition.altitude.altitudeConfidence
              << std::endl;

    std::cout << "cam.camParameters.highFrequencyContainer.present: "
              << cam.camParameters.highFrequencyContainer.present
              << std::endl;
                 
    // ******************************** BASIC VEHICLE HIGH FREQUENCY CONTAINER
    BasicVehicleContainerHighFrequency& bvc = cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency;
    std::cout << "cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.heading.headingValue: "
              << bvc.heading.headingValue
              << std::endl;
    std::cout << "cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.heading.headingConfidence: "
              << bvc.heading.headingConfidence
              << std::endl;
    std::cout << "cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue: "
              << bvc.speed.speedValue
              << std::endl;
    std::cout << "cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedConfidence: "
              << bvc.speed.speedConfidence
              << std::endl;

    std::cout << "cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.driveDirection: "
              << bvc.driveDirection
              << std::endl;
                 
    std::cout << "cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.longitudinalAcceleration.longitudinalAccelerationValue: "
              << bvc.longitudinalAcceleration.longitudinalAccelerationValue
              << std::endl;

    std::cout << "cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.vehicleLength.vehicleLengthValue: "
              << bvc.vehicleLength.vehicleLengthValue
              << std::endl;
    std::cout << "cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.vehicleLength.vehicleLengthConfidenceIndication: "
              << bvc.vehicleLength.vehicleLengthConfidenceIndication
              << std::endl;
    std::cout << "cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.vehicleWidth: "
              << bvc.vehicleWidth
              << std::endl;

    std::cout << "cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.curvature.curvatureValue: "
              << bvc.curvature.curvatureValue
              << std::endl;
    std::cout << "cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.curvature.curvatureConfidence"
              << bvc.curvature.curvatureConfidence
              << std::endl;
    std::cout << "cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.curvatureCalculationMode: "
              << bvc.curvatureCalculationMode
              << std::endl;

    std::cout << "cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.yawRate.yawRateValue: "
              << bvc.yawRate.yawRateValue
              << std::endl;

    std::string error;
    if (!message.validate(error)) {
        std::cout << "Invalid high frequency CAM: " << error << std::endl;
    }                  
       
}

void CamApplication::on_timer(const boost::system::error_code& ec)
{
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }

    vanetza::asn1::Cam message;

    ItsPduHeader_t& header = message->header;
    header.protocolVersion = 2;
    header.messageID = ItsPduHeader__messageID_cam;
    header.stationID = 1; // some dummy value

    const auto time_now = duration_cast<milliseconds>(runtime_.now().time_since_epoch());
    uint16_t gen_delta_time = time_now.count();

    CoopAwareness_t& cam = message->cam;
    cam.generationDeltaTime = gen_delta_time * GenerationDeltaTime_oneMilliSec;

    auto position = positioning_.position_fix();

    if (!position.confidence) {
        schedule_timer();

        std::cerr << "Skipping CAM, because no good position is available, yet." << std::endl;

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

    schedule_timer();
}
