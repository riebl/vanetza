#include "cam_application.hpp"
#include <vanetza/btp/ports.hpp>
#include <vanetza/asn1/cam.hpp>
#include <boost/units/systems/si/prefixes.hpp>
#include <chrono>
#include <exception>
#include <functional>
#include <iostream>

// This is rather simple application that sends CAMs in a regular interval.

using namespace vanetza;
using namespace vanetza::geonet;
using namespace std::chrono;

CamApplication::CamApplication(PositionProvider& positioning, const Runtime& rt, boost::asio::steady_timer& timer, milliseconds cam_interval)
    : positioning_(positioning), runtime_(rt), cam_interval_(cam_interval), timer_(timer)
{
    schedule_timer();
}

CamApplication::PortType CamApplication::port()
{
    return host_cast<uint16_t>(2001);
}

void CamApplication::indicate(const DataIndication& indication, UpPacketPtr packet)
{
    std::cout << "CAM application received a packet" << std::endl;
}

void CamApplication::schedule_timer()
{
    timer_.expires_from_now(cam_interval_);
    timer_.async_wait(std::bind(&CamApplication::on_timer, this, std::placeholders::_1));
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
    basic.referencePosition.altitude.altitudeValue = AltitudeValue_unavailable;
    basic.referencePosition.longitude = std::round(static_cast<geo_angle_i32t>(position.longitude).value());
    basic.referencePosition.latitude = std::round(static_cast<geo_angle_i32t>(position.latitude).value());
    basic.referencePosition.positionConfidenceEllipse.semiMajorOrientation = HeadingValue_unavailable;
    basic.referencePosition.positionConfidenceEllipse.semiMajorConfidence = SemiAxisLength_unavailable;
    basic.referencePosition.positionConfidenceEllipse.semiMinorConfidence = SemiAxisLength_unavailable;

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
