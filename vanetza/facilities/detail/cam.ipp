#include <vanetza/asn1/its/CAM.h>
#include <vanetza/asn1/its/r2/CAM.h>
#include <vanetza/facilities/detail/macros.ipp>
#include <iostream>

ASSERT_EQUAL_TYPE(AltitudeConfidence_t);
ASSERT_EQUAL_ENUM(AltitudeConfidence_alt_000_01);
ASSERT_EQUAL_ENUM(AltitudeConfidence_alt_200_00);
ASSERT_EQUAL_ENUM(AltitudeConfidence_outOfRange);
ASSERT_EQUAL_ENUM(AltitudeConfidence_unavailable);

ASSERT_EQUAL_TYPE(AltitudeValue_t);
ASSERT_EQUAL_ENUM(AltitudeValue_unavailable);

ASSERT_EQUAL_TYPE(DeltaAltitude_t);
ASSERT_EQUAL_ENUM(DeltaAltitude_unavailable);

ASSERT_EQUAL_TYPE(DeltaLatitude_t);
ASSERT_EQUAL_ENUM(DeltaLatitude_unavailable);

ASSERT_EQUAL_TYPE(DeltaLongitude_t);
ASSERT_EQUAL_ENUM(DeltaLongitude_unavailable);

ASSERT_EQUAL_TYPE(Latitude_t);
ASSERT_EQUAL_ENUM(Latitude_unavailable);

ASSERT_EQUAL_TYPE(Longitude_t);
ASSERT_EQUAL_ENUM(Longitude_unavailable);

ASSERT_EQUAL_TYPE(PathDeltaTime_t);

namespace vanetza
{
namespace facilities
{

bool check_service_specific_permissions(const ASN1_PREFIXED(CamParameters_t)& params, security::CamPermissions ssp)
{
    using security::CamPermission;
    using security::CamPermissions;

    CamPermissions required_permissions;

    if (params.highFrequencyContainer.present == ASN1_PREFIXED(HighFrequencyContainer_PR_rsuContainerHighFrequency)) {
        const ASN1_PREFIXED(RSUContainerHighFrequency_t)& rsu = params.highFrequencyContainer.choice.rsuContainerHighFrequency;
        if (rsu.protectedCommunicationZonesRSU) {
            required_permissions.add(CamPermission::CEN_DSRC_Tolling_Zone);
        }
    }

    if (const ASN1_PREFIXED(SpecialVehicleContainer_t)* special = params.specialVehicleContainer) {
        const ASN1_PREFIXED(EmergencyContainer_t)* emergency = nullptr;
        const ASN1_PREFIXED(SafetyCarContainer_t)* safety = nullptr;
        const ASN1_PREFIXED(RoadWorksContainerBasic_t)* roadworks = nullptr;

        switch (special->present) {
            case ASN1_PREFIXED(SpecialVehicleContainer_PR_publicTransportContainer):
                required_permissions.add(CamPermission::Public_Transport);
                break;
            case ASN1_PREFIXED(SpecialVehicleContainer_PR_specialTransportContainer):
                required_permissions.add(CamPermission::Special_Transport);
                break;
            case ASN1_PREFIXED(SpecialVehicleContainer_PR_dangerousGoodsContainer):
                required_permissions.add(CamPermission::Dangerous_Goods);
                break;
            case ASN1_PREFIXED(SpecialVehicleContainer_PR_roadWorksContainerBasic):
                required_permissions.add(CamPermission::Roadwork);
                roadworks = &special->choice.roadWorksContainerBasic;
                break;
            case ASN1_PREFIXED(SpecialVehicleContainer_PR_rescueContainer):
                required_permissions.add(CamPermission::Rescue);
                break;
            case ASN1_PREFIXED(SpecialVehicleContainer_PR_emergencyContainer):
                required_permissions.add(CamPermission::Emergency);
                emergency = &special->choice.emergencyContainer;
                break;
            case ASN1_PREFIXED(SpecialVehicleContainer_PR_safetyCarContainer):
                required_permissions.add(CamPermission::Safety_Car);
                safety = &special->choice.safetyCarContainer;
                break;
            default:
                break;
        }

        if (emergency && emergency->emergencyPriority && emergency->emergencyPriority->size == 1) {
            // testing bit strings from asn1c is such a mess...
            assert(emergency->emergencyPriority->buf);
            uint8_t bits = *emergency->emergencyPriority->buf;
            if (bits & (1 << (7 - ASN1_PREFIXED(EmergencyPriority_requestForRightOfWay)))) {
                required_permissions.add(CamPermission::Request_For_Right_Of_Way);
            }
            if (bits & (1 << (7 - ASN1_PREFIXED(EmergencyPriority_requestForFreeCrossingAtATrafficLight)))) {
                required_permissions.add(CamPermission::Request_For_Free_Crossing_At_Traffic_Light);
            }
        }

        if (roadworks && roadworks->closedLanes) {
            required_permissions.add(CamPermission::Closed_Lanes);
        }

        if (safety && safety->trafficRule) {
            switch (*safety->trafficRule) {
                case ASN1_PREFIXED(TrafficRule_noPassing):
                    required_permissions.add(CamPermission::No_Passing);
                    break;
                case ASN1_PREFIXED(TrafficRule_noPassingForTrucks):
                    required_permissions.add(CamPermission::No_Passing_For_Trucks);
                    break;
                default:
                    break;
            }
        }

        if (safety && safety->speedLimit) {
            required_permissions.add(CamPermission::Speed_Limit);
        }
    }

    return ssp.has(required_permissions);
}

void print_indented(std::ostream& os, const ASN1_PREFIXED(CAM_t)* message, const std::string& indent, unsigned level)
{
    auto prefix = [&](const char* field) -> std::ostream& {
        for (unsigned i = 0; i < level; ++i) {
            os << indent;
        }
        os << field << ": ";
        return os;
    };

    const ASN1_PREFIXED(ItsPduHeader_t)& header = message->header;
    prefix("ITS PDU Header") << "\n";
    ++level;
    prefix("Protocol Version") << header.protocolVersion << "\n";
    #if ITS_RELEASE == 1
    prefix("Message ID") << header.messageID << "\n";
    prefix("Station ID") << header.stationID << "\n";
    #else
    prefix("Message ID") << header.messageId << "\n";
    prefix("Station ID") << header.stationId << "\n";
    #endif
    --level;

    #if ITS_RELEASE == 1
    const ASN1_PREFIXED(CoopAwareness_t)& cam = message->cam;
    #else
    const ASN1_PREFIXED(CamPayload_t)& cam = message->cam;
    #endif
    prefix("CoopAwareness") << "\n";
    ++level;
    prefix("Generation Delta Time") << cam.generationDeltaTime << "\n";

    prefix("Basic Container") << "\n";
    ++level;
    const ASN1_PREFIXED(BasicContainer_t)& basic = cam.camParameters.basicContainer;
    prefix("Station Type") << basic.stationType << "\n";
    prefix("Reference Position") << "\n";
    ++level;
    prefix("Longitude") << basic.referencePosition.longitude << "\n";
    prefix("Latitude") << basic.referencePosition.latitude << "\n";
    #if ITS_RELEASE == 1
    prefix("Semi Major Orientation") << basic.referencePosition.positionConfidenceEllipse.semiMajorOrientation << "\n";
    prefix("Semi Major Confidence") << basic.referencePosition.positionConfidenceEllipse.semiMajorConfidence << "\n";
    prefix("Semi Minor Confidence") << basic.referencePosition.positionConfidenceEllipse.semiMinorConfidence << "\n";
    #else
    prefix("Semi Major Axis Orientation") << basic.referencePosition.positionConfidenceEllipse.semiMajorAxisOrientation << "\n";
    prefix("Semi Major Axis Length") << basic.referencePosition.positionConfidenceEllipse.semiMajorAxisLength << "\n";
    prefix("Semi Minor Axis Length") << basic.referencePosition.positionConfidenceEllipse.semiMinorAxisLength << "\n";
    #endif

    prefix("Altitude [Confidence]") << basic.referencePosition.altitude.altitudeValue
        << " [" << basic.referencePosition.altitude.altitudeConfidence << "]\n";
    --level;
    --level;

    if (cam.camParameters.highFrequencyContainer.present == ASN1_PREFIXED(HighFrequencyContainer_PR_basicVehicleContainerHighFrequency)) {
        prefix("High Frequency Container [Basic Vehicle]") << "\n";
        ++level;
        const ASN1_PREFIXED(BasicVehicleContainerHighFrequency)& bvc =
            cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency;
        prefix("Heading [Confidence]") << bvc.heading.headingValue
            << " [" << bvc.heading.headingConfidence << "]\n";
        prefix("Speed [Confidence]") << bvc.speed.speedValue
            << " [" << bvc.speed.speedConfidence << "]\n";
        prefix("Drive Direction") << bvc.driveDirection << "\n";
        #if ITS_RELEASE == 1
        prefix("Longitudinal Acceleration [Confidence]") << bvc.longitudinalAcceleration.longitudinalAccelerationValue
            << " [" << bvc.longitudinalAcceleration.longitudinalAccelerationConfidence << "]\n";
        #else
        prefix("Longitudinal Acceleration [Confidence]") << bvc.longitudinalAcceleration.value
            << " [" << bvc.longitudinalAcceleration.confidence << "]\n";
        #endif
        prefix("Vehicle Length [Confidence Indication]") << bvc.vehicleLength.vehicleLengthValue
            << " [" << bvc.vehicleLength.vehicleLengthConfidenceIndication << "]\n";
        prefix("Vehicle Width") << bvc.vehicleWidth << "\n";
        prefix("Curvature [Confidence]") << bvc.curvature.curvatureValue
            << " [" << bvc.curvature.curvatureConfidence << "]\n";
        prefix("Curvature Calculation Mode") << bvc.curvatureCalculationMode << "\n";
        prefix("Yaw Rate [Confidence]") << bvc.yawRate.yawRateValue
            << " [" << bvc.yawRate.yawRateConfidence << "]\n";
        --level;
    } else if (cam.camParameters.highFrequencyContainer.present == ASN1_PREFIXED(HighFrequencyContainer_PR_rsuContainerHighFrequency)) {
        prefix("High Frequency Container [RSU]") << "\n";
        const ASN1_PREFIXED(RSUContainerHighFrequency_t)& rsu = cam.camParameters.highFrequencyContainer.choice.rsuContainerHighFrequency;
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
                    #if ITS_RELEASE == 1
                    prefix("ID") << *(rsu.protectedCommunicationZonesRSU->list.array[i]->protectedZoneID) << "\n";
                    #else
                    prefix("ID") << *(rsu.protectedCommunicationZonesRSU->list.array[i]->protectedZoneId) << "\n";
                    #endif
                --level;
            }
            --level;
        }
    } else {
        prefix("High Frequency Container") << "empty\n";
    }

    if (nullptr != cam.camParameters.lowFrequencyContainer) {
        if (cam.camParameters.lowFrequencyContainer->present == ASN1_PREFIXED(LowFrequencyContainer_PR_basicVehicleContainerLowFrequency)) {
            prefix("Low Frequency Container") << "\n";
            const ASN1_PREFIXED(BasicVehicleContainerLowFrequency_t)& lfc =
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
        if (cam.camParameters.specialVehicleContainer->present == ASN1_PREFIXED(SpecialVehicleContainer_PR_publicTransportContainer)) {
            prefix("Special Vehicle Container [Public Transport]") << "\n";
            ASN1_PREFIXED(PublicTransportContainer_t)& ptc = cam.camParameters.specialVehicleContainer->choice.publicTransportContainer;
            ++level;
            prefix("Embarkation Status") << ptc.embarkationStatus << "\n";
            if (ptc.ptActivation) {
                prefix("PT Activation Type") << ptc.ptActivation->ptActivationType << "\n";
                if (0 != ptc.ptActivation->ptActivationData.size) {
                    for (size_t i = 0; i < ptc.ptActivation->ptActivationData.size; i++)
                    prefix("PT Activation Data") << (unsigned) ptc.ptActivation->ptActivationData.buf[i] << "\n";
                }
            }
            --level;
        } else if (cam.camParameters.specialVehicleContainer->present == ASN1_PREFIXED(SpecialVehicleContainer_PR_specialTransportContainer)) {
            prefix("Special Vehicle Container [Special Transport]") << "\n";
            ASN1_PREFIXED(SpecialTransportContainer_t)& stc = cam.camParameters.specialVehicleContainer->choice.specialTransportContainer;
            ++level;
            if (nullptr != stc.specialTransportType.buf && stc.specialTransportType.size > 0)
                prefix("Type") << (unsigned) stc.specialTransportType.buf[0] << "\n";
            if (nullptr != stc.lightBarSirenInUse.buf && stc.lightBarSirenInUse.size > 0)
                prefix("Light Bar Siren in Use") << (unsigned) stc.lightBarSirenInUse.buf[0] << "\n";
            --level;
        } else if (cam.camParameters.specialVehicleContainer->present == ASN1_PREFIXED(SpecialVehicleContainer_PR_dangerousGoodsContainer)) {
            prefix("Special Vehicle Container [Dangerous Goods]") << "\n";
            ASN1_PREFIXED(DangerousGoodsContainer_t)& dgc = cam.camParameters.specialVehicleContainer->choice.dangerousGoodsContainer;
            ++level;
            prefix("Dangerous Goods Basic Type") << (unsigned)dgc.dangerousGoodsBasic << "\n";
            --level;
        } else if (cam.camParameters.specialVehicleContainer->present == ASN1_PREFIXED(SpecialVehicleContainer_PR_roadWorksContainerBasic)) {
            prefix("Special Vehicle Container [Road Works]") << "\n";
            ASN1_PREFIXED(RoadWorksContainerBasic_t)& rwc = cam.camParameters.specialVehicleContainer->choice.roadWorksContainerBasic;
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
        } else if (cam.camParameters.specialVehicleContainer->present == ASN1_PREFIXED(SpecialVehicleContainer_PR_rescueContainer)) {
            prefix("Special Vehicle Container [Rescue]") << "\n";
            ASN1_PREFIXED(RescueContainer_t)& rc = cam.camParameters.specialVehicleContainer->choice.rescueContainer;
            ++level;
            if (nullptr != rc.lightBarSirenInUse.buf && rc.lightBarSirenInUse.size > 0)
                prefix("Light Bar Siren in Use") << (unsigned) rc.lightBarSirenInUse.buf[0] << "\n";
            --level;
        } else if (cam.camParameters.specialVehicleContainer->present == ASN1_PREFIXED(SpecialVehicleContainer_PR_emergencyContainer)) {
            prefix("Special Vehicle Container [Emergency]") << "\n";
            ASN1_PREFIXED(EmergencyContainer_t)& ec = cam.camParameters.specialVehicleContainer->choice.emergencyContainer;
            ++level;
            if (nullptr != ec.lightBarSirenInUse.buf && ec.lightBarSirenInUse.size > 0)
                prefix("Light Bar Siren in Use") << (unsigned) ec.lightBarSirenInUse.buf[0] << "\n";
            if (nullptr != ec.incidentIndication) {
                #if ITS_RELEASE == 1
                prefix("Incident Indication Cause Code") << ec.incidentIndication->causeCode << "\n";
                prefix("Incident Indication Sub Cause Code") << ec.incidentIndication->subCauseCode << "\n";
                #else
                prefix("Incident Indication Cause Code V2") << ec.incidentIndication->ccAndScc.present << "\n";
                prefix("Incident Indication Sub Cause Code V2") << ec.incidentIndication->ccAndScc.choice.reserved0 << "\n";
                #endif
            }
            if (nullptr != ec.emergencyPriority && nullptr != ec.emergencyPriority->buf
                && ec.emergencyPriority->size > 0) {
                prefix("Emergency Priority") << (unsigned) ec.emergencyPriority->buf[0] << "\n";
            }
            --level;
        } else if (cam.camParameters.specialVehicleContainer->present == ASN1_PREFIXED(SpecialVehicleContainer_PR_safetyCarContainer)) {
            prefix("Special Vehicle Container [Safety Car]") << "\n";
            ASN1_PREFIXED(SafetyCarContainer_t)& sc = cam.camParameters.specialVehicleContainer->choice.safetyCarContainer;
            ++level;
            if (nullptr != sc.lightBarSirenInUse.buf && sc.lightBarSirenInUse.size > 0)
                prefix("Light Bar Siren in Use") << (unsigned) sc.lightBarSirenInUse.buf[0] << "\n";
            if (nullptr != sc.incidentIndication) {
                #if ITS_RELEASE == 1
                prefix("Incident Indication Cause Code") << sc.incidentIndication->causeCode << "\n";
                prefix("Incident Indication Sub Cause Code") << sc.incidentIndication->subCauseCode << "\n";
                #else
                prefix("Incident Indication Cause Code V2") << sc.incidentIndication->ccAndScc.present << "\n";
                prefix("Incident Indication Sub Cause Code V2") << sc.incidentIndication->ccAndScc.choice.reserved0 << "\n";
                #endif
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

    --level;
}

} // namespace facilities
} // namespace vanetza
