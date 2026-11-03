#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/IntersectionAccessPoint.h>
#include <vanetza/asn1/its/RequestorType.h>
#include <vanetza/asn1/its/VehicleID.h>
#include <vanetza/asn1/its/SignalRequestList.h>
#include <vanetza/asn1/its/SignalRequestMessage.h>
#include <vanetza/asn1/its/SignalRequestPackage.h>
#include <vanetza/asn1/its/SignalRequesterInfo.h>
#include <vanetza/asn1/its/SignalStatus.h>
#include <vanetza/asn1/its/SignalStatusMessage.h>
#include <vanetza/asn1/its/SignalStatusPackage.h>
#include <vanetza/facilities/priority_functions.hpp>
#include <vanetza/facilities/spat_functions.hpp>
#include <chrono>
#include <stdexcept>

namespace vanetza
{
namespace facilities
{

namespace
{

void set_lane(IntersectionAccessPoint_t& point, unsigned lane)
{
    point.present = IntersectionAccessPoint_PR_lane;
    point.choice.lane = lane;
}

void set_station(VehicleID_t& id, std::uint32_t station_id)
{
    id.present = VehicleID_PR_stationID;
    id.choice.stationID = station_id;
}

long to_dsecond(Clock::duration duration)
{
    // check before truncating to milliseconds
    if (duration < Clock::duration::zero() || duration > std::chrono::milliseconds(65535)) {
        throw std::out_of_range("duration exceeds DSecond");
    }
    return static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(duration).count());
}

} // namespace

void set_requestor(SignalRequestMessage& message, std::uint32_t station_id, long role,
        boost::optional<long> vehicle_type)
{
    // Prepare the replacement before touching an existing, possibly decoded requestor.
    auto type = asn1::make_unique<RequestorType_t>(asn_DEF_RequestorType);
    type->role = role;
    if (vehicle_type.is_initialized()) {
        asn1::allocate_optional(type->hpmsType) = *vehicle_type;
    }
    ASN_STRUCT_RESET(asn_DEF_VehicleID, &message.requestor.id);
    set_station(message.requestor.id, station_id);
    ASN_STRUCT_FREE(asn_DEF_RequestorType, message.requestor.type);
    message.requestor.type = type.release();
}

void set_timestamp(SignalRequestMessage& message, const Clock::time_point& now)
{
    asn1::allocate_optional(message.timeStamp) = static_cast<long>(minute_of_the_year(now).count());
    message.second = static_cast<long>(dsecond(now).count());
}

void add_request(SignalRequestMessage& message, const PriorityRequest& request)
{
    auto package = asn1::make_unique<SignalRequestPackage_t>(asn_DEF_SignalRequestPackage);
    SignalRequest_t& details = package->request;
    details.id.id = request.intersection_id;
    details.requestID = request.request_id;
    details.requestType = request.request_type;
    set_lane(details.inBoundLane, request.inbound_lane);
    if (request.outbound_lane.is_initialized()) {
        set_lane(asn1::allocate_optional(details.outBoundLane), *request.outbound_lane);
    }
    if (request.arrival) {
        asn1::allocate_optional(package->minute) = static_cast<long>(minute_of_the_year(*request.arrival).count());
        asn1::allocate_optional(package->second) = static_cast<long>(dsecond(*request.arrival).count());
    }
    if (request.duration) {
        asn1::allocate_optional(package->duration) = to_dsecond(*request.duration);
    }
    if (message.requests) {
        asn1::append(*message.requests, std::move(package));
    } else {
        auto requests = asn1::make_unique<SignalRequestList_t>(asn_DEF_SignalRequestList);
        asn1::append(*requests, std::move(package));
        message.requests = requests.release();
    }
}

void set_timestamp(SignalStatusMessage& message, const Clock::time_point& now)
{
    asn1::allocate_optional(message.timeStamp) = static_cast<long>(minute_of_the_year(now).count());
    message.second = static_cast<long>(dsecond(now).count());
}

SignalStatus& add_status(SignalStatusMessage& message, unsigned intersection_id, unsigned sequence_number)
{
    auto status = asn1::make_unique<SignalStatus_t>(asn_DEF_SignalStatus);
    status->id.id = intersection_id;
    status->sequenceNumber = sequence_number;
    return asn1::append(message.status, std::move(status));
}

void add_response(SignalStatus& status, const PriorityResponse& response)
{
    auto package = asn1::make_unique<SignalStatusPackage_t>(asn_DEF_SignalStatusPackage);
    auto* requester = &asn1::allocate_optional(package->requester);
    set_station(requester->id, response.requester);
    requester->request = response.request_id;
    requester->sequenceNumber = response.request_sequence;
    asn1::allocate_optional(requester->role) = response.role;
    set_lane(package->inboundOn, response.inbound_lane);
    if (response.outbound_lane.is_initialized()) {
        set_lane(asn1::allocate_optional(package->outboundOn), *response.outbound_lane);
    }
    package->status = response.status;
    asn1::append(status.sigStatus, std::move(package));
}

} // namespace facilities
} // namespace vanetza
