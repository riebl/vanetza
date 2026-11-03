#ifndef PRIORITY_FUNCTIONS_HPP_M3RZ8WQE
#define PRIORITY_FUNCTIONS_HPP_M3RZ8WQE

#include <vanetza/common/clock.hpp>
#include <boost/optional/optional.hpp>
#include <cstdint>

// forward declaration of asn1c generated struct
struct SignalRequestMessage;
struct SignalStatus;
struct SignalStatusMessage;

namespace vanetza
{
namespace facilities
{

/**
 * Builders for signal request (SREM) and signal status (SSEM) messages
 * of the Traffic Light Control service (ETSI TS 103 301, ISO TS 19091 DSRC data elements).
 *
 * Time points are UTC based, as for minute_of_the_year() and dsecond(). The caller
 * sets the ITS header and message sequence number. Identifier and enumeration
 * constraints are checked by ASN.1 validation/encoding, as for the MAP/SPAT builders.
 */

/**
 * Set the requesting vehicle's identifier and type, replacing their previous values
 * \param message SignalRequestMessage (destination)
 * \param station_id station ID of the requesting vehicle
 * \param role BasicVehicleRole, e.g. publicTransport
 * \param vehicle_type optional VehicleType (HPMS), e.g. bus
 * \throw asn1::asn1c_exception if memory allocation fails, leaving the requestor unchanged
 */
void set_requestor(SignalRequestMessage& message, std::uint32_t station_id, long role,
        boost::optional<long> vehicle_type = boost::none);

/**
 * Set timeStamp and second of a signal request message
 * \param message SignalRequestMessage (destination)
 * \param now time of the message
 */
void set_timestamp(SignalRequestMessage& message, const Clock::time_point& now);

/** One request for priority or pre-emption at an intersection */
struct PriorityRequest
{
    unsigned intersection_id; /**< IntersectionID (0..65535) */
    unsigned request_id; /**< RequestID unique for this requestor (0..255) */
    long request_type; /**< PriorityRequestType, e.g. priorityRequest */
    unsigned inbound_lane; /**< ingress lane identifier (0..255) */
    boost::optional<unsigned> outbound_lane; /**< egress lane identifier (0..255) */
    boost::optional<Clock::time_point> arrival; /**< estimated time of arrival at the stop line */
    boost::optional<Clock::duration> duration; /**< expected duration of the service */
};

/**
 * Append a request to a signal request message
 * \param message SignalRequestMessage (destination)
 * \param request request details
 * \throw std::out_of_range if duration is outside DSecond (0..65.535 s)
 * \throw asn1::asn1c_exception if memory allocation fails
 */
void add_request(SignalRequestMessage& message, const PriorityRequest& request);

/**
 * Set timeStamp and second of a signal status message
 * \param message SignalStatusMessage (destination)
 * \param now time of the message
 */
void set_timestamp(SignalStatusMessage& message, const Clock::time_point& now);

/**
 * Append the status of an intersection to a signal status message
 * \param message SignalStatusMessage (destination)
 * \param intersection_id IntersectionID (0..65535)
 * \param sequence_number MsgCount, incremented when the status of any request changes
 * \return appended signal status, owned by message
 * \throw asn1::asn1c_exception if memory allocation fails
 */
SignalStatus& add_status(SignalStatusMessage& message, unsigned intersection_id, unsigned sequence_number);

/** Answer of the intersection to one request */
struct PriorityResponse
{
    std::uint32_t requester; /**< station ID of the requesting vehicle */
    unsigned request_id; /**< RequestID of the request (0..255) */
    unsigned request_sequence; /**< sequenceNumber of the answered request (0..127) */
    long role; /**< BasicVehicleRole of the requestor */
    unsigned inbound_lane; /**< ingress lane identifier (0..255) */
    boost::optional<unsigned> outbound_lane; /**< egress lane identifier (0..255) */
    long status; /**< PrioritizationResponseStatus, e.g. processing or granted */
};

/**
 * Append a response package to a signal status
 * \param status signal status (destination)
 * \param response response details
 * \throw asn1::asn1c_exception if memory allocation fails
 */
void add_response(SignalStatus& status, const PriorityResponse& response);

} // namespace facilities
} // namespace vanetza

#endif /* PRIORITY_FUNCTIONS_HPP_M3RZ8WQE */
