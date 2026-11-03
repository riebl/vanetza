#include <gtest/gtest.h>
#include <vanetza/asn1/its/SignalRequestPackage.h>
#include <vanetza/asn1/its/SignalStatus.h>
#include <vanetza/asn1/its/SignalStatusPackage.h>
#include <vanetza/asn1/srem.hpp>
#include <vanetza/asn1/ssem.hpp>
#include <stdexcept>

using namespace vanetza;

namespace
{

void fill_header(ItsPduHeader_t& header, long message_id)
{
    header.protocolVersion = 2;
    header.messageID = message_id;
    header.stationID = 1337;
}

void fill_srem(asn1::Srem& message)
{
    fill_header(message->header, ItsPduHeader__messageID_srem);
    auto& srm = message->srm;
    asn1::allocate_optional(srm.timeStamp) = 12345;
    srm.second = 30250;
    asn1::allocate_optional(srm.sequenceNumber) = 5;
    srm.requestor.id.present = VehicleID_PR_stationID;
    srm.requestor.id.choice.stationID = 4711;
    asn1::allocate_optional(srm.requestor.type).role = BasicVehicleRole_publicTransport;

    auto package = asn1::make_unique<SignalRequestPackage_t>(asn_DEF_SignalRequestPackage);
    package->request.id.id = 42;
    package->request.requestID = 7;
    package->request.requestType = PriorityRequestType_priorityRequest;
    package->request.inBoundLane.present = IntersectionAccessPoint_PR_lane;
    package->request.inBoundLane.choice.lane = 2;
    auto& outbound = asn1::allocate_optional(package->request.outBoundLane);
    outbound.present = IntersectionAccessPoint_PR_lane;
    outbound.choice.lane = 10;
    asn1::allocate_optional(package->minute) = 12345;
    asn1::allocate_optional(package->second) = 50250;
    asn1::allocate_optional(package->duration) = 8000;
    asn1::append(asn1::allocate_optional(srm.requests), std::move(package));
}

void fill_ssem(asn1::Ssem& message)
{
    fill_header(message->header, ItsPduHeader__messageID_ssem);
    auto& ssm = message->ssm;
    asn1::allocate_optional(ssm.timeStamp) = 12345;
    ssm.second = 31000;
    asn1::allocate_optional(ssm.sequenceNumber) = 6;
    auto status = asn1::make_unique<SignalStatus_t>(asn_DEF_SignalStatus);
    status->id.id = 42;
    status->sequenceNumber = 3;
    auto package = asn1::make_unique<SignalStatusPackage_t>(asn_DEF_SignalStatusPackage);
    auto& requester = asn1::allocate_optional(package->requester);
    requester.id.present = VehicleID_PR_stationID;
    requester.id.choice.stationID = 4711;
    requester.request = 7;
    requester.sequenceNumber = 5;
    asn1::allocate_optional(requester.role) = BasicVehicleRole_publicTransport;
    package->inboundOn.present = IntersectionAccessPoint_PR_lane;
    package->inboundOn.choice.lane = 2;
    auto& outbound = asn1::allocate_optional(package->outboundOn);
    outbound.present = IntersectionAccessPoint_PR_lane;
    outbound.choice.lane = 10;
    asn1::allocate_optional(package->minute) = 12345;
    asn1::allocate_optional(package->second) = 50250;
    asn1::allocate_optional(package->duration) = 8000;
    package->status = PrioritizationResponseStatus_granted;
    asn1::append(status->sigStatus, std::move(package));
    asn1::append(ssm.status, std::move(status));
}

template<typename Message>
void check_range(Message& message, long& field, long minimum, long maximum)
{
    const long original = field;
    for (long valid : {minimum, maximum}) {
        field = valid;
        EXPECT_TRUE(message.validate()) << "value " << valid;
        Message decoded;
        ASSERT_TRUE(decoded.decode(message.encode()));
        EXPECT_EQ(0, message.compare(decoded));
    }
    for (long invalid : {minimum - 1, maximum + 1}) {
        field = invalid;
        EXPECT_FALSE(message.validate()) << "value " << invalid;
        EXPECT_THROW(message.encode(), std::runtime_error);
    }
    field = original;
}

template<typename Message>
void check_truncated(const Message& message)
{
    const ByteBuffer encoded = message.encode();
    ASSERT_GT(encoded.size(), 2u);
    for (std::size_t length : {std::size_t(0), std::size_t(1), encoded.size() / 2, encoded.size() - 1}) {
        Message decoded;
        const auto end = encoded.begin() + static_cast<ByteBuffer::difference_type>(length);
        const ByteBuffer truncated(encoded.begin(), end);
        EXPECT_FALSE(decoded.decode(truncated)) << "length " << length;
    }
}

template<typename Message, typename List, typename Factory>
void check_list_size(Message& message, List& list, Factory make_element)
{
    // The populated fixture already covers the lower bound, SIZE(1).
    while (list.list.count < 32) {
        asn1::append(list, make_element());
    }
    ASSERT_TRUE(message.validate());
    Message decoded;
    ASSERT_TRUE(decoded.decode(message.encode()));
    EXPECT_EQ(0, message.compare(decoded));
    asn1::append(list, make_element());
    ASSERT_EQ(33, list.list.count);
    // Generated list constraints are enforced at the latest by the encoder.
    EXPECT_THROW(message.encode(), std::runtime_error);
}

} // namespace

TEST(SremSsemAsn1, srem_roundtrip)
{
    asn1::Srem tx;
    fill_srem(tx);
    std::string error;
    ASSERT_TRUE(tx.validate(error)) << error;
    const ByteBuffer encoded = tx.encode();
    EXPECT_EQ(tx.size(), encoded.size());
    asn1::Srem rx;
    ASSERT_TRUE(rx.decode(encoded));
    EXPECT_EQ(0, tx.compare(rx));
    EXPECT_EQ(ItsPduHeader__messageID_srem, rx->header.messageID);
    EXPECT_EQ(4711u, rx->srm.requestor.id.choice.stationID);
    ASSERT_NE(nullptr, rx->srm.requests);
    ASSERT_EQ(1, rx->srm.requests->list.count);
    const auto& package = *rx->srm.requests->list.array[0];
    EXPECT_EQ(42, package.request.id.id);
    EXPECT_EQ(7, package.request.requestID);
    EXPECT_EQ(2, package.request.inBoundLane.choice.lane);
    ASSERT_NE(nullptr, package.request.outBoundLane);
    EXPECT_EQ(10, package.request.outBoundLane->choice.lane);
    ASSERT_NE(nullptr, package.minute);
    EXPECT_EQ(12345, *package.minute);
    ASSERT_NE(nullptr, package.second);
    EXPECT_EQ(50250, *package.second);
    ASSERT_NE(nullptr, package.duration);
    EXPECT_EQ(8000, *package.duration);
}

TEST(SremSsemAsn1, ssem_roundtrip)
{
    asn1::Ssem tx;
    fill_ssem(tx);
    std::string error;
    ASSERT_TRUE(tx.validate(error)) << error;
    const ByteBuffer encoded = tx.encode();
    EXPECT_EQ(tx.size(), encoded.size());
    asn1::Ssem rx;
    ASSERT_TRUE(rx.decode(encoded));
    EXPECT_EQ(0, tx.compare(rx));
    EXPECT_EQ(ItsPduHeader__messageID_ssem, rx->header.messageID);
    ASSERT_EQ(1, rx->ssm.status.list.count);
    const auto& status = *rx->ssm.status.list.array[0];
    EXPECT_EQ(42, status.id.id);
    EXPECT_EQ(3, status.sequenceNumber);
    ASSERT_EQ(1, status.sigStatus.list.count);
    const auto& package = *status.sigStatus.list.array[0];
    ASSERT_NE(nullptr, package.requester);
    EXPECT_EQ(4711u, package.requester->id.choice.stationID);
    EXPECT_EQ(7, package.requester->request);
    EXPECT_EQ(5, package.requester->sequenceNumber);
    EXPECT_EQ(2, package.inboundOn.choice.lane);
    ASSERT_NE(nullptr, package.outboundOn);
    EXPECT_EQ(10, package.outboundOn->choice.lane);
    EXPECT_EQ(PrioritizationResponseStatus_granted, package.status);
    ASSERT_NE(nullptr, package.duration);
    EXPECT_EQ(8000, *package.duration);
}

TEST(SremSsemAsn1, srem_field_boundaries)
{
    asn1::Srem message;
    fill_srem(message);
    auto& package = *message->srm.requests->list.array[0];
    check_range(message, package.request.requestID, 0, 255); // RequestID
    check_range(message, package.request.id.id, 0, 65535); // IntersectionID
    check_range(message, package.request.inBoundLane.choice.lane, 0, 255); // LaneID
    check_range(message, *message->srm.sequenceNumber, 0, 127); // MsgCount
    check_range(message, message->srm.second, 0, 65535); // DSecond
    check_range(message, *package.duration, 0, 65535); // DSecond
}

TEST(SremSsemAsn1, ssem_field_boundaries)
{
    asn1::Ssem message;
    fill_ssem(message);
    auto& status = *message->ssm.status.list.array[0];
    auto& package = *status.sigStatus.list.array[0];
    check_range(message, package.requester->request, 0, 255); // RequestID
    check_range(message, status.id.id, 0, 65535); // IntersectionID
    check_range(message, package.inboundOn.choice.lane, 0, 255); // LaneID
    check_range(message, status.sequenceNumber, 0, 127); // MsgCount
    check_range(message, package.requester->sequenceNumber, 0, 127); // MsgCount
    check_range(message, message->ssm.second, 0, 65535); // DSecond
    check_range(message, *package.duration, 0, 65535); // DSecond
}

TEST(SremSsemAsn1, ssem_empty_status_list)
{
    asn1::Ssem message;
    fill_header(message->header, ItsPduHeader__messageID_ssem);
    // SignalStatusList ::= SEQUENCE (SIZE(1..32)) OF SignalStatus
    EXPECT_THROW(message.encode(), std::runtime_error);
}

TEST(SremSsemAsn1, srem_empty_request_list)
{
    asn1::Srem message;
    fill_header(message->header, ItsPduHeader__messageID_srem);
    message->srm.requestor.id.present = VehicleID_PR_stationID;
    asn1::allocate_optional(message->srm.requests);
    // An absent request list is allowed, a present SignalRequestList has SIZE(1..32).
    EXPECT_THROW(message.encode(), std::runtime_error);
}

TEST(SremSsemAsn1, srem_absent_request_list)
{
    asn1::Srem message;
    fill_header(message->header, ItsPduHeader__messageID_srem);
    message->srm.requestor.id.present = VehicleID_PR_stationID;
    ASSERT_TRUE(message.validate());
    asn1::Srem decoded;
    ASSERT_TRUE(decoded.decode(message.encode()));
    EXPECT_EQ(0, message.compare(decoded));
    EXPECT_EQ(nullptr, decoded->srm.requests);
}

TEST(SremSsemAsn1, srem_request_list_upper_bound)
{
    asn1::Srem message;
    fill_srem(message);
    check_list_size(message, *message->srm.requests, [] {
        auto request = asn1::make_unique<SignalRequestPackage_t>(asn_DEF_SignalRequestPackage);
        request->request.requestType = PriorityRequestType_priorityRequest;
        request->request.inBoundLane.present = IntersectionAccessPoint_PR_lane;
        return request;
    });
}

TEST(SremSsemAsn1, ssem_status_list_upper_bound)
{
    asn1::Ssem message;
    fill_ssem(message);
    check_list_size(message, message->ssm.status, [] {
        auto status = asn1::make_unique<SignalStatus_t>(asn_DEF_SignalStatus);
        auto package = asn1::make_unique<SignalStatusPackage_t>(asn_DEF_SignalStatusPackage);
        package->inboundOn.present = IntersectionAccessPoint_PR_lane;
        package->status = PrioritizationResponseStatus_granted;
        asn1::append(status->sigStatus, std::move(package));
        return status;
    });
}

TEST(SremSsemAsn1, ssem_empty_package_list)
{
    asn1::Ssem message;
    fill_header(message->header, ItsPduHeader__messageID_ssem);
    auto status = asn1::make_unique<SignalStatus_t>(asn_DEF_SignalStatus);
    asn1::append(message->ssm.status, std::move(status));
    // SignalStatusPackageList ::= SEQUENCE (SIZE(1..32)) OF SignalStatusPackage
    EXPECT_THROW(message.encode(), std::runtime_error);
}

TEST(SremSsemAsn1, srem_decode_truncated)
{
    asn1::Srem message;
    fill_srem(message);
    check_truncated(message);
}

TEST(SremSsemAsn1, ssem_decode_truncated)
{
    asn1::Ssem message;
    fill_ssem(message);
    check_truncated(message);
}
