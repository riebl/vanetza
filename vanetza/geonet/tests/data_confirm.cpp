#include <gtest/gtest.h>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/geonet/data_confirm.hpp>
#include <vanetza/geonet/data_request.hpp>
#include <vanetza/geonet/packet.hpp>
#include <algorithm>

using namespace vanetza::geonet;
using vanetza::units::si::seconds;
using vanetza::units::si::meter;

TEST(DataConfirm, ctor) {
    DataConfirm a;
    EXPECT_EQ(a.result_code, DataConfirm::ResultCode::Accepted);
    DataConfirm b(DataConfirm::ResultCode::Rejected_Unspecified);
    EXPECT_EQ(b.result_code, DataConfirm::ResultCode::Rejected_Unspecified);
}

TEST(DataConfirm, accepted_rejected) {
    DataConfirm a(DataConfirm::ResultCode::Rejected_Max_Lifetime);
    EXPECT_TRUE(a.rejected());
    EXPECT_FALSE(a.accepted());
    a.result_code = DataConfirm::ResultCode::Accepted;
    EXPECT_FALSE(a.rejected());
    EXPECT_TRUE(a.accepted());
}

TEST(DataConfirm, validate_data_request) {
    MIB mib;
    DataRequest req(mib);
    EXPECT_EQ(validate_data_request(req, mib),
            DataConfirm::ResultCode::Accepted);

    DataRequest req_lt(req);
    req_lt.maximum_lifetime.encode(mib.itsGnMaxPacketLifetime.decode() + 10.0 * seconds);
    EXPECT_EQ(validate_data_request(req_lt, mib),
            DataConfirm::ResultCode::Rejected_Max_Lifetime);

    DataRequest req_rep(req);
    req_rep.repetition = DataRequest::Repetition();
    req_rep.repetition->interval = mib.itsGnMinPacketRepetitionInterval - 1 * seconds;
    EXPECT_EQ(validate_data_request(req_rep, mib),
            DataConfirm::ResultCode::Rejected_Min_Repetition_Interval);
}

TEST(DataConfirm, validate_data_request_with_area) {
    MIB mib;
    DataRequestWithArea req(mib);
    EXPECT_EQ(validate_data_request(req, mib),
            DataConfirm::ResultCode::Accepted);

    Circle c;
    // radius = magnitude of max area size -> circle area is much larger
    c.r = vanetza::units::Length(mib.itsGnMaxGeoAreaSize / meter); // hack!
    req.destination.shape = c;
    EXPECT_EQ(validate_data_request(req, mib),
            DataConfirm::ResultCode::Rejected_Max_Geo_Area_Size);
}

TEST(DataConfirm, validate_payload) {
    MIB mib;
    std::unique_ptr<DownPacket> no_payload;
    std::unique_ptr<DownPacket> giant_payload(new DownPacket());
    {
        vanetza::ByteBuffer giant_buffer;
        std::fill_n(std::back_inserter(giant_buffer), 2048, 0x0f);
        (*giant_payload)[vanetza::OsiLayer::Link] = std::move(giant_buffer);
    }
    std::unique_ptr<DownPacket> ok_payload(new DownPacket());

    EXPECT_EQ(validate_payload(no_payload, mib),
            DataConfirm::ResultCode::Rejected_Unspecified);
    EXPECT_EQ(validate_payload(giant_payload, mib),
            DataConfirm::ResultCode::Rejected_Max_SDU_Size);
    EXPECT_EQ(validate_payload(ok_payload, mib),
            DataConfirm::ResultCode::Accepted);
}

TEST(DataConfirm, xor_op) {
    DataConfirm a;
    EXPECT_EQ(a.result_code, DataConfirm::ResultCode::Accepted);
    a ^= DataConfirm::ResultCode::Rejected_Max_Lifetime;
    EXPECT_EQ(a.result_code, DataConfirm::ResultCode::Rejected_Max_Lifetime);
    a ^= DataConfirm::ResultCode::Accepted;
    EXPECT_EQ(a.result_code, DataConfirm::ResultCode::Rejected_Max_Lifetime);
    a ^= DataConfirm::ResultCode::Rejected_Unspecified;
    EXPECT_EQ(a.result_code, DataConfirm::ResultCode::Rejected_Unspecified);
}

