#include <gtest/gtest.h>
#include <vanetza/geonet/data_confirm.hpp>

using namespace vanetza::geonet;

TEST(DataConfirm, ctor) {
    DataConfirm a;
    EXPECT_EQ(a.result_code, DataConfirm::ResultCode::REJECTED_UNSPECIFIED);
    DataConfirm b(DataConfirm::ResultCode::ACCEPTED);
    EXPECT_EQ(b.result_code, DataConfirm::ResultCode::ACCEPTED);
}

TEST(DataConfirm, accepted_rejected) {
    DataConfirm a(DataConfirm::ResultCode::REJECTED_MAX_LIFETIME);
    EXPECT_TRUE(a.rejected());
    EXPECT_FALSE(a.accepted());
    a.result_code = DataConfirm::ResultCode::ACCEPTED;
    EXPECT_FALSE(a.rejected());
    EXPECT_TRUE(a.accepted());
}

