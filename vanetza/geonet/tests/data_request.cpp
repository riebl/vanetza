#include <gtest/gtest.h>
#include <vanetza/geonet/data_request.hpp>

using namespace vanetza::geonet;

TEST(DataRequest, repetition) {
    MIB mib;
    DataRequest r(mib);
    EXPECT_FALSE(is_repetition_requested(r));
    r.repetition_interval = 30;
    EXPECT_FALSE(is_repetition_requested(r));
    r.max_repetition_time = 15;
    EXPECT_TRUE(is_repetition_requested(r));
    r.repetition_interval.reset();
    EXPECT_FALSE(is_repetition_requested(r));
}

