#include <gtest/gtest.h>
#include <vanetza/access/data_rates.hpp>

using namespace vanetza::access;

TEST(DataRates, bytes_per_second)
{
    EXPECT_EQ(G5_3Mbps.bytes_per_second(), 3 * 1000 * 1000 / 8);
    EXPECT_EQ(G5_6Mbps.bytes_per_second(), 6 * 1000 * 1000 / 8);
    EXPECT_EQ(G5_12Mbps.bytes_per_second(), 12 * 1000 * 1000 / 8);
}

TEST(DataRates, data_length)
{
    const std::size_t psdu_bytes = 385;
    const std::size_t data_bytes = G5_6Mbps.data_length(psdu_bytes);
    EXPECT_GE(data_bytes, psdu_bytes);
    EXPECT_LT(data_bytes, psdu_bytes + 12);
}
