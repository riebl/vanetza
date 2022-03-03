#include <gtest/gtest.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/TimestampIts.h>

using namespace vanetza;

TEST(ItsAsn1, TimestampIts)
{
    const std::int64_t max_timestamp = 4398046511103;
    asn1::asn1c_wrapper<TimestampIts_t> tx { asn_DEF_TimestampIts };
    asn_imax2INTEGER(&*tx, max_timestamp);
    auto buffer = tx.encode();
    EXPECT_EQ(6, buffer.size());
    asn1::asn1c_wrapper<TimestampIts_t> rx { asn_DEF_TimestampIts };
    EXPECT_TRUE(rx.decode(buffer));
    std::int64_t rx_timestamp = 0;
    asn_INTEGER2imax(&*tx, &rx_timestamp);
    EXPECT_EQ(rx_timestamp, max_timestamp);
}

