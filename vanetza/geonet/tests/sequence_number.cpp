#include <gtest/gtest.h>
#include <vanetza/geonet/sequence_number.hpp>

using namespace vanetza::geonet;

TEST(SequenceNumber, ctor) {
    SequenceNumber a;
    EXPECT_EQ(a, SequenceNumber(0));

    SequenceNumber b(348);
    EXPECT_EQ(b, SequenceNumber(348));
}

TEST(SequenceNumber, equality) {
    SequenceNumber a(2348);
    SequenceNumber b(a);
    SequenceNumber c(2334);
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST(SequenceNumber, addition) {
    SequenceNumber a(348);
    SequenceNumber b(568);
    a += b;
    EXPECT_EQ(a, SequenceNumber(916));
    EXPECT_EQ(static_cast<uint16_t>(b), 568);
    a += SequenceNumber(SequenceNumber::max);
    EXPECT_EQ(a, SequenceNumber(915));
}

TEST(SequenceNumber, subtration) {
    SequenceNumber a(348);
    SequenceNumber b(568);
    a -= b;
    EXPECT_EQ(a, SequenceNumber(65316));
    a -= b;
    EXPECT_EQ(a, SequenceNumber(64748));
    EXPECT_EQ(b, SequenceNumber(568));
}

