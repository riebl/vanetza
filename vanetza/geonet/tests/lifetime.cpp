#include <gtest/gtest.h>
#include <vanetza/geonet/lifetime.hpp>

using namespace vanetza::geonet;
using vanetza::units::si::seconds;

TEST(Lifetime, ctor) {
    Lifetime a;
    EXPECT_EQ(a.raw(), 0);
    Lifetime b(Lifetime::Base::One_Second, 34);
    EXPECT_EQ(b.raw(), 0x89);
}

TEST(Lifetime, set) {
    Lifetime a;
    a.set(Lifetime::Base::One_Second, 30);
    EXPECT_EQ(a.raw(), 0x79);
}

TEST(Lifetime, less) {
    Lifetime a(Lifetime::Base::Ten_Seconds, 6);
    Lifetime b(Lifetime::Base::Ten_Seconds, 5);
    Lifetime c(Lifetime::Base::One_Second, 55);
    EXPECT_LT(b, a);
    EXPECT_LT(b, c);
    EXPECT_LT(c, a);
}

TEST(Lifetime, equality) {
    Lifetime a(Lifetime::Base::One_Second, 30);
    Lifetime b(Lifetime::Base::Ten_Seconds, 3);
    Lifetime c(Lifetime::Base::One_Second, 29);
    Lifetime d(Lifetime::Base::Ten_Seconds, 3);
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
    EXPECT_EQ(b, d);
}

TEST(Lifetime, decode) {
    Lifetime a;
    a.set(Lifetime::Base::Ten_Seconds, 43);
    EXPECT_DOUBLE_EQ(a.decode() / seconds, 430.0);

    Lifetime b;
    b.set(Lifetime::Base::Fifty_Milliseconds, 3);
    EXPECT_DOUBLE_EQ(b.decode() / seconds, 0.150);

    Lifetime c;
    c.set(Lifetime::Base::One_Second, 15);
    EXPECT_DOUBLE_EQ(c.decode() / seconds, 15.0);

    Lifetime d;
    d.set(Lifetime::Base::Hundred_Seconds, 63);
    EXPECT_DOUBLE_EQ(d.decode() / seconds, 6300.0);
}

TEST(Lifetime, encode) {
    std::pair<double, double> pairs[] = {
        {0.050, 0.0},
        {0.075, 0.025},
        {0.100, 0.0},
        {0.158, 0.08},
        {1.43, 0.07},
        {3.00, 0.0},
        {3.5, 0.5},
        {16.3, 0.3},
        {52.0, 0.0},
        {64.0, 4.0},
        {78.3, 1.7},
        {138.0, 2.0},
        {612.0, 2.0},
        {700.0, 0.0},
        {780.0, 20.0}
    };

    Lifetime a;
    const double rel_error = 0.0000001; // fine enough, lifetime is not better than 50 ms
    for (auto pair : pairs) {
        a.encode(pair.first * seconds);
        EXPECT_NEAR(a.decode() / seconds, pair.first, pair.second + rel_error);
    }
}

TEST(Lifetime, zero) {
    const Lifetime a = Lifetime::zero();
    EXPECT_EQ(0.0 * seconds, a.decode());
}
