#include <gtest/gtest.h>
#include <vanetza/common/unit_interval.hpp>

using namespace vanetza;

namespace vanetza {
    void PrintTo(const UnitInterval& cl, std::ostream* os) { *os << cl.value(); }
}

TEST(UnitInterval, construction)
{
    UnitInterval v1;
    EXPECT_DOUBLE_EQ(0.0, v1.value());

    UnitInterval v2(0.42);
    EXPECT_DOUBLE_EQ(0.42, v2.value());

    UnitInterval v3 = v2;
    EXPECT_DOUBLE_EQ(0.42, v3.value());

    v3 = v1;
    EXPECT_DOUBLE_EQ(0.0, v3.value());
}

TEST(UnitInterval, partially_ordered)
{
    // only test < and == (other operators are provided by Boost)
    EXPECT_LT(UnitInterval(0.3), UnitInterval(0.4));
    EXPECT_EQ(UnitInterval(0.5), UnitInterval(0.5));

    // stress equality comparison
    UnitInterval v1 { 0.0000001 };
    UnitInterval v2 { 0.00000005 };
    EXPECT_EQ(v1 * 1000000, v2 * 2000000);
    EXPECT_NE(UnitInterval(0.000000001), UnitInterval(0.0000000011));
}

TEST(UnitInterval, range)
{
    UnitInterval v1 { 3.14 };
    EXPECT_EQ(UnitInterval(1.0), v1);

    UnitInterval v2 { -42.0 };
    EXPECT_EQ(UnitInterval(0.0), v2);
}

TEST(UnitInterval, arithmetic_interval)
{
    // only test +=, -=, *=, /= (symmetric operators by Boost)
    UnitInterval a1(0.45);
    a1 += UnitInterval(0.53);
    EXPECT_EQ(UnitInterval(0.98), a1);

    UnitInterval a2(0.45);
    a2 += UnitInterval(0.6);
    EXPECT_EQ(UnitInterval(1.0), a2);

    UnitInterval s1(0.45);
    s1 -= UnitInterval(0.35);
    EXPECT_EQ(UnitInterval(0.1), s1);

    UnitInterval s2(0.3);
    s2 -= UnitInterval(0.4);
    EXPECT_EQ(UnitInterval(0.0), s2);

    UnitInterval m1(0.2);
    m1 *= UnitInterval(0.5);
    EXPECT_EQ(UnitInterval(0.1), m1);

    UnitInterval m2(0.4);
    m2 *= UnitInterval(0.0);
    EXPECT_EQ(UnitInterval(0.0), m2);

    UnitInterval m3(1.0);
    m3 *= UnitInterval(1.0);
    EXPECT_EQ(UnitInterval(1.0), m3);

    UnitInterval d1(0.6);
    d1 /= UnitInterval(0.8);
    EXPECT_EQ(UnitInterval(0.75), d1);

    UnitInterval d2(0.5);
    d2 /= UnitInterval(0.1);
    EXPECT_EQ(UnitInterval(1.0), d2);
}

TEST(UnitInterval, arithmetic_double)
{
    // only test +=, -=, *=, /= (symmetric operators by Boost)
    UnitInterval a1(0.45);
    a1 += 0.53;
    EXPECT_EQ(UnitInterval(0.98), a1);

    UnitInterval a2(0.45);
    a2 += 0.6;
    EXPECT_EQ(UnitInterval(1.0), a2);

    UnitInterval a3(0.45);
    a3 += -0.7;
    EXPECT_EQ(UnitInterval(0.0), a3);

    UnitInterval s1(0.45);
    s1 -= 0.35;
    EXPECT_EQ(UnitInterval(0.1), s1);

    UnitInterval s2(0.3);
    s2 -= 0.4;
    EXPECT_EQ(UnitInterval(0.0), s2);

    UnitInterval s3(0.3);
    s3 -= -0.8;
    EXPECT_EQ(UnitInterval(1.0), s3);

    UnitInterval m1(0.2);
    m1 *= 0.5;
    EXPECT_EQ(UnitInterval(0.1), m1);

    UnitInterval m2(0.4);
    m2 *= 0.0;
    EXPECT_EQ(UnitInterval(0.0), m2);

    UnitInterval m3(1.0);
    m3 *= 1.2;
    EXPECT_EQ(UnitInterval(1.0), m3);

    UnitInterval m4(0.3);
    m4 *= -0.1;
    EXPECT_EQ(UnitInterval(0.0), m4);

    UnitInterval d1(0.6);
    d1 /= 0.8;
    EXPECT_EQ(UnitInterval(0.75), d1);

    UnitInterval d2(0.5);
    d2 /= 0.1;
    EXPECT_EQ(UnitInterval(1.0), d2);

    UnitInterval d3(0.2);
    d3 /= 2.0;
    EXPECT_EQ(UnitInterval(0.1), d3);

    UnitInterval d4(0.5);
    d4 /= -0.4;
    EXPECT_EQ(UnitInterval(0.0), d4);
}

TEST(UnitInterval, complement)
{
    EXPECT_EQ(UnitInterval(0.0), UnitInterval(1.0).complement());
    EXPECT_EQ(UnitInterval(1.0), UnitInterval(0.0).complement());
    EXPECT_EQ(UnitInterval(1.0), UnitInterval(0.67) + UnitInterval(0.67).complement());
}

TEST(UnitInterval, mean)
{
    EXPECT_EQ(UnitInterval(0.3), mean(UnitInterval(0.1), UnitInterval(0.5)));
    EXPECT_EQ(UnitInterval(0.0), mean(UnitInterval(0.0), UnitInterval(0.0)));
    EXPECT_EQ(UnitInterval(0.75), mean(UnitInterval(1.0), UnitInterval(0.5)));
}

TEST(UnitInterval, mean_range)
{
    UnitInterval a[3] = { UnitInterval (0.4), UnitInterval(0.2), UnitInterval(0.9) };
    EXPECT_EQ(UnitInterval(0.0), mean(a, a));
    EXPECT_EQ(UnitInterval(0.2), mean(a + 1, a + 2));
    EXPECT_EQ(UnitInterval(0.3), mean(a, a + 2 ));
    EXPECT_EQ(UnitInterval(0.5), mean(a, a + 3));
}
