#include <gtest/gtest.h>
#include <vanetza/dcc/mapping.hpp>

using namespace vanetza;
using namespace vanetza::dcc;

TEST(Mapping, map_profile_onto_ac)
{
    EXPECT_EQ(access::AccessCategory::VO, map_profile_onto_ac(Profile::DP0));
    EXPECT_EQ(access::AccessCategory::VI, map_profile_onto_ac(Profile::DP1));
    EXPECT_EQ(access::AccessCategory::BE, map_profile_onto_ac(Profile::DP2));
    EXPECT_EQ(access::AccessCategory::BK, map_profile_onto_ac(Profile::DP3));

    auto malicious_profile = static_cast<Profile>(4);
    EXPECT_THROW(map_profile_onto_ac(malicious_profile), std::invalid_argument);
}
