#include <gtest/gtest.h>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/geonet/address.hpp>
#include <vanetza/geonet/location_table.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/position_vector.hpp>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <memory>
#include <unordered_set>

using namespace vanetza::geonet;
using vanetza::Clock;
using vanetza::ManualRuntime;

class LocationTableTest : public ::testing::Test
{
protected:
    virtual void SetUp() override
    {
        mib.reset(new MIB());
        mib->itsGnLifetimeLocTE = 10 * vanetza::units::si::seconds;
        runtime.reset(new ManualRuntime());
        loct.reset(new LocationTable(*mib, *runtime));
    }

    virtual void TearDown() override
    {
        loct.reset();
        runtime.reset();
        loct.reset();
    }

    std::unique_ptr<MIB> mib;
    std::unique_ptr<ManualRuntime> runtime;
    std::unique_ptr<LocationTable> loct;
};

TEST_F(LocationTableTest, has_entry) {
    Address a;
    a.mid({1, 2, 3, 4, 5, 6});
    EXPECT_FALSE(loct->has_entry(a));

    LongPositionVector pv;
    pv.gn_addr = a;
    loct->update(pv);
    EXPECT_TRUE(loct->has_entry(a));

    // only MID of GN_ADDR should be used for look-up
    a.country_code(42);
    EXPECT_TRUE(loct->has_entry(a));

    a.mid({0, 2, 3, 4, 5, 6});
    EXPECT_FALSE(loct->has_entry(a));
}

TEST_F(LocationTableTest, position_vector) {
    Address a;
    a.mid({1, 2, 3, 4, 5, 6});
    EXPECT_FALSE(loct->get_position(a));

    LongPositionVector pv;
    pv.gn_addr = a;
    loct->update(pv);

    auto retrieved_pv = loct->get_position(a);
    ASSERT_TRUE(!!retrieved_pv);
    EXPECT_EQ(pv, *retrieved_pv);
}

TEST_F(LocationTableTest, neighbourhood) {
    EXPECT_FALSE(loct->has_neighbours());

    Address addr_a;
    addr_a.mid({1, 2, 3, 4, 5 ,6});
    LongPositionVector pv_a;
    pv_a.gn_addr = addr_a;
    loct->update(pv_a);
    EXPECT_FALSE(loct->has_neighbours());

    loct->update(pv_a).set_neighbour(true);
    EXPECT_TRUE(loct->has_neighbours());

    Address addr_b;
    addr_b.mid({2, 2, 2, 2, 2, 2});
    LongPositionVector pv_b;
    pv_b.gn_addr = addr_b;
    loct->update(pv_b);

    loct->update(pv_a).set_neighbour(false);
    EXPECT_FALSE(loct->has_neighbours());

    loct->update(pv_a).set_neighbour(true);
    loct->update(pv_b).set_neighbour(true);
    auto neighbours = loct->neighbours();
    EXPECT_EQ(2, std::distance(neighbours.begin(), neighbours.end()));
    EXPECT_TRUE(std::any_of(neighbours.begin(), neighbours.end(),
                [&pv_a](const LocationTableEntry& e) {
                    return e.get_position_vector() == pv_a;
                }));
    EXPECT_TRUE(std::any_of(neighbours.begin(), neighbours.end(),
                [&pv_b](const LocationTableEntry& e) {
                    return e.get_position_vector() == pv_b;
                }));

    loct->update(pv_a).set_neighbour(false);
    neighbours = loct->neighbours();
    EXPECT_EQ(1, std::distance(neighbours.begin(), neighbours.end()));
    EXPECT_EQ(pv_b, neighbours.begin()->get_position_vector());
}

TEST_F(LocationTableTest, update_pdr) {
    Address addr;
    addr.mid({1, 0, 1, 0, 1, 0});
    LongPositionVector pv;
    pv.gn_addr = addr;

    using std::chrono::milliseconds;
    auto& entry = loct->update(pv);
    EXPECT_TRUE(std::isnan(entry.get_pdr()));
    runtime->trigger(milliseconds(100));
    entry.update_pdr(30);
    EXPECT_DOUBLE_EQ(0.0, entry.get_pdr());
    runtime->trigger(milliseconds(100));
    entry.update_pdr(10);
    EXPECT_DOUBLE_EQ(50.0, entry.get_pdr());
    runtime->trigger(milliseconds(1000));
    entry.update_pdr(480);
    EXPECT_DOUBLE_EQ(265.0, entry.get_pdr());
    runtime->trigger(milliseconds(600));
    entry.update_pdr(312);
    EXPECT_DOUBLE_EQ(392.5, entry.get_pdr());
}

TEST_F(LocationTableTest, expire) {
    const auto almost_expire = std::chrono::seconds(9);
    const auto jiffy_expire = std::chrono::seconds(2);

    LongPositionVector pv;
    Address addr;
    addr.mid({3, 7, 3, 7, 3, 7});
    pv.gn_addr = addr;

    loct->update(pv);
    EXPECT_TRUE(loct->has_entry(addr));
    runtime->trigger(almost_expire);
    EXPECT_TRUE(loct->has_entry(addr));
    runtime->trigger(jiffy_expire);
    EXPECT_FALSE(loct->has_entry(addr));

    loct->update(pv);
    EXPECT_TRUE(loct->has_entry(addr));
    runtime->trigger(almost_expire);
    EXPECT_TRUE(loct->has_entry(addr));
    loct->update(pv); // no refresh with same PV
    runtime->trigger(jiffy_expire);
    EXPECT_FALSE(loct->has_entry(addr));

    loct->update(pv);
    runtime->trigger(almost_expire);
    EXPECT_TRUE(loct->has_entry(addr));
    pv.timestamp += 20 * Timestamp::millisecond();
    loct->update(pv); // refresh with updated PV
    runtime->trigger(jiffy_expire);
    EXPECT_TRUE(loct->has_entry(addr));
}

TEST_F(LocationTableTest, update_creates_entry) {
    LongPositionVector pv;
    pv.gn_addr.mid({ 0, 0, 0, 0, 0, 1 });

    EXPECT_FALSE(loct->has_entry(pv.gn_addr));
    loct->update(pv);
    const LongPositionVector* pv_loct = loct->get_position(pv.gn_addr);
    ASSERT_TRUE(pv_loct);
    EXPECT_EQ(pv, *pv_loct);
    EXPECT_TRUE(loct->has_entry(pv.gn_addr));
}

TEST_F(LocationTableTest, visit) {
    using vanetza::MacAddress;
    std::unordered_set<Address> addresses = {
        Address { MacAddress {0, 0, 0, 0, 0, 1}},
        Address { MacAddress {0, 0, 0, 0, 0, 2}},
        Address { MacAddress {0, 0, 0, 0, 0, 3}},
        Address { MacAddress {0, 0, 0, 0, 0, 4}},
        Address { MacAddress {0, 0, 0, 0, 0, 5}}
    };

    for (auto& addr : addresses) {
        LongPositionVector pv;
        pv.gn_addr = addr;
        loct->update(pv);
    }

    std::unordered_set<Address> visited_addresses;
    loct->visit([&visited_addresses](const MacAddress& mac, const LocationTableEntry& entry) {
            visited_addresses.insert(entry.geonet_address());
    });

    EXPECT_EQ(addresses.size(), visited_addresses.size());
}

TEST(LocationTableEntry, update_position_vector)
{
    ManualRuntime rt;
    LocationTableEntry locte(rt);

    LongPositionVector lpv;
    EXPECT_FALSE(locte.update_position_vector(lpv));

    lpv.latitude = geo_angle_i32t::from_value(91 * 10 * 1000 * 1000);
    EXPECT_FALSE(locte.update_position_vector(lpv));

    lpv.latitude = geo_angle_i32t::from_value(90 * 10 * 1000 * 1000);
    EXPECT_TRUE(locte.update_position_vector(lpv));
}

TEST(LocationTableEntry, init)
{
    ManualRuntime rt;
    LocationTableEntry locte(rt);
    EXPECT_FALSE(locte.has_position_vector());
    EXPECT_TRUE(std::isnan(locte.get_pdr()));
    EXPECT_FALSE(locte.is_neighbour());
}

TEST(LocationTableEntry, neighbour)
{
    ManualRuntime rt;
    LocationTableEntry locte(rt);

    locte.set_neighbour(true);
    EXPECT_TRUE(locte.is_neighbour());

    locte.set_neighbour(false);
    EXPECT_FALSE(locte.is_neighbour());

    locte.set_neighbour(true, std::chrono::seconds(5));
    rt.trigger(std::chrono::seconds(4));
    EXPECT_TRUE(locte.is_neighbour());
    rt.trigger(std::chrono::seconds(1));
    EXPECT_FALSE(locte.is_neighbour());

    locte.set_neighbour(false, std::chrono::seconds(1));
    EXPECT_FALSE(locte.is_neighbour());
    rt.trigger(std::chrono::seconds(2));
    EXPECT_FALSE(locte.is_neighbour());
}
