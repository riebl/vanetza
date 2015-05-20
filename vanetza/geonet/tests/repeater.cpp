#include <gtest/gtest.h>
#include <vanetza/geonet/data_request.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/repeater.hpp>

using namespace vanetza;
using namespace vanetza::geonet;

struct FakeRepetitionDispatcher : public boost::static_visitor<>
{
    FakeRepetitionDispatcher(Repeater& _repeater, const DownPacket& _packet, const Timestamp& _now) :
        repeater(_repeater), packet(std::move(_packet)), now(_now)
    {
    }

    template<typename REQUEST>
    void operator()(const REQUEST& request)
    {
        repeater.add(request, std::move(packet), now);
    }

    Repeater& repeater;
    const DownPacket& packet;
    const Timestamp& now;
};

class RepeaterTest : public ::testing::Test
{
protected:
    RepeaterTest() : dispatch_counter(0) {}

    void SetUp() override
    {
        repeater.set_callback(repetition_callback());
    }

    void dispatch_repetition(const DataRequestVariant& request, std::unique_ptr<DownPacket> packet)
    {
        ++dispatch_counter;
        FakeRepetitionDispatcher dispatcher(repeater, *packet, now);
        boost::apply_visitor(dispatcher, request);
    }

    Repeater::Callback repetition_callback()
    {
        using namespace std::placeholders;
        return std::bind(&RepeaterTest::dispatch_repetition, this, _1, _2);
    }

    MIB mib;
    Timestamp now;
    Repeater repeater;
    unsigned dispatch_counter;
    const DownPacket packet;
};



TEST_F(RepeaterTest, no_repetition) {
    repeater.trigger(now);
    EXPECT_EQ(0, dispatch_counter);
    now += 3000 * Timestamp::millisecond;
    EXPECT_EQ(0, dispatch_counter);

    ShbDataRequest shb(mib);
    EXPECT_FALSE(!!shb.repetition);
    repeater.add(shb, packet, now);
    now += 3000 * Timestamp::millisecond;
    repeater.trigger(now);
    EXPECT_EQ(0, dispatch_counter);

    DataRequest::Repetition repetition;
    repetition.interval = 5.0 * units::si::seconds;
    repetition.maximum = 4.9 * units::si::seconds;
    shb.repetition = repetition;
    repeater.add(shb, packet, now);
    EXPECT_EQ(0, dispatch_counter);
    now += 10000 * Timestamp::millisecond;
    repeater.trigger(now);
    EXPECT_EQ(0, dispatch_counter);
}

TEST_F(RepeaterTest, single_repetition) {
    ShbDataRequest shb(mib);
    DataRequest::Repetition repetition;
    repetition.interval = 1.0 * units::si::seconds;
    repetition.maximum = 1.0 * units::si::seconds;
    shb.repetition = repetition;
    repeater.add(shb, packet, now);
    EXPECT_EQ(0, dispatch_counter);
    repeater.trigger(now);
    EXPECT_EQ(0, dispatch_counter);
    repeater.trigger(now + 900 * Timestamp::millisecond);
    EXPECT_EQ(0, dispatch_counter);
    now += 1000 * Timestamp::millisecond;
    repeater.trigger(now);
    EXPECT_EQ(1, dispatch_counter);
    now += 5000 * Timestamp::millisecond;
    repeater.trigger(now);
    EXPECT_EQ(1, dispatch_counter);
}

TEST_F(RepeaterTest, multiple_repetition) {
    ShbDataRequest shb(mib);
    DataRequest::Repetition repetition;
    repetition.interval = 2.0 * units::si::seconds;
    repetition.maximum = 9.0 * units::si::seconds;
    shb.repetition = repetition;
    repeater.add(shb, packet, now);
    EXPECT_EQ(0, dispatch_counter);
    repeater.trigger(now);
    EXPECT_EQ(0, dispatch_counter);
    repeater.trigger(now += 1900 * Timestamp::millisecond);
    EXPECT_EQ(0, dispatch_counter);
    repeater.trigger(now += 100 * Timestamp::millisecond);
    EXPECT_EQ(1, dispatch_counter);
    repeater.trigger(now += 2000 * Timestamp::millisecond);
    EXPECT_EQ(2, dispatch_counter);
    // When triggered too slowly (large time difference), still just one repetition is triggered
    repeater.trigger(now += 5000 * Timestamp::millisecond);
    EXPECT_EQ(3, dispatch_counter);
    now += 5000 * Timestamp::millisecond;
    repeater.trigger(now += 5000 * Timestamp::millisecond);
    EXPECT_EQ(3, dispatch_counter);
}

TEST_F(RepeaterTest, no_callback) {
    // reset previously assigned callback explicitly
    repeater.set_callback(Repeater::Callback {});
    ShbDataRequest shb(mib);
    DataRequest::Repetition repetition;
    repetition.interval = 1.0 * units::si::seconds;
    repetition.maximum = 1.5 * units::si::seconds;
    shb.repetition = repetition;
    repeater.add(shb, packet, now);
    repeater.trigger(now);
    ASSERT_EQ(0, dispatch_counter);
    repeater.trigger(now += 2000 * Timestamp::millisecond);
    EXPECT_EQ(0, dispatch_counter);
}
