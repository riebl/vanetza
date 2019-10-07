#include <gtest/gtest.h>
#include <vanetza/access/data_request.hpp>
#include <vanetza/access/interface.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/dcc/flow_control.hpp>
#include <vanetza/dcc/transmit_rate_control.hpp>
#include <chrono>

using namespace vanetza;
using namespace vanetza::dcc;
using namespace std::chrono;

static const TransmissionLite dp0 { Profile::DP0, 0 };
static const TransmissionLite dp1 { Profile::DP1, 0 };
static const TransmissionLite dp2 { Profile::DP2, 0 };
static const TransmissionLite dp3 { Profile::DP3, 0 };

class FakeAccessInterface : public access::Interface
{
public:
    void request(const access::DataRequest& req, std::unique_ptr<ChunkPacket> packet) override
    {
        last_request = req;
        last_packet = std::move(packet);
        ++transmissions;
    }

    boost::optional<access::DataRequest> last_request;
    std::unique_ptr<ChunkPacket> last_packet;
    unsigned transmissions = 0;
};

class FakeTransmitRateControl : public TransmitRateControl
{
public:
    FakeTransmitRateControl(const Runtime& rt) :
        runtime(rt), trc_off(milliseconds(200)), last_notify(Clock::time_point::min()) {}

    Clock::duration delay(const Transmission&) override
    {
        auto delay = runtime.now() - last_notify + trc_off;
        return delay < Clock::duration::zero() ? Clock::duration::zero() : delay;
    }

    Clock::duration interval(const Transmission&) override { return trc_off; }
    void notify(const Transmission&) override { last_notify = runtime.now(); }

    const Runtime& runtime;
    Clock::duration trc_off;
    Clock::time_point last_notify;
};

class FlowControlTest : public testing::Test
{
protected:
    FlowControlTest() :
        runtime(), trc(runtime),
        flow_control(runtime, trc, access)
    {}

    std::unique_ptr<ChunkPacket> create_packet(std::size_t length = 0)
    {
        std::unique_ptr<ChunkPacket> packet { new ChunkPacket() };
        packet->layer(OsiLayer::Application) = ByteBuffer(length);
        return packet;
    }

    MacAddress mac(char x)
    {
        return MacAddress { 0, 0, 0, 0, 0, static_cast<uint8_t>(x) };
    }

    ManualRuntime runtime;
    FakeTransmitRateControl trc;
    FakeAccessInterface access;
    FlowControl flow_control;
};

TEST_F(FlowControlTest, immediate_transmission)
{
    ASSERT_EQ(milliseconds(0), trc.delay(dp1));
    ASSERT_FALSE(access.last_request);
    DataRequest request;
    request.dcc_profile = Profile::DP1;
    flow_control.request(request, create_packet());
    ASSERT_TRUE(!!access.last_request);
    EXPECT_EQ(access::AccessCategory::VI, access.last_request->access_category);

    EXPECT_EQ(trc.interval(dp2), trc.delay(dp2));
    request.dcc_profile = Profile::DP2;
    access.last_request = boost::none;
    flow_control.request(request, create_packet());
    EXPECT_FALSE(access.last_request);

    // DP0 bursts are implemented by TRC not by FlowControl
    EXPECT_EQ(trc.interval(dp0), trc.delay(dp0));
    request.dcc_profile = Profile::DP0;
    flow_control.request(request, create_packet());
    EXPECT_FALSE(access.last_request);
}

TEST_F(FlowControlTest, queuing)
{
    DataRequest request;
    request.lifetime = hours(1); // expired lifetime shall be no concern here

    trc.notify(dp1);
    EXPECT_LT(Clock::duration::zero(), trc.delay(dp1));
    EXPECT_LT(Clock::duration::zero(), trc.delay(dp2));
    EXPECT_LT(Clock::duration::zero(), trc.delay(dp3));

    request.destination = mac(1);
    request.dcc_profile = Profile::DP1;
    flow_control.request(request, create_packet());
    request.destination = mac(2);
    request.dcc_profile = Profile::DP3;
    flow_control.request(request, create_packet());
    request.destination = mac(3);
    request.dcc_profile = Profile::DP2;
    flow_control.request(request, create_packet());

    runtime.trigger(trc.delay(dp1));
    ASSERT_TRUE(!!access.last_request);
    EXPECT_EQ(mac(1), access.last_request->destination_addr);
    EXPECT_EQ(1, access.transmissions);

    runtime.trigger(trc.delay(dp2) / 2);
    EXPECT_EQ(1, access.transmissions);

    runtime.trigger(trc.delay(dp2));
    EXPECT_EQ(2, access.transmissions);
    EXPECT_EQ(mac(3), access.last_request->destination_addr);

    request.destination = mac(4);
    request.dcc_profile = Profile::DP2;
    flow_control.request(request, create_packet());
    request.destination = mac(5);
    request.dcc_profile = Profile::DP3;
    flow_control.request(request, create_packet());

    runtime.trigger(trc.delay(dp2));
    EXPECT_EQ(3, access.transmissions);
    EXPECT_EQ(mac(4), access.last_request->destination_addr);

    runtime.trigger(trc.delay(dp3));
    EXPECT_EQ(4, access.transmissions);
    EXPECT_EQ(mac(2), access.last_request->destination_addr);

    runtime.trigger(trc.delay(dp3));
    EXPECT_EQ(5, access.transmissions);
    EXPECT_EQ(mac(5), access.last_request->destination_addr);

    // no future transmissions queued anymore
    runtime.trigger(Clock::time_point::max());
    EXPECT_EQ(5, access.transmissions);
}

TEST_F(FlowControlTest, drop_expired)
{
    std::list<access::AccessCategory> drops;
    flow_control.set_packet_drop_hook([&drops](access::AccessCategory ac, const ChunkPacket*) {
            drops.push_back(ac);
    });

    trc.notify(dp3);
    DataRequest request;
    request.dcc_profile = Profile::DP3;
    request.lifetime = trc.delay(dp3) - milliseconds(10);
    flow_control.request(request, create_packet());
    runtime.trigger(trc.delay(dp3) + milliseconds(10));
    EXPECT_FALSE(access.last_request);
    ASSERT_FALSE(drops.empty());
    EXPECT_EQ(access::AccessCategory::BK, drops.back());
    EXPECT_EQ(0, access.transmissions);

    trc.notify(dp3);
    auto delay = trc.delay(dp3);
    EXPECT_NE(Clock::duration::zero(), delay);
    request.lifetime = delay;
    flow_control.request(request, create_packet());
    request.lifetime = delay / 2;
    flow_control.request(request, create_packet());
    request.lifetime = 3 * delay / 2;
    flow_control.request(request, create_packet());
    request.lifetime = 2 * delay;
    flow_control.request(request, create_packet());
    request.lifetime = delay / 4;
    flow_control.request(request, create_packet());
    runtime.trigger(delay);
    EXPECT_EQ(3, drops.size());
    EXPECT_EQ(1, access.transmissions);
    runtime.trigger(delay);
    EXPECT_EQ(4, drops.size());
    EXPECT_EQ(2, access.transmissions);

    // all queues should be empty now, no future transmissions
    runtime.trigger(Clock::time_point::max());
    EXPECT_EQ(2, access.transmissions);
}

TEST_F(FlowControlTest, queue_length)
{
    // set queue length limit (default is unlimited)
    flow_control.queue_length(2);

    // count drops
    std::size_t drops = 0;
    flow_control.set_packet_drop_hook([&drops](access::AccessCategory, const ChunkPacket*) { ++drops; });

    DataRequest request;
    request.dcc_profile = Profile::DP1;
    request.lifetime = std::chrono::seconds(5);

    // cause enqueuing of arriving DP1 packets
    trc.notify(dp1);
    ASSERT_LT(Clock::duration::zero(), trc.delay(dp1));

    flow_control.request(request, create_packet(1));
    flow_control.request(request, create_packet(2));
    EXPECT_EQ(0, access.transmissions);
    EXPECT_EQ(0, drops);

    flow_control.request(request, create_packet(3));
    EXPECT_EQ(0, access.transmissions);
    EXPECT_EQ(1, drops);

    runtime.trigger(trc.delay(dp1));
    EXPECT_EQ(1, access.transmissions);
    EXPECT_EQ(2, access.last_packet->size());

    runtime.trigger(trc.delay(dp1));
    EXPECT_EQ(2, access.transmissions);
    EXPECT_EQ(3, access.last_packet->size());
    EXPECT_EQ(1, drops);
}
