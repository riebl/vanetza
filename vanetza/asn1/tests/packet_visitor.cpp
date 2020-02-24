#include <gtest/gtest.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/packet_visitor.hpp>
#include <vanetza/asn1/its/VanetzaTest.h>
#include <vanetza/net/packet_variant.hpp>
#include <boost/variant/apply_visitor.hpp>

using namespace vanetza;

class TestWrapper : public asn1::asn1c_wrapper<VanetzaTest_t>
{
public:
    TestWrapper() : asn1::asn1c_wrapper<VanetzaTest_t>(asn_DEF_VanetzaTest) {}
};


TEST(PacketVisitor, fresh)
{
    asn1::PacketVisitor<TestWrapper> visitor;
    EXPECT_EQ(visitor.get_shared_wrapper(), std::shared_ptr<TestWrapper>());
}

TEST(PacketVisitor, deserialize_buffer)
{
    PacketVariant packet;
    {
        TestWrapper wrapper;
        wrapper->field = 23;
        CohesivePacket cohesive { wrapper.encode(), OsiLayer::Application };
        packet = std::move(cohesive);
    }

    asn1::PacketVisitor<TestWrapper> visitor;
    auto result = boost::apply_visitor(visitor, packet);
    ASSERT_TRUE(result);
    EXPECT_EQ((*result)->field, 23);
}

TEST(PacketVisitor, deserialize_start)
{
    PacketVariant packet;
    {
        TestWrapper wrapper;
        wrapper->field = 23;
        CohesivePacket cohesive { wrapper.encode(), OsiLayer::Session };
        packet = std::move(cohesive);
    }

    asn1::PacketVisitor<TestWrapper> visitor;
    EXPECT_TRUE(boost::apply_visitor(visitor, packet));
    visitor.start_deserialization_at(OsiLayer::Application);
    EXPECT_FALSE(boost::apply_visitor(visitor, packet));
}

TEST(PacketVisitor, cast_chunk)
{
    PacketVariant packet;
    const VanetzaTest_t* ptr = nullptr;
    {
        ChunkPacket chunk;
        TestWrapper wrapper;
        wrapper->field = 42;
        ptr = &(*wrapper);
        chunk[OsiLayer::Application] = std::move(wrapper);
        packet = std::move(chunk);
    }

    asn1::PacketVisitor<TestWrapper> visitor;
    auto result = boost::apply_visitor(visitor, packet);
    ASSERT_TRUE(result);
    EXPECT_EQ(&(**result), ptr);
    EXPECT_EQ((*result)->field, 42);
}

TEST(PacketVisitor, deserialize_chunk)
{
    PacketVariant packet;
    {
        ChunkPacket chunk;
        TestWrapper wrapper;
        wrapper->field = 123;
        chunk[OsiLayer::Application] = wrapper.encode();
        packet = std::move(chunk);
    }

    asn1::PacketVisitor<TestWrapper> visitor;
    visitor.allow_chunk_deserialization(false);
    EXPECT_FALSE(boost::apply_visitor(visitor, packet));

    visitor.allow_chunk_deserialization(true);
    EXPECT_TRUE(boost::apply_visitor(visitor, packet));
}

TEST(PacketVisitor, failed)
{
    asn1::PacketVisitor<TestWrapper> visitor;
    PacketVariant packet { ChunkPacket {} };
    auto result = boost::apply_visitor(visitor, packet);
    EXPECT_FALSE(result);
    EXPECT_FALSE(visitor.get_shared_wrapper());
}
