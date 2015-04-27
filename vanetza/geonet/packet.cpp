#include "packet.hpp"

namespace vanetza
{
namespace geonet
{

std::size_t size(const PacketVariant& packet, OsiLayer layer)
{
    struct size_visitor : public boost::static_visitor<std::size_t>
    {
        size_visitor(OsiLayer layer) : m_layer(layer) {}

        std::size_t operator()(const CohesivePacket& packet)
        {
            return size(packet, m_layer);
        }

        std::size_t operator()(const ChunkPacket& packet)
        {
            return size(packet, m_layer);
        }

        OsiLayer m_layer;
    };

    size_visitor visitor(layer);
    return boost::apply_visitor(visitor, packet);
}

std::size_t size(const PacketVariant& packet, OsiLayer from, OsiLayer to)
{
    struct size_visitor : public boost::static_visitor<std::size_t>
    {
        size_visitor(OsiLayer from, OsiLayer to) : m_from(from), m_to(to) {}

        std::size_t operator()(const CohesivePacket& packet)
        {
            return size(packet, m_from, m_to);
        }

        std::size_t operator()(const ChunkPacket& packet)
        {
            return size(packet, m_from, m_to);
        }

        OsiLayer m_from;
        OsiLayer m_to;
    };

    size_visitor visitor(from, to);
    return boost::apply_visitor(visitor, packet);
}

std::unique_ptr<ChunkPacket> duplicate(const PacketVariant& packet)
{
    struct duplication_visitor : public boost::static_visitor<>
    {
        void operator()(const CohesivePacket& packet)
        {
            m_duplicate.reset(new ChunkPacket());
            for (auto layer : osi_layers) {
                const auto range = packet[layer];
                m_duplicate->layer(layer) = ByteBuffer(range.begin(), range.end());
            }
        }

        void operator()(const ChunkPacket& packet)
        {
            m_duplicate.reset(new ChunkPacket(packet));
        }

        std::unique_ptr<ChunkPacket> m_duplicate;
    };

    duplication_visitor visitor;
    boost::apply_visitor(visitor, packet);
    return std::move(visitor.m_duplicate);
}

byte_view_range create_byte_view(const PacketVariant& packet, OsiLayer layer)
{
    struct payload_visitor : public boost::static_visitor<byte_view_range>
    {
        payload_visitor(OsiLayer layer) : m_layer(layer) {}

        byte_view_range operator()(const CohesivePacket& packet)
        {
            return create_byte_view(packet, m_layer);
        }

        byte_view_range operator()(const ChunkPacket& packet)
        {
            return create_byte_view(packet, m_layer);
        }

        OsiLayer m_layer;
    };

    payload_visitor visitor(layer);
    return boost::apply_visitor(visitor, packet);
}

byte_view_range create_byte_view(const ChunkPacket& packet, OsiLayer layer)
{
    return create_byte_view(packet[layer]);
}

byte_view_range create_byte_view(const CohesivePacket& packet, OsiLayer layer)
{
    CohesivePacket::buffer_const_range range = packet[layer];
    return byte_view_range { range.begin(), range.end() };
}

} // namespace geonet
} // namespace vanetza
