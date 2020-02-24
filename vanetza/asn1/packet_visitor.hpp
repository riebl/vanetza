#ifndef PACKET_VISITOR_HPP_UYSI8HXZ
#define PACKET_VISITOR_HPP_UYSI8HXZ

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/net/chunk_packet.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include <vanetza/net/osi_layer.hpp>
#include <boost/variant/static_visitor.hpp>
#include <memory>

namespace vanetza
{
namespace asn1
{

/**
 * PacketVisitor is a helper to extract the ASN.1 wrapper object from a packet's application layer.
 * This is a generalised version of the implementation found in Artery before.
 *
 * ChunkPacket's application layer is simply casted for the sake of speed whenever possible.
 * When casting fails, this helper can fall back to deserialization, see DeserializationChunk parameter.
 * Deserialization is the only option for CohesivePacket's application layer.
 *
 * \param T is the asn1c_wrapper<> type, e.g. Cam or Denm
 * \param DeserializeChunck determines if deserialisation of ChunkPacket is attempted when cast failed
 */
template<typename T, bool DeserializeChunk = true>
class PacketVisitor : public boost::static_visitor<std::shared_ptr<const T>>
{
    public:
        std::shared_ptr<const T> operator()(const ChunkPacket& packet)
        {
            using byte_buffer_impl = convertible::byte_buffer_impl<T>;
            auto impl = dynamic_cast<const byte_buffer_impl*>(packet[OsiLayer::Application].ptr());
            if (impl) {
                m_wrapper = impl->wrapper();
            } else if (DeserializeChunk) {
                ByteBuffer buffer;
                packet[OsiLayer::Application].convert(buffer);
                deserialize(buffer);
            } else {
                m_wrapper.reset();
            }
            return m_wrapper;
        }

        std::shared_ptr<const T> operator()(const CohesivePacket& packet)
        {
            const auto range = packet[OsiLayer::Application];
            ByteBuffer buffer { range.begin(), range.end() };
            deserialize(buffer);
            return m_wrapper;
        }

        std::shared_ptr<const T> get_shared_wrapper() const { return m_wrapper; }

    private:
        void deserialize(const ByteBuffer& buffer)
        {
            auto tmp = std::make_shared<T>();
            bool decoded = tmp->decode(buffer);
            m_wrapper = decoded ? tmp : nullptr;
        }

        std::shared_ptr<const T> m_wrapper;
};

} // namespace asn1
} // namespace vanetza

#endif /* PACKET_VISITOR_HPP_UYSI8HXZ */

