#include <vanetza/geonet/indication_context.hpp>
#include <vanetza/geonet/pdu_conversion.hpp>
#include <vanetza/geonet/secured_pdu.hpp>

namespace vanetza
{
namespace geonet
{

IndicationContextDeserialize::IndicationContextDeserialize(UpPacketPtr packet, CohesivePacket& cohesive, const LinkLayer& ll) :
    detail::IndicationContextParent(ll),
    m_packet(std::move(packet)), m_cohesive_packet(cohesive),
    m_parser(cohesive[OsiLayer::Network])
{
}

BasicHeader* IndicationContextDeserialize::parse_basic()
{
    auto bytes = m_parser.parse_basic(pdu().basic());
    return bytes > 0 ? &pdu().basic() : nullptr;
}

CommonHeader* IndicationContextDeserialize::parse_common()
{
    auto bytes = m_parser.parse_common(pdu().common());
    return bytes > 0 ? &pdu().common() : nullptr;
}

IndicationContext::SecuredMessage* IndicationContextDeserialize::parse_secured()
{
    IndicationContext::SecuredMessage tmp;
    auto bytes = m_parser.parse_secured(tmp);
    if (bytes > 0) {
        pdu().secured(std::move(tmp));
        return pdu().secured();
    } else {
        return nullptr;
    }
}

boost::optional<HeaderConstRefVariant> IndicationContextDeserialize::parse_extended(HeaderType ht)
{
    auto bytes = m_parser.parse_extended(pdu().extended_variant(), ht);
    return boost::optional<HeaderConstRefVariant>(bytes > 0, pdu().extended_variant());
}

IndicationContext::UpPacketPtr IndicationContextDeserialize::finish()
{
    m_cohesive_packet.set_boundary(OsiLayer::Network, m_parser.parsed_bytes());
    m_cohesive_packet.trim(OsiLayer::Transport, pdu().common().payload);
    return std::move(m_packet);
}


IndicationContextCast::IndicationContextCast(UpPacketPtr packet, ChunkPacket& chunk, const LinkLayer& ll) :
    detail::IndicationContextParent(ll), m_packet(std::move(packet))
{
    using convertible_pdu_t = convertible::byte_buffer_impl<std::unique_ptr<Pdu>>;
    auto convertible = chunk.layer(OsiLayer::Network).ptr();
    auto pdu_rx = dynamic_cast<convertible_pdu_t*>(convertible);
    if (pdu_rx) {
        pdu() = *pdu_rx->m_pdu;
    } else {
        throw std::runtime_error("Casting to Pdu failed");
    }
}

BasicHeader* IndicationContextCast::parse_basic()
{
    return &pdu().basic();
}

CommonHeader* IndicationContextCast::parse_common()
{
    return &pdu().common();
}

IndicationContext::SecuredMessage* IndicationContextCast::parse_secured()
{
    return pdu().secured();
}

boost::optional<HeaderConstRefVariant> IndicationContextCast::parse_extended(HeaderType)
{
    boost::optional<HeaderConstRefVariant> extended;
    HeaderConstRefVariant variant = pdu().extended_variant();
    extended.emplace(variant);
    return extended;
}

IndicationContext::UpPacketPtr IndicationContextCast::finish()
{
    // payload should be already in place (if any)
    return std::move(m_packet);
}

IndicationContextSecuredDeserialize::IndicationContextSecuredDeserialize(IndicationContext& parent, CohesivePacket& payload) :
    detail::IndicationContextChild(parent),
    m_packet(payload),
    m_parser(payload[OsiLayer::Network])
{
}

CommonHeader* IndicationContextSecuredDeserialize::parse_common()
{
    auto bytes = m_parser.parse_common(pdu().common());
    return bytes > 0 ? &pdu().common() : nullptr;
}

boost::optional<HeaderConstRefVariant> IndicationContextSecuredDeserialize::parse_extended(HeaderType ht)
{
    auto bytes = m_parser.parse_extended(pdu().extended_variant(), ht);
    return boost::optional<HeaderConstRefVariant>(bytes > 0, pdu().extended_variant());
}

IndicationContext::UpPacketPtr IndicationContextSecuredDeserialize::finish()
{
    m_packet.set_boundary(OsiLayer::Network, m_parser.parsed_bytes());
    auto packet = m_parent.finish();
    (*packet) = m_packet;
    return packet;
}

IndicationContextSecuredCast::IndicationContextSecuredCast(IndicationContext& parent, ChunkPacket& packet) :
    detail::IndicationContextChild(parent),
    m_packet(parent.finish())
{
    using convertible_pdu_t = convertible::byte_buffer_impl<SecuredPdu>;
    auto convertible = packet.layer(OsiLayer::Network).ptr();
    auto pdu_rx = dynamic_cast<convertible_pdu_t*>(convertible);
    if (pdu_rx) {
        pdu().common() = pdu_rx->pdu.common;
        pdu().extended_variant() = pdu_rx->pdu.extended;
    } else {
        throw std::runtime_error("Casting to SecuredPdu failed");
    }

    struct parent_packet_visitor : public boost::static_visitor<>
    {
        parent_packet_visitor(ChunkPacket& _secured_payload) : secured_payload(_secured_payload) {}

        void operator()(ChunkPacket& packet)
        {
            packet.merge(secured_payload, OsiLayer::Transport, max_osi_layer());
        }

        void operator()(CohesivePacket& packet)
        {
            // CohesivePacket and casting PDUs will probably never happen...
            ByteBuffer buffer(secured_payload.size());
            for (auto layer : osi_layer_range(OsiLayer::Transport, max_osi_layer())) {
                ByteBuffer layer_buffer;
                secured_payload.layer(layer).convert(layer_buffer);
                buffer.insert(buffer.end(), layer_buffer.begin(), layer_buffer.end());
            }
            packet = CohesivePacket(std::move(buffer), OsiLayer::Transport);
        }

        ChunkPacket& secured_payload;
    };

    parent_packet_visitor visitor(packet);
    boost::apply_visitor(visitor, *m_packet);
}

CommonHeader* IndicationContextSecuredCast::parse_common()
{
    return &pdu().common();
}

boost::optional<HeaderConstRefVariant> IndicationContextSecuredCast::parse_extended(HeaderType)
{
    boost::optional<HeaderConstRefVariant> extended;
    HeaderConstRefVariant variant = pdu().extended_variant();
    extended.emplace(variant);
    return extended;
}

IndicationContext::UpPacketPtr IndicationContextSecuredCast::finish()
{
    return std::move(m_packet);
}

} // namespace geonet
} // namespace vanetza
