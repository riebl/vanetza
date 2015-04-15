#include "port_dispatcher.hpp"
#include "data_indication.hpp"
#include <vanetza/geonet/data_indication.hpp>
#include <vanetza/geonet/serialization_buffer.hpp>
#include <cassert>

namespace vanetza
{
namespace btp
{

HeaderB parse_btp_b(CohesivePacket& packet)
{
    HeaderB hdr;
    geonet::deserialize_from_range(hdr, packet[OsiLayer::Transport]);
    packet.set_boundary(OsiLayer::Transport, btp::HeaderB::length_bytes);
    return hdr;
}

HeaderB parse_btp_b(ChunkPacket& packet)
{
    HeaderB hdr;
    ByteBuffer tmp;
    packet[OsiLayer::Transport].convert(tmp);
    geonet::deserialize_from_buffer(hdr, tmp);
    return hdr;
}

HeaderB parse_btp_b(geonet::PacketVariant& packet)
{
    struct parse_btp_visitor : public boost::static_visitor<HeaderB>
    {
        HeaderB operator()(CohesivePacket& packet) {
            return parse_btp_b(packet);
        }

        HeaderB operator()(ChunkPacket& packet) {
            return parse_btp_b(packet);
        }
    };

    parse_btp_visitor visitor;
    return boost::apply_visitor(visitor, packet);
}

void PortDispatcher::set_non_interactive_handler(
        port_type port,
        IndicationInterface* handler)
{
    m_non_interactive_handlers[port] = handler;
}

void PortDispatcher::indicate(
        const geonet::DataIndication& gn_ind,
        std::unique_ptr<UpPacket> packet)
{
    assert(packet);
    btp::IndicationInterface* handler = nullptr;
    btp::DataIndication btp_ind;

    switch (gn_ind.upper_protocol) {
        case geonet::UpperProtocol::BTP_A:
            // TODO: handle BTP_A
            break;
        case geonet::UpperProtocol::BTP_B: {
            HeaderB hdr = parse_btp_b(*packet);
            btp_ind = DataIndication(gn_ind, hdr);
            handler = m_non_interactive_handlers[hdr.destination_port];
            }
            break;
        default:
            // not a BTP packet, drop it
            break;
    }

    if (nullptr != handler) {
        handler->indicate(btp_ind, std::move(packet));
    }
}

} // namespace btp
} // namespace vanetza

