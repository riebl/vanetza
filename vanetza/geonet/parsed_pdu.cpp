#include "parsed_pdu.hpp"
#include "pdu.hpp"
#include "pdu_conversion.hpp"
#include "pdu_variant.hpp"
#include <vanetza/common/byte_buffer_source.hpp>
#include <vanetza/net/osi_layer.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/variant/static_visitor.hpp>

namespace vanetza
{
namespace geonet
{

std::unique_ptr<ParsedPdu> parse(PacketVariant& packet)
{
    struct parse_packet_visitor : public boost::static_visitor<>
    {
        void operator()(CohesivePacket& packet)
        {
            result = parse(packet);
        }

        void operator()(ChunkPacket& packet)
        {
            result = parse(packet);
        }

        std::unique_ptr<ParsedPdu> result;
    };

    parse_packet_visitor visitor;
    boost::apply_visitor(visitor, packet);
    return std::move(visitor.result);
}

std::unique_ptr<ParsedPdu> parse(CohesivePacket& packet)
{
    std::unique_ptr<ParsedPdu> pdu;

    static const std::size_t basic_common_pdu_length =
        BasicHeader::length_bytes + CommonHeader::length_bytes;
    if (packet.size(OsiLayer::Network) < basic_common_pdu_length) {
        assert(!pdu);
        return pdu;
    }

    byte_buffer_source source(packet[OsiLayer::Network]);
    boost::iostreams::stream_buffer<byte_buffer_source> stream(source);
    InputArchive ar(stream, boost::archive::no_header);

    pdu.reset(new ParsedPdu());
    BasicHeader& basic = pdu->basic;
    deserialize(basic, ar);

    CommonHeader& common = pdu->common;
    switch (basic.next_header) {
        case NextHeaderBasic::ANY:
        case NextHeaderBasic::COMMON:
            deserialize(common, ar);
            break;
        case NextHeaderBasic::SECURED:
            // TODO: invoke SN-DECAP.service
        default:
            // unhandled header type, reset PDU
            pdu.reset();
            break;
    }

    if (!pdu) {
        return pdu;
    }

    std::size_t extended_pdu_length = 0;
    switch (common.header_type) {
        case HeaderType::TSB_SINGLE_HOP: {
                ShbHeader shb;
                deserialize(shb, ar);
                pdu->extended = shb;
                extended_pdu_length = ShbHeader::length_bytes;
            }
            break;
        case HeaderType::GEOBROADCAST_CIRCLE:
        case HeaderType::GEOBROADCAST_RECT:
        case HeaderType::GEOBROADCAST_ELIP: {
                GeoBroadcastHeader gbc;
                deserialize(gbc, ar);
                pdu->extended = gbc;
                extended_pdu_length = GeoBroadcastHeader::length_bytes;
            }
            break;
        case HeaderType::ANY:
        case HeaderType::BEACON:
        case HeaderType::GEOUNICAST:
        case HeaderType::GEOANYCAST_CIRCLE:
        case HeaderType::GEOANYCAST_RECT:
        case HeaderType::GEOANYCAST_ELIP:
        case HeaderType::TSB_MULTI_HOP:
        case HeaderType::LS_REQUEST:
        case HeaderType::LS_REPLY:
            // unimplemented types
            pdu.reset();
            break;
        default:
            // invalid types
            pdu.reset();
            break;
    }

    if (pdu) {
        const std::size_t pdu_length = basic_common_pdu_length + extended_pdu_length;
        if (pdu_length + common.payload == packet.size(OsiLayer::Network, max_osi_layer())) {
            packet.set_boundary(OsiLayer::Network, pdu_length);
            assert(packet.size(OsiLayer::Transport, max_osi_layer()) == common.payload);
        } else {
            pdu.reset();
        }
    }

    return pdu;
}

std::unique_ptr<ParsedPdu> parse(ChunkPacket& packet)
{
    using convertible_pdu_t = convertible::byte_buffer_impl<std::unique_ptr<Pdu>>;

    std::unique_ptr<ParsedPdu> parsed_pdu;
    const convertible::byte_buffer* convertible = packet[OsiLayer::Network].ptr();
    const convertible_pdu_t* convertible_pdu =
        dynamic_cast<const convertible_pdu_t*>(convertible);

    if (nullptr != convertible_pdu) {
        assert(convertible_pdu->m_pdu);
        const Pdu* pdu_ptr = convertible_pdu->m_pdu.get();
        parsed_pdu.reset(new ParsedPdu());
        parsed_pdu->basic = pdu_ptr->basic();
        parsed_pdu->common = pdu_ptr->common();

        // TODO: dynamic_cast cascades are ugly, but getting the job done for now
        if (const ShbPdu* shb = dynamic_cast<const ShbPdu*>(pdu_ptr)) {
            parsed_pdu->extended = shb->extended();
        } else if (const GbcPdu* gbc = dynamic_cast<const GbcPdu*>(pdu_ptr)) {
            parsed_pdu->extended = gbc->extended();
        } else if (const BeaconPdu* beacon = dynamic_cast<const BeaconPdu*>(pdu_ptr)) {
            parsed_pdu->extended = beacon->extended();
        } else {
            parsed_pdu.reset();
        }
    }

    return parsed_pdu;
}

} // namespace geonet
} // namespace vanetza
