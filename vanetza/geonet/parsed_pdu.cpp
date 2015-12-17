#include "parsed_pdu.hpp"
#include "pdu.hpp"
#include "pdu_conversion.hpp"
#include "pdu_variant.hpp"
#include "secured_pdu.hpp"
#include <vanetza/common/byte_buffer_sink.hpp>
#include <vanetza/common/byte_buffer_source.hpp>
#include <vanetza/net/osi_layer.hpp>
#include <vanetza/security/exception.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/variant/static_visitor.hpp>
#include <boost/archive/archive_exception.hpp>

namespace vanetza
{
namespace geonet
{

boost::optional<BasicHeader> parse_basic(PacketVariant& packet)
{
    struct parse_packet_visitor : public boost::static_visitor<boost::optional<BasicHeader> >
    {
        boost::optional<BasicHeader> operator()(CohesivePacket& packet)
        {
            return parse_basic(packet);
        }

        boost::optional<BasicHeader> operator()(ChunkPacket& packet)
        {
            return parse_basic(packet);
        }
    };

    parse_packet_visitor visitor;
    return std::move(boost::apply_visitor(visitor, packet));
}

boost::optional<BasicHeader> parse_basic(CohesivePacket& packet)
{
    boost::optional<BasicHeader> header;

    static const std::size_t basic_pdu_length = BasicHeader::length_bytes;

    if (packet.size(OsiLayer::Network) < basic_pdu_length) {
        return boost::none;
    }

    byte_buffer_source source(packet[OsiLayer::Network]);
    boost::iostreams::stream_buffer<byte_buffer_source> stream(source);
    InputArchive ar(stream, boost::archive::no_header);

    try {
        BasicHeader basic;
        deserialize(basic, ar);
        header = std::move(basic);
    } catch (const boost::archive::archive_exception& e) {
        header = boost::none;
    } catch (security::deserialization_error& e) {
        header = boost::none;
    }

    return header;
}

boost::optional<BasicHeader> parse_basic(ChunkPacket& packet)
{
    boost::optional<BasicHeader> header;

    using convertible_pdu_t = convertible::byte_buffer_impl<std::unique_ptr<Pdu>>;

    const convertible::byte_buffer* convertible = packet[OsiLayer::Network].ptr();
    const convertible_pdu_t* convertible_pdu =
        dynamic_cast<const convertible_pdu_t*>(convertible);

    if (nullptr != convertible_pdu) {
        header = std::move(convertible_pdu->m_pdu.get()->basic());
    } else {
        header = boost::none;
    }

    return header;
}

std::size_t parse_extended(std::unique_ptr<ParsedPdu>& pdu, InputArchive& ar)
{
    std::size_t extended_pdu_length = 0;

    try {
        switch (pdu->common.header_type) {
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
    } catch (const boost::archive::archive_exception& e) {
        pdu.reset();
    } catch (security::deserialization_error& e) {
        pdu.reset();
    }

    return extended_pdu_length;
}

std::unique_ptr<ParsedPdu> parse_header(PacketVariant& packet, BasicHeader& basic)
{
    struct parse_packet_visitor : public boost::static_visitor<>
    {
        parse_packet_visitor(BasicHeader& basic) : m_basic(basic)
        {
        }

        void operator()(CohesivePacket& packet)
        {
            result = parse_header(packet, m_basic);
        }

        void operator()(ChunkPacket& packet)
        {
            result = parse_header(packet);
        }

        std::unique_ptr<ParsedPdu> result;

        BasicHeader m_basic;
    };

    parse_packet_visitor visitor(basic);
    boost::apply_visitor(visitor, packet);
    return std::move(visitor.result);
}

std::unique_ptr<ParsedPdu> parse_header(CohesivePacket& packet, BasicHeader& basic)
{
    std::unique_ptr<ParsedPdu> pdu(new ParsedPdu());

    static const std::size_t basic_common_pdu_length =
        BasicHeader::length_bytes + CommonHeader::length_bytes;

    if (packet.size(OsiLayer::Network) < basic_common_pdu_length) {
        pdu.reset();
        return pdu;
    }

    // set basic header in pdu
    pdu->basic = std::move(basic);

    ByteBuffer source_buffer(packet[OsiLayer::Network].begin() + BasicHeader::length_bytes, packet[OsiLayer::Network].end());
    byte_buffer_source source(std::move(source_buffer));
    boost::iostreams::stream_buffer<byte_buffer_source> stream(source);
    InputArchive ar(stream, boost::archive::no_header);

    try {
        CommonHeader& common = pdu->common;
        switch (basic.next_header) {
            case NextHeaderBasic::ANY:
            case NextHeaderBasic::COMMON:
                deserialize(common, ar);
                break;
            default:
                // unhandled header type, reset PDU
                pdu.reset();
                break;
        }
    } catch (const boost::archive::archive_exception& e) {
        pdu.reset();
    } catch (security::deserialization_error& e) {
        pdu.reset();
    }

    if (!pdu) {
        return pdu;
    }

    std::size_t extended_pdu_length = parse_extended(pdu, ar);

    if (pdu) {
        std::size_t pdu_length = basic_common_pdu_length + extended_pdu_length;
        if (pdu_length + pdu->common.payload == packet.size(OsiLayer::Network, max_osi_layer())) {
            packet.set_boundary(OsiLayer::Network, pdu_length);
            assert(packet.size(OsiLayer::Transport, max_osi_layer()) == pdu->common.payload);
        } else {
            pdu.reset();
        }
    }

    return pdu;
}

std::unique_ptr<ParsedPdu> parse_header(ChunkPacket& packet)
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

std::unique_ptr<ParsedPdu> parse_secured_header(PacketVariant& packet, const BasicHeader& basic)
{
    using PduPtr = std::unique_ptr<ParsedPdu>;
    PduPtr pdu(new ParsedPdu());

    // set basic header in pdu
    pdu->basic = basic;

    struct parse_visitor : public boost::static_visitor<>
    {
        parse_visitor(PduPtr& _pdu) : pdu(_pdu) {}

        void operator()(CohesivePacket& packet)
        {
            byte_buffer_source source(packet[OsiLayer::Network]);
            boost::iostreams::stream_buffer<byte_buffer_source> stream(source);
            InputArchive ar(stream, boost::archive::no_header);

            try {
                std::size_t pdu_length = CommonHeader::length_bytes;
                deserialize(pdu->common, ar);
                pdu_length += parse_extended(pdu, ar);
                packet.set_boundary(OsiLayer::Network, pdu_length);
            } catch (const boost::archive::archive_exception& e) {
                pdu.reset();
            } catch (security::deserialization_error& e) {
                pdu.reset();
            }

            if (pdu.get()) {
                if (pdu->common.payload != size(packet, OsiLayer::Transport, max_osi_layer())) {
                    pdu.reset();
                }
            }
        }

        void operator()(const ChunkPacket& packet)
        {
            using sec_pdu_ptr = const convertible::byte_buffer_impl<SecuredPdu>*;
            const ByteBufferConvertible& net = packet[OsiLayer::Network];
            const auto* sec_pdu = dynamic_cast<sec_pdu_ptr>(net.ptr());
            if (sec_pdu) {
                pdu->common = sec_pdu->pdu.common;
                pdu->extended = sec_pdu->pdu.extended;
            } else {
                pdu.reset();
            }
        }

        PduPtr& pdu;
    };

    parse_visitor visitor(pdu);
    boost::apply_visitor(visitor, packet);
    return pdu;
}

boost::optional<security::SecuredMessage> extract_secured_message(PacketVariant& packet)
{
    struct extract_secured_message_visitor : public boost::static_visitor<boost::optional<security::SecuredMessage>>
    {
        boost::optional<security::SecuredMessage> operator()(CohesivePacket& packet)
        {
            return extract_secured_message(packet);
        }

        boost::optional<security::SecuredMessage> operator()(ChunkPacket& packet)
        {
            return extract_secured_message(packet);
        }
    };

    extract_secured_message_visitor visitor;
    return std::move(boost::apply_visitor(visitor, packet));
}

boost::optional<security::SecuredMessage> extract_secured_message(ByteBuffer secured_buffer)
{
    boost::optional<security::SecuredMessage> secured_message;

    // create the InputArchive for deserialization
    byte_buffer_source source(std::move(secured_buffer));
    boost::iostreams::stream_buffer<byte_buffer_source> stream(source);
    InputArchive ar(stream, boost::archive::no_header);

    try {
        security::SecuredMessage secured;
        deserialize(ar, secured);
        secured_message = std::move(secured);
    } catch (const boost::archive::archive_exception& e) {
        secured_message = boost::none;
    } catch (security::deserialization_error& e) {
        secured_message = boost::none;
    }

    return secured_message;
}

boost::optional<security::SecuredMessage> extract_secured_message(CohesivePacket& packet)
{
    // get all data from Network layer
    ByteBuffer source_buffer(packet[OsiLayer::Network].begin() + BasicHeader::length_bytes, packet[OsiLayer::Network].end());

    return extract_secured_message(std::move(source_buffer));
}

boost::optional<security::SecuredMessage> extract_secured_message(ChunkPacket& packet)
{
    // get all data from Network layer
    ByteBuffer layer_buffer;
    packet[OsiLayer::Network].convert(layer_buffer);
    ByteBuffer source_buffer(layer_buffer.begin() + BasicHeader::length_bytes, layer_buffer.end());

    return extract_secured_message(std::move(source_buffer));
}

ByteBuffer convert_for_signing(const ParsedPdu& pdu)
{
    ByteBuffer buf;
    byte_buffer_sink sink(buf);

    boost::iostreams::stream_buffer<byte_buffer_sink> stream(sink);
    OutputArchive ar(stream, boost::archive::no_header);

    serialize(pdu.common, ar);
    serialize(pdu.extended, ar);

    return std::move(buf);
}

PacketVariant extract_secured_payload(PacketVariant& packet, std::size_t offset)
{
    struct extract_visitor : public boost::static_visitor<PacketVariant>
    {
        extract_visitor(std::size_t _offset) : offset(_offset) {}

        PacketVariant operator()(ChunkPacket& packet) const
        {
            return packet.extract(OsiLayer::Transport, max_osi_layer());
        }

        PacketVariant operator()(CohesivePacket& packet) const
        {
            assert(offset <= packet.size(OsiLayer::Network));
            CohesivePacket payload = std::move(packet);
            payload.set_boundary(OsiLayer::Network, offset);
            return payload;
        }

        const std::size_t offset;
    };

    extract_visitor visitor(offset);
    return boost::apply_visitor(visitor, packet);
}

} // namespace geonet
} // namespace vanetza
