#include <vanetza/btp/data_indication.hpp>
#include <vanetza/btp/data_request.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/interface.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/net/mac_address.hpp>
#include <vanetza/net/osi_layer.hpp>
#include <vanetza/units/frequency.hpp>
#include <vanetza/units/length.hpp>
#include <vanetza/units/time.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/cbf_counter.hpp>
#include <vanetza/geonet/data_confirm.hpp>
#include <vanetza/geonet/dcc_field_generator.hpp>
#include <vanetza/geonet/duplicate_packet_list.hpp>
#include <vanetza/geonet/indication_context.hpp>
#include <vanetza/geonet/loctex_g5.hpp>
#include <vanetza/geonet/next_hop.hpp>
#include <vanetza/geonet/pdu_conversion.hpp>
#include <vanetza/geonet/repetition_dispatcher.hpp>
#include <vanetza/geonet/transport_interface.hpp>
#include <vanetza/geonet/extended_pdu.hpp>
#include <vanetza/geonet/secured_pdu.hpp>
#include <boost/units/cmath.hpp>
#include <functional>
#include <stdexcept>
#include <tuple>
#include <type_traits>

namespace vanetza
{
namespace geonet
{
namespace
{

struct ControlInfo
{
    ControlInfo(const DataRequest request) :
        communication_profile(request.communication_profile),
        its_aid(request.its_aid) {}

    const CommunicationProfile communication_profile;
    const ItsAid its_aid;
};

template<typename PDU>
class PendingPacketBufferData : public packet_buffer::Data
{
public:
    PendingPacketBufferData(PendingPacket<PDU>&& packet) : m_packet(std::move(packet)) {}

    std::size_t length() const override
    {
        return m_packet.length();
    }

    Clock::duration reduce_lifetime(Clock::duration d) override
    {
        return m_packet.reduce_lifetime(d);
    }

    void flush() override
    {
        m_packet.process();
    }

protected:
    PendingPacket<PDU> m_packet;
};

dcc::RequestInterface* get_default_request_interface()
{
    static dcc::NullRequestInterface null;
    return &null;
}

DccFieldGenerator* get_default_dcc_field_generator()
{
    static NullDccFieldGenerator null;
    return &null;
}

template<typename PDU>
auto create_forwarding_duplicate(const PDU& pdu, const UpPacket& packet) ->
std::tuple<std::unique_ptr<ExtendedPdu<typename PDU::ExtendedHeader>>, std::unique_ptr<DownPacket>>
{
    using pdu_type = ExtendedPdu<typename PDU::ExtendedHeader>;
    std::unique_ptr<pdu_type> pdu_dup { new pdu_type { pdu }};
    std::unique_ptr<DownPacket> packet_dup;
    if (pdu.secured()) {
        packet_dup.reset(new DownPacket());
    } else {
        packet_dup = duplicate(packet);
    }
    return std::make_tuple(std::move(pdu_dup), std::move(packet_dup));
}

template<typename PDU>
PDU& get_pdu(const std::tuple<std::unique_ptr<PDU>, std::unique_ptr<DownPacket>>& packet)
{
    PDU* pdu = std::get<0>(packet).get();
    assert(pdu);
    return *pdu;
}

std::unique_ptr<CbfCounter> create_cbf_counter(Runtime& rt, const MIB& mib)
{
    std::unique_ptr<CbfCounter> counter;
    if (mib.vanetzaFadingCbfCounter) {
        counter.reset(new CbfCounterFading(rt, units::clock_cast(2.0 * mib.itsGnCbfMaxTime)));
    } else {
        counter.reset(new CbfCounterContending());
    }
    assert(counter);
    return counter;
}

} // namespace

using units::clock_cast;
using PendingPacketGbc = PendingPacket<GbcPdu>;

const access::EtherType ether_type = access::ethertype::GeoNetworking;

Router::Router(Runtime& rt, const MIB& mib) :
    m_mib(mib),
    m_runtime(rt),
    m_request_interface(get_default_request_interface()),
    m_dcc_field_generator(get_default_dcc_field_generator()),
    m_security_entity(nullptr),
    m_location_table(mib, m_runtime),
    m_bc_forward_buffer(mib.itsGnBcForwardingPacketBufferSize * 1024),
    m_uc_forward_buffer(mib.itsGnUcForwardingPacketBufferSize * 1024),
    m_cbf_buffer(m_runtime,
            [](PendingPacketGbc&& packet) { packet.process(); },
            create_cbf_counter(rt, mib),
            mib.itsGnCbfPacketBufferSize * 1024),
    m_local_sequence_number(0),
    m_repeater(m_runtime,
            std::bind(&Router::dispatch_repetition, this, std::placeholders::_1, std::placeholders::_2)),
    m_random_gen(mib.vanetzaDefaultSeed)
{
    if (!m_mib.vanetzaDisableBeaconing) {
        if (!m_mib.vanetzaDeferInitialBeacon) {
            // send Beacon immediately after start-up at next runtime trigger invocation
            reset_beacon_timer(Clock::duration::zero());
        } else {
            // defer initial Beacon transmission slightly
            std::uniform_real_distribution<double> dist(0.0, 1.0);
            const auto first_beacon = dist(m_random_gen) * m_mib.itsGnBeaconServiceRetransmitTimer;
            reset_beacon_timer(clock_cast(first_beacon));
        }
    }

    m_gbc_memory.capacity(m_mib.vanetzaGbcMemoryCapacity);
}

Router::~Router()
{
    m_runtime.cancel(this);
}

void Router::update_position(const PositionFix& position_fix)
{
    // EN 302 636-4-1 v1.3.1 is a little bit fuzzy regarding the time stamp:
    // "Expresses the time (...) at which the latitude and longitude (...) were acquired by the GeoAdhoc router."
    // My reading: use the current time stamp (now) when update_position is called (not the position fix time stamp)
    m_local_position_vector.timestamp = m_runtime.now();
    m_local_position_vector.latitude = static_cast<geo_angle_i32t>(position_fix.latitude);
    m_local_position_vector.longitude = static_cast<geo_angle_i32t>(position_fix.longitude);
    if (m_mib.itsGnIsMobile) {
        m_local_position_vector.speed = static_cast<LongPositionVector::speed_u15t>(position_fix.speed.value());
        m_local_position_vector.heading = static_cast<heading_u16t>(position_fix.course.value() - units::TrueNorth::from_value(0.0));
    } else {
        m_local_position_vector.speed = static_cast<LongPositionVector::speed_u15t>(0);
        m_local_position_vector.heading = static_cast<heading_u16t>(0);
    }
    // see field 5 (PAI) in table 2 (long position vector)
    m_local_position_vector.position_accuracy_indicator =
        position_fix.confidence.semi_major * 2.0 < m_mib.itsGnPaiInterval;
}

void Router::set_transport_handler(UpperProtocol proto, TransportInterface* ifc)
{
    m_transport_ifcs[proto] = ifc;
}

void Router::set_security_entity(security::SecurityEntity* entity)
{
    m_security_entity = entity;
}

void Router::set_access_interface(dcc::RequestInterface* ifc)
{
    m_request_interface = (ifc == nullptr ? get_default_request_interface() : ifc);
    assert(m_request_interface != nullptr);
}

void Router::set_dcc_field_generator(DccFieldGenerator* dcc)
{
    m_dcc_field_generator = (dcc == nullptr) ? get_default_dcc_field_generator() : dcc;
    assert(m_dcc_field_generator != nullptr);
}

void Router::set_address(const Address& addr)
{
    m_local_position_vector.gn_addr = addr;
}

void Router::set_random_seed(std::uint_fast32_t seed)
{
    m_random_gen.seed(seed);
}

DataConfirm Router::request(const ShbDataRequest& request, DownPacketPtr payload)
{
    DataConfirm result;
    result ^= validate_data_request(request, m_mib);
    result ^= validate_payload(payload, m_mib);

    if (result.accepted()) {
        using PendingPacket = PendingPacket<ShbPdu>;

        // step 4: set up packet repetition (NOTE 4 on page 57 requires re-execution of source operations)
        if (request.repetition) {
            // plaintext payload needs to get passed
            m_repeater.add(request, *payload);
        }

        // step 1: create PDU
        auto pdu = create_shb_pdu(request);
        pdu->common().payload = payload->size();

        ControlInfo ctrl(request);
        auto transmit = [this, ctrl](PendingPacket::Packet&& packet) {
            std::unique_ptr<ShbPdu> pdu;
            std::unique_ptr<DownPacket> payload;
            std::tie(pdu, payload) = std::move(packet);

            // update SO PV before actual transmission
            pdu->extended().source_position = m_local_position_vector;

            // step 2: encapsulate packet by security
            if (m_mib.itsGnSecurity) {
                payload = encap_packet(ctrl.its_aid, *pdu, std::move(payload));
            }

            // step 5: execute media-dependent procedures
            execute_media_procedures(ctrl.communication_profile);

            // step 6: pass packet down to link layer with broadcast destination
            pass_down(cBroadcastMacAddress, std::move(pdu), std::move(payload));

            // step 7: reset beacon timer
            reset_beacon_timer();
        };

        PendingPacket packet(std::make_tuple(std::move(pdu), std::move(payload)), transmit);

        // step 3: store & carry forwarding
        if (request.traffic_class.store_carry_forward() && !m_location_table.has_neighbours()) {
            PacketBuffer::data_ptr data { new PendingPacketBufferData<ShbPdu>(std::move(packet)) };
            m_bc_forward_buffer.push(std::move(data), m_runtime.now());
        } else {
            // tranmsit immediately
            packet.process();
        }
    }

    return result;
}

DataConfirm Router::request(const GbcDataRequest& request, DownPacketPtr payload)
{
    DataConfirm result;
    result ^= validate_data_request(request, m_mib);
    result ^= validate_payload(payload, m_mib);

    if (!result.accepted())
        return result;

    // step 6: set up packet repetition
    // packet repetition is done first because of "NOTE 2" on page 60:
    // "For every retransmission, the source operations need to be re-executed".
    // Hence, all routing decisions and security encapsulation have to be performed again.
    // Assumption: "omit execution of further steps" does not cancel the repetition procedure.
    if (request.repetition) {
        m_repeater.add(request, *payload);
    }

    using PendingPacket = PendingPacket<GbcPdu>;
    using Packet = PendingPacket::Packet;

    // step 1: create PDU and set header fields
    auto pdu = create_gbc_pdu(request);
    pdu->common().payload = payload->size();

    ControlInfo ctrl(request);
    auto transmit = [this, ctrl](Packet&& packet, const MacAddress& mac) {
        std::unique_ptr<GbcPdu> pdu;
        std::unique_ptr<DownPacket> payload;
        std::tie(pdu, payload) = std::move(packet);

        // update SO PV before actual transmission
        pdu->extended().source_position = m_local_position_vector;

        // step 5: apply security
        if (m_mib.itsGnSecurity) {
            assert(pdu->basic().next_header == NextHeaderBasic::Secured);
            payload = encap_packet(ctrl.its_aid, *pdu, std::move(payload));
        }

        // step 6: repetition is already set-up before

        // step 7: execute media-dependent procedures
        execute_media_procedures(ctrl.communication_profile);

        // step 8: pass PDU to link layer
        pass_down(mac, std::move(pdu), std::move(payload));
    };

    auto forwarding = [this, transmit](Packet&& packet) {
        // step 3: forwarding algorithm selection procedure
        NextHop nh = forwarding_algorithm_selection(PendingPacketForwarding(std::move(packet), transmit), nullptr);

        // step 4: omit execution of further steps when packet if buffered or discarded
        std::move(nh).process();
    };

    PendingPacket packet(std::make_tuple(std::move(pdu), std::move(payload)), forwarding);

    // step 2: check if neighbours are present
    const bool scf = request.traffic_class.store_carry_forward();
    if (scf && !m_location_table.has_neighbours()) {
        PacketBuffer::data_ptr data { new PendingPacketBufferData<GbcPdu>(std::move(packet)) };
        m_bc_forward_buffer.push(std::move(data), m_runtime.now());
    } else {
        packet.process();
    }

    return result;
}

DataConfirm Router::request(const GacDataRequest&, DownPacketPtr)
{
    return DataConfirm(DataConfirm::ResultCode::Rejected_Unspecified);
}

DataConfirm Router::request(const GucDataRequest&, DownPacketPtr)
{
    return DataConfirm(DataConfirm::ResultCode::Rejected_Unspecified);
}

DataConfirm Router::request(const TsbDataRequest&, DownPacketPtr)
{
    return DataConfirm(DataConfirm::ResultCode::Rejected_Unspecified);
}

void Router::indicate(UpPacketPtr packet, const MacAddress& sender, const MacAddress& destination)
{
    assert(packet);

    struct indication_visitor : public boost::static_visitor<>
    {
        indication_visitor(Router& router, const IndicationContext::LinkLayer& link_layer, UpPacketPtr packet) :
            m_router(router), m_link_layer(link_layer), m_packet(std::move(packet))
        {
        }

        void operator()(CohesivePacket& packet)
        {
            IndicationContextDeserialize ctx(std::move(m_packet), packet, m_link_layer);
            m_router.indicate_basic(ctx);
        }

        void operator()(ChunkPacket& packet)
        {
            IndicationContextCast ctx(std::move(m_packet), packet, m_link_layer);
            m_router.indicate_basic(ctx);
        }

        Router& m_router;
        const IndicationContext::LinkLayer& m_link_layer;
        UpPacketPtr m_packet;
    };

    IndicationContext::LinkLayer link_layer;
    link_layer.sender = sender;
    link_layer.destination = destination;

    UpPacket* packet_ptr = packet.get();
    indication_visitor visitor(*this, link_layer, std::move(packet));
    boost::apply_visitor(visitor, *packet_ptr);
}

void Router::indicate_basic(IndicationContextBasic& ctx)
{
    const BasicHeader* basic = ctx.parse_basic();
    if (!basic) {
        packet_dropped(PacketDropReason::Parse_Basic_Header);
    } else if (basic->version.raw() != m_mib.itsGnProtocolVersion) {
        packet_dropped(PacketDropReason::ITS_Protocol_Version);
    } else {
        DataIndication& indication = ctx.service_primitive();
        indication.remaining_packet_lifetime = basic->lifetime;
        indication.remaining_hop_limit = basic->hop_limit;

        if (basic->next_header == NextHeaderBasic::Secured) {
            indication.security_report = security::DecapReport::Incompatible_Protocol;
            indicate_secured(ctx, *basic);
        } else if (basic->next_header == NextHeaderBasic::Common) {
            if (!m_mib.itsGnSecurity || SecurityDecapHandling::Non_Strict == m_mib.itsGnSnDecapResultHandling) {
                indication.security_report = security::DecapReport::Unsigned_Message,
                indicate_common(ctx, *basic);
            } else {
                packet_dropped(PacketDropReason::Decap_Unsuccessful_Strict);
            }
        }
    }
}

void Router::indicate_common(IndicationContext& ctx, const BasicHeader& basic)
{
    const CommonHeader* common = ctx.parse_common();
    if (!common) {
        packet_dropped(PacketDropReason::Parse_Common_Header);
    } else if (common->maximum_hop_limit < basic.hop_limit) {
        // step 1) check the MHL field
        packet_dropped(PacketDropReason::Hop_Limit);
    } else {
        DataIndication& indication = ctx.service_primitive();
        indication.traffic_class = common->traffic_class;
        switch (common->next_header)
        {
            case NextHeaderCommon::BTP_A:
                indication.upper_protocol = UpperProtocol::BTP_A;
                break;
            case NextHeaderCommon::BTP_B:
                indication.upper_protocol = UpperProtocol::BTP_B;
                break;
            case NextHeaderCommon::IPv6:
                indication.upper_protocol = UpperProtocol::IPv6;
                break;
            default:
                indication.upper_protocol = UpperProtocol::Unknown;
                break;
        }

        // clean up location table at packet indication (nothing else creates entries)
        m_location_table.drop_expired();

        // step 2) process BC forwarding packet buffer
        flush_broadcast_forwarding_buffer();

        // step 3) execute steps depending on extended header type
        indicate_extended(ctx, *common);

        // NOTE: There is a good chance that processing of extended header updated the location table.
        // Thus, a routing decision may be possible for some packets in the BC packet forwarding buffer now, e.g.
        // those buffered due to greedy forwarding's SCF behaviour. However, flushing twice would induce additional
        // processing overhead. For now, we stick quite conservatively to the standard.
    }
}

void Router::indicate_secured(IndicationContextBasic& ctx, const BasicHeader& basic)
{
    struct secured_payload_visitor : public boost::static_visitor<>
    {
        secured_payload_visitor(Router& router, IndicationContextBasic& ctx, const BasicHeader& basic) :
            m_router(router), m_context(ctx), m_basic(basic)
        {
        }

        void operator()(ChunkPacket& packet)
        {
            IndicationContextSecuredCast ctx(m_context, packet);
            m_router.indicate_common(ctx, m_basic);
        }

        void operator()(CohesivePacket& packet)
        {
            IndicationContextSecuredDeserialize ctx(m_context, packet);
            m_router.indicate_common(ctx, m_basic);
        }

        Router& m_router;
        IndicationContextBasic& m_context;
        const BasicHeader& m_basic;
    };

    auto secured_message = ctx.parse_secured();
    if (!secured_message) {
        packet_dropped(PacketDropReason::Parse_Secured_Header);
    } else if (m_security_entity) {
        // Decap packet
        using namespace vanetza::security;
        DecapConfirm decap_confirm = m_security_entity->decapsulate_packet(DecapRequest(*secured_message));
        ctx.service_primitive().security_report = decap_confirm.report;
        ctx.service_primitive().its_aid = decap_confirm.its_aid;
        ctx.service_primitive().permissions = decap_confirm.permissions;
        secured_payload_visitor visitor(*this, ctx, basic);

        // check whether the received packet is valid
        if (DecapReport::Success == decap_confirm.report) {
            boost::apply_visitor(visitor, decap_confirm.plaintext_payload);
        } else if (SecurityDecapHandling::Non_Strict == m_mib.itsGnSnDecapResultHandling) {
            // according to ETSI EN 302 636-4-1 v1.2.1 section 9.3.3 Note 2
            // handle the packet anyway, when itsGnDecapResultHandling is set to NON-Strict (1)
            switch (decap_confirm.report) {
                case DecapReport::False_Signature:
                case DecapReport::Invalid_Certificate:
                case DecapReport::Revoked_Certificate:
                case DecapReport::Inconsistant_Chain:
                case DecapReport::Invalid_Timestamp:
                case DecapReport::Invalid_Mobility_Data:
                case DecapReport::Unsigned_Message:
                case DecapReport::Signer_Certificate_Not_Found:
                case DecapReport::Unsupported_Signer_Identifier_Type:
                case DecapReport::Unencrypted_Message:
                    // ok, continue
                    boost::apply_visitor(visitor, decap_confirm.plaintext_payload);
                    break;
                case DecapReport::Duplicate_Message:
                case DecapReport::Incompatible_Protocol:
                case DecapReport::Decryption_Error:
                default:
                    packet_dropped(PacketDropReason::Decap_Unsuccessful_Non_Strict);
                    break;
            }
        } else {
            // discard packet
            packet_dropped(PacketDropReason::Decap_Unsuccessful_Strict);
        }
    } else {
        packet_dropped(PacketDropReason::Security_Entity_Missing);
    }
}

void Router::indicate_extended(IndicationContext& ctx, const CommonHeader& common)
{
    struct extended_header_visitor : public boost::static_visitor<bool>
    {
        extended_header_visitor(Router& router, IndicationContext& ctx, const UpPacket& packet) :
            m_router(router), m_context(ctx), m_packet(packet)
        {
        }

        bool operator()(const ShbHeader& shb)
        {
            DataIndication& indication = m_context.service_primitive();
            indication.transport_type = TransportType::SHB;
            indication.source_position = static_cast<ShortPositionVector>(shb.source_position);

            auto& pdu = m_context.pdu();
            ExtendedPduConstRefs<ShbHeader> shb_pdu(pdu.basic(), pdu.common(), shb, pdu.secured());

            return m_router.process_extended(shb_pdu, m_packet, m_context.link_layer());
        }

        bool operator()(const GeoBroadcastHeader& gbc)
        {
            DataIndication& indication = m_context.service_primitive();
            indication.transport_type = TransportType::GBC;
            indication.source_position = static_cast<ShortPositionVector>(gbc.source_position);
            indication.destination = gbc.destination(m_context.pdu().common().header_type);

            auto& pdu = m_context.pdu();
            ExtendedPduConstRefs<GeoBroadcastHeader> gbc_pdu(pdu.basic(), pdu.common(), gbc, pdu.secured());
            return m_router.process_extended(gbc_pdu, m_packet, m_context.link_layer());
        }

        bool operator()(const BeaconHeader& beacon)
        {
            auto& pdu = m_context.pdu();
            ExtendedPduConstRefs<BeaconHeader> beacon_pdu(pdu.basic(), pdu.common(), beacon, pdu.secured());
            return m_router.process_extended(beacon_pdu, m_packet, m_context.link_layer());
        }

        Router& m_router;
        IndicationContext& m_context;
        const UpPacket& m_packet;
    };

    auto extended = ctx.parse_extended(common.header_type);
    UpPacketPtr packet = ctx.finish();
    assert(packet);

    if (!extended) {
        packet_dropped(PacketDropReason::Parse_Extended_Header);
    } else if (common.payload != size(*packet, OsiLayer::Transport, max_osi_layer())) {
        packet_dropped(PacketDropReason::Payload_Size);
    } else {
        extended_header_visitor visitor(*this, ctx, *packet);
        if (boost::apply_visitor(visitor, *extended)) {
            pass_up(ctx.service_primitive(), std::move(packet));
        }
    }
}

NextHop Router::forwarding_algorithm_selection(PendingPacketForwarding&& packet, const LinkLayer* ll)
{
    NextHop nh;
    const Area& destination = packet.pdu().extended().destination(packet.pdu().common().header_type);
    if (inside_or_at_border(destination, m_local_position_vector.position())) {
        switch (m_mib.itsGnAreaForwardingAlgorithm) {
            case BroadcastForwarding::Unspecified:
                // do simple forwarding
            case BroadcastForwarding::SIMPLE:
                // Simple always returns link-layer broadcast address (see Annex F.2)
                nh.transmit(std::move(packet), cBroadcastMacAddress);
                break;
            case BroadcastForwarding::CBF:
                nh = area_contention_based_forwarding(std::move(packet), ll ? &ll->sender : nullptr);
                break;
            case BroadcastForwarding::Advanced:
                nh = area_advanced_forwarding(std::move(packet), ll);
                break;
            default:
                throw std::runtime_error("unhandled area forwarding algorithm");
                break;
        };
    } else {
        // packets received from senders located inside destination area are not meant for non-area forwarding
        const LongPositionVector* pv_se = ll ? m_location_table.get_position(ll->sender) : nullptr;
        if (pv_se && pv_se->position_accuracy_indicator && inside_or_at_border(destination, pv_se->position())) {
            nh.discard();
            forwarding_stopped(ForwardingStopReason::Outside_Destination_Area);
        } else {
            switch (m_mib.itsGnNonAreaForwardingAlgorithm) {
                case UnicastForwarding::Unspecified:
                    // fall through to greedy forwarding
                case UnicastForwarding::Greedy:
                    nh = greedy_forwarding(std::move(packet));
                    break;
                case UnicastForwarding::CBF:
                    nh = non_area_contention_based_forwarding(std::move(packet), ll ? &ll->sender : nullptr);
                    break;
                default:
                    throw std::runtime_error("unhandled non-area forwarding algorithm");
                    break;
            };
        }
    }

    return nh;
}

void Router::execute_media_procedures(CommunicationProfile com_profile)
{
    switch (com_profile) {
        case CommunicationProfile::ITS_G5:
            execute_itsg5_procedures();
            break;
        case CommunicationProfile::Unspecified:
            // do nothing
            break;
        default:
            throw std::runtime_error("Unhandled communication profile");
            break;
    }
}

void Router::execute_itsg5_procedures()
{
    // TODO: implement ITS_G5A procedures, see EN 302636-4-2
}

void Router::pass_down(const dcc::DataRequest& request, PduPtr pdu, DownPacketPtr payload)
{
    assert(pdu);
    assert(payload);
    if (pdu->secured()) {
        if (pdu->basic().next_header != NextHeaderBasic::Secured) {
            throw std::runtime_error("PDU with secured message but Secured not set in basic header");
        }
        if (payload->size(OsiLayer::Transport, max_osi_layer()) > 0) {
            throw std::runtime_error("PDU with secured message and illegal upper layer payload");
        }
    } else {
        if (pdu->basic().next_header == NextHeaderBasic::Secured) {
            throw std::runtime_error("PDU without secured message but Secured set in basic header");
        }
    }

    (*payload)[OsiLayer::Network] = ByteBufferConvertible(std::move(pdu));
    assert(m_request_interface);
    m_request_interface->request(request, std::move(payload));
}

void Router::pass_down(const MacAddress& addr, PduPtr pdu, DownPacketPtr payload)
{
    assert(pdu);

    dcc::DataRequest request;
    request.destination = addr;
    request.source = m_local_position_vector.gn_addr.mid();
    request.dcc_profile = map_tc_onto_profile(pdu->common().traffic_class);
    request.ether_type = geonet::ether_type;
    request.lifetime = std::chrono::seconds(pdu->basic().lifetime.decode() / units::si::seconds);

    pass_down(request, std::move(pdu), std::move(payload));
}

void Router::pass_up(const DataIndication& ind, UpPacketPtr packet)
{
    TransportInterface* transport = m_transport_ifcs[ind.upper_protocol];
    if (transport != nullptr) {
        transport->indicate(ind, std::move(packet));
    }
}

void Router::on_beacon_timer_expired()
{
    if (m_mib.vanetzaDisableBeaconing) {
        // bail out immediately if beaconing has been disabled
        return;
    }

    // Beacons originate in GeoNet layer, therefore no upper layer payload
    DownPacketPtr payload { new DownPacket() };
    auto pdu = create_beacon_pdu();

    if (m_mib.itsGnSecurity) {
        pdu->basic().next_header = NextHeaderBasic::Secured;
        payload = encap_packet(aid::GN_MGMT, *pdu, std::move(payload));
    } else {
        pdu->basic().next_header = NextHeaderBasic::Common;
    }

    execute_media_procedures(m_mib.itsGnIfType);
    pass_down(cBroadcastMacAddress, std::move(pdu), std::move(payload));
    reset_beacon_timer();
}

void Router::reset_beacon_timer()
{
    using duration_t = decltype(m_mib.itsGnBeaconServiceRetransmitTimer);
    using real_t = duration_t::value_type;
    static_assert(std::is_floating_point<real_t>::value, "floating point type expected");

    std::uniform_real_distribution<real_t> dist_jitter(0.0, 1.0);
    const auto jitter = dist_jitter(m_random_gen);
    const duration_t next_beacon = m_mib.itsGnBeaconServiceRetransmitTimer +
        jitter * m_mib.itsGnBeaconServiceMaxJitter;
    reset_beacon_timer(clock_cast(next_beacon));
}

void Router::reset_beacon_timer(Clock::duration next_beacon)
{
    m_runtime.cancel(this);
    m_runtime.schedule(next_beacon, [this](Clock::time_point) {
        on_beacon_timer_expired();
    }, this);
}

void Router::dispatch_repetition(const DataRequestVariant& request, std::unique_ptr<DownPacket> payload)
{
    RepetitionDispatcher dispatcher(*this, std::move(payload));
    boost::apply_visitor(dispatcher, request);
}

NextHop Router::greedy_forwarding(PendingPacketForwarding&& packet)
{
    NextHop nh;
    GeodeticPosition dest = packet.pdu().extended().position();
    const units::Length own = distance(dest, m_local_position_vector.position());
    units::Length mfr_dist = own;

    MacAddress mfr_addr;
    for (const LocationTableEntry& neighbour : m_location_table.neighbours()) {
        if (neighbour.has_position_vector()) {
            const units::Length dist = distance(dest, neighbour.get_position_vector().position());
            if (dist < mfr_dist) {
                mfr_addr = neighbour.link_layer_address();
                mfr_dist = dist;
            }
        }
    }

    if (mfr_dist < own) {
        nh.transmit(std::move(packet), mfr_addr);
    } else {
        const bool scf = packet.pdu().common().traffic_class.store_carry_forward();
        if (scf) {
            std::function<void(PendingPacketForwarding&&)> greedy_fwd = [this](PendingPacketForwarding&& packet) {
                NextHop nh = greedy_forwarding(std::move(packet));
                std::move(nh).process();
            };
            PendingPacket<GbcPdu> greedy_packet(std::move(packet), greedy_fwd);
            PacketBuffer::data_ptr data { new PendingPacketBufferData<GbcPdu>(std::move(greedy_packet)) };
            m_bc_forward_buffer.push(std::move(data), m_runtime.now());
            nh.buffer();
        } else {
            nh.transmit(std::move(packet), cBroadcastMacAddress);
        }
    }

    return nh;
}

NextHop Router::non_area_contention_based_forwarding(PendingPacketForwarding&& packet, const MacAddress* sender)
{
    NextHop nh;
    const GeoBroadcastHeader& gbc = packet.pdu().extended();
    const auto cbf_id = identifier(gbc.source_position.gn_addr, gbc.sequence_number);

    // immediately broadcast packet if it is originating from local router
    if (!sender) {
        nh.transmit(std::move(packet), cBroadcastMacAddress);
    } else if (m_cbf_buffer.remove(cbf_id)) {
        // packet has been in CBF buffer (and is now dropped)
        nh.discard();
    } else {
        const HeaderType ht = packet.pdu().common().header_type;
        const Area destination = gbc.destination(ht);
        const auto& epv = m_local_position_vector;
        const LongPositionVector* pv_se = sender ? m_location_table.get_position(*sender) : nullptr;
        // condition "PV_SE = EPV" is omitted here
        if (pv_se && pv_se->position_accuracy_indicator) {
            const auto& pv_p = destination.position;
            const units::Length dist_sender = distance(pv_p, pv_se->position());
            const units::Length dist_local = distance(pv_p, epv.position());
            if (dist_sender > dist_local) {
                CbfPacket cbf { std::move(packet), *sender };
                const auto progress = dist_sender - dist_local;
                m_cbf_buffer.add(std::move(cbf), clock_cast(timeout_cbf(progress)));
                nh.buffer();

            } else {
                nh.discard();
            }
        } else {
            CbfPacket cbf { std::move(packet), *sender };
            const auto to_cbf_max = m_mib.itsGnCbfMaxTime;
            m_cbf_buffer.add(std::move(cbf), clock_cast(to_cbf_max));
            nh.buffer();
        }
    }
    return nh;
}

NextHop Router::area_contention_based_forwarding(PendingPacketForwarding&& packet, const MacAddress* sender)
{
    NextHop nh;
    const GeoBroadcastHeader& gbc = packet.pdu().extended();
    const auto cbf_id = identifier(gbc.source_position.gn_addr, gbc.sequence_number);

    if (!sender) {
        nh.transmit(std::move(packet), cBroadcastMacAddress);
    } else if (m_cbf_buffer.remove(cbf_id) || m_cbf_buffer.counter(cbf_id) >= m_mib.vanetzaCbfMaxCounter) {
        nh.discard();
    } else {
        const units::Duration timeout = timeout_cbf(*sender);
        m_cbf_buffer.add(CbfPacket { std::move(packet), *sender }, clock_cast(timeout));
        nh.buffer();
    }
    return nh;
}

units::Duration Router::timeout_cbf(units::Length prog) const
{
    // TODO: media-dependent maximum communication range
    const auto dist_max = m_mib.itsGnDefaultMaxCommunicationRange;
    const auto to_cbf_min = m_mib.itsGnCbfMinTime;
    const auto to_cbf_max = m_mib.itsGnCbfMaxTime;

    if (prog > dist_max) {
        return to_cbf_min;
    } else if (prog > 0.0 * units::si::meter) {
        return to_cbf_max + (to_cbf_min - to_cbf_max) / dist_max * prog;
    } else {
        return to_cbf_max;
    }
}

units::Duration Router::timeout_cbf(const MacAddress& sender) const
{
    // use maximum CBF time as fallback value
    units::Duration timeout = m_mib.itsGnCbfMaxTime;
    const LongPositionVector* pv_se = m_location_table.get_position(sender);
    if (pv_se && pv_se->position_accuracy_indicator) {
        units::Length dist = distance(pv_se->position(), m_local_position_vector.position());
        timeout = timeout_cbf(dist);
    }
    return timeout;
}

NextHop Router::area_advanced_forwarding(PendingPacketForwarding&& packet, const LinkLayer* ll)
{
    NextHop nh;
    if (!ll) {
        // packet is from local node (source operations)
        nh.transmit(std::move(packet), cBroadcastMacAddress);
    } else {
        const GeoBroadcastHeader& gbc = packet.pdu().extended();
        const HeaderType ht = packet.pdu().common().header_type;
        const Area destination_area = gbc.destination(ht);
        const std::size_t max_counter = m_mib.vanetzaCbfMaxCounter;
        const auto cbf_id = identifier(gbc.source_position.gn_addr, gbc.sequence_number);
        const CbfPacket* cbf_packet = m_cbf_buffer.find(cbf_id);

        if (cbf_packet) {
            // packet is already buffered
            if (m_cbf_buffer.counter(cbf_id) >= max_counter) {
                // stop contending if counter is exceeded
                m_cbf_buffer.remove(cbf_id);
                nh.discard();
            } else if (!outside_sectorial_contention_area(cbf_packet->sender(), ll->sender)) {
                // within sectorial area
                // - sender S = sender of buffered packet
                // - forwarder F = sender of now received packet
                m_cbf_buffer.remove(cbf_id);
                nh.discard();
            } else {
                m_cbf_buffer.update(cbf_id, clock_cast(timeout_cbf(ll->sender)));
                nh.buffer();
            }
        } else {
            if (ll->destination == m_local_position_vector.gn_addr.mid()) {
                // continue with greedy forwarding
                nh = greedy_forwarding(packet.duplicate());
                // optimization: avoid "double broadcast"
                if (nh.valid() && nh.mac() == cBroadcastMacAddress) {
                    // contending without further broadcasting
                    static const PendingPacketForwarding::Function noop_fn =
                        [](PendingPacketForwarding::Packet&&, const MacAddress&) {};
                    PendingPacketForwarding noop { std::move(packet).packet(), noop_fn };
                    CbfPacket cbf { std::move(noop), ll->sender };
                    m_cbf_buffer.add(std::move(cbf), clock_cast(m_mib.itsGnCbfMaxTime));
                } else {
                    // no immediate broadcast by greedy forwarding
                    CbfPacket cbf { std::move(packet), ll->sender };
                    m_cbf_buffer.add(std::move(cbf), clock_cast(m_mib.itsGnCbfMaxTime));
                }
                // next hop (nh) conveys result of greedy forwarding algorithm
            } else {
                // classical CBF (timeout_cbf_gbc looks up sender's position)
                nh.buffer();
                CbfPacket cbf { std::move(packet), ll->sender };
                m_cbf_buffer.add(std::move(cbf), clock_cast(timeout_cbf(ll->sender)));
            }
        }
    }

    return nh;
}

bool Router::outside_sectorial_contention_area(const MacAddress& sender, const MacAddress& forwarder) const
{
    using units::si::meter;
    auto position_sender = m_location_table.get_position(sender);
    auto position_forwarder = m_location_table.get_position(forwarder);

    // Assumption: if any position is missing, then sectorial area becomes infinite small
    // As a result of this assumption, everything lays outside then
    if (position_sender && position_forwarder) {
        auto dist_r = distance(position_sender->position(), m_local_position_vector.position());
        auto dist_f = distance(position_forwarder->position(), position_sender->position());
        const auto dist_max = m_mib.itsGnDefaultMaxCommunicationRange;

        auto dist_rf = distance(position_forwarder->position(), m_local_position_vector.position());
        auto angle_fsr = 0.0 * units::si::radians;
        if (dist_r > 0.0 * meter && dist_f > 0.0 * meter) {
            auto cos_fsr = (dist_rf * dist_rf - dist_r * dist_r - dist_f * dist_f) /
                (-2.0 * dist_r * dist_f);
            angle_fsr = boost::units::acos(cos_fsr);
        }
        const auto angle_th = m_mib.itsGnBroadcastCBFDefSectorAngle;

        return !(dist_r < dist_f && dist_f < dist_max && angle_fsr < angle_th);
    } else {
        return true;
    }
}

bool Router::process_extended(const ExtendedPduConstRefs<ShbHeader>& pdu, const UpPacket& packet, const LinkLayer& ll)
{
    const ShbHeader& shb = pdu.extended();
    const Address& source_addr = shb.source_position.gn_addr;

    // step 3: execute duplicate address detection (see 9.2.1.5)
    detect_duplicate_address(source_addr, ll.sender);

    // step 4: update location table with SO.PV (see C.2)
    auto& source_entry = m_location_table.update(shb.source_position);
    // NOTE: position vector (PV) may still be missing in location table when received PV has been invalid
    assert(source_entry.has_position_vector() || !is_valid(shb.source_position));

    // step 5: update SO.PDR in location table (see B.2)
    const std::size_t packet_size = size(packet, OsiLayer::Network, OsiLayer::Application);
    source_entry.update_pdr(packet_size, m_mib.itsGnMaxPacketDataRateEmaBeta);

    // step 6: set SO LocTE to neighbour
    source_entry.set_neighbour(true, m_mib.vanetzaNeighbourFlagExpiry);

    // media-dependent update of LocTEX_G5 (see TS 102 636-4-2 V1.1.1, section 6.1.2)
    if (m_mib.itsGnIfType == InterfaceType::ITS_G5) {
        boost::optional<DccMcoField> dcc_mco = get_dcc_mco(shb.dcc);
        if (dcc_mco) {
            auto& loctex = source_entry.extensions.get<LocTEX_G5>();
            loctex.local_update = m_runtime.now();
            loctex.source_update = shb.source_position.timestamp;
            loctex.dcc_mco = *dcc_mco;
        }
    }

    // step 7: pass up SHB packet anyways
    return true;
}

bool Router::process_extended(const ExtendedPduConstRefs<BeaconHeader>& pdu, const UpPacket& packet, const LinkLayer& ll)
{
    const BeaconHeader& beacon = pdu.extended();
    const Address& source_addr = beacon.source_position.gn_addr;

    // step 3: execute duplicate address detection (see 9.2.1.5)
    detect_duplicate_address(source_addr, ll.sender);

    // step 4: update location table with SO.PV (see C.2)
    auto& source_entry = m_location_table.update(beacon.source_position);

    // step 5: update SO.PDR in location table (see B.2)
    const std::size_t packet_size = size(packet, OsiLayer::Network, OsiLayer::Application);
    source_entry.update_pdr(packet_size, m_mib.itsGnMaxPacketDataRateEmaBeta);

    // step 6: set SO LocTE to neighbour
    source_entry.set_neighbour(true, m_mib.vanetzaNeighbourFlagExpiry);

    // step 7: never pass up Beacons
    return false;
}

bool Router::process_extended(const ExtendedPduConstRefs<GeoBroadcastHeader>& pdu, const UpPacket& packet, const LinkLayer& ll)
{
    // GBC forwarder and receiver operations (section 9.3.11.3 in EN 302 636-4-1 V1.2.1)
    const GeoBroadcastHeader& gbc = pdu.extended();
    const Address& source_addr = gbc.source_position.gn_addr;
    const Area dest_area = gbc.destination(pdu.common().header_type);

    // remember if LocTE(SO) exists (5) before duplicate packet detection might (3) silently create an entry
    const bool locte_exists = m_location_table.has_entry(source_addr);

    // step 3: determine position relative to destination area
    const bool within_destination = inside_or_at_border(dest_area, m_local_position_vector.position());
    // step 3a
    bool duplicate_packet = false;
    if (!within_destination) {
        if (m_mib.itsGnNonAreaForwardingAlgorithm == UnicastForwarding::Unspecified ||
            m_mib.itsGnNonAreaForwardingAlgorithm == UnicastForwarding::Greedy) {
            duplicate_packet = detect_duplicate_packet(source_addr, gbc.sequence_number);
        }
    // step 3b
    } else {
        if (m_mib.itsGnAreaForwardingAlgorithm == BroadcastForwarding::Unspecified ||
            m_mib.itsGnAreaForwardingAlgorithm == BroadcastForwarding::SIMPLE) {
            duplicate_packet = detect_duplicate_packet(source_addr, gbc.sequence_number);
        }
    }
    // step 3a & 3b
    if (duplicate_packet) {
        // omit execution of further steps
        return false;
    }

    // step 4: execute DAD
    if (m_mib.vanetzaMultiHopDuplicateAddressDetection) {
        // Be careful, DAD is broken with address mode AUTO for multi-hop communication
        detect_duplicate_address(source_addr, ll.sender);
    }

    // step 5 & step 6 (make sure IS_NEIGHBOUR is false for new location table entry)
    const std::size_t packet_size = size(packet, OsiLayer::Network, OsiLayer::Application);
    auto& source_entry = m_location_table.update(gbc.source_position);
    source_entry.update_pdr(packet_size, m_mib.itsGnMaxPacketDataRateEmaBeta);
    if (!locte_exists) {
        // step 5b only
        source_entry.set_neighbour(false);
    }

    // step 7: pass packet to upper layer if router is within destination area, return value

    // step 8a: TODO: flush SO LS packet buffer if LS_pending, reset LS_pending
    // step 8b: flush UC forwarding packet buffer
    flush_unicast_forwarding_buffer(source_addr);

    // step 9: discard packet (no forwarding) if hop limit is reached
    if (pdu.basic().hop_limit <= 1) {
        forwarding_stopped(ForwardingStopReason::Hop_Limit);
        return within_destination; // discard packet (step 9a)
    } else if (m_mib.itsGnMaxPacketDataRate < std::numeric_limits<decltype(m_mib.itsGnMaxPacketDataRate)>::max()) {
        // do packet data rate checks (annex B.2) if set maximum rate is not "infinity" (i.e. max unsigned value)
        if (source_entry.get_pdr() > m_mib.itsGnMaxPacketDataRate * 1000.0) {
            forwarding_stopped(ForwardingStopReason::Source_PDR);
            return within_destination; // omit forwarding, source exceeds PDR limit
        } else if (const auto* sender_entry = m_location_table.get_entry(ll.sender)) {
            if (sender_entry->get_pdr() > m_mib.itsGnMaxPacketDataRate * 1000.0) {
                forwarding_stopped(ForwardingStopReason::Sender_PDR);
                return within_destination; // omit forwarding, sender exceeds PDR limit
            }
        }
    }

    // step 9b: update hop limit in basic header
    auto fwd_dup = create_forwarding_duplicate(pdu, packet);
    GbcPdu& fwd_pdu = get_pdu(fwd_dup);
    --fwd_pdu.basic().hop_limit;
    assert(fwd_pdu.basic().hop_limit + 1 == pdu.basic().hop_limit);

    using Packet = PendingPacketGbc::Packet;

    auto transmit = [this](Packet&& packet, const MacAddress& mac) {
        // step 13: execute media-dependent procedures
        execute_media_procedures(m_mib.itsGnIfType);

        // step 14: pass down to link-layer
        std::unique_ptr<Pdu> pdu;
        std::unique_ptr<DownPacket> payload;
        std::tie(pdu, payload) = std::move(packet);

        dcc::DataRequest request;
        request.destination = mac;
        request.source = m_local_position_vector.gn_addr.mid();
        request.dcc_profile = dcc::Profile::DP3;
        request.ether_type = geonet::ether_type;
        request.lifetime = std::chrono::seconds(pdu->basic().lifetime.decode() / units::si::seconds);

        pass_down(request, std::move(pdu), std::move(payload));
    };

    auto forwarding = [this, transmit, ll](Packet&& packet) {
        // step 11: execute forwarding algorithm
        PendingPacket<GbcPdu, const MacAddress&> tmp(std::move(packet), transmit);
        NextHop forwarding = forwarding_algorithm_selection(std::move(tmp), &ll);

        // step 12: transmit immediately if not buffered or discarded
        std::move(forwarding).process();
    };

    PendingPacketGbc fwd_packet(std::move(fwd_dup), forwarding);

    // step 10: store & carry forwarding procedure
    const bool scf = pdu.common().traffic_class.store_carry_forward();
    if (scf && !m_location_table.has_neighbours()) {
        PacketBuffer::data_ptr data { new PendingPacketBufferData<GbcPdu>(std::move(fwd_packet)) };
        m_bc_forward_buffer.push(std::move(data), m_runtime.now());
    } else {
        fwd_packet.process();
    }

    if (m_mib.vanetzaGbcMemoryCapacity == 0) {
        // return pass up decision (step 7)
        return within_destination;
    } else if (within_destination) {
        // modified pass up: suppress passing up duplicate GBC packets
        return !m_gbc_memory.remember(std::make_tuple(gbc.source_position.gn_addr, gbc.sequence_number));
    } else {
        return false;
    }
}

void Router::flush_broadcast_forwarding_buffer()
{
    m_bc_forward_buffer.flush(m_runtime.now());
}

void Router::flush_unicast_forwarding_buffer(const Address& source)
{
    // TODO flush only packets for given source address (required for GUC packets)
    m_uc_forward_buffer.flush(m_runtime.now());
}

void Router::detect_duplicate_address(const Address& source, const MacAddress& sender)
{
    // EN 302 636-4-1 V1.3.1 10.2.1.5: DAD is only applied for Auto
    if (m_mib.itsGnLocalAddrConfMethod == AddrConfMethod::Auto) {
        const Address& local = m_local_position_vector.gn_addr;
        if (source == local || sender == local.mid()) {
            MacAddress random_mac_addr;
            std::uniform_int_distribution<unsigned> octet_dist;
            for (auto& octet : random_mac_addr.octets) {
                octet = octet_dist(m_random_gen);
            }

            m_local_position_vector.gn_addr.mid(random_mac_addr);
        }
    }
}

bool Router::detect_duplicate_packet(const Address& addr_so, SequenceNumber sn)
{
    bool is_duplicate = false;
    ObjectContainer& so_ext = m_location_table.get_or_create_entry(addr_so).extensions;
    DuplicatePacketList* dpl = so_ext.find<DuplicatePacketList>();
    if (dpl) {
        is_duplicate = dpl->check(sn);
    } else {
        std::unique_ptr<DuplicatePacketList> dpl { new DuplicatePacketList(m_mib.itsGnDPLLength) };
        is_duplicate = dpl->check(sn);
        so_ext.insert(std::move(dpl));
    }
    return is_duplicate;
}

std::unique_ptr<ShbPdu> Router::create_shb_pdu(const ShbDataRequest& request)
{
    std::unique_ptr<ShbPdu> pdu { new ShbPdu(request, m_mib) };
    pdu->basic().hop_limit = 1;
    pdu->common().header_type = HeaderType::TSB_Single_Hop;
    pdu->common().maximum_hop_limit = 1;
    pdu->extended().source_position = m_local_position_vector;
    pdu->extended().dcc = m_dcc_field_generator->generate_dcc_field();
    return pdu;
}

std::unique_ptr<BeaconPdu> Router::create_beacon_pdu()
{
    std::unique_ptr<BeaconPdu> pdu { new BeaconPdu(m_mib) };
    pdu->basic().hop_limit = 1;
    pdu->common().next_header = NextHeaderCommon::Any;
    pdu->common().header_type = HeaderType::Beacon;
    pdu->common().maximum_hop_limit = 1;
    // TODO: Beacons are sent with itsGnDefaultTrafficClass (DP0) at the moment, but DP3 may be more appropriate?
    pdu->extended().source_position = m_local_position_vector;
    return pdu;
}

std::unique_ptr<GbcPdu> Router::create_gbc_pdu(const GbcDataRequest& request)
{
    std::unique_ptr<GbcPdu> pdu { new GbcPdu(request, m_mib) };
    pdu->common().header_type = gbc_header_type(request.destination);
    pdu->extended().sequence_number = m_local_sequence_number++;
    pdu->extended().source_position = m_local_position_vector;
    pdu->extended().destination(request.destination);
    return pdu;
}

Router::DownPacketPtr Router::encap_packet(ItsAid its_aid, Pdu& pdu, DownPacketPtr packet)
{
    security::EncapRequest encap_request;

    DownPacket sec_payload;
    sec_payload[OsiLayer::Network] = SecuredPdu(pdu);
    sec_payload.merge(*packet, OsiLayer::Transport, max_osi_layer());
    encap_request.plaintext_payload = std::move(sec_payload);
    encap_request.its_aid = its_aid;

    if (m_security_entity) {
        security::EncapConfirm confirm = m_security_entity->encapsulate_packet(std::move(encap_request));
        pdu.secured(std::move(confirm.sec_packet));
    } else {
        throw std::runtime_error("security entity unavailable");
    }

    assert(size(*packet, OsiLayer::Transport, max_osi_layer()) == 0);
    assert(pdu.basic().next_header == NextHeaderBasic::Secured);
    return packet;
}

std::string stringify(Router::PacketDropReason pdr)
{
    std::string reason_string;

    // TODO replace this by something more elegant, e.g. https://github.com/aantron/better-enums
    switch (pdr) {
        case Router::PacketDropReason::Parse_Basic_Header:
            reason_string = "Parse_Basic_Header";
            break;
        case Router::PacketDropReason::Parse_Common_Header:
            reason_string = "Parse_Common_Header";
            break;
        case Router::PacketDropReason::Parse_Secured_Header:
            reason_string = "Parse_Secured_Header";
            break;
        case Router::PacketDropReason::Parse_Extended_Header:
            reason_string = "Parse_Extended_Header";
            break;
        case Router::PacketDropReason::ITS_Protocol_Version:
            reason_string = "ITS_Protocol_Version";
            break;
        case Router::PacketDropReason::Decap_Unsuccessful_Non_Strict:
            reason_string = "Decap_Unsuccessful_Non_Strict";
            break;
        case Router::PacketDropReason::Decap_Unsuccessful_Strict:
            reason_string = "Decap_Unsuccessful_Strict";
            break;
        case Router::PacketDropReason::Hop_Limit:
            reason_string = "Hop_Limit";
            break;
        case Router::PacketDropReason::Payload_Size:
            reason_string = "Payload_Size";
            break;
        case Router::PacketDropReason::Security_Entity_Missing:
            reason_string = "Security_Entity_Missing";
            break;
        default:
            reason_string = "UNKNOWN";
            break;
    }

    return reason_string;
}

} // namespace geonet
} // namespace vanetza
