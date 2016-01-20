#include "router.hpp"
#include "data_confirm.hpp"
#include "data_indication.hpp"
#include "data_request.hpp"
#include "next_hop.hpp"
#include "parsed_pdu.hpp"
#include "pdu_conversion.hpp"
#include "repetition_dispatcher.hpp"
#include "transport_interface.hpp"
#include <vanetza/dcc/access_control.hpp>
#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/net/mac_address.hpp>
#include <vanetza/units/frequency.hpp>
#include <vanetza/units/length.hpp>
#include <vanetza/units/time.hpp>
#include <boost/units/cmath.hpp>
#include <functional>
#include <stdexcept>

namespace vanetza
{
namespace geonet
{

template<typename PDU>
class PacketBufferData : public packet_buffer::Data
{
public:
    PacketBufferData(Router& router, std::unique_ptr<PDU> pdu, std::unique_ptr<DownPacket> payload) :
        m_router(router), m_pdu(std::move(pdu)), m_payload(std::move(payload))
    {
    }

    std::size_t length() const override
    {
        assert(m_pdu && m_payload);
        return m_pdu->length() +
                m_payload->size(OsiLayer::Transport, max_osi_layer());
    }

    Lifetime& lifetime() override
    {
        assert(m_pdu);
        return m_pdu->basic().lifetime;
    }

protected:
    Router& m_router;
    std::unique_ptr<PDU> m_pdu;
    std::unique_ptr<DownPacket> m_payload;
};

class BroadcastBufferData : public PacketBufferData<Pdu>
{
public:
    using PacketBufferData<Pdu>::PacketBufferData;

    NextHop flush() override
    {
        NextHop next_hop;
        next_hop.mac(cBroadcastMacAddress);
        next_hop.data(std::move(m_pdu), std::move(m_payload));
        next_hop.state(NextHop::State::VALID);
        return next_hop;
    }
};

const uint16be_t ether_type = host_cast<uint16_t>(0x8947);

Router::Router(const MIB& mib, dcc::RequestInterface& ifc) :
    m_mib(mib),
    m_request_interface(ifc),
    m_location_table(mib),
    m_bc_forward_buffer(mib.itsGnBcForwardingPacketBufferSize * 1024),
    m_uc_forward_buffer(mib.itsGnUcForwardingPacketBufferSize * 1024),
    m_cbf_buffer(mib.itsGnCbfPacketBufferSize * 1024)
{
    using namespace std::placeholders;
    m_repeater.set_callback(std::bind(&Router::dispatch_repetition, this, _1, _2));
}

Router::~Router()
{
}

Clock::duration Router::next_update() const
{
    const Timestamp::duration_type upper_bound { 1.0 / m_mib.itsGnMinimumUpdateFrequencyLPV };
    Timestamp next = m_time_now + upper_bound;
    const auto cbf_timer = m_cbf_buffer.next_timer_expiry();
    if (cbf_timer && *cbf_timer < next) {
        next = *cbf_timer;
    }
    const auto repeater_timer = m_repeater.next_trigger();
    if (repeater_timer && *repeater_timer < next) {
        next = *repeater_timer;
    }
    return std::chrono::milliseconds((next - m_time_now) / Timestamp::millisecond);
}

void Router::update(Clock::duration now)
{
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now);
    m_time_now += static_cast<Timestamp::value_type>(now_ms.count()) * Timestamp::millisecond;
    m_clock += now;

    if (m_next_beacon <= m_time_now) {
        on_beacon_timer_expired();
    }
    m_repeater.trigger(m_time_now);
    m_location_table.expire(m_time_now);

    for (auto& packet : m_cbf_buffer.packets_to_send(m_time_now)) {
        pass_down(cBroadcastMacAddress, std::move(packet.pdu), std::move(packet.payload));
    }
}

void Router::update(const LongPositionVector& lpv)
{
    // Check if LPV update frequency is fulfilled
    assert(!m_time_now.before(m_last_update_lpv));
    units::Duration time_since_last_update { m_time_now - m_last_update_lpv };
    if (time_since_last_update.value() > 0.0) {
        units::Frequency current_update_frequency =  1.0 / time_since_last_update;
        if (m_mib.itsGnMinimumUpdateFrequencyLPV > current_update_frequency) {
            throw std::runtime_error("LPV is not updated frequently enough");
        }
    }

    // Update LPV except for GN address
    Address gn_addr = m_local_position_vector.gn_addr;
    m_local_position_vector = lpv;
    m_local_position_vector.gn_addr = gn_addr;
    m_last_update_lpv = m_time_now;
}

void Router::set_transport_handler(UpperProtocol proto, TransportInterface& ifc)
{
    m_transport_ifcs[proto] = &ifc;
}

void Router::set_time(const Clock::time_point& init)
{
    m_clock = init;
    m_time_now = m_clock;
    m_last_update_lpv = m_time_now;
    m_next_beacon = m_time_now; // send BEACON at start-up
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
        auto pdu = create_shb_pdu(request);
        pdu->common().payload = payload->size();

        // Security
        if (request.security_profile) {
            // TODO: SN-ENCAP.request
            assert(pdu->basic().next_header == NextHeaderBasic::SECURED);
        }

        // forward buffering
        if (request.traffic_class.store_carry_forward() && !m_location_table.has_neighbours()) {
            std::unique_ptr<BroadcastBufferData> data {
                new BroadcastBufferData(*this, std::move(pdu), std::move(payload))
            };
            m_bc_forward_buffer.push(std::move(data), m_time_now);
        } else {
            if (request.repetition) {
                m_repeater.add(request, *payload, m_time_now);
            }
            execute_media_procedures(request.communication_profile);
            pass_down(cBroadcastMacAddress, std::move(pdu), std::move(payload));
            reset_beacon_timer();
        }
    }

    return result;
}

DataConfirm Router::request(const GbcDataRequest& request, DownPacketPtr payload)
{
    DataConfirm result;
    result ^= validate_data_request(request, m_mib);
    result ^= validate_payload(payload, m_mib);

    if (result.accepted()) {
        auto pdu = create_gbc_pdu(request);
        pdu->common().payload = payload->size();

        // Security
        if (request.security_profile) {
            // TODO: SN-ENCAP.request
            assert(pdu->basic().next_header == NextHeaderBasic::SECURED);
        }

        // Set up packet repetition
        if (request.repetition) {
            assert(payload);
            m_repeater.add(request, *payload, m_time_now);
        }

        // Forwarding
        NextHop first_hop;
        switch (m_mib.itsGnGeoBroadcastForwardingAlgorithm) {
            case BroadcastForwarding::UNSPECIFIED:
                // do simple forwarding
            case BroadcastForwarding::SIMPLE:
                throw std::runtime_error("simple BC forwarding not implemented");
                break;
            case BroadcastForwarding::CBF:
                first_hop = first_hop_contention_based_forwarding(
                        request.traffic_class.store_carry_forward(),
                        std::move(pdu), std::move(payload));
                break;
            case BroadcastForwarding::ADVANCED:
                first_hop = first_hop_gbc_advanced(request.traffic_class.store_carry_forward(),
                        std::move(pdu), std::move(payload));
                break;
            default:
                throw std::runtime_error("unhandled BC forwarding algorithm");
                break;
        };

        if (first_hop.valid()) {
            execute_media_procedures(request.communication_profile);
            std::unique_ptr<Pdu> pdu;
            std::unique_ptr<DownPacket> payload;
            std::tie(pdu, payload) = first_hop.data();
            pass_down(first_hop.mac(), std::move(pdu), std::move(payload));
        } else {
            result ^= DataConfirm::ResultCode::REJECTED_UNSPECIFIED;
        }
    }

    return result;
}

DataConfirm Router::request(const GacDataRequest&, DownPacketPtr)
{
    return DataConfirm(DataConfirm::ResultCode::REJECTED_UNSPECIFIED);
}

DataConfirm Router::request(const GucDataRequest&, DownPacketPtr)
{
    return DataConfirm(DataConfirm::ResultCode::REJECTED_UNSPECIFIED);
}

DataConfirm Router::request(const TsbDataRequest&, DownPacketPtr)
{
    return DataConfirm(DataConfirm::ResultCode::REJECTED_UNSPECIFIED);
}

void Router::indicate(UpPacketPtr packet, const MacAddress& sender, const MacAddress& destination)
{
    assert(packet);
    auto pdu = parse(*packet);
    if (!pdu) {
        // parsing of packet failed
        return;
    }

    BasicHeader& basic = pdu->basic;
    if (basic.version.raw() != m_mib.itsGnProtocolVersion) {
        // discard packet
        return;
    }

    CommonHeader& common = pdu->common;
    if (common.maximum_hop_limit < basic.hop_limit) {
        // discard packet
        return;
    } else if (common.payload != size(*packet, OsiLayer::Transport, max_osi_layer())) {
        // payload length does not match packet size
        return;
    }

    flush_broadcast_forwarding_buffer();

    struct extended_header_visitor : public boost::static_visitor<>
    {
        extended_header_visitor(Router* router,
                std::unique_ptr<UpPacket> packet,
                ParsedPdu& pdu,
                const MacAddress& sender,
                const MacAddress& destination) :
            m_router(router),
            m_packet(std::move(packet)),
            m_pdu(pdu),
            m_sender(sender),
            m_destination(destination) {}

        void operator()(ShbHeader& shb)
        {
            ExtendedPduRefs<ShbHeader> pdu(m_pdu.basic, m_pdu.common, shb);
            m_router->process_extended(pdu, std::move(m_packet));
        }

        void operator()(GeoBroadcastHeader& gbc)
        {
            ExtendedPduRefs<GeoBroadcastHeader> pdu(m_pdu.basic, m_pdu.common, gbc);
            m_router->process_extended(pdu, std::move(m_packet), m_sender, m_destination);
        }

        void operator()(BeaconHeader& beacon)
        {
            ExtendedPduRefs<BeaconHeader> pdu(m_pdu.basic, m_pdu.common, beacon);
            m_router->process_extended(pdu, std::move(m_packet));
        }

        Router* m_router;
        std::unique_ptr<UpPacket> m_packet;
        ParsedPdu& m_pdu;
        const MacAddress& m_sender;
        const MacAddress& m_destination;
    };

    extended_header_visitor visitor(this, std::move(packet), *pdu, sender, destination);
    boost::apply_visitor(visitor, pdu->extended);
}

void Router::execute_media_procedures(CommunicationProfile com_profile)
{
    switch (com_profile) {
        case CommunicationProfile::ITS_G5:
            execute_itsg5_procedures();
            break;
        case CommunicationProfile::UNSPECIFIED:
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
    // TODO: we could do a PDU consistency check here

    (*payload)[OsiLayer::Network] = ByteBufferConvertible(std::move(pdu));
    m_request_interface.request(request, std::move(payload));
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

void Router::pass_up(DataIndication& ind, UpPacketPtr packet)
{
    auto ifc = m_transport_ifcs.find(ind.upper_protocol);
    if (ifc != m_transport_ifcs.end()) {
        auto transport = ifc->second;
        if (transport != nullptr) {
            transport->indicate(ind, std::move(packet));
        }
    }
}

void Router::on_beacon_timer_expired()
{
    auto pdu = create_beacon_pdu();

    if (m_mib.itsGnSecurity) {
        // TODO: SN-ENCAP.request
        pdu->basic().next_header = NextHeaderBasic::SECURED;
    } else {
        pdu->basic().next_header = NextHeaderBasic::COMMON;
    }

    execute_media_procedures(m_mib.itsGnIfType);

    // BEACONs originate in GeoNet layer, therefore no upper layer payload
    DownPacketPtr payload { new DownPacket() };
    pass_down(cBroadcastMacAddress, std::move(pdu), std::move(payload));

    reset_beacon_timer();
}

void Router::reset_beacon_timer()
{
    typedef decltype(m_mib.itsGnBeaconServiceMaxJitter) duration_t;
    typedef duration_t::value_type real_t;
    const real_t max_jitter = m_mib.itsGnBeaconServiceMaxJitter.value();
    std::uniform_real_distribution<real_t> dist_jitter(0.0, max_jitter);
    const real_t random_jitter = dist_jitter(m_random_gen);
    const Timestamp::duration_type next_beacon_in {
        m_mib.itsGnBeaconServiceRetransmitTimer +
        duration_t::from_value(random_jitter) };
    m_next_beacon = m_time_now + next_beacon_in;
}

void Router::dispatch_repetition(const DataRequestVariant& request, std::unique_ptr<DownPacket> payload)
{
    RepetitionDispatcher dispatcher(*this, std::move(payload));
    boost::apply_visitor(dispatcher, request);
}

NextHop Router::first_hop_contention_based_forwarding(
        bool scf,
        std::unique_ptr<GbcPdu> pdu, DownPacketPtr payload)
{
    // TODO: EN 302 636-4-1 v1.2.5 does broadcast in any case
    NextHop nh;
    const Area& destination = pdu->extended().destination(pdu->common().header_type);
    if (inside_or_at_border(destination, m_local_position_vector.position())) {
        nh.mac(cBroadcastMacAddress);
        nh.data(std::move(pdu), std::move(payload));
        nh.state(NextHop::State::VALID);
    } else {
        nh = next_hop_greedy_forwarding(scf, std::move(pdu), std::move(payload));
    }
    return nh;
}

NextHop Router::next_hop_contention_based_forwarding(
        bool scf, const MacAddress& sender,
        std::unique_ptr<GbcPdu> pdu, DownPacketPtr payload)
{
    NextHop nh;
    const GeoBroadcastHeader& gbc = pdu->extended();
    const HeaderType ht = pdu->common().header_type;

    if (m_cbf_buffer.try_drop(gbc.source_position.gn_addr.mid(), gbc.sequence_number)) {
        nh.state(NextHop::State::DISCARDED);
    } else {
        const Area destination_area = gbc.destination(ht);
        if (inside_or_at_border(destination_area, m_local_position_vector.position())) {
            CbfPacketBuffer::packet_type packet(std::move(pdu), std::move(payload));
            m_cbf_buffer.push(std::move(packet), sender, timeout_cbf_gbc(sender), m_time_now);
            nh.state(NextHop::State::BUFFERED);
        } else {
            auto pv_se = m_location_table.get_position(sender);
            if (pv_se && pv_se.get().position_accuracy_indicator) {
                if (!inside_or_at_border(destination_area, pv_se.get().position())) {
                    nh = next_hop_greedy_forwarding(scf, std::move(pdu), std::move(payload));
                } else {
                    nh.state(NextHop::State::DISCARDED);
                }
            } else {
                nh.mac(cBroadcastMacAddress);
                nh.data(std::move(pdu), std::move(payload));
                nh.state(NextHop::State::VALID);
            }
        }
    }

    return nh;
}

NextHop Router::first_hop_gbc_advanced(bool scf, std::unique_ptr<GbcPdu> pdu, DownPacketPtr payload)
{
    const Area& destination = pdu->extended().destination(pdu->common().header_type);
    if (inside_or_at_border(destination, m_local_position_vector.position())) {
        units::Duration timeout = m_mib.itsGnGeoBroadcastCbfMaxTime;
        CbfPacketBuffer::packet_type packet(std::unique_ptr<GbcPdu> { pdu->clone() }, duplicate(*payload));
        m_cbf_buffer.push(std::move(packet), m_local_position_vector.gn_addr.mid(), timeout, m_time_now);
    }

    return next_hop_greedy_forwarding(scf, std::move(pdu), std::move(payload));
}

NextHop Router::next_hop_gbc_advanced(
        bool scf, const MacAddress& sender, const MacAddress& destination,
        std::unique_ptr<GbcPdu> pdu, DownPacketPtr payload)
{
    NextHop nh;
    const GeoBroadcastHeader& gbc = pdu->extended();
    const HeaderType ht = pdu->common().header_type;
    const Area destination_area = gbc.destination(ht);
    static const std::size_t max_counter = 3; // TODO: Where is this constant's definition in GN standard?
    auto cbf_meta = m_cbf_buffer.find(gbc.source_position.gn_addr.mid(), gbc.sequence_number);

    if (inside_or_at_border(destination_area, m_local_position_vector.position())) {
        if (cbf_meta) {
            if (cbf_meta->counter() >= max_counter) {
                m_cbf_buffer.try_drop(gbc.source_position.gn_addr.mid(), gbc.sequence_number);
                nh.state(NextHop::State::DISCARDED);
            } else {
                if (!outside_sectorial_contention_area(cbf_meta->sender(), sender)) {
                    m_cbf_buffer.try_drop(gbc.source_position.gn_addr.mid(), gbc.sequence_number);
                    nh.state(NextHop::State::DISCARDED);
                } else {
                    cbf_meta->set_timeout(timeout_cbf_gbc(sender), m_time_now);
                    cbf_meta->increment();
                    nh.state(NextHop::State::BUFFERED);
                }
            }
        } else {
            units::Duration timeout = 0.0 * units::si::seconds;
            if (destination == m_local_position_vector.gn_addr.mid()) {
                timeout = m_mib.itsGnGeoUnicastCbfMaxTime;
                nh = next_hop_greedy_forwarding(scf,
                        std::unique_ptr<GbcPdu> { pdu->clone() }, duplicate(*payload));
            } else {
                timeout = timeout_cbf_gbc(sender);
                nh.state(NextHop::State::BUFFERED);
            }

            CbfPacketBuffer::packet_type packet(std::move(pdu), std::move(payload));
            m_cbf_buffer.push(std::move(packet), sender, timeout, m_time_now);
            nh.state(NextHop::State::BUFFERED);
        }
    } else {
        auto pv_se = m_location_table.get_position(sender);
        if (pv_se && pv_se.get().position_accuracy_indicator) {
            if (!inside_or_at_border(destination_area, pv_se.get().position())) {
                nh = next_hop_greedy_forwarding(scf, std::move(pdu), std::move(payload));
            } else {
                nh.state(NextHop::State::DISCARDED);
            }
        } else {
            nh.mac(cBroadcastMacAddress);
            nh.data(std::move(pdu), std::move(payload));
            nh.state(NextHop::State::VALID);
        }
    }

    return nh;
}

NextHop Router::next_hop_greedy_forwarding(
        bool scf,
        std::unique_ptr<GbcPdu> pdu, DownPacketPtr payload)
{
    NextHop nh;

    GeodeticPosition dest = pdu->extended().position();
    const units::Length own = distance(dest, m_local_position_vector.position());
    units::Length mfr = own;

    for (auto& neighbour : m_location_table.neighbours()) {
        const units::Length dist = distance(dest, neighbour.position.position());
        if (dist < mfr) {
            nh.mac(neighbour.position.gn_addr.mid());
            mfr = dist;
        }
    }

    if (mfr < own) {
        nh.data(std::move(pdu), std::move(payload));
        nh.state(NextHop::State::VALID);
    } else {
        if (!m_location_table.has_neighbours() && scf) {
            class GbcGreedyBufferData : public PacketBufferData<GbcPdu>
            {
            public:
                using PacketBufferData<GbcPdu>::PacketBufferData;

                NextHop flush() override
                {
                    return m_router.next_hop_greedy_forwarding(true, std::move(m_pdu), std::move(m_payload));
                }
            };

            std::unique_ptr<GbcGreedyBufferData> data {
                new GbcGreedyBufferData(*this, std::move(pdu), std::move(payload))
            };
            m_uc_forward_buffer.push(std::move(data), m_time_now);
            nh.state(NextHop::State::BUFFERED);
        } else {
            nh.mac(cBroadcastMacAddress);
            nh.data(std::move(pdu), std::move(payload));
            nh.state(NextHop::State::VALID);
        }
    }

    return nh;
}

units::Duration Router::timeout_cbf_gbc(units::Length dist) const
{
    // TODO: media-dependent maximum communication range
    const auto dist_max = m_mib.itsGnDefaultMaxCommunicationRange;
    const auto to_cbf_min = m_mib.itsGnGeoBroadcastCbfMinTime;
    const auto to_cbf_max = m_mib.itsGnGeoBroadcastCbfMaxTime;
    auto to_cbf_gbc = to_cbf_min;

    if (dist <= dist_max) {
        to_cbf_gbc = to_cbf_max + (to_cbf_min - to_cbf_max) / dist_max * dist;
    } else {
        to_cbf_gbc = to_cbf_min;
    }

    return to_cbf_gbc;
}

units::Duration Router::timeout_cbf_gbc(const MacAddress& sender) const
{
    units::Duration timeout = 0.0 * units::si::seconds;
    auto pv_se = m_location_table.get_position(sender);
    if (pv_se && pv_se.get().position_accuracy_indicator) {
        units::Length dist = distance(pv_se.get().position(), m_local_position_vector.position());
        timeout = timeout_cbf_gbc(dist);
    } else {
        timeout = m_mib.itsGnGeoBroadcastCbfMaxTime;
    }
    return timeout;
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

void Router::process_extended(const ExtendedPduRefs<ShbHeader>& pdu, UpPacketPtr packet)
{
    const ShbHeader& shb = pdu.extended();
    const Address& source_addr = shb.source_position.gn_addr;
    const Timestamp& source_time = shb.source_position.timestamp;

    // execute duplicate packet detection (see A.3)
    if (m_location_table.is_duplicate_packet(source_addr, source_time)) {
        // discard packet
        return;
    }

    // execute duplicate address detection (see 9.2.1.5)
    detect_duplicate_address(source_addr);

    // update location table with SO.PV (see C.2)
    m_location_table.update(shb.source_position);
    // update SO.PDR in location table (see B.2)
    const std::size_t packet_size = size(*packet, OsiLayer::Network, OsiLayer::Application);
    m_location_table.update_pdr(source_addr, packet_size, m_time_now);
    // set SO LocTE to neighbour
    m_location_table.is_neighbour(source_addr, true);

    // pass packet to transport interface
    DataIndication ind(pdu.basic(), pdu.common());
    ind.source_position = static_cast<ShortPositionVector>(shb.source_position);
    ind.transport_type = TransportType::SHB;
    pass_up(ind, std::move(packet));
}

void Router::process_extended(const ExtendedPduRefs<BeaconHeader>& pdu, UpPacketPtr packet)
{
    const BeaconHeader& beacon = pdu.extended();
    const Address& source_addr = beacon.source_position.gn_addr;
    const Timestamp& source_time = beacon.source_position.timestamp;

    // execute duplicate packet detection (see A.3)
    if (m_location_table.is_duplicate_packet(source_addr, source_time)) {
        // discard packet
        return;
    }

    // execute duplicate address detection (see 9.2.1.5)
    detect_duplicate_address(source_addr);

    // update location table with SO.PV (see C.2)
    m_location_table.update(beacon.source_position);
    // update SO.PDR in location table (see B.2)
    const std::size_t packet_size = size(*packet, OsiLayer::Network, OsiLayer::Application);
    m_location_table.update_pdr(source_addr, packet_size, m_time_now);
    // set SO LocTE to neighbour
    m_location_table.is_neighbour(source_addr, true);
}

void Router::process_extended(const ExtendedPduRefs<GeoBroadcastHeader>& pdu,
        UpPacketPtr packet, const MacAddress& sender, const MacAddress& destination)
{
    assert(packet);
    const GeoBroadcastHeader& gbc = pdu.extended();
    const Address& source_addr = gbc.source_position.gn_addr;

    if (m_mib.itsGnGeoBroadcastForwardingAlgorithm == BroadcastForwarding::UNSPECIFIED ||
        m_mib.itsGnGeoBroadcastForwardingAlgorithm == BroadcastForwarding::SIMPLE) {
        const Timestamp& source_time = gbc.source_position.timestamp;
        const SequenceNumber& source_sn = gbc.sequence_number;
        if (m_location_table.is_duplicate_packet(source_addr, source_sn, source_time)) {
            return; // discard packet
        }
    }

    detect_duplicate_address(source_addr);

    const std::size_t packet_size = size(*packet, OsiLayer::Network, OsiLayer::Application);
    bool remove_neighbour_flag = !m_location_table.has_entry(source_addr);
    m_location_table.update(gbc.source_position);
    m_location_table.update_pdr(source_addr, packet_size, m_time_now);

    if (remove_neighbour_flag) {
        m_location_table.is_neighbour(source_addr, false);
    }

    DownPacketPtr payload = duplicate(*packet);

    const Area dest_area = gbc.destination(pdu.common().header_type);
    if (inside_or_at_border(dest_area, m_local_position_vector.position())) {
        DataIndication ind(pdu.basic(), pdu.common());
        ind.source_position = static_cast<ShortPositionVector>(gbc.source_position);
        ind.transport_type = TransportType::GBC;
        ind.destination = gbc.destination(pdu.common().header_type);
        pass_up(ind, std::move(packet));
    }

    // TODO: flush SO LS packet buffer if LS_pending, reset LS_pending
    flush_unicast_forwarding_buffer();

    if (pdu.basic().hop_limit == 0) {
        return; // discard packet
    }

    std::unique_ptr<GbcPdu> pdu_dup { pdu.clone() };
    assert(pdu_dup->basic().hop_limit > 0);
    pdu_dup->basic().hop_limit--;

    const bool scf = pdu.common().traffic_class.store_carry_forward();
    NextHop next_hop;
    switch (m_mib.itsGnGeoBroadcastForwardingAlgorithm) {
        case BroadcastForwarding::UNSPECIFIED:
        case BroadcastForwarding::SIMPLE:
            throw std::runtime_error("simple broadcast forwarding unimplemented");
            break;
        case BroadcastForwarding::CBF:
            next_hop = next_hop_contention_based_forwarding(scf, sender, std::move(pdu_dup), std::move(payload));
            break;
        case BroadcastForwarding::ADVANCED:
            next_hop = next_hop_gbc_advanced(scf, sender, destination, std::move(pdu_dup), std::move(payload));
            break;
        default:
            throw std::runtime_error("unhandeld broadcast forwarding algorithm");
            break;
    }

    if (next_hop.valid()) {
        execute_media_procedures(m_mib.itsGnIfType);
        const MacAddress& mac = next_hop.mac();
        dcc::DataRequest request;
        request.destination = mac;
        request.source = m_local_position_vector.gn_addr.mid();
        request.dcc_profile = dcc::Profile::DP3;
        request.ether_type = geonet::ether_type;

        std::unique_ptr<Pdu> pdu;
        std::unique_ptr<DownPacket> payload;
        std::tie(pdu, payload) = next_hop.data();
        pass_down(request, std::move(pdu), std::move(payload));
    }
}

void Router::flush_forwarding_buffer(PacketBuffer& buffer)
{
    dcc::DataRequest dcc_request;
    dcc_request.source = m_local_position_vector.gn_addr.mid();
    dcc_request.ether_type = geonet::ether_type;

    auto packets = buffer.flush(m_time_now);
    for (auto& packet : packets) {
        std::unique_ptr<Pdu> pdu;
        std::unique_ptr<DownPacket> payload;
        std::tie(pdu, payload) = packet.data();
        const auto tc = pdu->common().traffic_class;
        dcc_request.destination = packet.mac();
        dcc_request.dcc_profile = map_tc_onto_profile(tc);
        pass_down(dcc_request, std::move(pdu), std::move(payload));
    }
}

void Router::flush_broadcast_forwarding_buffer()
{
    flush_forwarding_buffer(m_bc_forward_buffer);
}

void Router::flush_unicast_forwarding_buffer()
{
    flush_forwarding_buffer(m_uc_forward_buffer);
}

void Router::detect_duplicate_address(const Address& addr_so)
{
    // Never change address for AUTO and ANONYMOUS here
    if (m_mib.itsGnLocalAddrConfMethod == AddrConfMethod::MANAGED
            && addr_so == m_local_position_vector.gn_addr) {

        MacAddress random_mac_addr;
        std::uniform_int_distribution<uint8_t> octet_dist;
        for (auto& octet : random_mac_addr.octets) {
            octet = octet_dist(m_random_gen);
        }

        m_local_position_vector.gn_addr.mid(random_mac_addr);
    }
}

std::unique_ptr<ShbPdu> Router::create_shb_pdu(const ShbDataRequest& request)
{
    std::unique_ptr<ShbPdu> pdu { new ShbPdu(request, m_mib) };
    pdu->common().header_type = HeaderType::TSB_SINGLE_HOP;
    pdu->extended().source_position = m_local_position_vector;
    return pdu;
}

std::unique_ptr<BeaconPdu> Router::create_beacon_pdu()
{
    std::unique_ptr<BeaconPdu> pdu { new BeaconPdu(m_mib) };
    pdu->basic().hop_limit = 1;
    pdu->common().next_header = NextHeaderCommon::ANY;
    pdu->common().header_type = HeaderType::BEACON;
    pdu->common().maximum_hop_limit = 1;
    // TODO: Shall we set traffic class to another DCC profile than DP0?
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

} // namespace geonet
} // namespace vanetza

