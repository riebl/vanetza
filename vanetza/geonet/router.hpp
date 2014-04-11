#ifndef ROUTER_HPP_UKYYCAR0
#define ROUTER_HPP_UKYYCAR0

#include <vanetza/common/byte_order.hpp>
#include <vanetza/geonet/beacon_header.hpp>
#include <vanetza/geonet/cbf_packet_buffer.hpp>
#include <vanetza/geonet/common_header.hpp>
#include <vanetza/geonet/extended_pdu.hpp>
#include <vanetza/geonet/gbc_header.hpp>
#include <vanetza/geonet/interface.hpp>
#include <vanetza/geonet/location_table.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/packet_buffer.hpp>
#include <vanetza/geonet/pdu.hpp>
#include <vanetza/geonet/pdu_variant.hpp>
#include <vanetza/geonet/repeater.hpp>
#include <vanetza/geonet/sequence_number.hpp>
#include <vanetza/geonet/shb_header.hpp>
#include <vanetza/geonet/timestamp.hpp>
#include <vanetza/units/length.hpp>
#include <vanetza/units/time.hpp>
#include <boost/variant.hpp>
#include <memory>
#include <random>
#include <map>

namespace vanetza
{

// forward declarations
class MacAddress;
namespace dcc
{
    class AccessControl;
    class DataRequest;
} // namespace dcc

namespace geonet
{

extern const uint16be_t ether_type;

class TransportInterface;
class NextHop;
struct ShbDataRequest;
struct GbcDataRequest;
struct DataConfirm;
struct DataIndication;


/**
 * Router is the central entity for GeoNet communication
 *
 * Incoming and outgoing GeoNet packets are handled by the router.
 * It may even dispatch own packets (beacons) if necessary.
 */
class Router
{
public:
    typedef std::unique_ptr<DataRequest> DataRequestPtr;
    typedef std::unique_ptr<Pdu> PduPtr;
    typedef std::unique_ptr<DownPacket> DownPacketPtr;
    typedef std::unique_ptr<UpPacket> UpPacketPtr;

    Router(const MIB&, dcc::AccessControl&);
    ~Router();
    DataConfirm request(const ShbDataRequest&, DownPacketPtr);
    DataConfirm request(const GbcDataRequest&, DownPacketPtr);
    // These three requests are not supported yet
    DataConfirm request(const GucDataRequest&, DownPacketPtr);
    DataConfirm request(const GacDataRequest&, DownPacketPtr);
    DataConfirm request(const TsbDataRequest&, DownPacketPtr);
    void indicate(UpPacketPtr, const MacAddress& sender);
    void update(Timestamp now);
    /**
     * Update router's local position vector
     * \note GN Address of given LongPositionVector is ignored!
     * \param lpv Set positional data according to this argument
     */
    void update(const LongPositionVector&);
    void set_transport_handler(UpperProtocol, TransportInterface&);
    void set_time(Timestamp init);

    std::unique_ptr<ShbPdu> create_shb_pdu(const ShbDataRequest&);
    std::unique_ptr<BeaconPdu> create_beacon_pdu();
    std::unique_ptr<GbcPdu> create_gbc_pdu(const GbcDataRequest&);

private:
    typedef std::map<UpperProtocol, TransportInterface*> transport_map_t;

    void on_beacon_timer_expired();
    void reset_beacon_timer();
    void process_extended(const ExtendedPduRefs<ShbHeader>&, UpPacketPtr);
    void process_extended(const ExtendedPduRefs<GeoBroadcastHeader>&, UpPacketPtr,
            const MacAddress& sender);
    void flush_forwarding_buffer(PacketBuffer&);
    void flush_broadcast_forwarding_buffer();
    void flush_unicast_forwarding_buffer();
    void execute_media_procedures(CommunicationProfile);
    void execute_itsg5_procedures();
    void pass_down(const MacAddress&, PduPtr, DownPacketPtr);
    void pass_down(const dcc::DataRequest&, PduPtr, DownPacketPtr);
    void pass_up(DataIndication&, UpPacketPtr);
    void detect_duplicate_address(const Address&);
    NextHop next_hop_contention_based_forwarding(bool scf, const MacAddress& sender,
            std::unique_ptr<GbcPdu>, DownPacketPtr);
    NextHop next_hop_greedy_forwarding(bool scf, std::unique_ptr<GbcPdu>, DownPacketPtr);
    NextHop first_hop_contention_based_forwarding(bool scf, std::unique_ptr<GbcPdu>, DownPacketPtr);
    units::Duration timeout_cbf_gbc(units::Length distance) const;

    const MIB& m_mib;
    dcc::AccessControl& m_access_control;
    transport_map_t m_transport_ifcs;
    LocationTable m_location_table;
    PacketBuffer m_bc_forward_buffer;
    PacketBuffer m_uc_forward_buffer;
    CbfPacketBuffer m_cbf_buffer;
    LongPositionVector m_local_position_vector;
    SequenceNumber m_local_sequence_number;
    Repeater m_repeater;
    Timestamp m_last_update_lpv;
    Timestamp m_time_now;
    Timestamp m_last_transmission;
    Timestamp m_next_beacon;
    std::mt19937 m_random_gen;
};

} // namespace geonet
} // namespace vanetza

#endif /* ROUTER_HPP_UKYYCAR0 */

