#ifndef ROUTER_HPP_UKYYCAR0
#define ROUTER_HPP_UKYYCAR0

#include <vanetza/common/byte_order.hpp>
#include <vanetza/common/hook.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/access/ethertype.hpp>
#include <vanetza/geonet/beacon_header.hpp>
#include <vanetza/geonet/cbf_packet_buffer.hpp>
#include <vanetza/geonet/common_header.hpp>
#include <vanetza/geonet/extended_pdu.hpp>
#include <vanetza/geonet/gbc_header.hpp>
#include <vanetza/geonet/gbc_memory.hpp>
#include <vanetza/geonet/interface.hpp>
#include <vanetza/geonet/location_table.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/packet_buffer.hpp>
#include <vanetza/geonet/pending_packet.hpp>
#include <vanetza/geonet/pdu.hpp>
#include <vanetza/geonet/pdu_variant.hpp>
#include <vanetza/geonet/repeater.hpp>
#include <vanetza/geonet/sequence_number.hpp>
#include <vanetza/geonet/shb_header.hpp>
#include <vanetza/geonet/timestamp.hpp>
#include <vanetza/units/length.hpp>
#include <vanetza/units/time.hpp>
#include <vanetza/security/security_entity.hpp>
#include <boost/variant.hpp>
#include <cstdint>
#include <memory>
#include <random>
#include <map>

namespace vanetza
{

// forward declarations
class MacAddress;
struct PositionFix;
class Runtime;

namespace dcc
{
    struct DataRequest;
    class RequestInterface;
} // namespace dcc

namespace geonet
{

extern const access::EtherType ether_type;

class DccFieldGenerator;
class IndicationContext;
class IndicationContextBasic;
class NextHop;
class TransportInterface;
struct ShbDataRequest;
struct GbcDataRequest;
struct DataConfirm;
struct DataIndication;
struct LinkLayer;

/**
 * Router is the central entity for GeoNet communication
 *
 * Incoming and outgoing GeoNet packets are handled by the router.
 * It may even dispatch own packets (beacons) if necessary.
 *
 * This implementation follows EN 302 636-4-1 v1.3.1
 */
class Router
{
public:
    typedef std::unique_ptr<DataRequest> DataRequestPtr;
    typedef std::unique_ptr<Pdu> PduPtr;
    typedef std::unique_ptr<DownPacket> DownPacketPtr;
    typedef std::unique_ptr<UpPacket> UpPacketPtr;

    using PendingPacketForwarding = PendingPacket<GbcPdu, const MacAddress&>;

    /// Reason for packet drop used by drop hook
    enum class PacketDropReason
    {
        Parse_Basic_Header,
        Parse_Common_Header,
        Parse_Secured_Header,
        Parse_Extended_Header,
        ITS_Protocol_Version,
        Decap_Unsuccessful_Non_Strict,
        Decap_Unsuccessful_Strict,
        Hop_Limit,
        Payload_Size,
        Security_Entity_Missing
    };

    // Reason for stopping packet forwarding
    enum class ForwardingStopReason
    {
        Hop_Limit,
        Source_PDR,
        Sender_PDR,
        Outside_Destination_Area
    };

    Router(Runtime&, const MIB&);
    ~Router();

    /**
     * \brief Request to send payload per single hop broadcast (SHB).
     * If security is enabled, the message gets encapsulated in a security envelope.
     * Returns whether data was valid to be sent.
     *
     * \param request
     * \param payload from upper layers
     * \return result code if packet has been accepted
     */
    DataConfirm request(const ShbDataRequest&, DownPacketPtr);

    /**
     * \brief Request to send payload per GeoBroadcast (GBC).
     * If security is enabled, the message gets encapsulated in a security envelope.
     * Returns whether data was valid to be sent.
     *
     * \param request
     * \param payload from upper layers
     * \return result code if packet has been accepted
     */
    DataConfirm request(const GbcDataRequest&, DownPacketPtr);

    // These three requests are not supported yet
    DataConfirm request(const GucDataRequest&, DownPacketPtr);
    DataConfirm request(const GacDataRequest&, DownPacketPtr);
    DataConfirm request(const TsbDataRequest&, DownPacketPtr);

    /**
     * \brief Handle the received packet on network layer.
     * Packet handling involves these steps:
     * - header processing
     * - packet forwarding
     * - passing to transport layer
     * - security decapsulation
     *
     * \param packet received packet from access layer
     * \param sender MAC address of sender
     * \param destination MAC address of destination (might be broadcast)
     */
    void indicate(UpPacketPtr, const MacAddress& sender, const MacAddress& destination);

    /**
     * \brief When a packet is dropped, this Hook is invoked
     * \tparam PacketDropReason why Router decided to drop packet
     */
    Hook<PacketDropReason> packet_dropped;

    /**
     * \brief When packet forwarding is stopped, this Hook is invoked
     * \tparam ForwardingStopReason why Router decided not to forward packet
     */
    Hook<ForwardingStopReason> forwarding_stopped;

    /**
     * \brief Update router's local position vector
     *
     * \param fix current position fix
     */
    void update_position(const PositionFix&);

    /**
     * \brief Register a transport protocol handler.
     *
     * \param proto register handler for this upper protocol
     * \param ifc use this interface or disable handling if nullptr
     */
    void set_transport_handler(UpperProtocol proto, TransportInterface* ifc);

    /**
     * \brief Register security entity used when itsGnSecurity is enabled
     *
     * \param entity security entity
     */
    void set_security_entity(security::SecurityEntity* entity);

    /**
     * \brief Register access layer interface
     *
     * \param ifc interface used for passing packets down to access layer
     */
    void set_access_interface(dcc::RequestInterface* ifc);

    /**
     * \brief Register generator for DCC-MCO fields
     *
     * \param dcc DCC-MCO field generator or nullptr for disabling feature
     */
    void set_dcc_field_generator(DccFieldGenerator* dcc);

    /**
     * \brief Set Router's own GeoNetworking address
     *
     * \param addr
     */
    void set_address(const Address&);

    /**
     * \brief Get Management Information Base (MIB)
     * \return read-only reference to MIB
     */
    const MIB& get_mib() const { return m_mib; }

    /**
     * \brief Get the Contention-Based-Forwarding buffer
     *
     * \return read-only reference to CBF packet buffer
     */
    const CbfPacketBuffer& get_cbf_buffer() const { return m_cbf_buffer; }

    /**
     * \brief Get the LocationTable.
     * The table holds information about neighbouring ITS-Routers.
     *
     * \return read-only reference to LocationTable
     */
    const LocationTable& get_location_table() const { return m_location_table; }

    /**
     * \brief Get the local position vector.
     * This vector describes the current position of the router.
     *
     * \return read-only reference to LongPositionVector
     */
    const LongPositionVector& get_local_position_vector() const { return m_local_position_vector; }

    /**
     * \brief Check if router is outside the sectorial contention area
     * See TS 102 636-4-1 v1.2.3 section E.4 and figure E.2 for details.
     *
     * \param sender
     * \param forwarder
     * \return bool true if either sender or forwarder is outside
     */
    bool outside_sectorial_contention_area(const MacAddress& sender, const MacAddress& forwarder) const;

    /**
     * \brief Set seed for internal random number generator (RNG)
     * RNG is used e.g. for random Beacon jitter
     *
     * \param seed reset RNG's state to this seed
     */
    void set_random_seed(std::uint_fast32_t seed);

    /**
     * Forwarding algorithm selection procedure as given by Annex D
     * \param pdu GeoNetworking PDU
     * \param payload packet payload
     * \param ll link-layer control info (unavailable for source operations)
     * \return routing decision (next hop's address, buffered, or discarded)
     */
    NextHop forwarding_algorithm_selection(PendingPacketForwarding&&, const LinkLayer* ll = nullptr);

private:
    typedef std::map<UpperProtocol, TransportInterface*> transport_map_t;

    /**
     * \brief Send Beacon packet to all neighbours with updated position vector.
     * Only to be called when the beacon timer expires.
     */
    void on_beacon_timer_expired();

    /**
     * \brief Reschedule timer for next Beacon transmission
     * Timer will be scheduled according to MIB's Beacon timer settings.
     */
    void reset_beacon_timer();

    /**
     * \brief Reschedule timer for next Beacon transmission
     * \param next Duration until next transmission
     */
    void reset_beacon_timer(Clock::duration next);

    /**
     * \brief Process BasicHeader at packet indication.
     * \param ctx Context holding data for further parsing
     */
    void indicate_basic(IndicationContextBasic&);

    /**
     * \brief Process CommonHeader at packet indication.
     * \param ctx Context holding data for further parsing
     * \param basic Previously decoded BasicHeader
     */
    void indicate_common(IndicationContext&, const BasicHeader&);

    /**
     * \brief Process ExtendedHeader at packet indication.
     * \param ctx Context holding data for further parsing
     * \param common Previously decoded CommonHeader
     */
    void indicate_extended(IndicationContext&, const CommonHeader&);

    /**
     * \brief Process SecuredMessage at packet indication.
     * \param ctx Context holding data for further parsing
     * \param basic Previously decoded BasicHeader
     */
    void indicate_secured(IndicationContextBasic&, const BasicHeader&);

    /**
     * \brief Process ExtendedHeader information.
     * Update router's LocationTable and neighbour relationship.
     *
     * \param pdu containing the ExtendedHeader
     * \param packet received packet
     * \param ll link-layer control info
     * \return pass up decision (always false for Beacons)
     */
    bool process_extended(const ExtendedPduConstRefs<BeaconHeader>&, const UpPacket&, const LinkLayer& ll);

    /**
     * \brief Process ExtendedHeader information.
     * Update router's LocationTable and neighbour relationship.
     * Pass packet up to transport layer for further processing.
     *
     * \param pdu containing the ExtendedHeader
     * \param packet received packet
     * \param ll link-layer control info
     * \return pass up decision (true for all non-duplicate SHBs)
     */
    bool process_extended(const ExtendedPduConstRefs<ShbHeader>&, const UpPacket&, const LinkLayer& ll);

    /**
     * \brief Process ExtendedHeader information.
     * Update router's LocationTable and neighbour relationship.
     * Pass packet up to transport layer for further processing.
     * Forward packets.
     *
     * \param pdu containing the ExtendedHeader
     * \param packet received packet
     * \param ll link-layer control info
     * \return pass up decision (depends on addressed area and router position)
     */
    bool process_extended(const ExtendedPduConstRefs<GeoBroadcastHeader>&, const UpPacket&, const LinkLayer& ll);

    /**
     * \brief Send all packets in the broadcast forwarding buffer with expired waiting time.
     */
    void flush_broadcast_forwarding_buffer();

    /**
     * \brief Send all matching packets in the unicast forwarding buffer with expired waiting time.
     * \param addr unicast packets for this address
     */
    void flush_unicast_forwarding_buffer(const Address& addr);

    /**
     * \brief Executes media specific functionalities
     * Details are described in TS 102 636-4-2.
     *
     * \param profile e.g. ITS-G5
     */
    void execute_media_procedures(CommunicationProfile);

    /**
     * \brief Executes ITS-G5 media specific procedures
     * Details are described in TS 102 636-4-2.
     */
    void execute_itsg5_procedures();

    /**
     * \brief Pass down the packet to the access layer.
     *
     * \param addr MAC address of destination
     * \param pdu header information
     * \param payload Packet payload
     */
    void pass_down(const MacAddress&, PduPtr, DownPacketPtr);

    /**
     * \brief Send packet using the information in the DataRequest.
     * The packet is formed using the data in PDU and payload.
     *
     * \param request containing transmission parameters
     * \param pdu header information
     * \param payload Packet payload
     */
    void pass_down(const dcc::DataRequest&, PduPtr, DownPacketPtr);

    /**
     * \brief Pass packet up to the transport layer.
     *
     * \param ind containing network information
     * \param packet payload to be passed up to the next layer
     */
    void pass_up(const DataIndication&, UpPacketPtr);

    /**
     * \brief Decide if GBC packet shall be passed up to transport layer.
     *
     * \param within_destination is router located within destination area
     * \param gbc GeoBroadcast header
     *
     * \return true if packet shall be passed up
     */
    bool decide_pass_up(bool within_destination, const GeoBroadcastHeader& gbc);

    /**
     * \brief Helper method to handle duplicate addresses.
     * If own address collides with the address of a received packet
     * Router's address is set to a new random address.
     * \note Behaviour depends on MIB's itsGnLocalAddrConfMethod.
     *
     * \param source address of source (from packet header)
     * \param sender address of sender (link layer)
     */
    void detect_duplicate_address(const Address& source, const MacAddress& sender);

    /**
     * \brief Detect duplicate packets
     * See EN 302 636-4-1 v1.3.1 Annex A.2
     *
     * \param source source address
     * \param sn sequence number
     * \return true if packet is detected as a duplicate
     */
    bool detect_duplicate_packet(const Address& source, SequenceNumber sn);

    /**
     * \brief Determine next hop for greedy forwarding.
     * See EN 302 636-4-1 v1.3.1 Annex E.2
     *
     * \param pdu
     * \param payload
     * \return next hop
     */
    NextHop greedy_forwarding(PendingPacketForwarding&&);

    /**
     * \brief Determine next hop for non-area contention-based forwarding
     * See EN 302 636-4-1 v1.3.1 Annex E.3
     *
     * \param pdu
     * \param payload
     * \param sender optional sender MAC address (if not first hop)
     * \return next hop
     */
    NextHop non_area_contention_based_forwarding(PendingPacketForwarding&&, const MacAddress* sender);

    /**
     * \brief Determine next hop for area contention-based forwarding
     * See EN 302 636-4-1 v1.3.1 Annex F.3
     *
     * \param pdu
     * \param payload
     * \param sender optional sender MAC address (if not first hop)
     * \return next hop
     */
    NextHop area_contention_based_forwarding(PendingPacketForwarding&&, const MacAddress* sender);

    /**
     * \brief Determine CBF buffering time for a packet.
     * Complies to EN 302 636-4-1 v1.3.1 Annex E.3 (non-area CBF, eq. E.1) and F.3 (area CBF, eq. F.1)
     *
     * \param dist distance or progress (interpretation depends on non-area vs. area CBF)
     * \return CBF time-out
     */
    units::Duration timeout_cbf(units::Length distance) const;

    /**
     * \brief Determine (area) CBF buffering time for a packet from a sender
     *
     * This is a shortcut for a re-curring pattern in Annex F.3 and F.4:
     * 1) sender position is looked up in location table
     * 2) position accuracy of sender is validated (if it is found)
     * 3) progress is then distance between sender and local router
     *
     * \param sender MAC address of sender
     * \return CBF time-out
     */
    units::Duration timeout_cbf(const MacAddress& sender) const;

    /**
     * \brief Determine next hop for area advanced forwarding
     * See EN 302 636-4-1 v1.3.1 Annex F.4
     *
     * \param pdu
     * \param payload
     * \param ll optional link-layer control info (if not source operations)
     * \return next hop
     */
    NextHop area_advanced_forwarding(PendingPacketForwarding&&, const LinkLayer* sender);

    /**
     * \brief Callback function for dispatching a packet repetition.
     * Invoked by Repeater when a scheduled repetition is due.
     *
     * \param request
     * \param payload
     */
    void dispatch_repetition(const DataRequestVariant&, DownPacketPtr);

    /**
     * \brief Encaspulate a packet according to security profile
     *
     * \param aid ITS-AID
     * \param pdu PDU
     * \param packet Packet with payload
     */
    DownPacketPtr encap_packet(ItsAid aid, Pdu& pdu, DownPacketPtr packet);

    /**
     * \brief Create an initialized Single-Hop-Broadcast PDU
     *
     * \param request
     * \return PDU object
     */
    std::unique_ptr<ShbPdu> create_shb_pdu(const ShbDataRequest&);

    /**
     * \brief Create an initialzed Beacon PDU
     *
     * \return PDU object
     */
    std::unique_ptr<BeaconPdu> create_beacon_pdu();

    /**
     * \brief Create an initialized GeoBroadcast PDU
     *
     * \param request
     * \return PDU object
     */
    std::unique_ptr<GbcPdu> create_gbc_pdu(const GbcDataRequest&);

    const MIB& m_mib;
    Runtime& m_runtime;
    dcc::RequestInterface* m_request_interface;
    DccFieldGenerator* m_dcc_field_generator;
    security::SecurityEntity* m_security_entity;
    transport_map_t m_transport_ifcs;
    LocationTable m_location_table;
    PacketBuffer m_bc_forward_buffer;
    PacketBuffer m_uc_forward_buffer;
    CbfPacketBuffer m_cbf_buffer;
    LongPositionVector m_local_position_vector;
    SequenceNumber m_local_sequence_number;
    Repeater m_repeater;
    std::mt19937 m_random_gen;
    GbcMemory m_gbc_memory;
};

/**
 * Get string representation of packet drop reason
 * \param pdr packet drop reason code
 * \return string representation
 */
std::string stringify(Router::PacketDropReason pdr);

} // namespace geonet
} // namespace vanetza

#endif /* ROUTER_HPP_UKYYCAR0 */
