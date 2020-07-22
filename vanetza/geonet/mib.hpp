#ifndef MIB_HPP_U3WJ4WES
#define MIB_HPP_U3WJ4WES

#include <vanetza/common/clock.hpp>
#include <vanetza/geonet/address.hpp>
#include <vanetza/geonet/lifetime.hpp>
#include <vanetza/geonet/station_type.hpp>
#include <vanetza/geonet/traffic_class.hpp>
#include <vanetza/units/angle.hpp>
#include <vanetza/units/area.hpp>
#include <vanetza/units/frequency.hpp>
#include <vanetza/units/length.hpp>
#include <vanetza/units/time.hpp>
#include <cstdint>
#include <string>

namespace vanetza
{
namespace geonet
{

enum class UnicastForwarding {
    Unspecified = 0,
    Greedy = 1,
    CBF = 2
};

enum class BroadcastForwarding {
    Unspecified = 0,
    SIMPLE = 1,
    CBF = 2,
    Advanced = 3
};

enum class AddrConfMethod {
    Auto = 0,
    Managed = 1,
    Anonymous = 2
};

enum class InterfaceType {
    Unspecified = 0,
    ITS_G5 = 1
};

enum class SecurityDecapHandling {
    Strict = 0,
    Non_Strict = 1
};

/**
 * The Management Information Base (MIB) defines the GeoNetworking protocol constants.
 *
 * \see EN 302 636-4-1 v1.3.1 Annex H
 */
struct ManagementInformationBase
{
    ManagementInformationBase();

    Address itsGnLocalGnAddr;
    AddrConfMethod itsGnLocalAddrConfMethod;
    unsigned itsGnProtocolVersion;
    bool itsGnIsMobile;
    InterfaceType itsGnIfType;
    units::Frequency itsGnMinimumUpdateFrequencyEPV;
    units::Length itsGnPaiInterval;
    unsigned itsGnMaxSduSize;
    unsigned itsGnMaxGeoNetworkingHeaderSize;
    units::Duration itsGnLifetimeLocTE;
    bool itsGnSecurity;
    SecurityDecapHandling itsGnSnDecapResultHandling;
    unsigned itsGnLocationServiceMaxRetrans;
    units::Duration itsGnLocationServiceRetransmitTimer;
    unsigned itsGnLocationServicePacketBufferSize; // byte
    units::Duration itsGnBeaconServiceRetransmitTimer;
    units::Duration itsGnBeaconServiceMaxJitter;
    unsigned itsGnDefaultHopLimit;
    unsigned itsGnDPLLength;
    Lifetime itsGnMaxPacketLifetime;
    Lifetime itsGnDefaultPacketLifetime;
    unsigned itsGnMaxPacketDataRate; // kbyte/s
    double itsGnMaxPacketDataRateEmaBeta; // percentage ]0; 1[
    units::Area itsGnMaxGeoAreaSize;
    units::Duration itsGnMinPacketRepetitionInterval;
    UnicastForwarding itsGnNonAreaForwardingAlgorithm;
    BroadcastForwarding itsGnAreaForwardingAlgorithm;
    units::Duration itsGnCbfMinTime;
    units::Duration itsGnCbfMaxTime;
    units::Length itsGnDefaultMaxCommunicationRange;
    units::Angle itsGnBroadcastCBFDefSectorAngle;
    unsigned itsGnUcForwardingPacketBufferSize; // kbyte
    unsigned itsGnBcForwardingPacketBufferSize; // kbyte
    unsigned itsGnCbfPacketBufferSize; // kbyte
    TrafficClass itsGnDefaultTrafficClass;
    std::uint32_t vanetzaDefaultSeed; /*< default seed for internal random number generator */
    std::size_t vanetzaCbfMaxCounter; /*< maximum counter value used for Advanced routing */
    bool vanetzaDeferInitialBeacon; /*< defer first beacon up to itsGnBeaconServiceRetransmitTimer */
    bool vanetzaDisableBeaconing; /*< disable transmission of beacons entirely */
    bool vanetzaMultiHopDuplicateAddressDetection; /*< execute DAD for multi-hop packets */
    bool vanetzaFadingCbfCounter; /*< use fading counters for CBF packet buffer */
    units::Duration vanetzaFadingCbfCounterLifetime; /*< lifetime until counter vanishes */
    Clock::duration vanetzaNeighbourFlagExpiry; /*< reset LocTE neighbour state without explicit updates */
    std::size_t vanetzaGbcMemoryCapacity; /*< do not pass up duplicate GBC packets (0 to disable this filter) */
};

// This name is too clumsy to write it out every time
typedef ManagementInformationBase MIB;

} // namespace geonet
} // namespace vanetza

#endif /* MIB_HPP_U3WJ4WES */

