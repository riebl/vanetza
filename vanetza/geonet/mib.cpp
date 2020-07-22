#include "mib.hpp"
#include <boost/units/systems/si/prefixes.hpp>

namespace vanetza
{
namespace geonet
{

using namespace vanetza::units::si;
using vanetza::units::degrees;
using boost::units::si::kilo;
using boost::units::si::milli;

const auto milliseconds = milli * seconds;

ManagementInformationBase::ManagementInformationBase() :
    itsGnLocalAddrConfMethod(AddrConfMethod::Managed),
    itsGnProtocolVersion(1),
    itsGnIsMobile(true),
    itsGnIfType(InterfaceType::ITS_G5),
    itsGnMinimumUpdateFrequencyEPV(1.0 / (1000.0 * milliseconds)),
    itsGnPaiInterval(80 * meters),
    itsGnMaxSduSize(1398),
    itsGnMaxGeoNetworkingHeaderSize(88),
    itsGnLifetimeLocTE(20 * seconds),
    itsGnSecurity(false),
    itsGnSnDecapResultHandling(SecurityDecapHandling::Strict),
    itsGnLocationServiceMaxRetrans(10),
    itsGnLocationServiceRetransmitTimer(1 * seconds),
    itsGnLocationServicePacketBufferSize(1024),
    itsGnBeaconServiceRetransmitTimer(3 * seconds),
    itsGnBeaconServiceMaxJitter(itsGnBeaconServiceRetransmitTimer / 4.0),
    itsGnDefaultHopLimit(10),
    itsGnDPLLength(8),
    itsGnMaxPacketLifetime(Lifetime::Base::Hundred_Seconds, 6),
    itsGnDefaultPacketLifetime(Lifetime::Base::Ten_Seconds, 6),
    itsGnMaxPacketDataRate(100),
    itsGnMaxPacketDataRateEmaBeta(0.9),
    itsGnMaxGeoAreaSize(10 * kilo * kilo * square_meters),
    itsGnMinPacketRepetitionInterval(100 * milliseconds),
    itsGnNonAreaForwardingAlgorithm(UnicastForwarding::Greedy),
    itsGnAreaForwardingAlgorithm(BroadcastForwarding::CBF),
    itsGnCbfMinTime(1 * milliseconds),
    itsGnCbfMaxTime(100 * milliseconds),
    itsGnDefaultMaxCommunicationRange(1000 * meters),
    itsGnBroadcastCBFDefSectorAngle(30 * degrees),
    itsGnUcForwardingPacketBufferSize(256),
    itsGnBcForwardingPacketBufferSize(1024),
    itsGnCbfPacketBufferSize(256),
    itsGnDefaultTrafficClass(false, false, 0),
    vanetzaDefaultSeed(0xc0114c2c),
    vanetzaCbfMaxCounter(1),
    vanetzaDeferInitialBeacon(false),
    vanetzaDisableBeaconing(false),
    vanetzaMultiHopDuplicateAddressDetection(false),
    vanetzaFadingCbfCounter(false),
    vanetzaFadingCbfCounterLifetime(4.0 * itsGnCbfMaxTime),
    vanetzaNeighbourFlagExpiry(Clock::duration::zero()),
    vanetzaGbcMemoryCapacity(0)
{
}

} // namespace geonet
} // namespace vanetza

