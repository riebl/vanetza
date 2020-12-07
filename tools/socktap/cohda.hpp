#ifndef COHDA_HPP_GBENHCVN
#define COHDA_HPP_GBENHCVN

#include <boost/optional/optional.hpp>
#include <vanetza/access/data_request.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/net/chunk_packet.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include <vanetza/net/ethernet_header.hpp>

namespace vanetza
{

/**
 * Add Physical and Link layer headers understood by Cohda V2X API
 * \param req access layer request parameters
 * \param packet packet to be transmitted
 */
void insert_cohda_tx_header(const access::DataRequest& req, std::unique_ptr<ChunkPacket>& packet);

/**
 * Remove packet headers by Cohda V2X API and build Ethernet header from them
 * \return equivalent EthernetHeader if successfully received
 */
boost::optional<EthernetHeader> strip_cohda_rx_header(CohesivePacket&);

} // namespace vanetza

#endif /* COHDA_HPP_GBENHCVN */

