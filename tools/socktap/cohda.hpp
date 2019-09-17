#ifndef COHDA_HPP_GBENHCVN
#define COHDA_HPP_GBENHCVN

#include <boost/optional/optional.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/net/chunk_packet.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/dcc/data_request.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <vanetza/net/cohesive_packet.hpp>

namespace vanetza
{

// forward declaration
namespace dcc { class DataRequest; }

void insert_cohda_tx_header(const dcc::DataRequest&, std::unique_ptr<ChunkPacket>&);

boost::optional<EthernetHeader> strip_cohda_rx_header(CohesivePacket&);

} // namespace vanetza

#endif /* COHDA_HPP_GBENHCVN */

