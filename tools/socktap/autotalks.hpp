#ifndef AUTOTALKS_HPP_
#define AUTOTALKS_HPP_

#include <cstddef>
#include <memory>
#include <vanetza/net/mac_address.hpp>
#include <vanetza/access/data_request.hpp>
#include <vanetza/net/chunk_packet.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include "atlk/sdk.h"
#include "atlk/v2x_service.h"
#include "autotalks_link.hpp"

namespace vanetza
{
namespace autotalks
{

/*
 * Device initialization.
 */
int autotalks_device_init(void);

/*
 * Device deinitialization.
 */
int autotalks_device_deinit(void);

/*
 * Request sending in the API.
 */
atlk_rc_t autotalks_send(const void*, size_t, const v2x_send_params_t*, const atlk_wait_t*);

/*
 * Request reception in the API.
 */
atlk_rc_t autotalks_receive(void*, size_t*, v2x_receive_params_t*, const atlk_wait_t*);

/*
 * Convert MAC address to the Vanetza format
 */
vanetza::MacAddress num_to_mac(eui48_t);

/*
 * Convert Vanetza MAC format to the array
 */
eui48_t mac_to_num(vanetza::MacAddress);

/*
 * Create autotalks header and send the packet.
 */
void insert_autotalks_header_transmit(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>&, uint8_t*, uint16_t);

/*
 * Parse information from received Autotalks packet.
 */
boost::optional<vanetza::EthernetHeader> strip_autotalks_rx_header(vanetza::CohesivePacket&, v2x_receive_params_t);

/*
 * Create a new thread for receiving data.
 */
void init_rx(AutotalksLink*);


} // namespace autotalks
} // namespace vanetza

#endif /* AUTOTALKS_HPP_ */
