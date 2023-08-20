#include "autotalks.hpp"

#include <vanetza/access/g5_link_layer.hpp>
#include <vanetza/common/serialization_buffer.hpp>
#include <vanetza/access/ethertype.hpp>
#include <pthread.h>
#include <iostream>

#include <atlk/sdk.h>
#include <atlk/v2x.h>
#include <atlk/v2x_service.h>
#include <atlk/ddm_service.h>
#include <atlk/wdm.h>
#include <atlk/dsm.h>
#include <atlk/wdm_service.h>
#include <atlk/log_service.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <extern/ref_sys.h>
#include <extern/target_type.h>
#include <extern/time_sync.h>

#ifdef __cplusplus
}
#endif

#include "autotalks_link.hpp"

// Update this if needed
#define SECTON_NET_NAME	"enx0002ccf00006"

namespace vanetza
{
namespace autotalks
{

v2x_socket_t* v2x_socket_ptr;
bool endRxThread = false;

static pthread_t v2x_rx_thread;
static uint8_t v2x_rx_buffer[2048];
static void* v2x_rx_thread_entry(void * arg);


int autotalks_device_init(void)
{
    atlk_rc_t rc;
    const char* arg[] = {NULL, SECTON_NET_NAME};
    /** Reference system initialization */
#if defined(CRATON_2)
    rc = ref_sys_init_ex(1, (char**) arg);
#elif defined(SECTON)
    rc = ref_sys_init_ex(2, (char**) arg);
#else
  #error Wrong configuration selected.
#endif

  // TODO                                                                     //
  // TODO: Take initialization from Autotalks basic example's main function   //
  // TODO                                                                     //
#error "Autotalks device initialization code is missing"
    
  v2x_socket_t *v2x_if[IF_INDEX_MAX];
  // Assign the socket to the global parameter
  v2x_socket_ptr = v2x_if[0];

  return EXIT_SUCCESS;
}

int autotalks_device_deinit(void)
{
    endRxThread = true;
    if (v2x_socket_ptr)
        v2x_socket_delete(v2x_socket_ptr);

    atlk_rc_t ret;

    ret = time_sync_deinit();
    if (atlk_error(ret))
        fprintf(stderr, "Fail of time_sync_deinit(). Error: %s\n", atlk_rc_to_str(ret));

    ret = ref_sys_deinit();
    if (atlk_error(ret))
        fprintf(stderr, "Fail of ref_sys_deinit(). Error: %s\n", atlk_rc_to_str(ret));

    return EXIT_SUCCESS;
}

atlk_rc_t autotalks_send(const void *data_ptr, size_t data_size,
                         const v2x_send_params_t *params_ptr, const atlk_wait_t *wait_ptr)
{
    atlk_rc_t ret = 0;
    if (v2x_socket_ptr == NULL)
        fprintf(stderr, "Invalid socket.\n");
    else if (v2x_socket_ptr != NULL)
        ret = v2x_send(v2x_socket_ptr, data_ptr, data_size, params_ptr, wait_ptr);
    // Check the return value
    if (atlk_error(ret)) {
        fprintf(stderr, "v2x_send failed: %d\n", ret);
    }
	return ret;
}

atlk_rc_t autotalks_receive(void *data_ptr, size_t *data_size_ptr,
    v2x_receive_params_t *params_ptr, const atlk_wait_t *wait_ptr)
{
    return v2x_receive(v2x_socket_ptr, data_ptr, data_size_ptr, params_ptr, wait_ptr);
}

vanetza::MacAddress num_to_mac(eui48_t addr)
{
    return vanetza::MacAddress({addr.octets[0], addr.octets[1], addr.octets[2], addr.octets[3], addr.octets[4], addr.octets[5]});
}

eui48_t mac_to_num(vanetza::MacAddress addr)
{
    eui48_t ret;
    ret.octets[0] = addr.octets[0];
    ret.octets[1] = addr.octets[1];
    ret.octets[2] = addr.octets[2];
    ret.octets[3] = addr.octets[3];
    ret.octets[4] = addr.octets[4];
    ret.octets[5] = addr.octets[5];
    return ret;
}

void insert_autotalks_header_transmit(const vanetza::access::DataRequest& request, std::unique_ptr<vanetza::ChunkPacket>& packet, uint8_t* pData, uint16_t length)
{
    // There cannot be an assignment as three dots (...) are gcc extension that does not work in g++
    // => initialize the structure manually
    //v2x_send_params_t send_params = V2X_SEND_PARAMS_INIT;
    v2x_send_params_t send_params;
    send_params.source_address = EUI48_ZERO_INIT;
    send_params.dest_address = EUI48_BCAST_INIT;
    send_params.user_priority = USER_PRIORITY_NA;
    send_params.channel_id = V2X_CHANNEL_ID_INIT;
    send_params.datarate = DATARATE_NA;
    send_params.power_dbm8 = POWER_DBM8_NA;
    send_params.transmit_diversity_power_dbm8 = POWER_DBM8_NA;
    send_params.expiry_time_ms = V2X_EXPIRY_TIME_MS_NA;
    for (uint8_t i = 0; i < RF_INDEX_MAX; i++)
        send_params.comp_data[i] = COMPENSATOR_DATA_INIT;

    vanetza::access::G5LinkLayer link_layer;
    vanetza::access::ieee802::dot11::QosDataHeader& mac_header = link_layer.mac_header;
    mac_header.destination = request.destination_addr;
    mac_header.source = request.source_addr;
    mac_header.qos_control.user_priority(request.access_category);

    send_params.dest_address = mac_to_num(request.destination_addr);
    send_params.source_address = mac_to_num(request.source_addr);
    //mac_header.qos_control.user_priority(request.access_category);
    //send_params.user_priority = mac_header.qos_control.raw; TODO later

    /* Set TX power to -10 dB */
    send_params.power_dbm8 = -80;

    /* Set user priority */
    send_params.user_priority = 0;

    /* Set default data rate */
    send_params.datarate = DATARATE_DEFAULT_VALUE;

    vanetza::ByteBuffer link_layer_buffer;
    vanetza::serialize_into_buffer(link_layer, link_layer_buffer);

    vanetza::ByteBuffer buffer;
    packet->layer(vanetza::OsiLayer::Physical).convert(buffer);

    autotalks_send(pData, length, &send_params, NULL);
}

boost::optional<vanetza::EthernetHeader> strip_autotalks_rx_header(vanetza::CohesivePacket& packet, v2x_receive_params_t rx_params)
{
    vanetza::access::G5LinkLayer link_layer;
    vanetza::ByteBuffer link_layer_buffer;
    link_layer.mac_header.destination = num_to_mac(rx_params.dest_address);
    link_layer.mac_header.source = num_to_mac(rx_params.source_address);
    link_layer.llc_snap_header.protocol_id = vanetza::access::ethertype::GeoNetworking;
    vanetza::serialize_into_buffer(link_layer, link_layer_buffer);
    assert(link_layer_buffer.size() == vanetza::access::G5LinkLayer::length_bytes);

    const vanetza::ByteBuffer& data_buffer = packet.buffer();
    vanetza::ByteBuffer final;
    for (auto i : link_layer_buffer)
        final.push_back(i);
    for (auto i : data_buffer)
        final.push_back(i);

    vanetza::CohesivePacket finalPkt(final, vanetza::OsiLayer::Physical);
    finalPkt.set_boundary(vanetza::OsiLayer::Physical, 0);
    finalPkt.set_boundary(vanetza::OsiLayer::Link, vanetza::access::G5LinkLayer::length_bytes);
    finalPkt.set_boundary(vanetza::OsiLayer::Network, packet.size());

    packet.set_boundary(vanetza::OsiLayer::Physical, 0);
    packet.set_boundary(vanetza::OsiLayer::Link, vanetza::access::G5LinkLayer::length_bytes);

    packet = finalPkt;

    vanetza::EthernetHeader eth;
    eth.destination = num_to_mac(rx_params.dest_address);
    eth.source = num_to_mac(rx_params.source_address);
    eth.type = vanetza::access::ethertype::GeoNetworking; // This is set in the Autotalks API initialization

    return eth;
}

static void* v2x_rx_thread_entry(void * arg)
{
    AutotalksLink* link = (AutotalksLink*) arg;
    atlk_rc_t rc;
    (void) arg;
    v2x_receive_params_t rx_params;
    size_t rx_buffer_size;

    while (!endRxThread) {
        rx_buffer_size = sizeof(v2x_rx_buffer);
        atlk_wait_t wait = {ATLK_WAIT_TYPE_INTERVAL, 100000};
        rc = autotalks_receive(v2x_rx_buffer, &rx_buffer_size, &rx_params, &wait);
        if (rc == ATLK_E_TIMEOUT)
            continue;
        else if (atlk_error(rc)) {
            std::cerr << "Receive failed: " << rc << ", " << atlk_rc_to_str(rc) << ", RX thread ends." << std::endl;
            break;
        }
        else {
            std::cout << "Autotalks receive successful" << std::endl;
            if (nullptr != link)
                link->data_received(v2x_rx_buffer, rx_buffer_size, rx_params);
        }
        usleep(1000);
    }
    return NULL;
}

void init_rx(AutotalksLink* link_layer)
{
    // Create new thread as Autotalks API does not have asynchronous callbacks
    int rv = pthread_create(&v2x_rx_thread, NULL, v2x_rx_thread_entry, link_layer);
    if (0 != rv) {
        fprintf(stderr, "pthread_create failed with %s\n", strerror(rv));
    }
    printf("pthread_create success!\n");
}

} // namespace autotalks
} // namespace vanetza

