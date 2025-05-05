#ifndef AUTOTALKSNET_HPP_
#define AUTOTALKSNET_HPP_

#include <boost/asio/io_service.hpp>
#include <kj/async.h>
#include <optional>
#include <thread>
#include <vanetza/net/mac_address.hpp>
#include <vanetza/access/data_request.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <vanetza/net/cohesive_packet.hpp>

#include "ll/vanetza.capnp.h"


namespace vanetza
{
namespace autotalks_net
{

#define V2X_TX_POWER                0           /* Transmit power in units of 1/8 dBm */
#define V2X_TX_DATARATE_DEFAULT     12          /* 6 MBbit/s */

/**
 * Convert received L2-ID value (vector) to MAC address (set first three octets to the value, following reset
 * to 0).
 * @param  addr 24-bit L2-ID
 * @retval MAC address
 */
vanetza::MacAddress numVecL2IdToMac(const std::vector<uint8_t>& data);

/**
 * Convert received MAC address from vector to the Vanetza format.
 * @param  pData Value to convert
 * @retval Converted value
 */
vanetza::MacAddress numVecToMac(std::vector<uint8_t> data);

/**
 * Physical layer operation mode.
 * Aligned with vanetza::geonet::InterfaceType
 */
typedef enum
{
    ITS_G5 = 1, /*< DSRC */
    C_V2X = 2   /*< LTE-V */

} V2XOperationMode_t;

/**
 * V2X frame structure for RPC communication
 */
struct V2xFrame
{
    std::vector<uint8_t> SrcAddress;    /*< Source address */
    std::vector<uint8_t> DstAddress;    /*< Destination address */
    std::vector<uint8_t> Data;          /*< Frame data */
    enum V2XPacketType
    {
        Unspecified,
        Wlan,
        CV2X
    };
    /**
     * Parameters for WLAN devices in OCB mode (IEEE 802.11 p and bd)
     */
    struct WlanParameters_t
    {
        uint8_t Priority;   /*< 802.1 user priority (0-7) */
        int16_t Power;      /*< dBm scaled by 8 */
        uint16_t Datarate;  /*< Mbps scaled by 2 (500kbps steps) */
    };
    /**
     * Parameters for C-V2X devices (LTE-V2X and 5G-V2X)
     */
    struct Cv2xParameters_t
    {
        uint8_t Priority;   /*< PPPP (0-7) */
        int16_t Power;      /*< dBm scaled by 8 */
    };
    WlanParameters_t WlanParameters;
    Cv2xParameters_t Cv2xParameters;
};

/**
 * Channel busy ration for RPC communication
 */
struct ChannelBusyRatio
{
    uint16_t Busy;      /*< Number of samples sensed as busy */
    uint16_t Samples;   /*< Total number of samples in measurement interval */
};


class AutotalksNet
{
    public:
        /**
         * Constructor.
         * @param  mode V2X radio mode
         * @param  io Boost IO service for reception
         * @param  endpoint RPC endpoint address (e.g. localhost:8947)
         * @retval None
         */
        AutotalksNet(V2XOperationMode_t mode, boost::asio::io_service& io, const std::string& endpoint);

        /**
         * Destructor.
         * @param  None
         * @retval None
         */
        ~AutotalksNet(void);

        /**
         * Request creating and sending of the packet from the upper layer.
         * @param  request Request parameters
         * @param  pData Data from link layer upwards
         * @param  length Length of the pData array
         * @param  interface V2X radio interface for correct parameter filling
         * @retval None
         */
        void Transmit(const vanetza::access::DataRequest& request, uint8_t* pData, uint16_t length,
                      vanetza::geonet::InterfaceType interface);

        /**
         * Send MAC address change request.
         * @param  addr MAC address to set
         * @retval None
         */
        void SetMac(const std::vector<uint8_t>& addr);

        /**
         * Set indication callback.
         * @param  callback Callback to set
         * @retval None
         */
        void Indicate(std::function<void(const V2xFrame&)> callback);

        /**
         * Set DCC indication callback.
         * @param  callback Callback to set
         * @retval None
         */
        void IndicateDcc(std::function<void(const ChannelBusyRatio&)> callback);

        /**
         * Set indication for device address change.
         * @param  callback Callback to set
         * @retval None
         */
        void IndicateAddressChange(std::function<void(const vanetza::MacAddress& address)> callback);

        /*
         * Parse information from received V2X packet.
         * @param  packet Packet abstraction to fill
         * @param  frame Received data
         * @retval Parser Ethernet header
         */
        boost::optional<vanetza::EthernetHeader> strip_rx_header(vanetza::CohesivePacket& packet,
                                                                 const V2xFrame& frame);

        /**
         * Set callback for requesting sending of V2X data to RPC.
         * @param  callback Callback to set
         * @retval None
         */
        void SetNetRequest(std::function<void(const vanetza::access::DataRequest&, uint8_t*, uint16_t,
                                              vanetza::geonet::InterfaceType)> callback);

        /**
         * Set callback for setting MAC address via RPC.
         * @param  callback Callback to set
         * @retval None
         */
        void SetNetMacRequest(std::function<void(const std::vector<uint8_t>& address)> callback);

        /**
         * Set exit callback.
         * @param  callback Callback to call on exiting
         * @retvak None
         */
        void SetExitCallback(std::function<void(kj::PromiseFulfillerPair<void>* pPaf)> callback);

        /**
         * V2X reception callback.
         * @param  frame Received V2X frame
         * @retval None
         */
        void PacketReception(const V2xFrame& frame);

        /**
         * CBR reception callback.
         * @param  cbr Received channel busy ratioReceived data
         * @retval None
         */
        void CbrReception(const ChannelBusyRatio& cbr);

        /**
         * Callback when device source address was changed.
         * @param  address Vanetza address structure
         * @retval None
         */
        void AddressChanged(const vanetza::MacAddress& address);

    private:
        /**
         * V2X reception callback to the upper layer.
         * @param  Received V2X frame
         * @retval None
         */
        std::function<void(const V2xFrame&)> packetRxCallback_;

        /**
         * CBR reception callback to the upper layer.
         * @param  Channel Busy Ratio
         * @retval None
         */
        std::function<void(const ChannelBusyRatio&)> packetCbrRxCallback_;

        /**
         * Device address change callback to the upper layer.
         * @param  Address
         * @retval None
         */
        std::function<void(const vanetza::MacAddress& address)> addressChangeCallback_;

        /**
         * Handle for RPC communication thread
         */
        std::thread rpcThread_;

        /**
         * Device operation mode. Note that correct DSP binary file must be used (rename
         * dsp_sw_rev3_cv2x.bin or dsp_sw_rev3_dsrc.bin to dsp_sw_rev3.bin after device reboot - set in
         * startup script located in ext-fs/usr/bin/at_startup)
         */
        V2XOperationMode_t mode_;

        /**
         * Start the kj event loop.
         * @param  endpoint String with IP address and port pair
         * @retval None
         */
        void rpcThreadMain(const std::string& endpoint);

        /**
         * Boost context for callbacks from KJ library
         */
        boost::asio::io_context& boostIoContext;

        std::function<void(const vanetza::access::DataRequest&, uint8_t*,
                           uint16_t, vanetza::geonet::InterfaceType)> rpcTransmit_;

        std::function<void(const std::vector<uint8_t>& address)> rpcMacTransmit_;

        /**
         * Called on destroying this class. This is needed so that rpcThread_ does not end sooner
         * than KJ event loop stops its execution.
         */
        std::function<void(kj::PromiseFulfillerPair<void>* pPaf)> exitCallback_;

        /**
         * Set to true when no more sending should be done
         */
        bool disconnected_;

        /**
         * Pointer to promise/fulfiller used when ending execution
         */
        std::atomic<kj::PromiseFulfillerPair<void>*> paf_;
};


/**
 * LinkLayer client implementation
 */
struct LinkLayerImpl final : public vanetza::rpc::LinkLayer::Server
{
    public:
        LinkLayerImpl(vanetza::rpc::LinkLayer::Client& client, AutotalksNet* pNet);

        virtual ~LinkLayerImpl(void);

        /**
         * Request packet transmission from the upper layer.
         * @param  request Vanetza data request
         * @param  pData Packet data
         * @param  length Packet data length
         */
        void Transmit(const vanetza::access::DataRequest& request, uint8_t* pData, uint16_t length,
                      vanetza::geonet::InterfaceType interface);

        /**
         * Request MAC address change request.
         * @param  address MAC address to set
         * @retval None
         */
        void TransmitMacChange(const std::vector<uint8_t>& address);

        /**
         * Identify the server.
         * @param  None
         * @retval None
         */
        void Identify(void);

        /**
         * Called when the program is exiting.
         * @param  Fulfiller for unblocking RPC thread.
         * @retval None
         */
        void Exit(kj::PromiseFulfillerPair<void>* pPaf);

    private:
        /**
         * RPC client
         */
        vanetza::rpc::LinkLayer::Client& linkLayerClient_;

        /**
         * Executor to be accessible from another threads
         */
        const kj::Executor& executor_;

        /**
         * This is needed for correct shutdown
         */
        AutotalksNet* net_;
};

/**
 * DataListener Implementation (Client-side callback)
 */
class DataListenerImpl final : public vanetza::rpc::LinkLayer::DataListener::Server
{
    public:
        /**
         * Constructor.
         * @param  io_context Boost IO context
         * @param  pNet RPC network connection
         * @retval None
         */
        DataListenerImpl(boost::asio::io_context& io_context, AutotalksNet* pNet);

        /**
         * Destructor.
         * @param  None
         * @retval None
         */
        virtual ~DataListenerImpl(void) { }

        /**
         * Server data reception callback.
         * @param  context Data indication context
         * @retval Fulfilled promise
         */
        kj::Promise<void> onDataIndication(OnDataIndicationContext context) override;

    private:
        /**
         * IO context for passing messages back to Boost runtime
         */
        boost::asio::io_context& io_context_;

        /**
         * Executor to be accessible from another threads
         */
        const kj::Executor& executor_;

        /**
         * This is needed for correct shutdown
         */
        AutotalksNet* net_;
};


/**
 * DataListener Implementation (Client-side callback)
 */
class CbrListenerImpl final : public vanetza::rpc::LinkLayer::CbrListener::Server
{
    public:
        /**
         * Constructor.
         * @param  io_context Boost IO context
         * @param  pNet RPC network connection
         * @retval None
         */
        CbrListenerImpl(boost::asio::io_context& io_context, AutotalksNet* pNet);

        /**
         * Destructor.
         * @param  None
         * @retval None
         */
        virtual ~CbrListenerImpl(void) { }

        /**
         * Server CBR reception callback.
         * @param  context CBR report indication context
         * @retval Fulfilled promise
         */
        kj::Promise<void> onCbrReport(OnCbrReportContext context) override;

    private:
        /**
         * IO context for passing messages back to Boost runtime
         */
        boost::asio::io_context& io_context_;

        /**
         * Executor to be accessible from another threads
         */
        const kj::Executor& executor_;

        /**
         * This is needed for correct shutdown
         */
        AutotalksNet* net_;
};



}   // namespace vanetza
}   // namespace autotalks_net



#endif /* AUTOTALKS_NET_HPP_ */
