#ifndef AUTOTALKS_LINK_HPP_
#define AUTOTALKS_LINK_HPP_

#include <boost/asio/io_context.hpp>
#include <functional>
#include <memory>   /* std::unique_ptr */
#include <vanetza/access/interface.hpp>
#include <vanetza/dcc/channel_load.hpp>

#include "autotalks_net.hpp"
#include "link_layer.hpp"



class AutotalksLink : public LinkLayer
{
    public:
        AutotalksLink(boost::asio::io_context&, const std::string& endpoint, vanetza::geonet::MIB& mib);

        virtual ~AutotalksLink(void) noexcept { }

        /**
         * Request sending of a packet.
         * @param  dataRequest Request to send
         * @param  chunkPacket Packet with the data
         * @retval None
         */
        void request(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>);

        /**
         * Set MAC address.
         * @param  addr Address to set
         * @retval None
         */
        void setMac(const std::vector<uint8_t>& addr);

        /**
         * Set the indication callback.
         * @param  callback Callback to set
         * @retval None
         */
        void indicate(IndicationCallback);

        /**
         * Callback when V2X data is received.
         * @param  frame Received frame
         * @retval None
         */
        void data_received(const vanetza::autotalks_net::V2xFrame& frame);

        /**
         * Add CBR measurement callback to the upper layer.
         * @param  callback Function to be called when CBR measurement (DCC) is received.
         * @retval None
         */
        void addDccCallback(std::function<void(vanetza::dcc::ChannelLoad)> callback);

        /**
         * Called by the lower layer when CBR was measured.
         * @param  cbr Measured channel busy ratio
         * @retval None
         */
        void DccMeasuredCallback(vanetza::dcc::ChannelLoad cbr);

        /**
         * Network data was received.
         * @param  frame Received V2X frame
         * @retval None
         */
        void NetIndicate(const vanetza::autotalks_net::V2xFrame& frame);

        /**
         * DCC data was received.
         * @param  frame DCC value (CBR)
         * @retval None
         */
        void NetDccIndicate(const vanetza::autotalks_net::ChannelBusyRatio& frame);

        /**
         * Sets callback when address was successfully changed.
         * @param  callback Function to call when the address was successfully changed.
         * @retval None
         */
        void setAddressChangeCallback(std::function<void(const vanetza::MacAddress&)> callback);

    protected:
        /**
         * Callback to the upper layer that some data was received
         */
        IndicationCallback callback_;

        /**
         * Callback to the upper layer that CBR measurement was received
         */
        std::function<void(vanetza::dcc::ChannelLoad)> cbrCallback_;

        /**
         * Boost IO context for reception
         */
        boost::asio::io_context& io_;

        /**
         * Transmission to the Autotalks layer
         */
        vanetza::autotalks_net::AutotalksNet autotalksNet_;

        /**
         * Management information base for changing MAC address
         */
        vanetza::geonet::MIB& mib_;
};



#endif /* AUTOTALKS_LINK_HPP_ */
