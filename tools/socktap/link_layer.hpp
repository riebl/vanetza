#ifndef LINK_LAYER_HPP_FGEK0QTH
#define LINK_LAYER_HPP_FGEK0QTH

#include "ethernet_device.hpp"
#include <vanetza/access/interface.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <boost/asio/io_service.hpp>
#include <memory>
#include <string>

class LinkLayerIndication
{
public:
    using IndicationCallback = std::function<void(vanetza::CohesivePacket&&, const vanetza::EthernetHeader&)>;

    virtual void indicate(IndicationCallback) = 0;
    virtual ~LinkLayerIndication() = default;
};

class LinkLayer : public vanetza::access::Interface, public LinkLayerIndication
{
};

std::unique_ptr<LinkLayer>
create_link_layer(boost::asio::io_service&, const EthernetDevice&, const std::string& name);

#endif /* LINK_LAYER_HPP_FGEK0QTH */

