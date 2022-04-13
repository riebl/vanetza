#ifndef AUTOTALKS_LINK_HPP_
#define AUTOTALKS_LINK_HPP_

#include "raw_socket_link.hpp"
#include "atlk/v2x_service.h"
#include <iostream>

class AutotalksLink : public LinkLayer
{
public:

    AutotalksLink(void);
    void request(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>) override;
    void indicate(IndicationCallback callback) override;
    void data_received(uint8_t*, uint16_t, v2x_receive_params_t);

private:
    static constexpr std::size_t layers_ = num_osi_layers(vanetza::OsiLayer::Physical, vanetza::OsiLayer::Application);
    IndicationCallback callback_;
    std::array<vanetza::ByteBuffer, layers_> buffers_;
};



#endif /* AUTOTALKS_LINK_HPP_ */

