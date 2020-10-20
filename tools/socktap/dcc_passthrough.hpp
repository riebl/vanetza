#ifndef DCC_PASSTHROUGH_HPP_GSDFESAE
#define DCC_PASSTHROUGH_HPP_GSDFESAE

#include "time_trigger.hpp"
#include <vanetza/access/interface.hpp>
#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/interface.hpp>
#include <vanetza/net/cohesive_packet.hpp>

class DccPassthrough : public vanetza::dcc::RequestInterface
{
public:
    DccPassthrough(vanetza::access::Interface&, TimeTrigger& trigger);

    void request(const vanetza::dcc::DataRequest& request, std::unique_ptr<vanetza::ChunkPacket> packet) override;

    void allow_packet_flow(bool allow);
    bool allow_packet_flow();

private:
    vanetza::access::Interface& access_;
    TimeTrigger& trigger_;
    bool allow_packet_flow_ = true;
};

#endif /* DCC_PASSTHROUGH_HPP_GSDFESAE */
