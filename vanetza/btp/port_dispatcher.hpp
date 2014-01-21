#ifndef PORT_DISPATCHER_HPP_YZ0UTAUF
#define PORT_DISPATCHER_HPP_YZ0UTAUF

#include <vanetza/btp/data_interface.hpp>
#include <vanetza/btp/header.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/transport_interface.hpp>
#include <unordered_map>

namespace vanetza
{

namespace btp
{

using geonet::UpPacket;

class PortDispatcher : public geonet::TransportInterface
{
public:
    void set_non_interactive_handler(port_type, IndicationInterface*);
    void indicate(const geonet::DataIndication&, std::unique_ptr<UpPacket>) override;

private:
    typedef std::unordered_map<port_type, IndicationInterface*> port_map;
    port_map m_non_interactive_handlers;
};

} // namespace btp
} // namespace vanetza

#endif /* PORT_DISPATCHER_HPP_YZ0UTAUF */

