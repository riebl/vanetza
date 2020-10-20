#ifndef ROUTER_CONTEXT_HPP_KIPUYBY2
#define ROUTER_CONTEXT_HPP_KIPUYBY2

#include "dcc_passthrough.hpp"
#include "link_layer.hpp"
#include <vanetza/btp/port_dispatcher.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/router.hpp>
#include <array>
#include <list>
#include <memory>

class Application;
class TimeTrigger;

class RouterContext
{
public:
    RouterContext(const vanetza::geonet::MIB&, TimeTrigger&, vanetza::PositionProvider&, vanetza::security::SecurityEntity*);
    ~RouterContext();
    void enable(Application*);
    void disable(Application*);

    /**
     * Allow/disallow transmissions without GNSS position fix
     *
     * \param flag true if transmissions shall be dropped when no GNSS position fix is available
     */
    void require_position_fix(bool flag);

    void set_link_layer(LinkLayer*);

private:
    void indicate(vanetza::CohesivePacket&& packet, const vanetza::EthernetHeader& hdr);
    void log_packet_drop(vanetza::geonet::Router::PacketDropReason);
    void update_position_vector();
    void update_packet_flow(const vanetza::geonet::LongPositionVector&);

    vanetza::geonet::MIB mib_;
    vanetza::geonet::Router router_;
    TimeTrigger& trigger_;
    vanetza::PositionProvider& positioning_;
    vanetza::btp::PortDispatcher dispatcher_;
    std::unique_ptr<DccPassthrough> request_interface_;
    std::list<Application*> applications_;
    bool require_position_fix_ = false;
};

#endif /* ROUTER_CONTEXT_HPP_KIPUYBY2 */
