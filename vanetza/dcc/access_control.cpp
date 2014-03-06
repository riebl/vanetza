#include "access_control.hpp"
#include "scheduler.hpp"
#include <vanetza/access/data_request.hpp>
#include <vanetza/access/interface.hpp>

namespace vanetza
{
namespace dcc
{

AccessControl::AccessControl(Scheduler& sc, access::Interface& ifc) :
    m_scheduler(sc), m_access(ifc)
{
}

void AccessControl::request(const DataRequest& dcc_req, std::unique_ptr<ChunkPacket> packet)
{
    const auto tx_delay = m_scheduler.delay(dcc_req.dcc_profile);
    const auto ac = map_profile_onto_ac(dcc_req.dcc_profile);

    if (tx_delay <= std::chrono::milliseconds(0)) {
        access::DataRequest mac_req;
        mac_req.source_addr = dcc_req.source;
        mac_req.destination_addr = dcc_req.destination;
        mac_req.ether_type = dcc_req.ether_type;
        mac_req.access_category = ac;

        m_scheduler.notify(dcc_req.dcc_profile);
        m_access.request(mac_req, std::move(packet));
    } else {
        // drop packet
    }
}

AccessCategory map_profile_onto_ac(Profile dp_id)
{
    AccessCategory ac = AccessCategory::BE;

    switch (dp_id)
    {
        case Profile::DP0:
            ac = AccessCategory::VO;
            break;
        case Profile::DP1:
            ac = AccessCategory::VI;
            break;
        case Profile::DP2:
            ac = AccessCategory::BE;
            break;
        case Profile::DP3:
            ac = AccessCategory::BK;
            break;
        default:
            throw std::invalid_argument("Invalid DCC Profile ID");
            break;
    }

    return ac;
}

} // namespace dcc
} // namespace vanetza
