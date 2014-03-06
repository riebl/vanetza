#ifndef ACCESS_CONTROL_HPP_OXJ73CEM
#define ACCESS_CONTROL_HPP_OXJ73CEM

#include <vanetza/common/clock.hpp>
#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/net/access_category.hpp>
#include <vanetza/net/chunk_packet.hpp>
#include <memory>

namespace vanetza
{

// forward declarations
class ChunkPacket;
namespace access { class Interface; }

namespace dcc
{

// forward declarations
struct DataRequest;
class Scheduler;

class AccessControl
{
public:
    AccessControl(Scheduler&, access::Interface&);
    void request(const DataRequest&, std::unique_ptr<ChunkPacket>);

private:
    Scheduler& m_scheduler;
    access::Interface& m_access;
};

/**
 * Map DCC Profile to EDCA access category
 * \param profile DCC Profile ID
 * \return mapped access category
 */
AccessCategory map_profile_onto_ac(Profile);

} // namespace dcc
} // namespace vanetza

#endif /* ACCESS_CONTROL_HPP_OXJ73CEM */

