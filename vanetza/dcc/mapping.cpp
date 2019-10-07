#include "mapping.hpp"
#include <stdexcept>

namespace vanetza
{
namespace dcc
{

access::AccessCategory map_profile_onto_ac(Profile dp_id)
{
    access::AccessCategory ac = access::AccessCategory::BE;

    switch (dp_id)
    {
        case Profile::DP0:
            ac = access::AccessCategory::VO;
            break;
        case Profile::DP1:
            ac = access::AccessCategory::VI;
            break;
        case Profile::DP2:
            ac = access::AccessCategory::BE;
            break;
        case Profile::DP3:
            ac = access::AccessCategory::BK;
            break;
        default:
            throw std::invalid_argument("Invalid DCC Profile ID");
            break;
    }

    return ac;
}

} // namespace dcc
} // namespace vanetza
