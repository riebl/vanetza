#ifndef CAM_SSP_HPP_GGBE8KES
#define CAM_SSP_HPP_GGBE8KES

#include <vanetza/common/byte_buffer.hpp>
#include <cstdint>
#include <set>
#include <string>

namespace vanetza
{
namespace security
{

/**
 * CAM permission bits
 *
 * These bitmasks describe CA station roles, e.g. emergency vehicles.
 * Some CAM data containers are linked to these roles. Misuse is opposed by checking CAM SSPs.
 *
 * \see EN 302 637-2 V1.3.2, Table 4
 */
enum class CamPermission : uint16_t
{
    // first octet
    CEN_DSRC_Tolling_Zone = 0x80,
    Public_Transport = 0x40,
    Special_Transport = 0x20,
    Dangerous_Goods = 0x10,
    Roadwork = 0x08,
    Rescue = 0x04,
    Emergency = 0x02,
    Safety_Car = 0x01,

    // second octet
    Closed_Lanes = 0x8000,
    Request_For_Right_Of_Way = 0x4000,
    Request_For_Free_Crossing_At_Traffic_Light = 0x2000,
    No_Passing = 0x1000,
    No_Passing_For_Trucks = 0x0800,
    Speed_Limit = 0x0400,
    // 0x0200 and 0x0100 are reserved for future usage
};

/**
 * Set of CAM permissions, i.e. Service Specific Permissions
 *
 * \see EN 302 637-2 V1.3.2, section 6.2.2.2
 */
class CamPermissions
{
public:
    CamPermissions();
    CamPermissions(CamPermission);
    CamPermissions(const std::initializer_list<CamPermission>&);

    // check for permission
    bool has(CamPermission) const;
    bool has(const std::initializer_list<CamPermission>&) const;
    bool has(const CamPermissions&) const;
    bool none() const;

    /**
     * Get set of all included permissions
     * \return permission set
     */
    std::set<CamPermission> permissions() const;

    // permission manipulation (with chaining)
    CamPermissions& add(CamPermission);
    CamPermissions& remove(CamPermission);

    // serialization helpers
    ByteBuffer encode() const;
    static CamPermissions decode(const ByteBuffer&);

private:
    using value_type = std::underlying_type<CamPermission>::type;
    value_type m_bits;
};

/**
 * Get string representation of CAM permission flag
 * \param cp CAM permission flag
 * \return string representation (empty for unknown flags)
 */
std::string stringify(CamPermission);

} // namespace security
} // namespace vanetza

#endif /* CAM_SSP_HPP_GGBE8KES */

