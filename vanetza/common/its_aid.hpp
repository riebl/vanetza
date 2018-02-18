#ifndef ITS_AID_HPP_URKJ51RA
#define ITS_AID_HPP_URKJ51RA

#include <cstdint>

namespace vanetza
{

// uint32_t can hold all relevant ITS AIDs (for now)
using ItsAid = uint32_t;

namespace aid
{

/**
 * ITS-AID assigned for ETSI ITS
 * \see TS 102 965 V1.3.1 Annex A
 */
constexpr ItsAid CA = 36;
constexpr ItsAid DEN = 37;
constexpr ItsAid TLM = 137;
constexpr ItsAid RLT = 138;
constexpr ItsAid IVI = 139;
constexpr ItsAid TLC = 140;
constexpr ItsAid GN_MGMT = 141;
constexpr ItsAid IPV6_ROUTING = 270549118;

} // namespace aid
} // namespace vanetza

#endif /* ITS_AID_HPP_URKJ51RA */

