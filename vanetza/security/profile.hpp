#ifndef PROFILE_HPP_K04O16SX
#define PROFILE_HPP_K04O16SX

#include <cstdint>

namespace vanetza
{
namespace security
{

enum class Profile : uint8_t
{
    Generic = 0,
    CAM = 1,
    DENM = 2
};

} // namespace security
} // namespace vanetza

#endif /* PROFILE_HPP_K04O16SX */

