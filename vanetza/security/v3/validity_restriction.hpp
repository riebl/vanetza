#pragma once
#include <cstdint>

namespace vanetza
{
namespace security
{
namespace v3
{

using Time32 = std::uint32_t;

struct StartAndEndValidity
{
    StartAndEndValidity() = default;
    StartAndEndValidity(Time32 start, Time32 end);

    Time32 start_validity;
    Time32 end_validity;
};

} // namespace v3
} // namespace security
} // namespace vanetza
