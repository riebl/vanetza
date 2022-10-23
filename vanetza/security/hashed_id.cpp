#include <vanetza/security/hashed_id.hpp>
#include <algorithm>
#include <cassert>

namespace vanetza
{
namespace security
{

HashedId3 truncate(const HashedId8& in)
{
    HashedId3 out;
    assert(out.size() <= in.size());
    std::copy_n(in.rbegin(), out.size(), out.rbegin());
    return out;
}

} // namespace security
} // namespace vanetza