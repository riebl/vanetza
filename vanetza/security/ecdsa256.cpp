#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <algorithm>
#include <cassert>

namespace vanetza
{
namespace security
{
namespace ecdsa256
{

PublicKey create_public_key(const Uncompressed& unc)
{
    PublicKey pb;
    assert(unc.x.size() == pb.x.size());
    assert(unc.y.size() == pb.y.size());
    std::copy_n(unc.x.begin(), pb.x.size(), pb.x.begin());
    std::copy_n(unc.y.begin(), pb.y.size(), pb.y.begin());
    return pb;
}

bool operator==(const PublicKey& lhs, const PublicKey& rhs)
{
    return lhs.x == rhs.x && lhs.y == rhs.y;
}

bool operator!=(const PublicKey& lhs, const PublicKey& rhs)
{
    return !(lhs == rhs);
}

bool operator==(const PrivateKey& lhs, const PrivateKey& rhs)
{
    return lhs.key == rhs.key;
}

bool operator!=(const PrivateKey& lhs, const PrivateKey& rhs)
{
    return !(lhs == rhs);
}

} // namespace ecdsa256
} // namespace security
} // namespace vanetza
