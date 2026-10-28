#include <vanetza/security/security_module.hpp>

namespace vanetza
{
namespace security
{

bool SecurityModule::can_sign(const PublicKey& key)
{
    static const ByteBuffer probe { 0x12, 0x34, 0x56, 0x78 };
    return sign(probe, key).has_value();
}

} // namespace security
} // namespace vanetza
