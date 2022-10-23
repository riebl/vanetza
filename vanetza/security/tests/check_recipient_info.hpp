#ifndef CHECK_RECIPIENT_INFO_HPP_NMX7BFYV
#define CHECK_RECIPIENT_INFO_HPP_NMX7BFYV

#include <vanetza/security/v2/recipient_info.hpp>

namespace vanetza
{
namespace security
{
namespace v2
{

void check(const EciesEncryptedKey&, const EciesEncryptedKey&);
void check(const OpaqueKey&, const OpaqueKey&);
void check(const Key&, const Key&);
void check(const RecipientInfo&, const RecipientInfo&);

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* CHECK_RECIPIENT_INFO_HPP_NMX7BFYV */
