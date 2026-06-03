#include "signed_data.hpp"
#include <vanetza/asn1/security/Ieee1609Dot2Content.h>

namespace vanetza
{
namespace pki
{

void SignedData::move_into(Vanetza_Security_Ieee1609Dot2Data_t& dest) &&
{
    auto* self = content();
    // Release anything dest already held (normally none) to avoid leaks.
    ASN_STRUCT_FREE(asn_DEF_Vanetza_Security_Ieee1609Dot2Content, dest.content);
    dest.protocolVersion = self->protocolVersion;
    dest.content = self->content;
    self->content = nullptr;
}

} // namespace pki
} // namespace vanetza
