#include <vanetza/security/v3/certificate.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

Certificate::Certificate() :
    asn1::asn1c_oer_wrapper<EtsiTs103097Certificate_t>(asn_DEF_EtsiTs103097Certificate)
{

}

HashedId8 calculate_hash(const Certificate& cert)
{
    
}

} // namespace v3
} // namespace security
} // namespace vanetza
