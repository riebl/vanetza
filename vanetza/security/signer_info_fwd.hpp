#ifndef SIGNER_INFO_FWD_HPP_9K6GXK4R
#define SIGNER_INFO_FWD_HPP_9K6GXK4R

#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/public_key.hpp>
#include <cstdint>
#include <list>

namespace vanetza
{
namespace security
{

struct Certificate;

enum class SignerInfoType : uint8_t
{
    Self = 0,                                   //nothing
    Certificate_Digest_With_EDCSAP256 = 1,      //HashedId8
    Certificate = 2,                            //Certificate
    Certificate_Chain = 3,                      //std::list<Certificate>
    Certificate_Digest_With_Other_Algorithm = 4 //CertificateDigestWithOtherAlgorithm
};

struct CertificateDigestWithOtherAlgorithm
{
    PublicKeyAlgorithm algorithm;
    HashedId8 digest;
};

typedef boost::variant<HashedId8, Certificate, std::list<Certificate>, CertificateDigestWithOtherAlgorithm> SignerInfo;

} // namespace security
} // namespace vanetza

#endif /* SIGNER_INFO_FWD_HPP_9K6GXK4R */
