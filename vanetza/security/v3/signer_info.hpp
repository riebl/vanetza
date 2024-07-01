
#pragma once

#include <vanetza/security/v2/basic_elements.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/public_key.hpp>
#include <boost/variant/recursive_wrapper.hpp>
#include <boost/variant/variant.hpp>
#include <cstddef>
#include <cstdint>
#include <list>

namespace vanetza
{
namespace security
{
namespace v3
{

struct Certificate;

/// described in TS 103 097 v1.2.1, section 4.2.11
enum class SignerInfoType : uint8_t
{
    Self = 0,                                   // nothing -> nullptr_t
    Certificate_Digest_With_SHA256 = 1,         // HashedId8
    Certificate = 2,                            // Certificate
    Certificate_Chain = 3,                      // std::list<Certificate>
};

/// described in TS 103 097 v1.2.1, section 4.2.10
using SignerInfo = boost::variant<
    std::nullptr_t,
    HashedId8,
    Certificate,
    std::list<Certificate>
>;

} // namespace v3
} // namespace security
} // namespace vanetza