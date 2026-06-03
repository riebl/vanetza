#pragma once

#include "asn1.hpp"
#include <vanetza/asn1/security/AuthorizationResponseCode.h>
#include <vanetza/asn1/security/EnrolmentResponseCode.h>
#include <string>

namespace vanetza
{
namespace pki
{

using EnrolmentResponseCode = asn1c_enum<enum Vanetza_Security_EnrolmentResponseCode>;
using AuthorizationResponseCode = asn1c_enum<enum Vanetza_Security_AuthorizationResponseCode>;

std::string to_string(EnrolmentResponseCode);
std::string to_string(AuthorizationResponseCode);

} // namespace pki
} // namespace vanetza
