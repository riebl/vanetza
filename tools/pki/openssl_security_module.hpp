#pragma once

#include "keys.hpp"
#include "security_module.hpp"
#include "sha.hpp"
#include <vanetza/security/openssl_security_module.hpp>

namespace vanetza
{
namespace pki
{

using security::CredentialStorage;
using security::OpenSslSecurityModule;

} // namespace pki
} // namespace vanetza
