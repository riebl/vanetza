#pragma once

#include "keys.hpp"
#include "security_module.hpp"
#include "sha.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <cstddef>

namespace vanetza
{
namespace pki
{

struct EncryptedSymmetricKey
{
    PublicKey public_key;
    ByteBuffer authentication_tag;
    ByteBuffer wrapped_key;
};

EncryptedSymmetricKey encrypt_key(SecurityModule&, const SecurityModule::EciesContext&, const ByteBuffer& key,
    const Sha256Hash& info);

} // namespace pki
} // namespace vanetza
