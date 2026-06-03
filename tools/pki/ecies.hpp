#pragma once

#include "security_module.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <cstddef>

namespace vanetza
{
namespace pki
{

using Sha256Function = std::function<Sha256Hash(const ByteBuffer&)>;

ByteBuffer calculate_kdf2(SecurityModule&, const ByteBuffer& shared_secret, const ByteBuffer& kdp, std::size_t dl);
ByteBuffer calculate_kdf2(Sha256Function, const ByteBuffer& shared_secret, const ByteBuffer& kdp, std::size_t dl);

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
