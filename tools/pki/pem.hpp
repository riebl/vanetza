#pragma once

#include "keys.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <boost/optional/optional.hpp>
#include <filesystem>
#include <string>

namespace vanetza
{
namespace pki
{

boost::optional<PrivateKey> parse_pem_private_key(const std::string&);
boost::optional<PrivateKey> parse_pem_private_key(const ByteBuffer&);

/**
 * Encode an EC private key as unencrypted PKCS#8 PEM.
 * Round-trips through parse_pem_private_key.
 */
std::string make_pem(const PrivateKey&);

/**
 * Encode `priv` as PEM and write it to `path`.
 *
 * \throws std::runtime_error if the file cannot be created
 * \throws OpenSslException on write failure
 */
void write_pem_private_key(const PrivateKey& priv, const std::filesystem::path& path);

} // namespace pki
} // namespace vanetza
