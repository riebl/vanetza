#pragma once
#include <vanetza/common/expected.hpp>
#include <vanetza/security/public_key.hpp>
#include <filesystem>
#include <system_error>

namespace vanetza
{
namespace security
{
namespace persistence
{

/**
 * Load an EC public key from a PEM file containing its SubjectPublicKeyInfo
 * \param path PEM file of label "PUBLIC KEY"
 * \return public key or error, std::errc::illegal_byte_sequence for malformed content
 */
expected<PublicKey> load_public_key_pem(const std::filesystem::path& path);

/**
 * Load an EC public key from a DER file containing its SubjectPublicKeyInfo
 * \param path DER file
 * \return public key or error, std::errc::illegal_byte_sequence for malformed content
 */
expected<PublicKey> load_public_key_der(const std::filesystem::path& path);

/**
 * Save an EC public key as PEM file containing its SubjectPublicKeyInfo
 * \param path PEM file, replaced if it exists
 * \param key public key
 * \return error, std::errc::invalid_argument for a malformed key
 */
std::error_code save_public_key_pem(const std::filesystem::path& path, const PublicKey& key);

/**
 * Save an EC public key as DER file containing its SubjectPublicKeyInfo
 * \param path DER file, replaced if it exists
 * \param key public key
 * \return error, std::errc::invalid_argument for a malformed key
 */
std::error_code save_public_key_der(const std::filesystem::path& path, const PublicKey& key);

} // namespace persistence
} // namespace security
} // namespace vanetza
