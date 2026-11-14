#pragma once
#include <vanetza/common/expected.hpp>
#include <vanetza/security/key_reference.hpp>
#include <filesystem>
#include <system_error>

namespace vanetza
{
namespace security
{
namespace persistence
{

/**
 * Load a key reference of a SecurityModule from a file
 * \param path file containing the reference
 * \return key reference or error, std::errc::illegal_byte_sequence for an empty file
 */
expected<KeyReference> load_key_reference(const std::filesystem::path& path);

/**
 * Save a key reference of a SecurityModule to a file accessible only by its owner
 *
 * References may contain private key material depending on their SecurityModule, see write_owner_only_file.
 * \param path file, replaced if it exists
 * \param reference key reference
 * \return error, std::errc::invalid_argument for an empty reference
 */
std::error_code save_key_reference(const std::filesystem::path& path, const KeyReference& reference);

} // namespace persistence
} // namespace security
} // namespace vanetza
