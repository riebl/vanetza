#pragma once
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/expected.hpp>
#include <filesystem>
#include <system_error>

namespace vanetza
{
namespace security
{
namespace persistence
{

/**
 * Read a file's content
 * \param path file
 * \return content or error, e.g. std::errc::no_such_file_or_directory
 */
expected<ByteBuffer> read_file(const std::filesystem::path& path);

/**
 * Write a file, replacing any previous content
 * \param path file
 * \param content written content
 * \return error, e.g. std::errc::no_such_file_or_directory for a missing directory
 */
std::error_code write_file(const std::filesystem::path& path, const ByteBuffer& content);

/**
 * Write a file accessible only by its owner, replacing any previous content
 *
 * Existing files are restricted before content is written to them,
 * as far as std::filesystem::permissions supports it on the platform.
 * \param path file
 * \param content written content
 * \return error, e.g. std::errc::no_such_file_or_directory for a missing directory
 */
std::error_code write_owner_only_file(const std::filesystem::path& path, const ByteBuffer& content);

} // namespace persistence
} // namespace security
} // namespace vanetza
