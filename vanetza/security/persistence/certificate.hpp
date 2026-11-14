#pragma once
#include <vanetza/common/expected.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <filesystem>
#include <system_error>

namespace vanetza
{
namespace security
{
namespace persistence
{

/**
 * Load a v3 certificate from a file containing its OER encoding
 * \param path certificate file
 * \return certificate or error, std::errc::illegal_byte_sequence for malformed content
 */
expected<v3::Certificate> load_v3_certificate(const std::filesystem::path& path);

/**
 * Save a v3 certificate as file containing its OER encoding
 * \param path certificate file, replaced if it exists
 * \param certificate saved certificate
 * \return error, std::errc::invalid_argument for a certificate failing OER encoding
 */
std::error_code save_certificate(const std::filesystem::path& path, const v3::Certificate& certificate);

} // namespace persistence
} // namespace security
} // namespace vanetza
