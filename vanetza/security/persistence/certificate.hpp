#pragma once
#include <vanetza/common/expected.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <filesystem>
#include <system_error>
#include <type_traits>

namespace vanetza
{
namespace security
{
namespace persistence
{

/**
 * Load a v2 certificate from a file containing its serialization
 * \param path certificate file
 * \return certificate or error, std::errc::illegal_byte_sequence for malformed content
 */
expected<v2::Certificate> load_v2_certificate(const std::filesystem::path& path);

/**
 * Save a v2 certificate as file containing its serialization
 * \param path certificate file, replaced if it exists
 * \param certificate saved certificate
 * \return error, std::errc::invalid_argument for a certificate failing serialization
 */
std::error_code save_certificate(const std::filesystem::path& path, const v2::Certificate& certificate);

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

/**
 * Load a certificate of given type from a file
 * \tparam Certificate v2::Certificate or v3::Certificate
 * \param path certificate file
 * \return certificate or error, see load_v2_certificate and load_v3_certificate
 */
template<typename Certificate>
expected<Certificate> load_certificate(const std::filesystem::path& path)
{
    if constexpr (std::is_same_v<Certificate, v2::Certificate>) {
        return load_v2_certificate(path);
    } else {
        static_assert(std::is_same_v<Certificate, v3::Certificate>, "unsupported certificate type");
        return load_v3_certificate(path);
    }
}

} // namespace persistence
} // namespace security
} // namespace vanetza
