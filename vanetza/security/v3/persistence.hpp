#pragma once
#include <vanetza/security/v3/certificate.hpp>
#include <string>

namespace vanetza
{
namespace security
{
namespace v3
{

/**
 * \brief Loads a certificate from a file
 * \param certificate_path file to load the certificate from
 * \return loaded certificate
 */
Certificate load_certificate_from_file(const std::string& certificate_path);

/**
 * \brief Saves a certificate to a file
 * \param certificate_path file to save the certificate to
 * \param certificate certificate to save
 */
void save_certificate_to_file(const std::string& certificate_path, const Certificate& certificate);

} // namespace v3
} // namespace security
} // namespace vanetza
