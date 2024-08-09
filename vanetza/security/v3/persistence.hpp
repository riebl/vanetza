#pragma once
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v2/public_key.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

/**
 * \brief Loads a private key from a file
 * \param key_path file to load the key from
 * \return loaded key
 */
ecdsa256::KeyPair load_private_key_from_file(const std::string& key_path);

/**
 * \brief Loads a public key from a file
 * \param key_path file to load the key from
 * \return loaded key
 */
v2::PublicKey load_public_key_from_file(const std::string& key_path);

/**
 * \brief Saves a public key to a file
 * \param key_path file to save the key to
 * \param public_key key to save
 */
void save_public_key_to_file(const std::string& key_path, const v2::PublicKey& public_key);

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

} // namespace v2
} // namespace security
} // namespace vanetza

