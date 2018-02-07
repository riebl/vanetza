#ifndef VANETZA_SECURITY_PERSISTENCE_HPP
#define VANETZA_SECURITY_PERSISTENCE_HPP

#include <vanetza/security/certificate.hpp>
#include <vanetza/security/ecdsa256.hpp>

namespace vanetza
{
namespace security
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
PublicKey load_public_key_from_file(const std::string& key_path);

/**
 * \brief Saves a public key to a file
 * \param key_path file to save the key to
 * \param public_key key to save
 */
void save_public_key_to_file(const std::string& key_path, const PublicKey& public_key);

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

} // namespace security
} // namespace vanetza

#endif /* VANETZA_SECURITY_PERSISTENCE_HPP */
