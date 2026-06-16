#ifndef VANETZA_SECURITY_PERSISTENCE_HPP
#define VANETZA_SECURITY_PERSISTENCE_HPP

#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/public_key.hpp>
#include <iosfwd>

namespace vanetza
{
namespace security
{
namespace v2
{

/**
 * \brief Loads a private key from a file
 * \param key_path file to load the key from
 * \return loaded key
 */
ecdsa256::KeyPair load_private_key_from_file(const std::string& key_path);

/**
 * \brief Save a private key pair to a stream in PKCS#8 DER format (secp256r1)
 * \param os destination stream
 * \param key_pair key pair to be stored
 * \return true if successfully written
 */
bool save_private_key_pkcs8_der(std::ostream& os, const ecdsa256::KeyPair& key_pair);

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

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* VANETZA_SECURITY_PERSISTENCE_HPP */
