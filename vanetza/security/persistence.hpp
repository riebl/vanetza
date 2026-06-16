#pragma once
#include <vanetza/security/private_key.hpp>
#include <string>

namespace vanetza
{
namespace security
{

/**
 * Load a private key from a PEM file, deriving its type from the stored curve.
 * \param key_path PEM file to load the key from
 * \return loaded private key
 */
PrivateKey load_private_key_from_pem_file(const std::string& key_path);

/**
 * Load a private key from a DER file, deriving its type from the stored curve.
 * \param key_path DER file to load the key from
 * \return loaded private key
 */
PrivateKey load_private_key_from_der_file(const std::string& key_path);

#ifdef VANETZA_WITH_OPENSSL
PrivateKey load_private_key_from_pem_file_openssl(const std::string& key_path);
PrivateKey load_private_key_from_der_file_openssl(const std::string& key_path);
#endif

#ifdef VANETZA_WITH_CRYPTOPP
PrivateKey load_private_key_from_pem_file_cryptopp(const std::string& key_path);
PrivateKey load_private_key_from_der_file_cryptopp(const std::string& key_path);
#endif

} // namespace security
} // namespace vanetza
