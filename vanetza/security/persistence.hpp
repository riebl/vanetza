#pragma once
#include <vanetza/security/ecdsa256.hpp>
#include <iosfwd>
#include <string>

namespace vanetza
{
namespace security
{

ecdsa256::KeyPair load_private_key_from_pem_file(const std::string& key_path);
ecdsa256::KeyPair load_private_key_from_der_file(const std::string& key_path);

/**
 * Save private key to stream in PKCS#8 DER format.
 * 
 * \param os destination stream
 * \param key_pair key pair to be stored
 * \return true if succesfully written
 */
bool save_private_key_pkcs8_der(std::ostream& os, const ecdsa256::KeyPair& key_pair);

#ifdef VANETZA_WITH_OPENSSL
ecdsa256::KeyPair load_private_key_from_pem_file_openssl(const std::string& key_path);
ecdsa256::KeyPair load_private_key_from_der_file_openssl(const std::string& key_path);
#endif

#ifdef VANETZA_WITH_CRYPTOPP
ecdsa256::KeyPair load_private_key_from_pem_file_cryptopp(const std::string& key_path);
ecdsa256::KeyPair load_private_key_from_der_file_cryptopp(const std::string& key_path);
#endif

} // namespace security
} // namespace vanetza
