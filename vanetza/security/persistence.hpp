#pragma once
#include <vanetza/security/ecdsa256.hpp>
#include <string>

namespace vanetza
{
namespace security
{

ecdsa256::KeyPair load_private_key_from_pem_file(const std::string& key_path);
ecdsa256::KeyPair load_private_key_from_der_file(const std::string& key_path);

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
