#ifndef SOCKTAP_UTILS
#define SOCKTAP_UTILS

#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/certificate.hpp>

/**
 * \brief Loads a private key from the local filesystem.
 */
vanetza::security::ecdsa256::KeyPair load_private_key_from_file(const std::string& key_path);

/**
 * \brief Loads a certificate from the local filesystem.
 */
vanetza::security::Certificate load_certificate_from_file(const std::string& certificate_path);

#endif /* SOCKTAP_UTILS */
