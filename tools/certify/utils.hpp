#ifndef CERTIFY_UTILS_HPP
#define CERTIFY_UTILS_HPP

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <memory>
#include <string>

void permission_string_to_buffer(const std::string&, vanetza::ByteBuffer&);

/**
 * Names of built-in security modules including the default, e.g. for help texts
 */
std::string security_module_names();

/**
 * Create a built-in security module
 * \param name name of module or "default"
 * \return module, std::runtime_error is thrown if it is not built in
 */
std::unique_ptr<vanetza::security::SecurityModule> create_security_module_or_throw(const std::string& name);

/**
 * Create the default crypto provider
 * \return crypto provider, std::runtime_error is thrown if none is built in
 */
std::unique_ptr<vanetza::security::CryptoProvider> create_crypto_provider_or_throw();

/**
 * Load a v2 certificate file
 * \return certificate, std::runtime_error is thrown if it cannot be loaded
 */
vanetza::security::v2::Certificate load_v2_certificate_or_throw(const std::string& path);

/**
 * Load a key reference file
 * \return key reference, std::runtime_error is thrown if it cannot be loaded
 */
vanetza::security::KeyReference load_key_reference_or_throw(const std::string& path);

/**
 * Check if a file starts like a PEM-encoded file
 * \return true for a PEM file, std::runtime_error is thrown if it cannot be read
 */
bool is_pem_file(const std::string& path);

/**
 * Get public key of a referenced key, v2 certificates require NIST P-256 keys
 * \param path key reference file
 * \return public key, std::runtime_error is thrown otherwise
 */
vanetza::security::PublicKey referenced_public_key_or_throw(vanetza::security::SecurityModule& module,
    const vanetza::security::KeyReference& key, const std::string& path);

/**
 * Load public key of a subject, i.e. of a PEM SubjectPublicKeyInfo file or a key reference file
 * \param module security module holding referenced keys
 * \return NIST P-256 public key, std::runtime_error is thrown otherwise
 */
vanetza::security::PublicKey load_subject_key_or_throw(const std::string& path,
    vanetza::security::SecurityModule& module);

/**
 * Verification key attribute of v2 certificates
 */
vanetza::security::v2::VerificationKey make_v2_verification_key(const vanetza::security::PublicKey& key);

/**
 * Sign a v2 certificate by a referenced NIST P-256 key, see TS 103 097 v1.2.1 clause 7.4
 */
void sign_v2_certificate_or_throw(vanetza::security::v2::Certificate& certificate,
    vanetza::security::SecurityModule& module, vanetza::security::CryptoProvider& crypto,
    const vanetza::security::KeyReference& key);

/**
 * Save a v2 certificate file
 */
void save_v2_certificate_or_throw(const std::string& path, const vanetza::security::v2::Certificate& certificate);

#endif /* CERTIFY_UTILS_HPP */
