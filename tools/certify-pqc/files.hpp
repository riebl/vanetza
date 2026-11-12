#pragma once

#include <vanetza/security/key_reference.hpp>
#include <vanetza/security/pqc/fndsa512.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <string>

vanetza::security::KeyReference load_ecc_key_reference(const std::string& base_path);
vanetza::security::PublicKey load_ecc_public_key(const std::string& base_path);
void save_ecc_key(
    const std::string& base_path, const vanetza::security::KeyReference&, const vanetza::security::PublicKey&);

vanetza::security::KeyReference load_pqc_key_reference(const std::string& base_path);
vanetza::security::pqc::PublicKey load_pqc_public_key(const std::string& base_path);
void save_pqc_key(const std::string& base_path, const vanetza::security::pqc::SigningKey&);

vanetza::security::v3::Certificate load_v3_certificate(const std::string& path);
void save_v3_certificate(
    const std::string& path, const vanetza::security::v3::Certificate&);
