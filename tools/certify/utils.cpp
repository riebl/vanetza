#include "utils.hpp"
#include <vanetza/security/persistence/certificate.hpp>
#include <vanetza/security/persistence/file.hpp>
#include <vanetza/security/persistence/key_reference.hpp>
#include <vanetza/security/persistence/public_key.hpp>
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <sstream>

void permission_string_to_buffer(const std::string& in, vanetza::ByteBuffer& out)
{
    if (out.empty()) {
        throw std::invalid_argument("SSP buffer lacks version byte.");
    }

    const std::size_t expected_bits = (out.size() - 1 /* version */) * 8;
    if (in.size() != expected_bits) {
        std::stringstream ss;
        ss << "Size mismatch, expected " << (out.size() - 1) << " bytes encoded with one bit per byte.";
        throw std::runtime_error(ss.str());
    }

    uint8_t byte = 0;
    int index = 0;

    for (auto it = in.begin(); it < in.end(); ++it) {
        byte <<= 1;

        if (*it == '0') {
            byte &= 0xFE; // clear last bit
        } else if (*it == '1') {
            byte |= 1; // set last bit
        } else {
            throw std::runtime_error("Unexpected character in permissions, expected only '0' and '1'.");
        }

        if ((index + 1) % 8 == 0) {
            out.at(1 /* version */ + (index / 8)) = byte;
            byte = 0;
        }

        ++index;
    }
}

std::string security_module_names()
{
    std::string names = "default";
    for (const std::string& name : vanetza::security::builtin_security_modules().names()) {
        names += "," + name;
    }
    return names;
}

std::unique_ptr<vanetza::security::SecurityModule> create_security_module_or_throw(const std::string& name)
{
    std::unique_ptr<vanetza::security::SecurityModule> module = vanetza::security::create_security_module(name);
    if (!module) {
        throw std::runtime_error("security module '" + name + "' is not built in");
    }
    return module;
}

std::unique_ptr<vanetza::security::CryptoProvider> create_crypto_provider_or_throw()
{
    std::unique_ptr<vanetza::security::CryptoProvider> crypto = vanetza::security::create_crypto_provider();
    if (!crypto) {
        throw std::runtime_error("no crypto provider is built in");
    }
    return crypto;
}

vanetza::security::v2::Certificate load_v2_certificate_or_throw(const std::string& path)
{
    vanetza::expected<vanetza::security::v2::Certificate> certificate =
        vanetza::security::persistence::load_v2_certificate(path);
    if (!certificate) {
        throw std::runtime_error("cannot load certificate " + path + ": " + certificate.error().message());
    }
    return std::move(*certificate);
}

vanetza::security::KeyReference load_key_reference_or_throw(const std::string& path)
{
    vanetza::expected<vanetza::security::KeyReference> reference =
        vanetza::security::persistence::load_key_reference(path);
    if (!reference) {
        throw std::runtime_error("cannot load key reference " + path + ": " + reference.error().message());
    }
    return std::move(*reference);
}

bool is_pem_file(const std::string& path)
{
    static const std::string pem_begin = "-----BEGIN";
    const vanetza::expected<vanetza::ByteBuffer> content = vanetza::security::persistence::read_file(path);
    if (!content) {
        throw std::runtime_error("cannot read " + path + ": " + content.error().message());
    }
    return content->size() >= pem_begin.size() && std::equal(pem_begin.begin(), pem_begin.end(), content->begin());
}

vanetza::security::PublicKey referenced_public_key_or_throw(vanetza::security::SecurityModule& module,
    const vanetza::security::KeyReference& key, const std::string& path)
{
    const vanetza::expected<vanetza::security::PublicKey> public_key = module.public_key(key);
    if (!public_key) {
        throw std::runtime_error("cannot use key reference " + path + ": " + public_key.error().message());
    } else if (public_key->type != vanetza::security::KeyType::NistP256) {
        throw std::runtime_error("key of " + path + " is no NIST P-256 key as required by v2 certificates");
    }
    return *public_key;
}

vanetza::security::PublicKey load_subject_key_or_throw(const std::string& path,
    vanetza::security::SecurityModule& module)
{
    if (!is_pem_file(path)) {
        return referenced_public_key_or_throw(module, load_key_reference_or_throw(path), path);
    }

    const vanetza::expected<vanetza::security::PublicKey> public_key =
        vanetza::security::persistence::load_public_key_pem(path);
    if (!public_key) {
        throw std::runtime_error("cannot load public key " + path + ": " + public_key.error().message());
    } else if (public_key->type != vanetza::security::KeyType::NistP256) {
        throw std::runtime_error("public key of " + path + " is no NIST P-256 key as required by v2 certificates");
    }
    return *public_key;
}

vanetza::security::v2::VerificationKey make_v2_verification_key(const vanetza::security::PublicKey& key)
{
    using namespace vanetza::security;
    v2::ecdsa_nistp256_with_sha256 ecdsa;
    switch (key.compression) {
        case KeyCompression::Y0:
            ecdsa.public_key = Compressed_Lsb_Y_0 { key.x };
            break;
        case KeyCompression::Y1:
            ecdsa.public_key = Compressed_Lsb_Y_1 { key.x };
            break;
        default:
            ecdsa.public_key = Uncompressed { key.x, key.y };
            break;
    }
    v2::VerificationKey verification_key;
    verification_key.key = ecdsa;
    return verification_key;
}

void sign_v2_certificate_or_throw(vanetza::security::v2::Certificate& certificate,
    vanetza::security::SecurityModule& module, vanetza::security::CryptoProvider& crypto,
    const vanetza::security::KeyReference& key)
{
    using namespace vanetza::security;
    sort(certificate);
    const vanetza::ByteBuffer data = v2::convert_for_signing(certificate);
    const Sha256Hash digest = crypto.calculate_sha256_hash(data.data(), data.size());
    const vanetza::expected<Signature> signature =
        module.sign(vanetza::ByteBuffer(digest.octets.begin(), digest.octets.end()), key);
    if (!signature) {
        throw std::runtime_error("cannot sign certificate: " + signature.error().message());
    } else if (signature->type != KeyType::NistP256) {
        throw std::runtime_error("cannot sign certificate: v2 certificates require a NIST P-256 key");
    }

    EcdsaSignature ecdsa;
    ecdsa.R = X_Coordinate_Only { signature->r };
    ecdsa.s = signature->s;
    certificate.signature = ecdsa;
}

void save_v2_certificate_or_throw(const std::string& path, const vanetza::security::v2::Certificate& certificate)
{
    const std::error_code error = vanetza::security::persistence::save_certificate(path, certificate);
    if (error) {
        throw std::runtime_error("cannot save certificate " + path + ": " + error.message());
    }
}
