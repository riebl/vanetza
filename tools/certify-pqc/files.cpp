#include "files.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/persistence/certificate.hpp>
#include <vanetza/security/persistence/file.hpp>
#include <vanetza/security/persistence/key_reference.hpp>
#include <stdexcept>
#include <utility>

namespace
{

using vanetza::ByteBuffer;
using vanetza::expected;
namespace persistence = vanetza::security::persistence;

// commands of this tool report failures by exceptions
[[noreturn]] void fail(const std::string& action, const std::string& path, std::error_code error)
{
    throw std::runtime_error("cannot " + action + " " + path + ": " + error.message());
}

template<typename T>
T value_or_fail(expected<T> result, const std::string& action, const std::string& path)
{
    if (!result) {
        fail(action, path, result.error());
    }
    return std::move(*result);
}

void succeed_or_fail(std::error_code error, const std::string& action, const std::string& path)
{
    if (error) {
        fail(action, path, error);
    }
}

template<typename T>
T load_exact(const std::string& path, std::size_t expected_size, const char* description)
{
    T output { value_or_fail(persistence::read_file(path), "read", path) };
    if (output.bytes.size() != expected_size) {
        throw std::runtime_error(
            std::string(description) + " has an invalid size in: " + path);
    }
    return output;
}

} // namespace

vanetza::security::KeyReference load_ecc_key_reference(const std::string& base_path)
{
    const std::string path = base_path + ".key";
    return value_or_fail(persistence::load_key_reference(path), "load ECC key reference", path);
}

vanetza::security::PublicKey load_ecc_public_key(const std::string& base_path)
{
    using namespace vanetza::security;
    const std::string path = base_path + ".pub";
    const ByteBuffer point = value_or_fail(persistence::read_file(path), "read", path);
    const boost::optional<PublicKey> public_key = decode_ec_point(KeyType::NistP256, point);
    if (!public_key) {
        throw std::runtime_error("ECC public key is no NIST P-256 point in: " + path);
    }
    return *public_key;
}

void save_ecc_key(
    const std::string& base_path, const vanetza::security::KeyReference& reference,
    const vanetza::security::PublicKey& public_key)
{
    const ByteBuffer point = vanetza::security::encode_ec_point(public_key);
    if (reference.data.empty() || point.empty()) {
        throw std::invalid_argument("cannot save malformed ECC key");
    }
    succeed_or_fail(persistence::save_key_reference(base_path + ".key", reference),
        "save ECC key reference", base_path + ".key");
    succeed_or_fail(persistence::write_file(base_path + ".pub", point), "write", base_path + ".pub");
}

vanetza::security::KeyReference load_pqc_key_reference(const std::string& base_path)
{
    const std::string path = base_path + ".pqc.key";
    return value_or_fail(persistence::load_key_reference(path), "load FN-DSA-512 key reference", path);
}

vanetza::security::pqc::PublicKey load_pqc_public_key(const std::string& base_path)
{
    using namespace vanetza::security::pqc;
    return load_exact<PublicKey>(base_path + ".pqc.pub", fndsa512_public_key_size, "FN-DSA-512 public key");
}

void save_pqc_key(const std::string& base_path, const vanetza::security::pqc::SigningKey& key)
{
    using namespace vanetza::security::pqc;
    if (key.reference.data.empty() || key.public_key.bytes.size() != fndsa512_public_key_size) {
        throw std::invalid_argument("cannot save malformed FN-DSA-512 key");
    }
    succeed_or_fail(persistence::save_key_reference(base_path + ".pqc.key", key.reference),
        "save FN-DSA-512 key reference", base_path + ".pqc.key");
    succeed_or_fail(persistence::write_file(base_path + ".pqc.pub", key.public_key.bytes),
        "write", base_path + ".pqc.pub");
}

vanetza::security::v3::Certificate load_v3_certificate(const std::string& path)
{
    return value_or_fail(persistence::load_v3_certificate(path), "load V3 certificate", path);
}

void save_v3_certificate(
    const std::string& path, const vanetza::security::v3::Certificate& certificate)
{
    std::string error;
    if (!certificate.validate(error)) {
        throw std::runtime_error("refusing to save invalid V3 certificate: " + error);
    }
    succeed_or_fail(persistence::save_certificate(path, certificate), "save V3 certificate", path);
}
