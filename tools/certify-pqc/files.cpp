#include "files.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <sys/stat.h>

namespace
{

using vanetza::ByteBuffer;

ByteBuffer read_file(const std::string& path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("cannot open file for reading: " + path);
    }
    return ByteBuffer(std::istreambuf_iterator<char>(stream), {});
}

void write_file(const std::string& path, const ByteBuffer& data)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream || !stream.write(
            reinterpret_cast<const char*>(data.data()), data.size())) {
        throw std::runtime_error("cannot write file: " + path);
    }
}

// key references give access to private keys, thus only their owner may read them
void write_key_reference(const std::string& path, const vanetza::security::KeyReference& reference)
{
    write_file(path, reference.data);
    if (::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        throw std::runtime_error("cannot restrict key reference permissions: " + path);
    }
}

template<typename T>
T load_exact(const std::string& path, std::size_t expected_size, const char* description)
{
    T output { read_file(path) };
    if (output.bytes.size() != expected_size) {
        throw std::runtime_error(
            std::string(description) + " has an invalid size in: " + path);
    }
    return output;
}

} // namespace

vanetza::security::KeyReference load_ecc_key_reference(const std::string& base_path)
{
    return vanetza::security::KeyReference { read_file(base_path + ".key") };
}

vanetza::security::PublicKey load_ecc_public_key(const std::string& base_path)
{
    using namespace vanetza::security;
    const std::string path = base_path + ".pub";
    const boost::optional<PublicKey> public_key = decode_ec_point(KeyType::NistP256, read_file(path));
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
    write_key_reference(base_path + ".key", reference);
    write_file(base_path + ".pub", point);
}

vanetza::security::KeyReference load_pqc_key_reference(const std::string& base_path)
{
    return vanetza::security::KeyReference { read_file(base_path + ".pqc.key") };
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
    write_key_reference(base_path + ".pqc.key", key.reference);
    write_file(base_path + ".pqc.pub", key.public_key.bytes);
}

vanetza::security::v3::Certificate load_v3_certificate(const std::string& path)
{
    vanetza::security::v3::Certificate certificate;
    const auto encoded = read_file(path);
    if (encoded.empty() || !certificate.decode(encoded)) {
        throw std::runtime_error("cannot decode V3 certificate: " + path);
    }
    return certificate;
}

void save_v3_certificate(
    const std::string& path, const vanetza::security::v3::Certificate& certificate)
{
    std::string error;
    if (!certificate.validate(error)) {
        throw std::runtime_error("refusing to save invalid V3 certificate: " + error);
    }
    write_file(path, certificate.encode());
}
