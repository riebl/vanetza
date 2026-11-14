#include <vanetza/security/pem.hpp>
#include <vanetza/security/persistence/file.hpp>
#include <vanetza/security/persistence/public_key.hpp>
#include <string>

namespace vanetza
{
namespace security
{
namespace persistence
{

namespace
{

const std::string pem_label = "PUBLIC KEY";

expected<PublicKey> decode_public_key(const ByteBuffer& der)
{
    const boost::optional<PublicKey> key = decode_subject_public_key_info(der);
    if (!key) {
        return std::make_error_code(std::errc::illegal_byte_sequence);
    }
    return *key;
}

} // namespace

expected<PublicKey> load_public_key_pem(const std::filesystem::path& path)
{
    const expected<ByteBuffer> content = read_file(path);
    if (!content) {
        return content.error();
    }
    const boost::optional<ByteBuffer> der = decode_pem(pem_label, std::string(content->begin(), content->end()));
    if (!der) {
        return std::make_error_code(std::errc::illegal_byte_sequence);
    }
    return decode_public_key(*der);
}

expected<PublicKey> load_public_key_der(const std::filesystem::path& path)
{
    const expected<ByteBuffer> der = read_file(path);
    if (!der) {
        return der.error();
    }
    return decode_public_key(*der);
}

std::error_code save_public_key_pem(const std::filesystem::path& path, const PublicKey& key)
{
    const ByteBuffer der = encode_subject_public_key_info(key);
    if (der.empty()) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    const std::string pem = encode_pem(pem_label, der);
    return write_file(path, ByteBuffer(pem.begin(), pem.end()));
}

std::error_code save_public_key_der(const std::filesystem::path& path, const PublicKey& key)
{
    const ByteBuffer der = encode_subject_public_key_info(key);
    if (der.empty()) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    return write_file(path, der);
}

} // namespace persistence
} // namespace security
} // namespace vanetza
