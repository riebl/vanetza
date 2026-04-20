#include <vanetza/security/public_key.hpp>
#include <boost/algorithm/hex.hpp>
#include <cstdint>
#include <iterator>

namespace vanetza
{
namespace security
{

std::string canonical_hexstring(const PublicKey& key)
{
    const std::size_t expected_length = key_length(key.type);
    if (expected_length == 0 || key.x.size() != expected_length) {
        return {};
    }

    std::string input;
    switch (key.compression) {
        case KeyCompression::NoCompression:
            if (key.y.size() != expected_length) {
                return {};
            }
            input.push_back(*key.y.rbegin() % 2 == 0 ? 0x02 : 0x03);
            break;
        case KeyCompression::Y0:
            input.push_back(0x02);
            break;
        case KeyCompression::Y1:
            input.push_back(0x03);
            break;
        default:
            return {};
    }
    std::copy(key.x.begin(), key.x.end(), std::back_inserter(input));
    return boost::algorithm::hex(input);
}

ByteBuffer encode_subject_public_key_info(const PublicKey& key)
{
    const std::size_t expected_length = key_length(key.type);
    if (expected_length == 0 || key.x.size() != expected_length) {
        return {};
    }

    // RFC 5480: id-ecPublicKey OBJECT IDENTIFIER ::= { 1.2.840.10045.2.1 }
    static const uint8_t oid_ec_public_key[] = {
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
    };
    // RFC 5480: secp256r1 (NIST P-256) OID 1.2.840.10045.3.1.7
    static const uint8_t oid_secp256r1[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    // RFC 5639: brainpoolP256r1 OID 1.3.36.3.3.2.8.1.1.7
    static const uint8_t oid_brainpoolP256r1[] = {
        0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07
    };
    // RFC 5639: brainpoolP384r1 OID 1.3.36.3.3.2.8.1.1.11
    static const uint8_t oid_brainpoolP384r1[] = {
        0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B
    };

    const uint8_t* named_curve_oid = nullptr;
    std::size_t named_curve_oid_size = 0;
    switch (key.type) {
        case KeyType::NistP256:
            named_curve_oid = oid_secp256r1;
            named_curve_oid_size = sizeof(oid_secp256r1);
            break;
        case KeyType::BrainpoolP256r1:
            named_curve_oid = oid_brainpoolP256r1;
            named_curve_oid_size = sizeof(oid_brainpoolP256r1);
            break;
        case KeyType::BrainpoolP384r1:
            named_curve_oid = oid_brainpoolP384r1;
            named_curve_oid_size = sizeof(oid_brainpoolP384r1);
            break;
        default:
            return {};
    }

    uint8_t ec_point_prefix = 0;
    std::size_t ec_point_size = 0;
    switch (key.compression) {
        case KeyCompression::NoCompression:
            if (key.y.size() != expected_length) {
                return {};
            }
            ec_point_prefix = 0x04;
            ec_point_size = 1 + 2 * expected_length;
            break;
        case KeyCompression::Y0:
            ec_point_prefix = 0x02;
            ec_point_size = 1 + expected_length;
            break;
        case KeyCompression::Y1:
            ec_point_prefix = 0x03;
            ec_point_size = 1 + expected_length;
            break;
        default:
            return {};
    }

    const std::size_t algo_content_size = sizeof(oid_ec_public_key) + named_curve_oid_size;
    const std::size_t bit_string_content_size = 1 + ec_point_size; // leading "unused bits" byte
    const std::size_t spki_content_size = 2 + algo_content_size + 2 + bit_string_content_size;

    ByteBuffer result;
    result.reserve(2 + spki_content_size);

    result.push_back(0x30); // SEQUENCE (SubjectPublicKeyInfo)
    result.push_back(static_cast<uint8_t>(spki_content_size));

    result.push_back(0x30); // SEQUENCE (AlgorithmIdentifier)
    result.push_back(static_cast<uint8_t>(algo_content_size));
    result.insert(result.end(), oid_ec_public_key, oid_ec_public_key + sizeof(oid_ec_public_key));
    result.insert(result.end(), named_curve_oid, named_curve_oid + named_curve_oid_size);

    result.push_back(0x03); // BIT STRING (subjectPublicKey)
    result.push_back(static_cast<uint8_t>(bit_string_content_size));
    result.push_back(0x00); // unused bits
    result.push_back(ec_point_prefix);
    result.insert(result.end(), key.x.begin(), key.x.end());
    if (key.compression == KeyCompression::NoCompression) {
        result.insert(result.end(), key.y.begin(), key.y.end());
    }

    return result;
}

} // namespace security
} // namespace vanetza
