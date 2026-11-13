#include <vanetza/security/public_key.hpp>
#include <vanetza/common/byte_view.hpp>
#include <boost/algorithm/hex.hpp>
#include <algorithm>
#include <array>
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

namespace
{

/**
 * Append big-endian integer with exactly the given length
 * \return false if the integer is missing or its value needs more octets
 */
bool append_integer(ByteBuffer& buffer, const ByteBuffer& integer, std::size_t length)
{
    auto significant = std::find_if(integer.begin(), integer.end(), [](std::uint8_t octet) { return octet != 0; });
    const std::size_t significant_length = std::distance(significant, integer.end());
    if (integer.empty() || significant_length > length) {
        return false;
    }
    buffer.insert(buffer.end(), length - significant_length, 0x00);
    buffer.insert(buffer.end(), significant, integer.end());
    return true;
}

// RFC 5480: id-ecPublicKey OBJECT IDENTIFIER ::= { 1.2.840.10045.2.1 }
const std::array<uint8_t, 9> oid_ec_public_key = {{
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
}};

// RFC 5480: secp256r1 (NIST P-256) OID 1.2.840.10045.3.1.7
const std::array<uint8_t, 10> oid_secp256r1 = {{
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
}};

// RFC 5639: brainpoolP256r1 OID 1.3.36.3.3.2.8.1.1.7
const std::array<uint8_t, 11> oid_brainpoolP256r1 = {{
    0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07
}};

// RFC 5639: brainpoolP384r1 OID 1.3.36.3.3.2.8.1.1.11
const std::array<uint8_t, 11> oid_brainpoolP384r1 = {{
    0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B
}};

/**
 * DER encoded OBJECT IDENTIFIER of a key type's named curve
 * \return OID, or empty range for unsupported key types
 */
byte_view_range named_curve_oid(KeyType type)
{
    switch (type) {
        case KeyType::NistP256:
            return create_byte_view(oid_secp256r1);
        case KeyType::BrainpoolP256r1:
            return create_byte_view(oid_brainpoolP256r1);
        case KeyType::BrainpoolP384r1:
            return create_byte_view(oid_brainpoolP384r1);
        default:
            return byte_view_range { byte_view_iterator {}, byte_view_iterator {} };
    }
}

// AlgorithmIdentifier content of EC public keys: id-ecPublicKey followed by the named curve OID of a key type
bool matches_ec_algorithm(const byte_view_range& algorithm, KeyType type)
{
    const byte_view_range ec_public_key = create_byte_view(oid_ec_public_key);
    const auto curve_begin = algorithm.begin() + ec_public_key.size();
    return algorithm.size() == ec_public_key.size() + named_curve_oid(type).size() &&
        byte_view_range { algorithm.begin(), curve_begin } == ec_public_key &&
        byte_view_range { curve_begin, algorithm.end() } == named_curve_oid(type);
}

/**
 * Read DER header with short-form length, which suffices for SubjectPublicKeyInfo of supported curves
 * \param position of header, advanced to its content
 * \return content length, or none if header mismatches tag or its content exceeds der
 */
boost::optional<std::size_t> read_der_header(const ByteBuffer& der, std::size_t& position, uint8_t tag)
{
    if (position + 2 > der.size() || der[position] != tag || der[position + 1] >= 0x80) {
        return boost::none;
    }
    const std::size_t length = der[position + 1];
    position += 2;
    if (position + length > der.size()) {
        return boost::none;
    }
    return length;
}

} // namespace

ByteBuffer encode_ec_point(const PublicKey& key)
{
    const std::size_t length = key_length(key.type);
    if (length == 0) {
        return {};
    }

    ByteBuffer encoded;
    switch (key.compression) {
        case KeyCompression::NoCompression:
            encoded.reserve(1 + 2 * length);
            encoded.push_back(0x04);
            break;
        case KeyCompression::Y0:
            encoded.reserve(1 + length);
            encoded.push_back(0x02);
            break;
        case KeyCompression::Y1:
            encoded.reserve(1 + length);
            encoded.push_back(0x03);
            break;
        default:
            return {};
    }

    if (!append_integer(encoded, key.x, length)) {
        return {};
    } else if (key.compression == KeyCompression::NoCompression && !append_integer(encoded, key.y, length)) {
        return {};
    }
    return encoded;
}

boost::optional<PublicKey> decode_ec_point(KeyType type, const ByteBuffer& encoded)
{
    const std::size_t length = key_length(type);
    if (length == 0 || encoded.empty()) {
        return boost::none;
    }

    PublicKey key;
    key.type = type;
    const auto x = encoded.begin() + 1;
    if (encoded.front() == 0x04 && encoded.size() == 1 + 2 * length) {
        key.compression = KeyCompression::NoCompression;
        key.x.assign(x, x + length);
        key.y.assign(x + length, encoded.end());
    } else if ((encoded.front() == 0x02 || encoded.front() == 0x03) && encoded.size() == 1 + length) {
        key.compression = encoded.front() == 0x02 ? KeyCompression::Y0 : KeyCompression::Y1;
        key.x.assign(x, encoded.end());
    } else {
        return boost::none;
    }
    return key;
}

ByteBuffer encode_subject_public_key_info(const PublicKey& key)
{
    const byte_view_range curve_oid = named_curve_oid(key.type);
    if (curve_oid.size() == 0) {
        return {};
    }

    const ByteBuffer ec_point = encode_ec_point(key);
    if (ec_point.empty()) {
        return {};
    }

    const std::size_t algo_content_size = oid_ec_public_key.size() + curve_oid.size();
    const std::size_t bit_string_content_size = 1 + ec_point.size(); // leading "unused bits" byte
    const std::size_t spki_content_size = 2 + algo_content_size + 2 + bit_string_content_size;

    ByteBuffer result;
    result.reserve(2 + spki_content_size);

    result.push_back(0x30); // SEQUENCE (SubjectPublicKeyInfo)
    result.push_back(static_cast<uint8_t>(spki_content_size));

    result.push_back(0x30); // SEQUENCE (AlgorithmIdentifier)
    result.push_back(static_cast<uint8_t>(algo_content_size));
    result.insert(result.end(), oid_ec_public_key.begin(), oid_ec_public_key.end());
    result.insert(result.end(), curve_oid.begin(), curve_oid.end());

    result.push_back(0x03); // BIT STRING (subjectPublicKey)
    result.push_back(static_cast<uint8_t>(bit_string_content_size));
    result.push_back(0x00); // unused bits
    result.insert(result.end(), ec_point.begin(), ec_point.end());

    return result;
}

boost::optional<PublicKey> decode_subject_public_key_info(const ByteBuffer& der)
{
    std::size_t position = 0;
    const boost::optional<std::size_t> spki_length = read_der_header(der, position, 0x30);
    if (!spki_length || position + *spki_length != der.size()) {
        return boost::none;
    }

    // AlgorithmIdentifier: id-ecPublicKey followed by the OID of a supported named curve
    const boost::optional<std::size_t> algorithm_length = read_der_header(der, position, 0x30);
    if (!algorithm_length) {
        return boost::none;
    }
    const auto algorithm_begin = der.begin() + position;
    const byte_view_range algorithm { algorithm_begin, algorithm_begin + *algorithm_length };
    position += *algorithm_length;
    KeyType type = KeyType::Unspecified;
    for (KeyType candidate : { KeyType::NistP256, KeyType::BrainpoolP256r1, KeyType::BrainpoolP384r1 }) {
        if (matches_ec_algorithm(algorithm, candidate)) {
            type = candidate;
        }
    }
    if (type == KeyType::Unspecified) {
        return boost::none;
    }

    // subjectPublicKey: BIT STRING without unused bits enclosing the EC point
    const boost::optional<std::size_t> bit_string_length = read_der_header(der, position, 0x03);
    if (!bit_string_length || *bit_string_length == 0 || position + *bit_string_length != der.size()) {
        return boost::none;
    } else if (der[position] != 0x00) {
        return boost::none;
    }
    return decode_ec_point(type, ByteBuffer(der.begin() + position + 1, der.end()));
}

} // namespace security
} // namespace vanetza
