#include "validation.hpp"
#include "certificate.hpp"
#include "hashed_id8.hpp"
#include "security_module.hpp"
#include <vanetza/asn1/security/Certificate.h>
#include <algorithm>
#include <cstring>

namespace vanetza
{
namespace pki
{

static bool operator==(const Vanetza_Security_HashedId8_t& asn, const HashedId8& own)
{
    if (asn.size == own.octets.size()) {
        return std::memcmp(asn.buf, own.octets.data(), own.octets.size()) == 0;
    } else {
        return false;
    }
}

bool check_request_hash(const Sha256Hash& request_digest, const ByteBuffer& response_hash)
{
    constexpr std::size_t request_hash_length = 16;
    return response_hash.size() == request_hash_length &&
           std::equal(response_hash.begin(), response_hash.end(), request_digest.octets.begin());
}

bool validate(SecurityModule& security, const Vanetza_Security_EtsiTs103097Data_t& data, const Certificate& cert)
{
    const Vanetza_Security_SignedData_t* signed_data = get_signed_data(data);
    if (signed_data) {
        return validate(security, *signed_data, cert.raw());
    } else {
        return false;
    }
}

bool validate(SecurityModule& security, const Vanetza_Security_SignedData_t& data,
    const Vanetza_Security_Certificate_t& cert)
{
    HashAlgorithm hash_algo = get_hash_algorithm(data);
    PublicKey public_key = get_public_key(cert);
    Signature signature = make_signature(data.signature);

    if (hash_algo == HashAlgorithm::SHA256) {
        Sha256Hash digest = calculate_digest<Sha256Hash>(security, *data.tbsData, &cert);
        return security.verify(digest, signature, public_key);
    } else if (hash_algo == HashAlgorithm::SHA384) {
        Sha384Hash digest = calculate_digest<Sha384Hash>(security, *data.tbsData, &cert);
        return security.verify(digest, signature, public_key);
    } else {
        return false;
    }
}

const Vanetza_Security_SignedData_t* get_signed_data(const Vanetza_Security_EtsiTs103097Data_t& data)
{
    const Vanetza_Security_SignedData_t* result = nullptr;
    if (data.content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
        result = data.content->choice.signedData;
    }
    return result;
}

const Vanetza_Security_Opaque_t* get_unsecured_data(const Vanetza_Security_EtsiTs103097Data_t& data)
{
    const Vanetza_Security_Opaque_t* result = nullptr;
    if (data.content->present == Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData) {
        result = &data.content->choice.unsecuredData;
    }
    return result;
}

bool signed_by(SecurityModule& security, const Vanetza_Security_SignedData_t& data, const HashedId8& digest)
{
    bool result = false;
    if (data.signer.present == Vanetza_Security_SignerIdentifier_PR_digest) {
        result = (data.signer.choice.digest == digest);
    } else if (data.signer.present == Vanetza_Security_SignerIdentifier_PR_certificate) {
        if (data.signer.choice.certificate.list.count >= 1) {
            HashedId8 cert_hid8 = calculate_hashed_id8(security, *data.signer.choice.certificate.list.array[0]);
            result = (cert_hid8 == digest);
        }
    }

    return result;
}

HashAlgorithm get_hash_algorithm(const Vanetza_Security_SignedData_t& data)
{
    switch (data.hashId) {
        case Vanetza_Security_HashAlgorithm_sha256:
            return HashAlgorithm::SHA256;
        case Vanetza_Security_HashAlgorithm_sha384:
            return HashAlgorithm::SHA384;
        default:
            return HashAlgorithm::Unspecified;
    }
}

template<>
Sha256Hash calculate_digest(SecurityModule& security, const Vanetza_Security_ToBeSignedData_t& data,
    const Vanetza_Security_Certificate_t* cert)
{
    std::array<std::uint8_t, 2 * 32> concat_hash;
    ByteBuffer tbs = asn1::encode_oer(asn_DEF_Vanetza_Security_ToBeSignedData, &data);
    Sha256Hash tbs_hash = security.calculate_sha256_hash(tbs.data(), tbs.size());
    std::copy(tbs_hash.octets.begin(), tbs_hash.octets.end(), concat_hash.data());
    if (cert) {
        Sha256Hash signer_hash = calculate_sha256_hash(security, *cert);
        std::copy(signer_hash.octets.begin(), signer_hash.octets.end(), concat_hash.data() + 32);
    } else {
        static const Sha256Hash empty_string_hash = security.calculate_sha256_hash(nullptr, 0);
        std::copy(empty_string_hash.octets.begin(), empty_string_hash.octets.end(), concat_hash.data() + 32);
    }

    return security.calculate_sha256_hash(concat_hash.data(), concat_hash.size());
}

template<>
Sha384Hash calculate_digest(SecurityModule& security, const Vanetza_Security_ToBeSignedData_t& data,
    const Vanetza_Security_Certificate_t* cert)
{
    std::array<std::uint8_t, 2 * 48> concat_hash;
    ByteBuffer tbs = asn1::encode_oer(asn_DEF_Vanetza_Security_ToBeSignedData, &data);
    Sha384Hash tbs_hash = security.calculate_sha384_hash(tbs.data(), tbs.size());
    std::copy(tbs_hash.octets.begin(), tbs_hash.octets.end(), concat_hash.data());
    if (cert) {
        Sha384Hash signer_hash = calculate_sha384_hash(security, *cert);
        std::copy(signer_hash.octets.begin(), signer_hash.octets.end(), concat_hash.data() + 48);
    } else {
        static const Sha384Hash empty_string_hash = security.calculate_sha384_hash(nullptr, 0);
        std::copy(empty_string_hash.octets.begin(), empty_string_hash.octets.end(), concat_hash.data() + 48);
    }

    return security.calculate_sha384_hash(concat_hash.data(), concat_hash.size());
}

} // namespace pki
} // namespace vanetza
