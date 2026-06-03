#include "certificate_revocation_list.hpp"
#include "asn1.hpp"
#include "certificate.hpp"
#include "exception.hpp"
#include "filesystem.hpp"
#include "validation.hpp"
#include <vanetza/asn1/security/ToBeSignedCrl.h>

namespace vanetza
{
namespace pki
{

CertificateRevocationList::CertificateRevocationList() :
    m_asn1(asn_DEF_Vanetza_Security_CertificateRevocationListMessage)
{
}

bool CertificateRevocationList::decode(const std::string& buffer)
{
    return m_asn1.decode(buffer.data(), buffer.size());
}

bool CertificateRevocationList::decode(const ByteBuffer& buffer)
{
    return m_asn1.decode(buffer.data(), buffer.size());
}

ByteBuffer CertificateRevocationList::encode() const
{
    return m_asn1.encode();
}

CertificateRevocationList CertificateRevocationList::from_file(const std::filesystem::path& path)
{
    ByteBuffer buffer = read(path);
    if (buffer.empty()) {
        throw DecodingFailure("CRL file is empty or missing");
    }

    CertificateRevocationList crl;
    if (!crl.decode(buffer)) {
        throw DecodingFailure("CRL message could not be decoded");
    }
    return crl;
}

boost::optional<HashedId8> CertificateRevocationList::get_hashed_id8(SecurityModule& security) const
{
    const Vanetza_Security_SignedData_t* signed_data = get_signed_data(raw());
    if (signed_data) {
        switch (signed_data->signer.present) {
            case Vanetza_Security_SignerIdentifier_PR_digest:
                return HashedId8::from_buffer(signed_data->signer.choice.digest);
            case Vanetza_Security_SignerIdentifier_PR_certificate: {
                const Vanetza_Security_SequenceOfCertificate_t& certs = signed_data->signer.choice.certificate;
                if (certs.list.count == 1 && certs.list.array[0]) {
                    return calculate_hashed_id8(security, *certs.list.array[0]);
                }
            } break;
            default:
                break;
        }
    }

    return boost::none;
}

boost::optional<std::vector<HashedId8>> CertificateRevocationList::revoked_entries() const
{
    const OCTET_STRING_t* opaque = get_signed_payload(raw().content);
    if (!opaque) {
        return boost::none;
    }

    // Signed payload is an EtsiTs102941Data carrying the ToBeSignedCrl in its content CHOICE.
    MgmtData mgmt;
    if (!mgmt.decode(*opaque)) {
        return boost::none;
    }
    if (mgmt->content.present != Vanetza_Security_EtsiTs102941DataContent_PR_certificateRevocationList) {
        return boost::none;
    }
    const Vanetza_Security_ToBeSignedCrl_t& tbs = mgmt->content.choice.certificateRevocationList;

    const auto& list = tbs.entries.list;
    std::vector<HashedId8> result;
    result.reserve(list.count);
    for (int i = 0; i < list.count; ++i) {
        const Vanetza_Security_CrlEntry_t* entry = list.array[i];
        if (!entry) {
            continue;
        }
        if (auto id = HashedId8::from_buffer(*entry)) {
            result.push_back(*id);
        }
    }
    return result;
}

} // namespace pki
} // namespace vanetza
