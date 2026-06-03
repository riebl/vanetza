#pragma once

#include "hashed_id8.hpp"
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/CertificateRevocationListMessage.h>
#include <boost/optional/optional.hpp>
#include <filesystem>
#include <string>
#include <vector>

namespace vanetza
{
namespace pki
{

class SecurityModule;

class CertificateRevocationList
{
public:
    CertificateRevocationList();
    bool decode(const std::string&);
    bool decode(const ByteBuffer&);
    ByteBuffer encode() const;

    /**
     * Read the OER-encoded CRL message from a file and decode it.
     *
     * \throws DecodingFailure if the file is empty or decoding fails
     */
    static CertificateRevocationList from_file(const std::filesystem::path&);

    boost::optional<HashedId8> get_hashed_id8(SecurityModule&) const;

    /**
     * Decode the signed payload and return the revoked HashedId8 entries.
     * An empty vector is valid: CRLs are reissued periodically even when
     * nothing is revoked. boost::none indicates a decode failure.
     */
    boost::optional<std::vector<HashedId8>> revoked_entries() const;

    const Vanetza_Security_EtsiTs103097Data_t& raw() const
    {
        return *m_asn1;
    }

private:
    asn1::asn1c_oer_wrapper<Vanetza_Security_CertificateRevocationListMessage_t> m_asn1;
};

} // namespace pki
} // namespace vanetza
